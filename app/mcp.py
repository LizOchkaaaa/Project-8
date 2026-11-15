"""Stateless Streamable HTTP, JSON responses, explicit local bearer mode."""

import json
import os
import secrets
from urllib.parse import urlsplit

from flask import jsonify, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from app.local_security import api_error, local_request, same_origin
from security_assistant.parsers import MAX_BYTES, SCANNERS, strict_json
from security_assistant.runtime import PROTOCOL_VERSION, ConfigError
from security_assistant.service import BusyError

VERSIONS = {PROTOCOL_VERSION, "2025-03-26"}
MCP_LIMIT = 5 * MAX_BYTES + 64 * 1024
EMPTY_SCHEMA = {"type": "object", "properties": {}, "additionalProperties": False}
POLICY_SCHEMA = {
    "type": "object",
    "required": ["revision", "effective_policy"],
    "properties": {"revision": {"type": "string"}, "effective_policy": {"type": "object"}},
    "additionalProperties": False,
}
ANALYSIS_SCHEMA = {
    "type": "object",
    "required": [
        "schema_version",
        "gate",
        "scans",
        "groups",
        "advisory",
        "runtime_revision",
        "duration_ms",
    ],
    "properties": {
        "schema_version": {"type": "integer", "const": 1},
        "gate": {"type": "object"},
        "scans": {"type": "object"},
        "groups": {"type": "array"},
        "advisory": {"type": "object"},
        "runtime_revision": {"type": "string"},
        "duration_ms": {"type": "integer", "minimum": 0},
        "tool_fetch": {"type": "object"},
    },
    "additionalProperties": False,
}
TOOLS = [
    {
        "name": "get_policy",
        "description": "Read the effective report policy and runtime revision.",
        "inputSchema": EMPTY_SCHEMA,
        "outputSchema": POLICY_SCHEMA,
    },
    {
        "name": "analyze_reports",
        "description": "Analyze raw scanner JSON. Missing or invalid reports block the gate. No freshness or release claim.",
        "inputSchema": {
            "type": "object",
            "required": ["reports"],
            "additionalProperties": False,
            "properties": {
                "reports": {
                    "type": "object",
                    "minProperties": 1,
                    "maxProperties": 5,
                    "properties": {name: {} for name in SCANNERS},
                    "additionalProperties": False,
                }
            },
        },
        "outputSchema": ANALYSIS_SCHEMA,
    },
    {
        "name": "run_tools",
        "description": "GET ready JSON reports from configured connectors; does not start scanners or verify freshness.",
        "inputSchema": EMPTY_SCHEMA,
        "outputSchema": ANALYSIS_SCHEMA,
    },
]


def rpc_error(identifier, code, message, status=200):
    return jsonify(jsonrpc="2.0", id=identifier, error={"code": code, "message": message}), status


def tool_result(value, error=False):
    result = {
        "content": [{"type": "text", "text": json.dumps(value, ensure_ascii=True)}],
        "isError": error,
    }
    if not error:
        result["structuredContent"] = value
    return result


def configured_origins():
    origins = os.environ.get("PROJECT8_MCP_ALLOWED_ORIGINS", "")
    allowed = []
    for origin in origins.split(",") if origins else ():
        try:
            parsed = urlsplit(origin)
            valid = (
                parsed.scheme in {"http", "https"}
                and parsed.hostname
                and parsed.port != 0
                and not parsed.username
                and not parsed.password
                and not parsed.path
                and not parsed.query
                and not parsed.fragment
                and origin.isascii()
                and not any(c.isspace() or c in "*\\" for c in origin)
            )
        except ValueError:
            valid = False
        if valid:
            allowed.append(origin)
    return tuple(allowed)


def register_mcp(app, service):
    token = os.environ.get("PROJECT8_MCP_TOKEN", "")
    enabled = (
        bool(token)
        and len(token) <= 4096
        and token.isascii()
        and all(33 <= ord(c) <= 126 for c in token)
    )
    origins = configured_origins()

    def call_tool(params):
        if (
            type(params) is not dict
            or not {"name"} <= params.keys()
            or not params.keys() <= {"name", "arguments", "_meta"}
            or type(params["name"]) is not str
        ):
            return None
        name, arguments = params["name"], params.get("arguments", {})
        if name not in {tool["name"] for tool in TOOLS} or type(arguments) is not dict:
            return None
        if name in {"get_policy", "run_tools"} and arguments:
            return None
        reports = {}
        if name == "analyze_reports":
            if set(arguments) != {"reports"} or type(arguments["reports"]) is not dict:
                return None
            values = arguments["reports"]
            if not 1 <= len(values) <= 5 or not values.keys() <= set(SCANNERS):
                return None
        try:
            if name == "get_policy":
                snapshot = service.store.snapshot()
                return tool_result(
                    {
                        "revision": snapshot["revision"],
                        "effective_policy": snapshot["effective_policy"],
                    }
                )
            with service.admission() as snapshot:
                if name == "analyze_reports":
                    for scanner, value in values.items():
                        raw = json.dumps(value, ensure_ascii=True, allow_nan=False).encode()
                        if len(raw) > MAX_BYTES:
                            return tool_result(
                                {
                                    "error": {
                                        "code": "report_too_large",
                                        "message": "Report exceeds the size limit.",
                                    }
                                },
                                True,
                            )
                        reports[scanner] = raw
                value = (
                    service.run_tools(snapshot)
                    if name == "run_tools"
                    else service.process(reports, snapshot)
                )
                return tool_result(value)
        except ConfigError:
            return tool_result(
                {
                    "error": {
                        "code": "config_unavailable",
                        "message": "Runtime configuration is unavailable. Analysis is blocked.",
                    }
                },
                True,
            )
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            return tool_result(
                {"error": {"code": "analysis_failed", "message": "Could not analyze reports."}},
                True,
            )

    @app.before_request
    def guard_mcp():
        if request.path != "/mcp":
            return None
        if not enabled:
            return api_error("mcp_disabled", 404)
        if (
            not local_request()
            or not same_origin(origins)
            or not secrets.compare_digest(
                request.headers.get("Authorization", "").encode(), ("Bearer " + token).encode()
            )
        ):
            return api_error("forbidden", 403)
        if request.method != "POST":
            response = jsonify(
                error={
                    "code": "method_not_allowed",
                    "message": "Only POST is supported; SSE is unavailable.",
                }
            )
            response.headers["Allow"] = "POST"
            return response, 405

    @app.route("/mcp", methods=["GET", "POST"], provide_automatic_options=False)
    def mcp():
        version = request.headers.get("MCP-Protocol-Version", "2025-03-26")
        if version not in VERSIONS:
            return rpc_error(None, -32600, "Unsupported protocol version.", 400)
        if (
            request.mimetype != "application/json"
            or request.mimetype_params.get("charset", "utf-8").lower() != "utf-8"
        ):
            return rpc_error(None, -32600, "Content-Type must be application/json UTF-8.", 415)
        if any(
            request.accept_mimetypes[media] <= 0
            for media in ("application/json", "text/event-stream")
        ):
            return rpc_error(
                None, -32600, "Accept must allow application/json and text/event-stream.", 406
            )
        try:
            request.max_content_length = MCP_LIMIT
            message = strict_json(request.stream.read(MCP_LIMIT + 1), MCP_LIMIT)
        except RequestEntityTooLarge:
            return rpc_error(None, -32600, "Request exceeds the size limit.", 413)
        except (BadRequest, OSError, ValueError, TypeError, RecursionError):
            return rpc_error(None, -32700, "Invalid JSON.", 400)
        if (
            type(message) is not dict
            or message.get("jsonrpc") != "2.0"
            or type(message.get("method")) is not str
            or not message.keys() <= {"jsonrpc", "id", "method", "params"}
            or ("id" in message and type(message["id"]) not in (str, int))
        ):
            return rpc_error(None, -32600, "Invalid request.", 400)
        identifier, method = message.get("id"), message["method"]
        status = 200
        params = message.get("params", {})
        if "id" not in message:
            if type(params) is not dict or (
                method == "notifications/initialized" and params and set(params) != {"_meta"}
            ):
                return rpc_error(None, -32602, "Invalid notification params.", 400)
            # Notifications never execute tools and never receive JSON-RPC replies.
            return "", 202
        if type(params) is not dict:
            return rpc_error(identifier, -32602, "Invalid params.")
        if method == "initialize":
            if (
                not {"protocolVersion", "capabilities", "clientInfo"} <= params.keys()
                or not params.keys() <= {"protocolVersion", "capabilities", "clientInfo", "_meta"}
                or type(params["protocolVersion"]) is not str
                or type(params["capabilities"]) is not dict
                or type(params["clientInfo"]) is not dict
                or any(
                    type(params["clientInfo"].get(key)) is not str for key in ("name", "version")
                )
            ):
                return rpc_error(identifier, -32602, "Invalid params.")
            result = {
                "protocolVersion": params["protocolVersion"]
                if params["protocolVersion"] in VERSIONS
                else PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "project8-reports", "version": "1.0.0"},
                "instructions": "Local stateless report analysis. Reports do not prove freshness or authorize a release.",
            }
        elif method == "ping":
            if params and set(params) != {"_meta"}:
                return rpc_error(identifier, -32602, "Invalid params.")
            result = {}
        elif method == "tools/list":
            if params and set(params) != {"_meta"}:
                return rpc_error(identifier, -32602, "Invalid params.")
            result = {"tools": TOOLS}
        elif method == "tools/call":
            try:
                result = call_tool(params)
            except BusyError:
                result = tool_result(
                    {"error": {"code": "busy", "message": "An analysis is already running."}}, True
                )
                status = 429
            if result is None:
                return rpc_error(identifier, -32602, "Unknown tool or invalid arguments.")
        else:
            return rpc_error(identifier, -32601, "Method not found.")
        return jsonify(jsonrpc="2.0", id=identifier, result=result), status

    return enabled
