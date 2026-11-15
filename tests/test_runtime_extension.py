import copy
import io
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from jinja2 import DictLoader

from app.main import create_app
from security_assistant import service as service_module
from security_assistant.parsers import SCANNERS, strict_json
from security_assistant.runtime import (
    CONFIG_LIMIT,
    ConfigError,
    RuntimeConfig,
    credential_name,
    default_config,
    validate_config,
)


@pytest.fixture
def web(tmp_path, monkeypatch):
    monkeypatch.setenv("PROJECT8_MCP_TOKEN", "dedicated-test-mcp-token")
    app = create_app()
    app.testing = True
    service = app.extensions["security_service"]
    service.store.path = tmp_path / "instance" / "runtime-config.json"
    client = app.test_client()
    token = re.search(r'data-token="([^"]+)"', client.get("/security").text).group(1)
    return app, client, {"X-Assistant-Token": token}, service


@pytest.fixture
def reports():
    return {
        "gitleaks": [],
        "bandit": {"errors": [], "metrics": {"_totals": {"loc": 4}}, "results": []},
        "pip-audit": {"dependencies": [{"name": "demo", "version": "1.0", "vulns": []}]},
        "trivy": {
            "SchemaVersion": 2,
            "ArtifactName": "demo:image",
            "ArtifactType": "container_image",
            "Results": [
                {
                    "Target": "demo",
                    "Class": "lang-pkgs",
                    "Type": "python-pkg",
                    "Vulnerabilities": [],
                }
            ],
        },
        "zap": {"@version": "2.16.1", "site": [{"@name": "http://localhost", "alerts": []}]},
    }


def rpc(client, method, params=None, **kwargs):
    headers = {
        "Authorization": "Bearer dedicated-test-mcp-token",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-11-25",
    }
    headers.update(kwargs.pop("headers", {}))
    message = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        message["params"] = params
    return client.post("/mcp", json=message, headers=headers, **kwargs)


def upload(client, headers, reports):
    return client.post(
        "/api/security/analyze",
        headers=headers,
        data={
            "reports": [
                (io.BytesIO(json.dumps(value).encode()), name + ".json")
                for name, value in reports.items()
            ]
        },
    )


def test_config_roundtrip_revision_and_secret_isolation(web, monkeypatch):
    _, client, headers, service = web
    monkeypatch.setenv("OPENAI_API_KEY", "private-server-model")
    monkeypatch.setenv("PROJECT8_CONNECTOR_ZAP_TOKEN", "private-connector")
    response = client.get("/api/security/config", headers=headers)
    snapshot = response.json
    assert snapshot["config"] == default_config()
    assert snapshot["revision"] == "0"
    assert snapshot["mcp"] == {
        "enabled": True,
        "endpoint": "/mcp",
        "protocol_version": "2025-11-25",
    }
    config = snapshot["config"]
    config["thresholds"]["bandit"] = "critical"
    config["connectors"]["zap"]["credential_env"] = credential_name("zap")
    response = client.put(
        "/api/security/config",
        json=config,
        headers={**headers, "If-Match": response.headers["ETag"]},
    )
    assert response.status_code == 200
    assert response.json["revision"] != "0"
    assert service.store.snapshot()["config"] == config
    assert RuntimeConfig(service.store.path).snapshot()["config"] == config
    persisted = service.store.path.read_text()
    combined = persisted + response.text
    assert not any(
        secret in combined
        for secret in ("private-server-model", "private-connector", "dedicated-test-mcp-token")
    )
    assert (
        client.put(
            "/api/security/config", json=config, headers={**headers, "If-Match": "0"}
        ).status_code
        == 409
    )
    assert client.get("/api/security/policy", headers=headers).json == {
        key: response.json[key] for key in ("revision", "effective_policy")
    }


def test_config_concurrent_writers_and_write_failure(tmp_path, monkeypatch):
    store = RuntimeConfig(tmp_path / "runtime-config.json")
    barrier = threading.Barrier(2)

    def update(level):
        config = default_config()
        config["thresholds"]["bandit"] = level
        barrier.wait(timeout=3)
        try:
            return store.update(config, "0")["revision"]
        except ConfigError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(update, ("low", "critical")))
    assert results.count("revision_conflict") == 1
    before = store.snapshot()
    raw = store.path.read_bytes()

    def fail_replace(*args):
        raise OSError("private path and secret")

    monkeypatch.setattr("security_assistant.runtime.os.replace", fail_replace)
    with pytest.raises(ConfigError, match="config_write_failed"):
        store.update(default_config(), before["revision"])
    assert store.snapshot() == before and store.path.read_bytes() == raw
    assert list(tmp_path.iterdir()) == [store.path]


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b'{"revision":"0","config":{},"config":{}}',
        b"x",
        b" " * (CONFIG_LIMIT + 1),
        b'{"schema_version":NaN}',
    ],
    ids=["empty_object", "duplicate_keys", "malformed", "oversized", "non_finite"],
)
def test_corrupted_config_blocks_every_analysis_without_repair(web, raw, reports):
    _, client, headers, service = web
    service.store.path.parent.mkdir()
    service.store.path.write_bytes(raw)
    response = client.get("/api/security/config", headers=headers)
    assert response.status_code == 503 and response.json["error"]["code"] == "config_unavailable"
    assert upload(client, headers, reports).status_code == 503
    assert client.post("/api/security/tools/run", json={}, headers=headers).status_code == 503
    result = rpc(
        client, "tools/call", {"name": "analyze_reports", "arguments": {"reports": reports}}
    ).json["result"]
    assert result["isError"] and "config_unavailable" in result["content"][0]["text"]
    assert service.store.path.read_bytes() == raw
    service.store.path.unlink()
    assert upload(client, headers, reports).status_code == 200


@pytest.mark.parametrize(
    "change",
    [
        lambda c: c.update(schema_version=True),
        lambda c: c.update(fail_closed=False),
        lambda c: c.update(required_scanners=[]),
        lambda c: c["thresholds"].pop("zap"),
        lambda c: c["thresholds"].update(zap="info"),
        lambda c: c["thresholds"].update(zap=True),
        lambda c: c["connectors"].pop("zap"),
        lambda c: c["connectors"]["zap"].update(enabled=1),
        lambda c: c["connectors"]["zap"].update(credential_env="OPENAI_API_KEY"),
        lambda c: c["connectors"]["zap"].update(credential_env="PROJECT8_MCP_TOKEN"),
        lambda c: c["connectors"]["pip-audit"].update(
            credential_env="PROJECT8_CONNECTOR_ZAP_TOKEN"
        ),
        lambda c: c["connectors"]["zap"].update(command="scan"),
        lambda c: c["timeouts"].update(workers=True),
        lambda c: c["timeouts"].update(workers=4),
        lambda c: c["timeouts"].update(total_seconds=16),
        lambda c: c["timeouts"].update(read_seconds=1.5),
    ],
)
def test_config_exact_types_and_mandatory_policy(web, change):
    _, client, headers, _ = web
    config = default_config()
    change(config)
    response = client.put("/api/security/config", json=config, headers={**headers, "If-Match": "0"})
    assert response.status_code == 400 and response.json["error"]["code"] == "invalid_config"


@pytest.mark.parametrize(
    "origin", ["null", "http://localhost:81", "https://localhost", "http://evil.example"]
)
def test_api_origin_and_independent_tokens(web, origin):
    _, client, headers, _ = web
    for route in ("/api/security/config", "/api/security/policy"):
        assert client.get(route, headers={**headers, "Origin": origin}).status_code == 403
        assert (
            client.get(route, headers={"X-Assistant-Token": "dedicated-test-mcp-token"}).status_code
            == 403
        )
    assert (
        client.post("/api/security/analyze", headers={**headers, "Origin": origin}).status_code
        == 403
    )
    assert (
        client.post(
            "/api/security/tools/run", json={}, headers={**headers, "Origin": origin}
        ).status_code
        == 403
    )
    assert (
        client.get(
            "/api/security/config", headers={**headers, "Origin": "http://localhost"}
        ).status_code
        == 200
    )


@pytest.mark.parametrize(
    "host,remote",
    [
        ("evil.example", "127.0.0.1"),
        ("localhost:81", "127.0.0.1"),
        ("localhost:0", "127.0.0.1"),
        ("localhost", "192.0.2.1"),
        ("localhost.", "127.0.0.1"),
    ],
)
def test_strict_local_host_and_no_forwarded_trust(web, host, remote):
    _, client, headers, _ = web
    headers = {
        **headers,
        "Host": host,
        "Forwarded": "for=127.0.0.1;host=localhost",
        "X-Forwarded-For": "127.0.0.1",
        "X-Forwarded-Host": "localhost",
    }
    env = {"REMOTE_ADDR": remote}
    assert client.get("/admin", headers=headers, environ_overrides=env).status_code == 403
    assert (
        client.get("/api/security/config", headers=headers, environ_overrides=env).status_code
        == 403
    )


def test_admin_template_context_and_no_token_url(web):
    app, client, headers, _ = web
    app.jinja_loader = DictLoader({"admin.html": "{{ assistant_token }}"})
    assert client.get("/admin").text == headers["X-Assistant-Token"]
    assert (
        client.get("/api/security/config?token=" + headers["X-Assistant-Token"]).status_code == 403
    )


def test_duplicate_depth_and_oversized_json_are_bounded(web):
    _, client, headers, _ = web
    for raw in (b'{"schema_version":1,"schema_version":1}', b"[" * 65 + b"]" * 65):
        assert (
            client.put(
                "/api/security/config", data=raw, content_type="application/json", headers=headers
            ).status_code
            == 400
        )
    assert (
        client.put(
            "/api/security/config",
            data=b"x" * (CONFIG_LIMIT + 1),
            content_type="application/json",
            headers=headers,
        ).status_code
        == 413
    )
    with pytest.raises(ValueError):
        strict_json(b'{"x":Infinity}', CONFIG_LIMIT)
    assert validate_config(default_config()) == default_config()


@pytest.mark.parametrize("arguments", [[], {"url": "http://localhost"}, {"reports": {}}, None])
def test_run_tools_accepts_exact_empty_object(web, arguments):
    _, client, headers, _ = web
    response = client.post(
        "/api/security/tools/run",
        data=json.dumps(arguments),
        content_type="application/json",
        headers=headers,
    )
    assert response.status_code == 400


def test_disabled_connectors_are_missing_and_blocked(web):
    _, client, headers, _ = web
    response = client.post("/api/security/tools/run", json={}, headers=headers)
    assert response.status_code == 200 and response.json["gate"]["status"] == "blocked"
    assert response.json["runtime_revision"] == "0"
    assert all(state["status"] == "error" for state in response.json["scans"].values())
    assert all(
        state["status"] == "disabled"
        for state in response.json["tool_fetch"]["connectors"].values()
    )


@pytest.mark.parametrize("severity", ["LOW", "UNKNOWN", "CRITICAL"])
def test_same_policy_snapshot_gate_upload_tools_mcp(web, reports, monkeypatch, severity):
    _, client, headers, service = web
    config = default_config()
    config["thresholds"]["bandit"] = "critical"
    snapshot = service.store.update(config, "0")
    reports["bandit"]["results"] = [
        {"test_id": "B602", "issue_severity": severity, "filename": "example.py", "line_number": 1}
    ]
    raw = {name: json.dumps(value).encode() for name, value in reports.items()}
    monkeypatch.setattr(service_module, "fetch_all", lambda config: (raw, {}))
    monkeypatch.setenv("OPENAI_API_KEY", "never-inherit-this")
    uploaded = upload(client, headers, reports).json
    tools = client.post("/api/security/tools/run", json={}, headers=headers).json
    mcp = rpc(
        client, "tools/call", {"name": "analyze_reports", "arguments": {"reports": reports}}
    ).json["result"]
    assert mcp["isError"] is False
    assert json.loads(mcp["content"][0]["text"]) == mcp["structuredContent"]
    results = [uploaded, tools, mcp["structuredContent"]]
    for result in results:
        assert result["gate"] == uploaded["gate"]
        assert result["runtime_revision"] == snapshot["revision"]
        assert result["advisory"]["mode"] == "fallback"
        assert result["gate"]["scope"] == "reports_only"
    assert uploaded["gate"]["status"] == ("passed" if severity == "LOW" else "blocked")


def test_gitleaks_is_always_blocking(web, reports):
    _, client, headers, service = web
    config = default_config()
    config["thresholds"] = dict.fromkeys(SCANNERS, "critical")
    service.store.update(config, "0")
    reports["gitleaks"] = [{"RuleID": "example", "File": "example.py", "StartLine": 1}]
    assert upload(client, headers, reports).json["gate"]["status"] == "blocked"


@pytest.mark.parametrize("source", ["upload", "tools", "mcp"])
def test_shared_admission_across_transports_and_release(web, reports, monkeypatch, source):
    app, client, headers, _ = web
    started, finish = threading.Event(), threading.Event()
    original = service_module.AnalysisService.process

    def slow(self, *args, **kwargs):
        started.set()
        assert finish.wait(5)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(service_module.AnalysisService, "process", slow)
    responses = []

    def first():
        other = app.test_client()
        if source == "upload":
            responses.append(upload(other, headers, reports).status_code)
        elif source == "tools":
            responses.append(
                other.post("/api/security/tools/run", json={}, headers=headers).status_code
            )
        else:
            responses.append(
                rpc(
                    other,
                    "tools/call",
                    {"name": "analyze_reports", "arguments": {"reports": reports}},
                ).status_code
            )

    thread = threading.Thread(target=first)
    thread.start()
    try:
        assert started.wait(3)
        assert client.post("/api/security/analyze", headers=headers).status_code == 429
        assert client.post("/api/security/tools/run", json={}, headers=headers).status_code == 429
        response = rpc(client, "tools/call", {"name": "run_tools", "arguments": {}})
        assert response.status_code == 429
        result = response.json["result"]
        assert result["isError"] and '"busy"' in result["content"][0]["text"]
    finally:
        finish.set()
        thread.join(5)
    assert not thread.is_alive() and responses == [200]
    assert upload(client, headers, reports).status_code == 200


def test_semaphore_released_on_unexpected_error(web, monkeypatch):
    _, client, headers, service = web

    def fail(snapshot):
        raise RuntimeError("unexpected private failure")

    with monkeypatch.context() as patch:
        patch.setattr(service, "run_tools", fail)
        with pytest.raises(RuntimeError):
            client.post("/api/security/tools/run", json={}, headers=headers)
    assert client.post("/api/security/tools/run", json={}, headers=headers).status_code == 200


def test_analysis_uses_immutable_revision_during_config_update(web, reports, monkeypatch):
    _, _, _, service = web
    initial = service.store.snapshot()
    config = copy.deepcopy(initial["config"])
    config["thresholds"]["bandit"] = "critical"

    def fetch(old_config):
        service.store.update(config, initial["revision"])
        assert old_config["thresholds"]["bandit"] == "medium"
        return {name: json.dumps(value).encode() for name, value in reports.items()}, {}

    monkeypatch.setattr(service_module, "fetch_all", fetch)
    with service.admission() as snapshot:
        result = service.run_tools(snapshot)
    assert result["runtime_revision"] == "0" and service.store.snapshot()["revision"] != "0"


def test_mcp_handshake_tools_and_stateless_compatibility(web, reports):
    _, client, _, _ = web
    response = rpc(
        client,
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    )
    assert response.status_code == 200
    assert response.json["result"]["protocolVersion"] == "2025-11-25"
    assert response.json["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert "Mcp-Session-Id" not in response.headers
    headers = {
        "Authorization": "Bearer dedicated-test-mcp-token",
        "Accept": "application/json, text/event-stream",
    }
    notification = client.post(
        "/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    assert notification.status_code == 202 and not notification.data
    assert rpc(client, "ping").json["result"] == {}
    listing = rpc(client, "tools/list").json["result"]["tools"]
    assert {tool["name"] for tool in listing} == {"get_policy", "analyze_reports", "run_tools"}
    assert all("inputSchema" in tool and "outputSchema" in tool for tool in listing)
    result = rpc(client, "tools/call", {"name": "get_policy", "arguments": {}}).json["result"]
    assert not result["isError"] and set(result["structuredContent"]) == {
        "revision",
        "effective_policy",
    }
    result = rpc(
        client, "tools/call", {"name": "analyze_reports", "arguments": {"reports": {"bandit": {}}}}
    ).json["result"]
    assert not result["isError"] and result["structuredContent"]["gate"]["status"] == "blocked"
    result = rpc(client, "tools/call", {"name": "run_tools", "arguments": {}}).json["result"]
    assert not result["isError"] and result["structuredContent"]["gate"]["status"] == "blocked"
    fallback = client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": "legacy",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        },
    )
    assert fallback.json["result"]["protocolVersion"] == "2025-03-26"
    assert (
        client.post(
            "/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 9, "method": "ping"}
        ).json["result"]
        == {}
    )
    negotiated = rpc(
        client,
        "initialize",
        {
            "protocolVersion": "2099-01-01",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    )
    assert negotiated.json["result"]["protocolVersion"] == "2025-11-25"


@pytest.mark.parametrize(
    "params",
    [
        {"name": "unknown", "arguments": {}},
        {"name": "get_policy", "arguments": {"policy": {}}},
        {"name": "run_tools", "arguments": {"url": "http://localhost"}},
        {"name": "run_tools", "arguments": {"scanners": ["gitleaks"]}},
        {"name": "analyze_reports", "arguments": {"reports": {}}},
        {"name": "analyze_reports", "arguments": {"reports": {"unknown": []}}},
        {"name": "analyze_reports", "arguments": {"reports": {"gitleaks": []}, "policy": {}}},
        {"name": "analyze_reports", "arguments": {"reports": {"gitleaks": []}, "model": "x"}},
        {"name": "analyze_reports", "arguments": {"reports": {"gitleaks": []}, "path": "private"}},
        {"name": "get_policy", "arguments": []},
        {"name": "get_policy", "arguments": {}, "extra": True},
    ],
)
def test_mcp_protocol_errors_for_invalid_tool_arguments(web, params):
    _, client, _, _ = web
    result = rpc(client, "tools/call", params).json
    assert result["error"]["code"] == -32602 and "result" not in result


@pytest.mark.parametrize(
    "raw,code",
    [
        (b"{", -32700),
        (b"[]", -32600),
        (b'{"jsonrpc":"2.0","id":true,"method":"ping"}', -32600),
        (b'{"jsonrpc":"2.0","id":null,"method":"ping"}', -32600),
        (b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}', -32700),
        (b'{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}', -32602),
        (b"\xff", -32700),
    ],
)
def test_mcp_invalid_json_rpc(web, raw, code):
    _, client, _, _ = web
    response = client.post(
        "/mcp",
        data=raw,
        content_type="application/json",
        headers={
            "Authorization": "Bearer dedicated-test-mcp-token",
            "Accept": "application/json, text/event-stream",
        },
    )
    assert response.json["error"]["code"] == code


@pytest.mark.parametrize(
    "changed,status",
    [
        ({"Authorization": ""}, 403),
        ({"Authorization": "Bearer é"}, 403),
        ({"Origin": "null"}, 403),
        ({"Origin": "http://localhost:81"}, 403),
        ({"Origin": "https://localhost"}, 403),
        ({"Host": "evil.example"}, 403),
        ({"MCP-Protocol-Version": "2024-11-05"}, 400),
        ({"Accept": "application/json"}, 406),
        ({"Accept": "text/event-stream"}, 406),
        ({"Accept": "application/json, text/event-stream;q=0"}, 406),
        ({"Content-Type": "text/plain"}, 415),
        ({"Content-Type": "application/json; charset=latin-1"}, 415),
    ],
)
def test_mcp_transport_validation(web, changed, status):
    _, client, _, _ = web
    assert rpc(client, "ping", headers=changed).status_code == status


def test_mcp_auth_independence_methods_and_disabled(web, monkeypatch):
    _, client, headers, _ = web
    assert (
        rpc(
            client, "ping", headers={"Authorization": "Bearer " + headers["X-Assistant-Token"]}
        ).status_code
        == 403
    )
    assert (
        rpc(
            client,
            "ping",
            environ_overrides={"REMOTE_ADDR": "192.0.2.1"},
            headers={"X-Forwarded-For": "127.0.0.1"},
        ).status_code
        == 403
    )
    for method in (
        "GET",
        "DELETE",
        "OPTIONS",
        "PUT",
        "PATCH",
        "HEAD",
        "TRACE",
        "CONNECT",
        "CUSTOM",
    ):
        response = client.open(
            "/mcp", method=method, headers={"Authorization": "Bearer dedicated-test-mcp-token"}
        )
        assert response.status_code == 405 and response.headers["Allow"] == "POST"
        assert client.open("/mcp", method=method).status_code == 403
    monkeypatch.delenv("PROJECT8_MCP_TOKEN")
    other = create_app().test_client()
    assert other.post("/mcp", json={}).status_code == 404
    html = client.get("/security").text
    assert "dedicated-test-mcp-token" not in html


def test_mcp_unknown_method_notification_has_no_side_effect(web, monkeypatch):
    _, client, _, service = web
    assert rpc(client, "unknown").json["error"]["code"] == -32601
    assert rpc(client, "initialize", {}).json["error"]["code"] == -32602

    def fail(*args):
        pytest.fail("A notification must not execute an analysis")

    monkeypatch.setattr(service, "run_tools", fail)
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "run_tools", "arguments": {}},
        },
        headers={
            "Authorization": "Bearer dedicated-test-mcp-token",
            "Accept": "application/json, text/event-stream",
        },
    )
    assert response.status_code == 202 and not response.data


def test_mcp_restrictive_origin_allowlist(tmp_path, monkeypatch):
    monkeypatch.setenv("PROJECT8_MCP_TOKEN", "dedicated-test-mcp-token")
    monkeypatch.setenv("PROJECT8_MCP_ALLOWED_ORIGINS", "*,null,http://trusted.example:1234")
    client = create_app().test_client()
    assert rpc(client, "ping", headers={"Origin": "http://trusted.example:1234"}).status_code == 200
    assert rpc(client, "ping", headers={"Origin": "http://trusted.example:1235"}).status_code == 403
    assert rpc(client, "ping", headers={"Origin": "null"}).status_code == 403


def test_mcp_body_bound_before_parsing(web, monkeypatch):
    _, client, _, _ = web
    monkeypatch.setattr("app.mcp.MCP_LIMIT", 64)
    response = client.post(
        "/mcp",
        data=b" " * 65,
        content_type="application/json",
        headers={
            "Authorization": "Bearer dedicated-test-mcp-token",
            "Accept": "application/json, text/event-stream",
        },
    )
    assert response.status_code == 413


def test_config_fsync_failure_keeps_disk_and_revision(web, monkeypatch):
    _, client, headers, service = web
    initial = service.store.update(default_config(), "0")
    raw = service.store.path.read_bytes()

    def fail(*args):
        raise OSError("private disk error")

    monkeypatch.setattr("security_assistant.runtime.os.fsync", fail)
    response = client.put(
        "/api/security/config",
        json=default_config(),
        headers={**headers, "If-Match": initial["revision"]},
    )
    assert response.status_code == 503 and response.json["error"]["code"] == "config_write_failed"
    assert service.store.path.read_bytes() == raw and service.store.snapshot() == initial
    assert list(service.store.path.parent.iterdir()) == [service.store.path]
    assert "private" not in response.text


def test_mcp_non_finite_and_invalid_notification_rejected(web):
    _, client, _, _ = web
    headers = {
        "Authorization": "Bearer dedicated-test-mcp-token",
        "Accept": "application/json, text/event-stream",
    }
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"analyze_reports","arguments":{"reports":{"gitleaks":[1e999]}}}}'
    response = client.post("/mcp", data=raw, content_type="application/json", headers=headers)
    assert response.status_code == 400 and response.json["error"]["code"] == -32700
    assert (
        client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": []},
            headers=headers,
        ).status_code
        == 400
    )


def test_cli_subset_still_uses_version_controlled_policy(tmp_path):
    from security_assistant.__main__ import main

    (tmp_path / "gitleaks.json").write_text("[]")
    assert (
        main(
            [
                "--reports",
                str(tmp_path),
                "--output",
                str(tmp_path / "out"),
                "--gate",
                "--scanner",
                "gitleaks",
            ]
        )
        == 0
    )
    result = json.loads((tmp_path / "out" / "analysis.json").read_text(encoding="utf-8"))
    assert set(result["scans"]) == {"gitleaks"} and result["gate"]["status"] == "passed"


def test_mcp_per_report_bound_is_tool_error(web, monkeypatch):
    _, client, _, _ = web
    monkeypatch.setattr("app.mcp.MAX_BYTES", 4)
    result = rpc(
        client,
        "tools/call",
        {"name": "analyze_reports", "arguments": {"reports": {"gitleaks": ["oversized"]}}},
    ).json["result"]
    assert result["isError"] and "report_too_large" in result["content"][0]["text"]


def test_http_ready_reports_end_to_end_api_and_mcp(web, reports, monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    _, client, headers, service = web
    observed = []
    monkeypatch.setenv("PROJECT8_CONNECTOR_BANDIT_TOKEN", "only-bandit-credential")
    monkeypatch.setenv("OPENAI_API_KEY", "private-model-key")

    class ReadyReports(BaseHTTPRequestHandler):
        def do_GET(self):
            scanner = self.path.rsplit("/", 1)[-1]
            observed.append((scanner, self.headers.get("Authorization")))
            raw = json.dumps(reports[scanner]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), ReadyReports)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = default_config()
    for name in SCANNERS:
        config["connectors"][name] = {
            "enabled": True,
            "url": f"http://127.0.0.1:{server.server_port}/ready/{name}",
            "credential_env": credential_name(name) if name == "bandit" else None,
        }
    revision = service.store.update(config, "0")["revision"]
    try:
        api = client.post("/api/security/tools/run", json={}, headers=headers)
        mcp = rpc(client, "tools/call", {"name": "run_tools", "arguments": {}})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
    for result in (api.json, mcp.json["result"]["structuredContent"]):
        assert result["runtime_revision"] == revision and result["gate"]["status"] == "passed"
        assert result["gate"]["scope"] == "reports_only"
        assert all(state["status"] == "clean" for state in result["scans"].values())
        assert all(
            state["status"] == "fetched" for state in result["tool_fetch"]["connectors"].values()
        )
        assert result["advisory"]["mode"] == "fallback"
    assert len(observed) == 10
    assert all(
        auth == ("Bearer only-bandit-credential" if name == "bandit" else None)
        for name, auth in observed
    )
    assert all(
        secret not in api.text + mcp.text
        for secret in ("only-bandit-credential", "private-model-key", "dedicated-test-mcp-token")
    )


def test_admission_is_process_wide_across_app_factories(web):
    _, _, _, service = web
    other = create_app().test_client()
    token = re.search(r'data-token="([^"]+)"', other.get("/security").text).group(1)
    with service.admission():
        assert (
            other.post("/api/security/analyze", headers={"X-Assistant-Token": token}).status_code
            == 429
        )


def test_safe_analysis_failure_and_semaphore_release(web, monkeypatch):
    _, client, headers, service = web

    def fail(*args):
        raise OSError("private path, credential, response body")

    with monkeypatch.context() as patch:
        patch.setattr(service, "run_tools", fail)
        response = client.post("/api/security/tools/run", json={}, headers=headers)
        assert response.status_code == 503 and response.json["error"]["code"] == "analysis_failed"
        assert "private" not in response.text
        result = rpc(client, "tools/call", {"name": "run_tools", "arguments": {}}).json["result"]
        assert result["isError"] and "private" not in result["content"][0]["text"]
    assert client.post("/api/security/tools/run", json={}, headers=headers).status_code == 200


def test_official_mcp_sdk_http_smoke(web, reports):
    """Check compatibility with the optional MCP SDK."""
    import asyncio

    pytest.importorskip("mcp")
    httpx = pytest.importorskip("httpx2")
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    from werkzeug.serving import WSGIRequestHandler, make_server

    app, _, _, _ = web

    class QuietHandler(WSGIRequestHandler):
        def log(self, *args, **kwargs):
            pass

    server = make_server("127.0.0.1", 0, app, threaded=True, request_handler=QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    async def smoke():
        async with httpx.AsyncClient(
            headers={"Authorization": "Bearer dedicated-test-mcp-token"}, trust_env=False
        ) as http:
            async with streamable_http_client(
                f"http://127.0.0.1:{server.server_port}/mcp", http_client=http
            ) as streams:
                async with ClientSession(*streams[:2]) as session:
                    initialized = await session.initialize()
                    assert initialized.model_dump(by_alias=True)["protocolVersion"] == "2025-11-25"
                    assert {tool.name for tool in (await session.list_tools()).tools} == {
                        "get_policy",
                        "analyze_reports",
                        "run_tools",
                    }
                    policy = (await session.call_tool("get_policy", {})).model_dump(by_alias=True)
                    assert not policy["isError"] and policy["structuredContent"]["revision"] == "0"
                    analyzed = (
                        await session.call_tool("analyze_reports", {"reports": reports})
                    ).model_dump(by_alias=True)
                    assert (
                        not analyzed["isError"]
                        and analyzed["structuredContent"]["gate"]["status"] == "passed"
                    )
                    blocked = (
                        await session.call_tool("analyze_reports", {"reports": {"bandit": {}}})
                    ).model_dump(by_alias=True)
                    assert (
                        not blocked["isError"]
                        and blocked["structuredContent"]["gate"]["status"] == "blocked"
                    )
                    fetched = (await session.call_tool("run_tools", {})).model_dump(by_alias=True)
                    assert (
                        not fetched["isError"]
                        and fetched["structuredContent"]["gate"]["status"] == "blocked"
                    )

    try:
        asyncio.run(smoke())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
