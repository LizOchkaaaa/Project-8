import json
import secrets
import tempfile
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from app.local_security import api_error, local_request, same_origin
from app.mcp import register_mcp
from security_assistant.analysis import analyze
from security_assistant.model import endpoint
from security_assistant.parsers import MAX_BYTES, SCANNERS, ReportError, strict_json
from security_assistant.runtime import (
    CONFIG_LIMIT,
    PROTOCOL_VERSION,
    ConfigError,
    RuntimeConfig,
)
from security_assistant.service import AnalysisService, BusyError

security_api = Blueprint("security_api", __name__)


def register_security(app):
    token = secrets.token_urlsafe(32)
    store = RuntimeConfig(Path(app.instance_path) / "runtime-config.json")
    service = AnalysisService(store)
    app.extensions["security_service"] = service
    mcp_enabled = register_mcp(app, service)

    def authorized():
        return (
            local_request()
            and same_origin()
            and secrets.compare_digest(
                request.headers.get("X-Assistant-Token", "").encode(), token.encode()
            )
        )

    def config_response(snapshot):
        response = jsonify(
            **snapshot,
            mcp={"enabled": mcp_enabled, "endpoint": "/mcp", "protocol_version": PROTOCOL_VERSION},
        )
        response.set_etag(snapshot["revision"])
        return response

    @app.context_processor
    def assistant_context():
        return {"assistant_token": token if local_request() else ""}

    @app.get("/admin")
    def admin():
        if not local_request():
            return api_error("forbidden", 403)
        return render_template("admin.html")

    @app.route("/api/security/config", methods=["GET", "PUT"])
    def runtime_config():
        if not authorized():
            return api_error("forbidden", 403)
        try:
            if request.method == "GET":
                return config_response(store.snapshot())
            request.max_content_length = CONFIG_LIMIT
            if request.mimetype != "application/json":
                return api_error("invalid_config", 400)
            config = strict_json(request.stream.read(CONFIG_LIMIT + 1), CONFIG_LIMIT)
            revision = request.headers.get("If-Match", "")
            if revision.startswith('"') and revision.endswith('"'):
                revision = revision[1:-1]
            return config_response(store.update(config, revision))
        except ConfigError as error:
            return api_error(error.code, error.status)
        except RequestEntityTooLarge:
            return api_error("too_large", 413)
        except (BadRequest, OSError, ValueError, TypeError, RecursionError):
            return api_error("invalid_config", 400)

    @app.get("/api/security/policy")
    def runtime_policy():
        if not authorized():
            return api_error("forbidden", 403)
        try:
            snapshot = store.snapshot()
            return jsonify(
                revision=snapshot["revision"], effective_policy=snapshot["effective_policy"]
            )
        except ConfigError as error:
            return api_error(error.code, error.status)

    @app.post("/api/security/tools/run")
    def run_tools():
        if not authorized():
            return api_error("forbidden", 403)
        try:
            request.max_content_length = CONFIG_LIMIT
            if (
                request.mimetype != "application/json"
                or strict_json(request.stream.read(CONFIG_LIMIT + 1), CONFIG_LIMIT) != {}
            ):
                return api_error("invalid_request", 400)
        except RequestEntityTooLarge:
            return api_error("too_large", 413)
        except (BadRequest, OSError, ValueError, TypeError, KeyError, RecursionError):
            return api_error("invalid_request", 400)
        try:
            with service.admission() as snapshot:
                return jsonify(service.run_tools(snapshot))
        except BusyError:
            return api_error("busy", 429)
        except ConfigError as error:
            return api_error(error.code, error.status)
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            return api_error("analysis_failed", 503)

    @app.post("/api/security/analyze")
    def analyze_uploads():
        if not authorized():
            return jsonify(error="Анализ доступен только локально со страницы /security."), 403
        request.max_content_length = 5 * MAX_BYTES + 64 * 1024
        request.max_form_memory_size = 512 * 1024
        request.max_form_parts = 12
        try:
            with service.admission() as snapshot:
                files = request.files.getlist("reports")
                names = [file.filename for file in files]
                allowed = {f"{scanner}.json" for scanner in SCANNERS}
                if (
                    not files
                    or len(files) > 5
                    or len(set(names)) != len(names)
                    or not set(names) <= allowed
                ):
                    return jsonify(
                        error="Выберите до пяти разных JSON-файлов с именами сканеров."
                    ), 400
                use_model = request.form.get("use_model") == "on"
                config = {
                    "OPENAI_API_KEY": request.form.get("api_key", "").strip(),
                    "OPENAI_BASE_URL": request.form.get("base_url", "").strip(),
                    "OPENAI_MODEL": request.form.get("model", "").strip(),
                }
                if use_model:
                    if (
                        not config["OPENAI_API_KEY"]
                        or len(config["OPENAI_API_KEY"]) > 4096
                        or any(character.isspace() for character in config["OPENAI_API_KEY"])
                        or not config["OPENAI_MODEL"]
                        or len(config["OPENAI_MODEL"]) > 200
                        or len(config["OPENAI_BASE_URL"]) > 2000
                    ):
                        return jsonify(error="Укажите корректные ключ, адрес API и модель."), 400
                    endpoint(config["OPENAI_BASE_URL"] or "https://api.openai.com/v1")
                reports = {}
                for file in files:
                    raw = file.stream.read(MAX_BYTES + 1)
                    if not raw or len(raw) > MAX_BYTES:
                        return jsonify(
                            error="Каждый отчёт должен быть непустым и не больше 8 МиБ."
                        ), 400
                    reports[file.filename[:-5]] = raw
                return jsonify(
                    service.process(
                        reports,
                        snapshot,
                        offline=not use_model,
                        model_config=config,
                        analyzer=analyze,
                    )
                )
        except BusyError:
            return jsonify(error="Анализ уже выполняется. Дождитесь результата."), 429
        except ConfigError:
            return jsonify(error="Конфигурация недоступна или повреждена. Анализ запрещён."), 503
        except (OSError, ReportError, ValueError, TypeError, KeyError):
            return jsonify(error="Не удалось обработать отчёты или настройки API."), 400

    app.register_blueprint(security_api)


@security_api.get("/api/security/demo/<case>")
def demo(case):
    if case not in {"fail", "fixed"}:
        return jsonify(error="Неизвестный учебный пример."), 404
    reports = {
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
    if case == "fail":
        reports["bandit"]["results"] = [
            {
                "test_id": "B602",
                "issue_severity": "HIGH",
                "filename": "demo/example.py",
                "line_number": 4,
            }
        ]
    with tempfile.TemporaryDirectory(prefix="project8-demo-") as directory:
        for scanner, data in reports.items():
            (Path(directory) / f"{scanner}.json").write_text(json.dumps(data), encoding="utf-8")
        result = analyze(directory, offline=True)
    result["advisory"]["message"] = (
        "Учебные синтетические отчёты. Модель и сканеры не запускались. "
        "Для реальной проверки загрузите свои отчёты."
    )
    return jsonify(result)
