"""Минимальный REST API (Flask): список заметок в памяти.

Приложение намеренно простое: оно нужно как мишень для проверок
Gitleaks, Bandit, pip-audit, Trivy и OWASP ZAP.
"""
import os
import threading

from flask import Flask, jsonify, request

MAX_TEXT_LENGTH = 200
MAX_ITEMS = 1000


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 КБ на запрос

    items: list[dict] = []
    lock = threading.Lock()

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        response.headers.pop("Server", None)
        return response

    @app.get("/")
    def index():
        return jsonify(name="secure-release-app", version="1.0.0")

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.get("/api/items")
    def list_items():
        with lock:
            return jsonify(items=list(items))

    @app.post("/api/items")
    def create_item():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error="ожидается JSON-объект"), 400

        text = data.get("text")
        if not isinstance(text, str) or not text.strip():
            return jsonify(error="поле 'text' обязательно"), 400
        text = text.strip()
        if len(text) > MAX_TEXT_LENGTH:
            return jsonify(error="текст слишком длинный"), 400

        with lock:
            if len(items) >= MAX_ITEMS:
                return jsonify(error="хранилище переполнено"), 507
            item = {"id": len(items) + 1, "text": text}
            items.append(item)
        return jsonify(item), 201

    @app.errorhandler(404)
    def not_found(_):
        return jsonify(error="не найдено"), 404

    @app.errorhandler(405)
    def method_not_allowed(_):
        return jsonify(error="метод не разрешён"), 405

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(error="запрос слишком большой"), 413

    return app


app = create_app()

if __name__ == "__main__":
    # Только для локальной разработки. В Docker используется gunicorn.
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "8000")))
