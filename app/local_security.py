"""Local transport guards; forwarded headers are deliberately unused."""

import ipaddress
from urllib.parse import urlsplit

from flask import jsonify, request

MESSAGES = {
    "forbidden": "Локальный доступ не разрешён.",
    "invalid_config": "Некорректная конфигурация.",
    "config_unavailable": "Конфигурация недоступна или повреждена. Анализ запрещён.",
    "config_write_failed": "Не удалось сохранить конфигурацию.",
    "revision_conflict": "Конфигурация уже изменена. Загрузите актуальную версию.",
    "invalid_request": "Некорректный запрос.",
    "too_large": "Запрос слишком большой.",
    "busy": "Анализ уже выполняется. Дождитесь результата.",
    "analysis_failed": "Не удалось обработать отчёты.",
    "mcp_disabled": "MCP отключён.",
}


def api_error(code, status):
    return jsonify(error={"code": code, "message": MESSAGES[code]}), status


def local_request():
    try:
        host = request.host
        if (
            not host.isascii()
            or any(c.isspace() for c in host)
            or any(c in host for c in "/\\@?#%")
        ):
            return False
        parsed = urlsplit("//" + host)
        port = (
            parsed.port if parsed.port is not None else (443 if request.scheme == "https" else 80)
        )
        return (
            ipaddress.ip_address(request.remote_addr).is_loopback
            and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            and port == int(request.environ["SERVER_PORT"])
            and not host.endswith(":")
        )
    except (ValueError, TypeError, KeyError):
        return False


def same_origin(allowed=()):
    origin = request.headers.get("Origin")
    return origin is None or origin == request.scheme + "://" + request.host or origin in allowed
