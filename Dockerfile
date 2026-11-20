FROM python:3.13-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PROJECT8_INSTANCE_DIR=/app/instance

WORKDIR /app

RUN apk upgrade --no-cache

COPY requirements.txt .
# Installation tooling is not needed in the running container.
RUN python -m pip install --no-cache-dir -r requirements.txt \
    && python -m pip check \
    && python -m pip uninstall -y pip \
    && rm -rf /usr/local/lib/python3.13/ensurepip

COPY app ./app
COPY security_assistant ./security_assistant
COPY .security ./.security
COPY docs ./docs

# Запуск не от root
RUN adduser -S -D -H -u 10001 appuser \
    && install -d -m 0700 -o appuser "$PROJECT8_INSTANCE_DIR"
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1

# Профиль модели может ждать до 120 секунд; конфигурация и ключи привязаны к одному процессу.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--timeout", "150", "app.main:app"]
