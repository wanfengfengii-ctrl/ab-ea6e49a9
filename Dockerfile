FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8080 \
    TELEMETRY_DB=/data/nonces.db \
    TELEMETRY_KEYS_FILE=/app/config/keys.json \
    RUNNING_IN_IMAGE=1

WORKDIR /app

# Application is pure standard library; install app + config + test assets.
COPY app/ ./app/
COPY config/ ./config/
COPY smoke/ ./smoke/
COPY tests/ ./tests/

RUN mkdir -p /data && adduser --system --uid 1001 gateway && chown -R gateway /data /app
USER gateway

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD python -c "import json,urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2); sys.exit(0 if r.status==200 else 1)"

CMD ["python", "-m", "app.server"]
