FROM docker.io/library/python:3.12-slim

LABEL org.opencontainers.image.title="CloudPulse Platform" \
      org.opencontainers.image.description="Infrastructure, identity and security operations console"

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libpq-dev curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/     ./app/
COPY static/  ./static/
COPY scripts/ ./scripts/

RUN useradd -m -u 1000 cloudpulse && chown -R cloudpulse:cloudpulse /app
USER cloudpulse

ENV PYTHONUNBUFFERED=1 TZ=Asia/Dubai
EXPOSE 8694

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fs http://127.0.0.1:8694/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8694", "--workers", "2"]
