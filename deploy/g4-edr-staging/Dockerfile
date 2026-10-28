# G4 backend build from repository root. Application source is untouched.
FROM python:3.11-slim AS wheels
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /wheels
COPY backend/requirements.txt ./requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends build-essential gcc libmagic1 \
    && pip wheel --wheel-dir=/wheels -r requirements.txt

FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=wheels /wheels /wheels
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-index --find-links=/wheels -r /tmp/requirements.txt \
    && rm -rf /wheels /tmp/requirements.txt
COPY backend/ /app/
COPY deploy/g4-edr-staging/entrypoint.py /opt/nivx/g4-entrypoint.py
RUN useradd --create-home --uid 1001 nivx-g4 && chown -R nivx-g4:nivx-g4 /app
USER nivx-g4
EXPOSE 8001
# /api/health is liveness only. Acceptance must verify /api/health/deep.
HEALTHCHECK --interval=30s --timeout=4s --start-period=25s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${PORT:-8001}/api/health || exit 1
CMD ["python", "/opt/nivx/g4-entrypoint.py"]
