# ─────────────────────────────────────────────────────────────
# NivXRay XDR · Backend production image (P0-F · Sprint 1)
# Multi-stage.  Non-root runtime.  Health-probe-ready.
# ─────────────────────────────────────────────────────────────
FROM python:3.11-slim AS deps

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /wheels

# Build wheels once so the final stage stays small.
COPY backend/requirements.txt .
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential gcc libmagic1 \
 && pip wheel --wheel-dir=/wheels -r requirements.txt


# ── Stage 2 · runtime ───────────────────────────────────────────
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    LOG_LEVEL=INFO \
    OBSERVABILITY_METRICS_ENABLED=1

# libmagic1 is required at runtime by file-type sniffing.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libmagic1 curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install pre-built wheels from the deps stage.
COPY --from=deps /wheels /wheels
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-index --find-links=/wheels -r /tmp/requirements.txt \
 && rm -rf /wheels /tmp/requirements.txt

# Copy the backend source.
COPY backend/ /app/

# Non-root user (defence-in-depth).
RUN useradd --create-home --shell /bin/bash --uid 1001 nivxray \
 && chown -R nivxray:nivxray /app
USER nivxray

EXPOSE 8001

# Container healthcheck hits the cheap liveness route (never Mongo).
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8001/api/health || exit 1

# Uvicorn with a single worker per container — scale by adding
# containers behind the ingress, not by adding workers here.
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
