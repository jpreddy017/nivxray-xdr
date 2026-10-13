# Packaging wrapper around deploy/backend.Dockerfile; application is untouched.
ARG PYTHON_BASE
FROM ${PYTHON_BASE} AS deps
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /wheels
COPY backend/requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends build-essential gcc libmagic1 && pip wheel --wheel-dir=/wheels -r requirements.txt
FROM ${PYTHON_BASE} AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 curl && rm -rf /var/lib/apt/lists/*
COPY --from=deps /wheels /wheels
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-index --find-links=/wheels -r /tmp/requirements.txt && rm -rf /wheels /tmp/requirements.txt
COPY backend/ /app/
RUN useradd --create-home --uid 1001 nivxray && chown -R nivxray:nivxray /app
USER nivxray
ARG SOURCE_SHA
ARG SOURCE_TREE
LABEL org.opencontainers.image.revision=${SOURCE_SHA} io.nivxray.source-tree=${SOURCE_TREE}
EXPOSE 8001
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "1"]
