"""P0-E · Observability foundation — Prometheus metrics + JSON logging.

Sprint 1 · owner-locked closure rule: no P0 closes until
CODE + TEST + INTEGRATION + PRODUCTION evidence is present.

This module provides:
    1. Prometheus counters + histograms for HTTP requests.
    2. A structured JSON logging formatter with a stable envelope.
    3. A FastAPI middleware wiring both together.
    4. A ``/api/metrics`` endpoint (registered separately in server.py).

Design invariants (aligned with NivXRay honest-state rules):
    · Metrics are observations, never marketing.
    · Log envelope carries: ``trace_id``, ``tenant_id``, ``route``,
      ``method``, ``status``, ``latency_ms`` — the minimum a SIEM
      needs to correlate a request across the pipeline.
    · No PII in metric labels.  Only path templates (``/api/incidents``
      not ``/api/incidents/abc-123``) — otherwise cardinality explodes.
    · Metrics disabled via ``OBSERVABILITY_METRICS_ENABLED=0`` env
      var when running short-lived tests.
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any

from fastapi import Request, Response
from fastapi.routing import APIRoute
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware


# ── Registry (owned) ─────────────────────────────────────────────
# Own the registry so tests can spin up a fresh one and there is no
# collision with library-default collectors.
REGISTRY = CollectorRegistry(auto_describe=True)


HTTP_REQUESTS = Counter(
    "nivxray_http_requests_total",
    "Total HTTP requests processed by the NivXRay API.",
    labelnames=("method", "route", "status"),
    registry=REGISTRY,
)


HTTP_LATENCY = Histogram(
    "nivxray_http_request_duration_seconds",
    "HTTP request latency in seconds by route.",
    labelnames=("method", "route"),
    # SOC-realistic buckets: fast reads / normal writes / slow
    # aggregation / timed-out endpoints.
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    registry=REGISTRY,
)


HTTP_IN_FLIGHT = Counter(
    "nivxray_http_requests_in_flight",
    "Requests currently being processed (approximate — increments "
    "on entry, does not decrement; use rate for backpressure).",
    labelnames=("method",),
    registry=REGISTRY,
)


# ── Structured JSON log envelope ─────────────────────────────────
class _JsonFormatter(logging.Formatter):
    """Stable JSON envelope — safe to ship straight to a SIEM.

    Envelope keys (locked):
        ts, level, logger, msg,
        trace_id, tenant_id, route, method, status, latency_ms.
    Any extra keys attached via ``extra=`` are folded into the top-level
    object.  Never fabricates values — a key is omitted rather than
    populated with a placeholder.
    """

    _BASE_KEYS = {"ts", "level", "logger", "msg"}
    _CTX_KEYS = ("trace_id", "tenant_id", "route", "method",
                 "status", "latency_ms")

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        # Millisecond-precision ISO-8601 UTC — SIEM-friendly.
        import datetime as _dt
        ts = _dt.datetime.fromtimestamp(record.created,
                                        tz=_dt.timezone.utc).isoformat(timespec="milliseconds")
        base: dict[str, Any] = {
            "ts":     ts,
            "level":  record.levelname,
            "logger": record.name,
            "msg":    record.getMessage(),
        }
        for k in self._CTX_KEYS:
            v = getattr(record, k, None)
            if v is not None:
                base[k] = v
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)
        # Merge any additional structured payload.
        payload = getattr(record, "payload", None)
        if isinstance(payload, dict):
            for k, v in payload.items():
                if k not in base:
                    base[k] = v
        return json.dumps(base, ensure_ascii=False, default=str)


def install_json_logging(level: str = "INFO") -> None:
    """Attach the JSON formatter to the root logger.

    Idempotent — safe to call multiple times.  The FastAPI /
    uvicorn / supervisor stack keeps logging to stdout, so this
    single call converts every log line to a SIEM-shippable JSON
    document.
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    fmt = _JsonFormatter()
    # Replace handlers so we don't stack duplicates on reload.
    for h in list(root.handlers):
        h.setFormatter(fmt)
    if not root.handlers:
        h = logging.StreamHandler()
        h.setFormatter(fmt)
        root.addHandler(h)


# ── Middleware ────────────────────────────────────────────────────
def _route_template(request: Request) -> str:
    """Return the path template (``/api/incidents/{id}``) rather
    than the resolved URL — cardinality-safe metric label."""
    try:
        route = request.scope.get("route")
        if isinstance(route, APIRoute) and route.path:
            return route.path
    except Exception:  # pragma: no cover — defensive
        pass
    return request.url.path or "unknown"


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """Records request duration, increments counters, injects
    ``trace_id`` + ``tenant_id`` into the log envelope."""

    async def dispatch(self, request: Request, call_next):
        started = time.perf_counter()
        method = request.method
        # trace id: honour inbound header, else mint.
        trace_id = (request.headers.get("x-request-id")
                    or request.headers.get("traceparent")
                    or uuid.uuid4().hex[:16])
        request.state.trace_id = trace_id
        tenant_id = (request.headers.get("x-tenant-id")
                     or getattr(request.state, "tenant_id", None)
                     or "default")
        HTTP_IN_FLIGHT.labels(method=method).inc()
        try:
            response = await call_next(request)
        except Exception:                # never swallow — re-raise
            latency = time.perf_counter() - started
            HTTP_REQUESTS.labels(method=method,
                                  route=_route_template(request),
                                  status="500").inc()
            HTTP_LATENCY.labels(method=method,
                                 route=_route_template(request)).observe(latency)
            logging.getLogger("nivxray.request").exception(
                "unhandled_exception",
                extra={"trace_id": trace_id, "tenant_id": tenant_id,
                       "route":    _route_template(request),
                       "method":   method,
                       "status":   500,
                       "latency_ms": round(latency * 1000, 3)},
            )
            raise
        latency = time.perf_counter() - started
        route = _route_template(request)
        HTTP_REQUESTS.labels(method=method, route=route,
                              status=str(response.status_code)).inc()
        HTTP_LATENCY.labels(method=method, route=route).observe(latency)
        logging.getLogger("nivxray.request").info(
            "request",
            extra={"trace_id": trace_id, "tenant_id": tenant_id,
                   "route":    route,
                   "method":   method,
                   "status":   response.status_code,
                   "latency_ms": round(latency * 1000, 3)},
        )
        response.headers["x-request-id"] = trace_id
        return response


# ── Metrics endpoint ─────────────────────────────────────────────
def metrics_response() -> Response:
    """Prometheus scrape endpoint payload."""
    data = generate_latest(REGISTRY)
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)


def is_enabled() -> bool:
    """True when observability wiring should mount.  Off during
    corpus / unit tests to keep latency measurements clean."""
    return os.environ.get("OBSERVABILITY_METRICS_ENABLED", "1") != "0"


__all__ = [
    "REGISTRY",
    "HTTP_REQUESTS", "HTTP_LATENCY", "HTTP_IN_FLIGHT",
    "install_json_logging",
    "ObservabilityMiddleware",
    "metrics_response",
    "is_enabled",
]
