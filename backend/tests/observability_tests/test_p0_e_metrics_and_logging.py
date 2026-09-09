"""P0-E · Observability acceptance tests.

Sprint 1 · owner-locked closure rule:
    A P0 closes only when CODE + TEST + INTEGRATION + PRODUCTION
    evidence satisfies the acceptance criterion.

This test file provides the TEST layer for P0-E.  The
INTEGRATION layer is proved by the live pod running the middleware
(smoke-tested via curl in the sprint report).  The PRODUCTION
layer is proved when the metrics counter increments non-zero
during real traffic.
"""
from __future__ import annotations

import json
import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from observability import (
    HTTP_LATENCY,
    HTTP_REQUESTS,
    ObservabilityMiddleware,
    _JsonFormatter,
    install_json_logging,
    metrics_response,
)


@pytest.fixture()
def app_with_metrics() -> FastAPI:
    app = FastAPI()
    app.add_middleware(ObservabilityMiddleware)

    @app.get("/api/ping")
    async def ping():
        return {"ok": True}

    @app.get("/api/boom")
    async def boom():
        raise RuntimeError("intentional")

    @app.get("/api/metrics")
    async def metrics_ep():
        return metrics_response()

    return app


# ── Metrics ─────────────────────────────────────────────────────
def test_metrics_endpoint_returns_prometheus_format(app_with_metrics):
    client = TestClient(app_with_metrics, raise_server_exceptions=False)
    client.get("/api/ping")  # warm the counter
    r = client.get("/api/metrics")
    assert r.status_code == 200
    body = r.text
    assert body.startswith("# HELP")
    assert "nivxray_http_requests_total" in body
    assert "nivxray_http_request_duration_seconds" in body


def test_middleware_increments_counter_per_request(app_with_metrics):
    client = TestClient(app_with_metrics, raise_server_exceptions=False)
    before = _sample_value("nivxray_http_requests_total",
                           {"method": "GET", "route": "/api/ping",
                            "status": "200"})
    client.get("/api/ping")
    client.get("/api/ping")
    after = _sample_value("nivxray_http_requests_total",
                          {"method": "GET", "route": "/api/ping",
                           "status": "200"})
    assert after - before == 2, f"counter delta {after - before} != 2"


def test_middleware_records_latency_histogram(app_with_metrics):
    client = TestClient(app_with_metrics, raise_server_exceptions=False)
    client.get("/api/ping")
    # Sample the histogram _count series.
    count = _sample_value("nivxray_http_request_duration_seconds_count",
                          {"method": "GET", "route": "/api/ping"})
    assert count >= 1


def test_middleware_records_exception_status(app_with_metrics):
    client = TestClient(app_with_metrics, raise_server_exceptions=False)
    r = client.get("/api/boom")
    assert r.status_code == 500
    n500 = _sample_value("nivxray_http_requests_total",
                          {"method": "GET", "route": "/api/boom",
                           "status": "500"})
    assert n500 >= 1


def test_middleware_injects_trace_id_header(app_with_metrics):
    client = TestClient(app_with_metrics, raise_server_exceptions=False)
    r = client.get("/api/ping")
    tid = r.headers.get("x-request-id")
    assert tid and len(tid) == 16


def test_middleware_honours_inbound_trace_id(app_with_metrics):
    client = TestClient(app_with_metrics, raise_server_exceptions=False)
    r = client.get("/api/ping", headers={"x-request-id": "abcdef0123456789"})
    assert r.headers.get("x-request-id") == "abcdef0123456789"


# ── JSON logging ────────────────────────────────────────────────
def test_json_formatter_stable_envelope():
    fmt = _JsonFormatter()
    rec = logging.LogRecord(name="nivxray.test", level=logging.INFO,
                             pathname=__file__, lineno=10,
                             msg="hello %s", args=("world",), exc_info=None)
    rec.trace_id = "abc123"
    rec.tenant_id = "acme-corp"
    rec.route = "/api/ping"
    rec.method = "GET"
    rec.status = 200
    rec.latency_ms = 4.2
    out = json.loads(fmt.format(rec))
    assert out["level"] == "INFO"
    assert out["logger"] == "nivxray.test"
    assert out["msg"] == "hello world"
    assert out["trace_id"] == "abc123"
    assert out["tenant_id"] == "acme-corp"
    assert out["route"] == "/api/ping"
    assert out["latency_ms"] == 4.2
    assert out["ts"].endswith("+00:00") or out["ts"].endswith("Z")


def test_install_json_logging_is_idempotent():
    install_json_logging()
    install_json_logging()
    root = logging.getLogger()
    fmts = {type(h.formatter).__name__ for h in root.handlers if h.formatter}
    assert fmts == {"_JsonFormatter"}, f"unexpected formatters: {fmts}"


# ── Helpers ─────────────────────────────────────────────────────
def _sample_value(name: str, labels: dict) -> float:
    """Read a specific labelled sample from the observability
    registry.  Returns 0.0 if the sample doesn't exist yet."""
    from observability import REGISTRY
    for metric in REGISTRY.collect():
        for s in metric.samples:
            if s.name == name and s.labels == labels:
                return s.value
    return 0.0
