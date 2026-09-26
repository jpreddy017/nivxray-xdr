"""Preflight endpoint tests."""
import httpx
import pytest
from contextlib import asynccontextmanager

from framework.authz import collector_guard
from main import app


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t")


@asynccontextmanager
async def _lifespan_client():
    """Collector Auth P0 · standalone fails closed, so the preflight
    behaviour tests override the guard and the fail-closed contract is
    asserted separately (`test_standalone_preflight_fails_closed`)."""
    app.dependency_overrides[collector_guard] = lambda: "HUMAN_CONTROL"
    try:
        async with app.router.lifespan_context(app):
            async with _client() as c:
                yield c
    finally:
        app.dependency_overrides.pop(collector_guard, None)


@pytest.mark.asyncio
async def test_standalone_preflight_fails_closed():
    async with app.router.lifespan_context(app):
        async with _client() as c:
            r = await c.post("/api/xdr/ingest-preflight",
                             headers={"X-Tenant-Id": "acme"})
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "COLLECTOR_AUTH_UNAVAILABLE"


def _mock_only_ingest(monkeypatch, ingest_response):
    """Patch httpx.AsyncClient so requests to ingest.example are mocked
    but ASGI test-client traffic to the app itself is untouched."""
    orig_client = httpx.AsyncClient

    def _factory(*a, **kw):
        # Only inject transport when no transport was passed AND base_url
        # isn't the ASGI one.
        transport = kw.get("transport")
        if transport is None:
            def handler(request):
                if "ingest.example" in str(request.url):
                    return ingest_response(request)
                # let unknown URLs fail
                return httpx.Response(599, text="unexpected url in mock")
            kw["transport"] = httpx.MockTransport(handler)
        return orig_client(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", _factory)


@pytest.mark.asyncio
async def test_preflight_reports_not_configured_when_ingest_missing(monkeypatch):
    monkeypatch.delenv("NIVX_INGEST_URL", raising=False)
    async with _lifespan_client() as c:
        r = await c.post("/api/xdr/ingest-preflight",
                              headers={"X-Tenant-Id": "acme"})
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is False
    assert j["state"] == "not_configured"


@pytest.mark.asyncio
async def test_preflight_returns_healthy_when_ingest_2xx(monkeypatch):
    monkeypatch.setenv("NIVX_INGEST_URL",   "https://ingest.example/api/xdr/ingest")
    monkeypatch.setenv("NIVX_INGEST_TOKEN", "t")
    _mock_only_ingest(monkeypatch,
                          lambda req: httpx.Response(202, json={"accepted": 1}))
    async with _lifespan_client() as c:
        r = await c.post("/api/xdr/ingest-preflight",
                              headers={"X-Tenant-Id": "acme"})
    j = r.json()
    assert j["ok"] is True
    assert j["outcome"] == "ok"
    assert j["state"] == "healthy"
    assert j["status_code"] == 202


@pytest.mark.asyncio
async def test_preflight_returns_degraded_on_5xx(monkeypatch):
    monkeypatch.setenv("NIVX_INGEST_URL",   "https://ingest.example/api/xdr/ingest")
    monkeypatch.setenv("NIVX_INGEST_TOKEN", "t")
    _mock_only_ingest(monkeypatch,
                          lambda req: httpx.Response(503, text="upstream down"))
    async with _lifespan_client() as c:
        r = await c.post("/api/xdr/ingest-preflight",
                              headers={"X-Tenant-Id": "acme"})
    j = r.json()
    assert j["ok"] is False
    assert j["outcome"] == "retryable"
    assert j["state"] == "degraded"
    assert j["status_code"] == 503


@pytest.mark.asyncio
async def test_preflight_without_a_tenant_is_refused(monkeypatch):
    """B7 Option A · a probe does not get to invent a tenancy.

    This used to default to the literal `"preflight"`, injecting a synthetic
    envelope labelled with a tenant that exists in no registry into the real
    ingest pipeline.
    """
    monkeypatch.setenv("NIVX_INGEST_URL",   "https://ingest.example/api/xdr/ingest")
    monkeypatch.setenv("NIVX_INGEST_TOKEN", "t")
    _mock_only_ingest(monkeypatch,
                          lambda req: httpx.Response(202, json={"accepted": 1}))
    async with _lifespan_client() as c:
        r = await c.post("/api/xdr/ingest-preflight")
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "TENANT_REQUIRED"


@pytest.mark.asyncio
async def test_preflight_tenant_is_checked_before_configuration(monkeypatch):
    """Authority before capability · an unauthorised probe must not even
    learn whether the ingest pipeline is configured."""
    monkeypatch.delenv("NIVX_INGEST_URL", raising=False)
    async with _lifespan_client() as c:
        r = await c.post("/api/xdr/ingest-preflight")
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "TENANT_REQUIRED"
