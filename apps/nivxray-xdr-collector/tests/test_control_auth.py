import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from security.control_auth import CollectorControlAuthenticationMiddleware


def _app():
    app = FastAPI()
    app.add_middleware(CollectorControlAuthenticationMiddleware)

    @app.get("/api/xdr/connectors")
    async def connectors(request: Request):
        return {"tenant": request.headers.get("X-Tenant-Id")}

    @app.post("/api/xdr/webhooks/example")
    async def webhook():
        return {"hmac_boundary": True}
    return app


@pytest.mark.asyncio
async def test_anonymous_collector_management_denied(monkeypatch):
    monkeypatch.setenv("XDR_COLLECTOR_ENV", "production")
    monkeypatch.setenv("COLLECTOR_CONTROL_SERVICE_CREDENTIAL", "collector-secret")
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.get("/api/xdr/connectors")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_authenticated_tenant_required(monkeypatch):
    monkeypatch.setenv("XDR_COLLECTOR_ENV", "production")
    monkeypatch.setenv("COLLECTOR_CONTROL_SERVICE_CREDENTIAL", "collector-secret")
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.get("/api/xdr/connectors",
                        headers={"Authorization": "Bearer collector-secret"})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_forged_tenant_header_cannot_override_authenticated_tenant(monkeypatch):
    monkeypatch.setenv("XDR_COLLECTOR_ENV", "production")
    monkeypatch.setenv("COLLECTOR_CONTROL_SERVICE_CREDENTIAL", "collector-secret")
    headers = {
        "Authorization": "Bearer collector-secret",
        "X-Authenticated-Tenant": "tenant-a",
        "X-Tenant-Id": "tenant-b",
    }
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.get("/api/xdr/connectors", headers=headers)
    assert r.status_code == 200
    assert r.json()["tenant"] == "tenant-a"


@pytest.mark.asyncio
async def test_webhook_uses_separate_hmac_boundary(monkeypatch):
    monkeypatch.setenv("XDR_COLLECTOR_ENV", "production")
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.post("/api/xdr/webhooks/example")
    assert r.status_code == 200
