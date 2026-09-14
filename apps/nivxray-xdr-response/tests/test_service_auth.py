import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from security.service_auth import ServiceAuthenticationMiddleware


def _app():
    app = FastAPI()
    app.add_middleware(ServiceAuthenticationMiddleware)

    @app.post("/api/respond/execute")
    async def execute(request: Request):
        return {"service": request.state.authenticated_service}

    @app.get("/health")
    async def health():
        return {"ok": True}
    return app


@pytest.mark.asyncio
async def test_direct_anonymous_response_access_denied(monkeypatch):
    monkeypatch.setenv("XDR_RESPOND_ENV", "production")
    monkeypatch.setenv("RESPONSE_ENGINE_SERVICE_CREDENTIAL", "service-secret")
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.post("/api/respond/execute")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_invalid_service_credential_denied(monkeypatch):
    monkeypatch.setenv("XDR_RESPOND_ENV", "production")
    monkeypatch.setenv("RESPONSE_ENGINE_SERVICE_CREDENTIAL", "service-secret")
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.post("/api/respond/execute",
                         headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_missing_server_credential_is_not_ready(monkeypatch):
    monkeypatch.setenv("XDR_RESPOND_ENV", "production")
    monkeypatch.delenv("RESPONSE_ENGINE_SERVICE_CREDENTIAL", raising=False)
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.post("/api/respond/execute")
    assert r.status_code == 503


@pytest.mark.asyncio
async def test_valid_backend_service_identity_accepted(monkeypatch):
    monkeypatch.setenv("XDR_RESPOND_ENV", "production")
    monkeypatch.setenv("RESPONSE_ENGINE_SERVICE_CREDENTIAL", "service-secret")
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.post("/api/respond/execute",
                         headers={"Authorization": "Bearer service-secret"})
    assert r.status_code == 200
    assert r.json()["service"] == "authoritative-backend"


@pytest.mark.asyncio
async def test_health_remains_public(monkeypatch):
    monkeypatch.setenv("XDR_RESPOND_ENV", "production")
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.get("/health")
    assert r.status_code == 200
