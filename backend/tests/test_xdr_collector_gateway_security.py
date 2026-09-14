"""P0.1 proof for authoritative backend Collector tenant isolation."""
from __future__ import annotations

from copy import deepcopy

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from deps import get_current_user
from routers import xdr_collectors as mod


class _Cursor(list):
    def sort(self, *args): return self
    def limit(self, n): return _Cursor(self[:n])


class _Collection:
    def __init__(self):
        self.rows = [
            {"_id": "db-a", "id": "col-a", "tenant_id": "acme", "name": "A",
             "protocol": "webhook", "state": "CONFIGURED", "enabled": True},
            {"_id": "db-b", "id": "col-b", "tenant_id": "globex", "name": "B",
             "protocol": "webhook", "state": "CONFIGURED", "enabled": True},
        ]

    def find_one(self, query):
        return next((deepcopy(r) for r in self.rows
                     if all(r.get(k) == v for k, v in query.items())), None)

    def find(self, query):
        return _Cursor([deepcopy(r) for r in self.rows
                        if all(r.get(k) == v for k, v in query.items())])

    def insert_one(self, doc):
        self.rows.append(deepcopy(doc))

    def update_one(self, query, update):
        row = next(r for r in self.rows if all(r.get(k) == v for k, v in query.items()))
        row.update(deepcopy(update.get("$set", {})))

    def delete_one(self, query):
        self.rows = [r for r in self.rows
                     if not all(r.get(k) == v for k, v in query.items())]


def _app(monkeypatch, user=None):
    coll = _Collection()
    monkeypatch.setattr(mod, "_coll", lambda: coll)
    monkeypatch.setattr(mod, "emit_audit", lambda **kwargs: {"id": "audit-test"})
    monkeypatch.setattr(mod, "check_access", lambda *args, **kwargs: {"allow": False})
    app = FastAPI()
    app.include_router(mod.router)
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app, coll


async def _request(app, method, path, **kwargs):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.request(method, path, **kwargs)


@pytest.mark.asyncio
async def test_anonymous_collector_request_denied(monkeypatch):
    app, _ = _app(monkeypatch)
    response = await _request(app, "GET", "/api/xdr/collectors")
    assert response.status_code in {401, 403}


@pytest.mark.asyncio
async def test_tenant_a_can_read_own_collector(monkeypatch):
    app, _ = _app(monkeypatch, {"email": "admin@acme.test",
                                "tenant_id": "acme", "role": "admin"})
    response = await _request(app, "GET", "/api/xdr/collectors/col-a")
    assert response.status_code == 200
    assert response.json()["data"]["tenant_id"] == "acme"


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,json_body", [
    ("GET", "/api/xdr/collectors/col-b", None),
    ("PUT", "/api/xdr/collectors/col-b", {"name": "changed"}),
    ("POST", "/api/xdr/collectors/col-b/start", None),
    ("POST", "/api/xdr/collectors/col-b/stop", None),
])
async def test_cross_tenant_resource_is_not_disclosed(monkeypatch, method, path, json_body):
    app, _ = _app(monkeypatch, {"email": "admin@acme.test",
                                "tenant_id": "acme", "role": "admin"})
    response = await _request(app, method, path, json=json_body)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_forged_tenant_header_cannot_widen_scope(monkeypatch):
    app, _ = _app(monkeypatch, {"email": "admin@acme.test",
                                "tenant_id": "acme", "role": "admin"})
    response = await _request(app, "GET", "/api/xdr/collectors/col-b",
                              headers={"X-Tenant-Id": "globex"})
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "TENANT_ASSERTION_MISMATCH"


@pytest.mark.asyncio
async def test_forged_body_tenant_is_ignored_and_server_tenant_persisted(monkeypatch):
    app, coll = _app(monkeypatch, {"email": "admin@acme.test",
                                   "tenant_id": "acme", "role": "admin"})
    response = await _request(app, "POST", "/api/xdr/collectors",
                              json={"name": "new", "protocol": "webhook",
                                    "tenant_id": "globex", "role": "admin"})
    assert response.status_code == 200
    created = next(r for r in coll.rows if r.get("name") == "new")
    assert created["tenant_id"] == "acme"
    assert created["created_by"] == "admin@acme.test"


@pytest.mark.asyncio
async def test_insufficient_role_denied(monkeypatch):
    app, _ = _app(monkeypatch, {"email": "viewer@acme.test",
                                "tenant_id": "acme", "role": "read_only"})
    response = await _request(app, "POST", "/api/xdr/collectors/col-a/start")
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "ACCESS_DENIED"
