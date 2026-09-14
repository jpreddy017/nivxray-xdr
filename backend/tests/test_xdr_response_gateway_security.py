"""Focused Option-3 trust-boundary tests. No MongoDB or endpoint action."""
from __future__ import annotations

import copy
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import routers.xdr_response_gateway as gw
from deps import get_current_user


class Col:
    def __init__(self, rows=None): self.rows = list(rows or [])
    def find_one(self, q, projection=None):
        for row in self.rows:
            if all(row.get(k) == v for k, v in q.items()):
                return copy.deepcopy(row)
        return None
    def find(self, q, projection=None):
        rows = [copy.deepcopy(r) for r in self.rows
                if all(r.get(k) == v for k, v in q.items())]
        class Cur(list):
            def limit(self, n): return Cur(self[:n])
        return Cur(rows)
    def insert_one(self, row): self.rows.append(copy.deepcopy(row))
    def update_one(self, q, patch):
        row = self.find_one(q)
        if not row: return
        original = next(r for r in self.rows if all(r.get(k) == v for k, v in q.items()))
        original.update(copy.deepcopy(patch.get("$set") or {}))


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setattr(gw, "_cases", Col([
        {"id": "case-a", "tenant_id": "tenant-a"},
        {"id": "case-b", "tenant_id": "tenant-b"},
    ]))
    monkeypatch.setattr(gw, "_xdr_users", Col())
    monkeypatch.setattr(gw, "_requests", Col())
    monkeypatch.setattr(gw, "_approvals", Col())
    monkeypatch.setattr(gw, "_dispatches", Col())
    api = FastAPI()
    api.include_router(gw.router, prefix="/api")
    api.dependency_overrides[get_current_user] = lambda: {
        "email": "responder@a.example", "tenant_id": "tenant-a", "role": "admin"
    }
    return api


def body(case_id="case-a"):
    return {
        "case_id": case_id,
        "action": {"action_id": "endpoint.isolate"},
        "target": {"host_id": "host-a"},
        "reason": "confirmed incident response",
    }


@pytest.mark.asyncio
async def test_cross_tenant_target_denied_before_dispatch(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/api/xdr/response/requests", json=body("case-b"))
    assert r.status_code == 404
    assert gw._requests.rows == []


@pytest.mark.asyncio
async def test_forged_tenant_denied(app):
    forged = {**body(), "tenant_id": "tenant-b"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/api/xdr/response/requests", json=forged)
    assert r.status_code == 403
    assert r.json()["detail"]["field"] == "tenant_id"


@pytest.mark.asyncio
async def test_forged_invoker_denied(app):
    forged = {**body(), "invoker": "admin@nivxray.com"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/api/xdr/response/requests", json=forged)
    assert r.status_code == 403
    assert r.json()["detail"]["field"] == "invoker"


@pytest.mark.asyncio
async def test_forged_browser_approval_is_ignored(app):
    forged = {**body(), "approved_by": "admin", "authorization": {"approved": True}}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/api/xdr/response/requests", json=forged)
    assert r.status_code == 200
    assert r.json()["approval_status"] == "pending"
    assert r.json()["state"] == "REQUESTED"


@pytest.mark.asyncio
async def test_exact_approval_is_bound_to_action_and_target(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        created = (await c.post("/api/xdr/response/requests", json=body())).json()
        decision = await c.post(
            f"/api/xdr/response/requests/{created['response_request_id']}/approval",
            json={"decision": "approve", "reason": "manager verified"},
        )
    assert decision.status_code == 200
    approval = gw._approvals.rows[0]
    request = gw._requests.rows[0]
    assert approval["binding_digest"] == gw._digest(request["action"], request["target"])
    assert approval["tenant_id"] == request["tenant_id"]


@pytest.mark.asyncio
async def test_changed_target_invalidates_approval(app, monkeypatch):
    monkeypatch.setenv("RESPONSE_ENGINE_URL", "https://response.invalid")
    monkeypatch.setenv("RESPONSE_ENGINE_SERVICE_CREDENTIAL", "secret")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        created = (await c.post("/api/xdr/response/requests", json=body())).json()
        rid = created["response_request_id"]
        await c.post(f"/api/xdr/response/requests/{rid}/approval",
                     json={"decision": "approve", "reason": "manager verified"})
        gw._requests.rows[0]["target"] = {"host_id": "host-b"}
        denied = await c.post(f"/api/xdr/response/requests/{rid}/dispatch")
    assert denied.status_code == 403
    assert denied.json()["detail"]["error"] == "approval_binding_mismatch"


@pytest.mark.asyncio
async def test_changed_action_invalidates_approval(app, monkeypatch):
    monkeypatch.setenv("RESPONSE_ENGINE_URL", "https://response.invalid")
    monkeypatch.setenv("RESPONSE_ENGINE_SERVICE_CREDENTIAL", "secret")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        created = (await c.post("/api/xdr/response/requests", json=body())).json()
        rid = created["response_request_id"]
        await c.post(f"/api/xdr/response/requests/{rid}/approval",
                     json={"decision": "approve", "reason": "manager verified"})
        gw._requests.rows[0]["action"] = {"action_id": "endpoint.delete"}
        denied = await c.post(f"/api/xdr/response/requests/{rid}/dispatch")
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_missing_service_credential_blocks_dispatch(app, monkeypatch):
    monkeypatch.setenv("RESPONSE_ENGINE_URL", "https://response.invalid")
    monkeypatch.delenv("RESPONSE_ENGINE_SERVICE_CREDENTIAL", raising=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        created = (await c.post("/api/xdr/response/requests",
                                json={**body(), "dry_run": True})).json()
        r = await c.post(
            f"/api/xdr/response/requests/{created['response_request_id']}/dispatch"
        )
    assert r.status_code == 503
    assert r.json()["detail"]["error"] == "response_engine_not_ready"
