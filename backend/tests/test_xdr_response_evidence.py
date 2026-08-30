"""
Tests for POST /api/xdr/response-evidence — the ONLY base-backend
endpoint the standalone Response Engine writes to.

Owner-locked: SSOT / Verdict / IKG must NOT be modified.  These tests
inject a fake Motor-style db into ``app.state.db`` (used by the router's
``_resolve_db`` helper) so we don't need MongoDB to validate contract
semantics: idempotency, provenance validation, and the three-ref
invariant.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI
from httpx   import AsyncClient, ASGITransport

from routers.xdr_response_evidence import router


# ── Minimal in-memory Motor stand-in ─────────────────────────────────
class _FakeCollection:
    def __init__(self) -> None:
        self.rows: List[Dict[str, Any]] = []

    async def find_one(self, q: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for r in self.rows:
            if all(r.get(k) == v for k, v in q.items()):
                return r
        return None

    async def insert_one(self, doc: Dict[str, Any]) -> None:
        self.rows.append(dict(doc))


class _FakeDb:
    def __init__(self) -> None:
        self.xdr_response_evidence   = _FakeCollection()
        self.xdr_response_audit      = _FakeCollection()
        self.xdr_response_timeline   = _FakeCollection()
        self.xdr_response_executions = _FakeCollection()


def _app() -> FastAPI:
    app = FastAPI()
    app.state.db = _FakeDb()
    app.include_router(router, prefix="/api")
    return app


BODY = {
    "execution_id":     "exec-abc",
    "tenant_id":        "acme",
    "invoker":          {"kind": "analyst", "id": "user:a@acme.com",
                            "context": {"incident_id": "INC-1"}},
    "action":           {"action_id": "endpoint.isolate",
                            "provider":  "endpoint",
                            "capability": "isolate_endpoint"},
    "parameters":       {"host_id": "HOST-A"},
    "canonical_target": {"asset": "asset:HOST-A"},
    "adapter_result":   {"stub": True},
    "adapter_ok":       True,
    "authorization":    {"approved_by": "user:lead@acme.com",
                            "approval_ref": "appr-1", "reason": "IR"},
}


@pytest.mark.asyncio
async def test_response_evidence_returns_three_refs():
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app),
                              base_url="http://t") as c:
        r = await c.post("/api/xdr/response-evidence", json=BODY)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["evidence_ref"] and j["audit_ref"] and j["timeline_ref"]
    assert j["evidence_ref"].startswith("evidence-")
    assert j["audit_ref"].startswith("audit-")
    assert j["timeline_ref"].startswith("timeline-")


@pytest.mark.asyncio
async def test_response_evidence_is_idempotent_on_execution_id():
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app),
                              base_url="http://t") as c:
        r1 = await c.post("/api/xdr/response-evidence", json=BODY)
        r2 = await c.post("/api/xdr/response-evidence", json=BODY)
    a, b = r1.json(), r2.json()
    assert a["evidence_ref"] == b["evidence_ref"]
    assert a["audit_ref"]    == b["audit_ref"]
    assert a["timeline_ref"] == b["timeline_ref"]
    assert b.get("idempotent_replay") is True


@pytest.mark.asyncio
async def test_response_evidence_rejects_invalid_provenance():
    """The engine stamps ``provenance.kind = response_action``.  A hand-
    crafted payload with a different kind is untrusted → 400."""
    app = _app()
    bad = {**BODY, "execution_id": "exec-bad-prov",
              "provenance": {"kind": "manual_upload"}}
    async with AsyncClient(transport=ASGITransport(app=app),
                              base_url="http://t") as c:
        r = await c.post("/api/xdr/response-evidence", json=bad)
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "invalid_provenance"


@pytest.mark.asyncio
async def test_response_evidence_writes_all_three_collections():
    app = _app()
    body = {**BODY, "execution_id": "exec-collections"}
    async with AsyncClient(transport=ASGITransport(app=app),
                              base_url="http://t") as c:
        await c.post("/api/xdr/response-evidence", json=body)
    db: _FakeDb = app.state.db
    assert len(db.xdr_response_evidence.rows) == 1
    assert len(db.xdr_response_audit.rows)    == 1
    assert len(db.xdr_response_timeline.rows) == 1
    # Provenance was stamped by the endpoint even though the request
    # omitted it.
    prov = db.xdr_response_evidence.rows[0]["provenance"]
    assert prov["kind"] == "response_action"
    assert prov["execution_id"] == "exec-collections"


@pytest.mark.asyncio
async def test_response_evidence_read_after_write():
    app = _app()
    body = {**BODY, "execution_id": "exec-read"}
    async with AsyncClient(transport=ASGITransport(app=app),
                              base_url="http://t") as c:
        await c.post("/api/xdr/response-evidence", json=body)
        r = await c.get("/api/xdr/response-evidence/exec-read",
                             params={"tenant_id": "acme"})
    assert r.status_code == 200
    assert r.json()["execution_id"] == "exec-read"


@pytest.mark.asyncio
async def test_response_evidence_tenant_scoped_read():
    app = _app()
    body = {**BODY, "execution_id": "exec-tenant"}
    async with AsyncClient(transport=ASGITransport(app=app),
                              base_url="http://t") as c:
        await c.post("/api/xdr/response-evidence", json=body)
        # Different tenant → 404
        r = await c.get("/api/xdr/response-evidence/exec-tenant",
                             params={"tenant_id": "globex"})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_response_evidence_marks_dry_run_as_simulation():
    app = _app()
    body = {**BODY, "execution_id": "exec-dry", "dry_run": True}
    async with AsyncClient(transport=ASGITransport(app=app),
                              base_url="http://t") as c:
        await c.post("/api/xdr/response-evidence", json=body)
    row = app.state.db.xdr_response_evidence.rows[0]
    assert row["simulation"] is True
    assert row["dry_run"]    is True
