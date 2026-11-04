"""XDR Audit Log — P0-1 pytest.

Covers:
- emit → persist → read-back with all required fields
- tenant isolation (tenant A cannot read tenant B events)
- HMAC signature chain (verify/chain endpoint returns valid)
- tamper detection (mutating a persisted doc breaks verify)
- filter by action / resource_kind / principal / outcome
"""
from __future__ import annotations

import os
import uuid

import pytest

#: L3 (LLM decoder fallback) is opt-in and irrelevant to these planes. It is
#: disabled here because its dedicated-loop worker keeps a Starlette
#: threadpool slot busy, which makes the application's shutdown — and hence
#: this module's teardown — hang for the full pytest timeout.
os.environ.setdefault("NIVX_L3_DISABLE", "1")
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")

from routers import xdr_audit_log as al
from server import app

from tests._verified_session import admin_token, hdrs, register_tenants

#: MODERNIZED 2026-06 — this suite now authenticates. `X-Principal-Id` and
#: the bootstrap bypass were deleted from the platform (P0-SEC); the suite
#: had kept speaking that dialect, so every request was correctly refused.
#: See `tests/_verified_session.py`. Nothing was relaxed server-side.

client = TestClient(app)

TEN_A = f"tenant-a-{uuid.uuid4().hex[:8]}"
TEN_B = f"tenant-b-{uuid.uuid4().hex[:8]}"

_TOKEN: list[str] = []


def _h(tenant: str) -> dict:
    return hdrs(_TOKEN[0], tenant)


def _emit(tenant, action, rid, outcome="SUCCESS"):
    r = client.post(
        "/api/xdr/audit-log/emit",
        headers=_h(tenant),
        json={"action": action, "resource_kind": "user",
                 "resource_id": rid, "outcome": outcome,
                 "after": {"email": "x@example.com"}},
    )
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["ok"] is True
    assert j["audit_ref"].startswith("aud_")
    return j["data"]


@pytest.fixture(scope="module", autouse=True)
def _clean():
    # ONE client for the whole module, context-managed so the application
    # lifespan (config validation + database init) is live for every request.
    # Mixing a lifespan client with a second non-lifespan client puts the two
    # on different event loops, which surfaces as a `Task ... got Future
    # attached to a different loop` 500 rather than as a test failure.
    global client
    with TestClient(app) as c:
        client = c
        _TOKEN.append(admin_token(c))
        register_tenants(TEN_A, TEN_B, label="auditlog")
        if al._MONGO_URL:
            al._get_coll().delete_many({"tenant_id": {"$in": [TEN_A, TEN_B]}})
        yield
        if al._MONGO_URL:
            al._get_coll().delete_many({"tenant_id": {"$in": [TEN_A, TEN_B]}})


def test_emit_and_readback():
    if not al._MONGO_URL:
        pytest.skip("MONGO_URL not configured")
    ev = _emit(TEN_A, "USER_CREATED", "usr_1")
    assert ev["tenant_id"] == TEN_A
    assert ev["action"] == "USER_CREATED"
    assert ev["outcome"] == "SUCCESS"
    assert ev["sig"] and ev["prev_sig"]  # chain fields present
    # Provenance is the VERIFIED principal, not a value the client chose.
    # This assertion is the point of the P0-SEC hardening: an audit record
    # attributes the authenticated session, so `X-Principal-Id` can no longer
    # forge who did it.
    assert ev["principal_id"] == os.environ["ADMIN_EMAIL"]

    r = client.get("/api/xdr/audit-log",
                          headers=_h(TEN_A))
    j = r.json()
    assert j["ok"] is True
    assert j["data"]["count"] >= 1
    assert any(e["id"] == ev["id"] for e in j["data"]["events"])


def test_tenant_isolation():
    if not al._MONGO_URL:
        pytest.skip("MONGO_URL not configured")
    a = _emit(TEN_A, "ROLE_CREATED", "role_a1")
    b = _emit(TEN_B, "ROLE_CREATED", "role_b1")
    # Tenant A must NOT see Tenant B events.
    r = client.get("/api/xdr/audit-log",
                          headers=_h(TEN_A))
    ids = {e["id"] for e in r.json()["data"]["events"]}
    assert a["id"] in ids
    assert b["id"] not in ids
    # And the fetch-by-id endpoint refuses cross-tenant reads.
    r2 = client.get(f"/api/xdr/audit-log/{b['id']}",
                             headers=_h(TEN_A))
    assert r2.status_code == 404


def test_chain_valid():
    if not al._MONGO_URL:
        pytest.skip("MONGO_URL not configured")
    _emit(TEN_A, "API_KEY_CREATED", "key_1")
    _emit(TEN_A, "API_KEY_ROTATED", "key_1")
    _emit(TEN_A, "API_KEY_REVOKED", "key_1")
    r = client.get("/api/xdr/audit-log/verify/chain",
                          headers=_h(TEN_A))
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert d["status"] == "valid", d
    assert d["checked"] >= 3


def test_chain_tamper_detection():
    if not al._MONGO_URL:
        pytest.skip("MONGO_URL not configured")

    doc = al._get_coll().find_one({"tenant_id": TEN_A})
    assert doc is not None
    al._get_coll().update_one(
        {"_id": doc["_id"]},
        {"$set": {"after": {"email": "tampered@example.com"}}},
    )
    r = client.get("/api/xdr/audit-log/verify/chain",
                          headers=_h(TEN_A))
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["status"] == "chain_broken"
    assert d["reason"] in ("signature_mismatch", "prev_sig_mismatch")


def test_filters():
    if not al._MONGO_URL:
        pytest.skip("MONGO_URL not configured")
    # Emit fresh tenant so the tamper test doesn't affect filter counts.
    ten = f"tenant-f-{uuid.uuid4().hex[:8]}"
    register_tenants(ten, label="auditlog-filters")
    _emit(ten, "WEBHOOK_CREATED", "wh_1")
    _emit(ten, "WEBHOOK_UPDATED", "wh_1")
    _emit(ten, "WEBHOOK_DELETED", "wh_1", outcome="SUCCESS")
    r = client.get("/api/xdr/audit-log?action=WEBHOOK_UPDATED",
                          headers=_h(ten))
    j = r.json()["data"]
    assert j["count"] == 1
    assert j["events"][0]["action"] == "WEBHOOK_UPDATED"
    # cleanup
    al._get_coll().delete_many({"tenant_id": ten})
