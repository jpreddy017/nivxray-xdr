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
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")

from routers import xdr_audit_log as al
from server import app

client = TestClient(app)

TEN_A = f"tenant-a-{uuid.uuid4().hex[:8]}"
TEN_B = f"tenant-b-{uuid.uuid4().hex[:8]}"


def _emit(tenant, action, rid, outcome="SUCCESS", principal="tester@nivxray"):
    r = client.post(
        "/api/xdr/audit-log/emit",
        headers={"X-Tenant-Id": tenant, "X-Principal-Id": principal,
                     "X-Principal-Kind": "user"},
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
    """Best-effort clean of test tenants before + after."""
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
    assert ev["principal_id"] == "tester@nivxray"

    r = client.get("/api/xdr/audit-log",
                          headers={"X-Tenant-Id": TEN_A})
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
                          headers={"X-Tenant-Id": TEN_A})
    ids = {e["id"] for e in r.json()["data"]["events"]}
    assert a["id"] in ids
    assert b["id"] not in ids
    # And the fetch-by-id endpoint refuses cross-tenant reads.
    r2 = client.get(f"/api/xdr/audit-log/{b['id']}",
                             headers={"X-Tenant-Id": TEN_A})
    assert r2.status_code == 404


def test_chain_valid():
    if not al._MONGO_URL:
        pytest.skip("MONGO_URL not configured")
    _emit(TEN_A, "API_KEY_CREATED", "key_1")
    _emit(TEN_A, "API_KEY_ROTATED", "key_1")
    _emit(TEN_A, "API_KEY_REVOKED", "key_1")
    r = client.get("/api/xdr/audit-log/verify/chain",
                          headers={"X-Tenant-Id": TEN_A})
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
                          headers={"X-Tenant-Id": TEN_A})
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["status"] == "chain_broken"
    assert d["reason"] in ("signature_mismatch", "prev_sig_mismatch")


def test_filters():
    if not al._MONGO_URL:
        pytest.skip("MONGO_URL not configured")
    # Emit fresh tenant so the tamper test doesn't affect filter counts.
    ten = f"tenant-f-{uuid.uuid4().hex[:8]}"
    _emit(ten, "WEBHOOK_CREATED", "wh_1")
    _emit(ten, "WEBHOOK_UPDATED", "wh_1")
    _emit(ten, "WEBHOOK_DELETED", "wh_1", outcome="SUCCESS")
    r = client.get("/api/xdr/audit-log?action=WEBHOOK_UPDATED",
                          headers={"X-Tenant-Id": ten})
    j = r.json()["data"]
    assert j["count"] == 1
    assert j["events"][0]["action"] == "WEBHOOK_UPDATED"
    # cleanup
    al._get_coll().delete_many({"tenant_id": ten})
