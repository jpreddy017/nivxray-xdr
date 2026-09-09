"""XDR API Keys — P0-4 pytest.

Covers:
- creation returns plaintext ONCE + hash-only persistence
- list/get return masked docs (never `hash`)
- rotate returns fresh plaintext, old key stops verifying
- expired keys never verify
- revoked/disabled keys never verify
- delete removes and audits
- duplicate name rejected
- invalid scope rejected
- verify_api_key() stamps last_used_at + increments use_count
- RBAC 403 when principal lacks api_keys.create
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")

from routers import xdr_api_keys as ak
from routers import xdr_audit_log as al
from routers import xdr_rbac as rb
from server import app

client = TestClient(app)

TEN = f"apikey-tenant-{uuid.uuid4().hex[:8]}"
ADMIN = "root@apikeys.nivxray.com"
ANALYST = "l1@apikeys.nivxray.com"


def _hdrs(email=ADMIN):
    return {"X-Tenant-Id": TEN,
                "X-Principal-Id": email,
                "X-Principal-Kind": "user"}


@pytest.fixture(scope="module", autouse=True)
def _seed():
    # Clean.
    for c in (ak._coll, rb._c_users, rb._c_roles, rb._c_assignments):
        if c() is not None:
            c().delete_many({"tenant_id": TEN})
            c().delete_many({})   # roles / users are per-tenant scoped anyway
    if al._get_coll() is not None:
        al._get_coll().delete_many({"tenant_id": TEN})
    # Seed admin + analyst users for RBAC enforcement path.
    client.post("/api/xdr/rbac/users", headers=_hdrs(),
                    json={"email": ADMIN, "initial_roles": ["platform_admin"]})
    client.post("/api/xdr/rbac/users", headers=_hdrs(),
                    json={"email": ANALYST, "initial_roles": ["l1_analyst"]})
    yield


def _skip_if_no_mongo():
    if ak._coll() is None:
        pytest.skip("MONGO_URL not configured")


# ── 1 · create + masked persistence + audit_ref ──────────────────
def test_create_key_returns_plaintext_once():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/api-keys", headers=_hdrs(),
                          json={"name": "ci-runner", "scopes": ["lolbas.sync",
                                                                                          "audit.read"]})
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert d["id"].startswith("key_")
    assert d["prefix"].startswith("nvx_") and len(d["prefix"]) == 12
    assert d["plaintext"].startswith("nvx_")
    assert "hash" not in d, "hash must never leak"
    assert d["scopes"] == ["lolbas.sync", "audit.read"]
    assert r.json()["audit_ref"].startswith("aud_")

    # Second GET does NOT return plaintext.
    r2 = client.get(f"/api/xdr/api-keys/{d['id']}", headers=_hdrs())
    d2 = r2.json()["data"]
    assert "plaintext" not in d2
    assert "hash" not in d2


def test_duplicate_name_rejected():
    _skip_if_no_mongo()
    client.post("/api/xdr/api-keys", headers=_hdrs(),
                    json={"name": "dup-key", "scopes": []})
    r = client.post("/api/xdr/api-keys", headers=_hdrs(),
                          json={"name": "dup-key", "scopes": []})
    assert r.status_code == 409


def test_invalid_scope_rejected():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/api-keys", headers=_hdrs(),
                          json={"name": "bad-scope", "scopes": ["fake.thing"]})
    assert r.status_code == 400


# ── 2 · verify_api_key + rotation invalidates old plaintext ──────
def test_verify_and_rotate_invalidates_old():
    _skip_if_no_mongo()
    created = client.post("/api/xdr/api-keys", headers=_hdrs(),
                                    json={"name": "rot-key", "scopes": ["audit.read"]})
    plaintext_v1 = created.json()["data"]["plaintext"]
    kid = created.json()["data"]["id"]

    v1 = ak.verify_api_key(plaintext_v1, source_ip="1.2.3.4")
    assert v1 is not None
    assert v1["id"] == kid
    assert v1["use_count"] == 1
    assert v1["last_used_ip"] == "1.2.3.4"

    r = client.post(f"/api/xdr/api-keys/{kid}/rotate", headers=_hdrs())
    plaintext_v2 = r.json()["data"]["plaintext"]
    assert plaintext_v1 != plaintext_v2

    # Old plaintext no longer verifies.
    assert ak.verify_api_key(plaintext_v1) is None
    # New plaintext verifies.
    assert ak.verify_api_key(plaintext_v2) is not None


# ── 3 · expiration ───────────────────────────────────────────────
def test_expired_key_never_verifies():
    _skip_if_no_mongo()
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    r = client.post("/api/xdr/api-keys", headers=_hdrs(),
                          json={"name": "expired-key", "scopes": [],
                                    "expires_at": past})
    plaintext = r.json()["data"]["plaintext"]
    assert ak.verify_api_key(plaintext) is None


# ── 4 · revoke + delete ──────────────────────────────────────────
def test_revoke_disables_verification():
    _skip_if_no_mongo()
    created = client.post("/api/xdr/api-keys", headers=_hdrs(),
                                    json={"name": "to-revoke", "scopes": []})
    kid       = created.json()["data"]["id"]
    plaintext = created.json()["data"]["plaintext"]
    assert ak.verify_api_key(plaintext) is not None
    client.post(f"/api/xdr/api-keys/{kid}/revoke", headers=_hdrs())
    assert ak.verify_api_key(plaintext) is None
    doc = client.get(f"/api/xdr/api-keys/{kid}", headers=_hdrs()).json()["data"]
    assert doc["enabled"] is False
    assert doc["revoked_at"] is not None


def test_delete_removes_and_audits():
    _skip_if_no_mongo()
    created = client.post("/api/xdr/api-keys", headers=_hdrs(),
                                    json={"name": "to-delete", "scopes": []})
    kid = created.json()["data"]["id"]
    r = client.delete(f"/api/xdr/api-keys/{kid}", headers=_hdrs())
    assert r.status_code == 200 and r.json()["data"]["deleted"] is True
    r2 = client.get(f"/api/xdr/api-keys/{kid}", headers=_hdrs())
    assert r2.status_code == 404
    events = client.get("/api/xdr/audit-log?action=API_KEY_DELETED",
                                  headers=_hdrs()).json()["data"]["events"]
    assert any(e["resource_id"] == kid for e in events)


# ── 5 · RBAC enforcement ─────────────────────────────────────────
def test_rbac_denies_analyst_creating_key():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/api-keys", headers=_hdrs(email=ANALYST),
                          json={"name": "sneaky", "scopes": []})
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "ACCESS_DENIED"
    assert r.json()["detail"]["permission"] == "api_keys.create"


# ── 6 · Audit chain remains valid across full lifecycle ──────────
def test_audit_chain_valid():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/audit-log/verify/chain", headers=_hdrs())
    assert r.json()["data"]["status"] == "valid", r.json()
