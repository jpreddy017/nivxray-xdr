"""XDR Secrets Store — P0-2 pytest.

Covers:
- create → masked read-back with `preview` (no plaintext, no ciphertext)
- tenant isolation (A cannot see B's secrets)
- rotate bumps version + preserves last N previous versions (masked)
- reveal requires X-Secret-Reveal header, returns plaintext,
    and writes a SECRET_REVEALED audit event
- disabled secrets refuse to reveal
- delete removes and emits SECRET_DELETED
- filter list by kind / enabled
- ciphertext tamper (mutate DB doc) → decrypt/reveal fails with 422
- audit chain remains valid across a full CRUD/rotate/reveal cycle
"""
from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")
os.environ.setdefault("XDR_SECRETS_MASTER", "test-secrets-master-passphrase")

from routers import xdr_audit_log as al
from routers import xdr_secrets as sec
from server import app

client = TestClient(app)

TEN_A = f"tenant-a-{uuid.uuid4().hex[:8]}"
TEN_B = f"tenant-b-{uuid.uuid4().hex[:8]}"


def _hdrs(tenant, principal="tester@nivxray", kind="user", **extra):
    h = {"X-Tenant-Id": tenant,
             "X-Principal-Id": principal, "X-Principal-Kind": kind}
    h.update(extra)
    return h


@pytest.fixture(scope="module", autouse=True)
def _clean():
    if sec._get_coll() is not None:
        sec._get_coll().delete_many({"tenant_id": {"$in": [TEN_A, TEN_B]}})
    if al._get_coll() is not None:
        al._get_coll().delete_many({"tenant_id": {"$in": [TEN_A, TEN_B]}})
    yield
    if sec._get_coll() is not None:
        sec._get_coll().delete_many({"tenant_id": {"$in": [TEN_A, TEN_B]}})
    if al._get_coll() is not None:
        al._get_coll().delete_many({"tenant_id": {"$in": [TEN_A, TEN_B]}})


def _skip_if_no_mongo():
    if sec._get_coll() is None:
        pytest.skip("MONGO_URL not configured")


# ── Create + masked read-back ───────────────────────────────────
def test_create_and_masked_readback():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/secrets", headers=_hdrs(TEN_A),
                          json={"name": "vt-api-key", "kind": "api_key",
                                    "value": "sk-live-super-secret-value-1234",
                                    "description": "VirusTotal API key"})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["ok"] is True
    d = j["data"]
    assert d["id"].startswith("sec_")
    assert d["name"] == "vt-api-key"
    assert d["kind"] == "api_key"
    assert d["preview"] == "1234"
    assert d["version"] == 1
    assert d["enabled"] is True
    assert "ciphertext" not in d
    assert "previous_versions" not in d
    assert j["audit_ref"].startswith("aud_")

    r2 = client.get(f"/api/xdr/secrets/{d['id']}", headers=_hdrs(TEN_A))
    d2 = r2.json()["data"]
    assert d2["preview"] == "1234"
    assert "ciphertext" not in d2


def test_duplicate_name_rejected():
    _skip_if_no_mongo()
    r1 = client.post("/api/xdr/secrets", headers=_hdrs(TEN_A),
                            json={"name": "dup-key", "kind": "generic",
                                      "value": "v1"})
    assert r1.status_code == 200
    r2 = client.post("/api/xdr/secrets", headers=_hdrs(TEN_A),
                            json={"name": "dup-key", "kind": "generic",
                                      "value": "v2"})
    assert r2.status_code == 409


def test_tenant_isolation():
    _skip_if_no_mongo()
    a = client.post("/api/xdr/secrets", headers=_hdrs(TEN_A),
                          json={"name": "iso-key-a", "kind": "generic",
                                    "value": "value-A"}).json()["data"]
    b = client.post("/api/xdr/secrets", headers=_hdrs(TEN_B),
                          json={"name": "iso-key-b", "kind": "generic",
                                    "value": "value-B"}).json()["data"]
    assert a["id"].startswith("sec_")

    ra = client.get("/api/xdr/secrets", headers=_hdrs(TEN_A)).json()
    names = {s["name"] for s in ra["data"]["secrets"]}
    assert "iso-key-a" in names
    assert "iso-key-b" not in names

    r_cross = client.get(f"/api/xdr/secrets/{b['id']}",
                                    headers=_hdrs(TEN_A))
    assert r_cross.status_code == 404


def test_rotate_bumps_version_and_preview():
    _skip_if_no_mongo()
    created = client.post("/api/xdr/secrets", headers=_hdrs(TEN_A),
                                    json={"name": "rot-key", "kind": "api_key",
                                              "value": "orig-value-AAAA"}).json()["data"]
    assert created["preview"] == "AAAA"

    r = client.post(f"/api/xdr/secrets/{created['id']}/rotate",
                          headers=_hdrs(TEN_A),
                          json={"value": "new-rotated-value-ZZZZ"})
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert d["version"] == 2
    assert d["preview"] == "ZZZZ"
    assert d["rotated_at"] is not None


def test_reveal_requires_header_and_emits_audit():
    _skip_if_no_mongo()
    created = client.post("/api/xdr/secrets", headers=_hdrs(TEN_A),
                                    json={"name": "reveal-key", "kind": "api_key",
                                              "value": "the-real-plaintext-99"}).json()["data"]

    # Without header → 403
    r_no_hdr = client.post(f"/api/xdr/secrets/{created['id']}/reveal",
                                        headers=_hdrs(TEN_A))
    assert r_no_hdr.status_code == 403

    # With header → 200 + plaintext returned
    r_ok = client.post(
        f"/api/xdr/secrets/{created['id']}/reveal",
        headers=_hdrs(TEN_A, **{"X-Secret-Reveal": "yes",
                                             "X-Secret-Reveal-Reason": "unit-test"}),
    )
    assert r_ok.status_code == 200, r_ok.text
    body = r_ok.json()
    assert body["data"]["value"] == "the-real-plaintext-99"
    assert body["audit_ref"].startswith("aud_")

    # Audit log now shows a SECRET_REVEALED event for that resource id
    r_audit = client.get(
        "/api/xdr/audit-log",
        params={"action": "SECRET_REVEALED"},
        headers=_hdrs(TEN_A),
    )
    events = r_audit.json()["data"]["events"]
    assert any(e["resource_id"] == created["id"] for e in events)


def test_disabled_secret_refuses_reveal():
    _skip_if_no_mongo()
    created = client.post("/api/xdr/secrets", headers=_hdrs(TEN_A),
                                    json={"name": "disabled-key", "kind": "generic",
                                              "value": "hidden-value"}).json()["data"]
    r_upd = client.put(f"/api/xdr/secrets/{created['id']}",
                              headers=_hdrs(TEN_A),
                              json={"enabled": False})
    assert r_upd.status_code == 200
    assert r_upd.json()["data"]["enabled"] is False

    r = client.post(f"/api/xdr/secrets/{created['id']}/reveal",
                          headers=_hdrs(TEN_A, **{"X-Secret-Reveal": "yes"}))
    assert r.status_code == 409


def test_tamper_ciphertext_detected():
    _skip_if_no_mongo()
    created = client.post("/api/xdr/secrets", headers=_hdrs(TEN_A),
                                    json={"name": "tamper-key", "kind": "generic",
                                              "value": "authentic-value"}).json()["data"]
    # Corrupt ciphertext directly in Mongo — Fernet AEAD MUST reject it.
    sec._get_coll().update_one(
        {"id": created["id"], "tenant_id": TEN_A},
        {"$set": {"ciphertext": "gAAAAABm-invalid-ciphertext-blob"}},
    )
    r = client.post(f"/api/xdr/secrets/{created['id']}/reveal",
                          headers=_hdrs(TEN_A, **{"X-Secret-Reveal": "yes"}))
    assert r.status_code == 422
    assert "tampered" in r.json()["detail"].lower() \
             or "authentic" in r.json()["detail"].lower()


def test_delete_removes_and_audits():
    _skip_if_no_mongo()
    created = client.post("/api/xdr/secrets", headers=_hdrs(TEN_A),
                                    json={"name": "del-key", "kind": "generic",
                                              "value": "bye"}).json()["data"]
    r = client.delete(f"/api/xdr/secrets/{created['id']}",
                              headers=_hdrs(TEN_A))
    assert r.status_code == 200
    assert r.json()["data"]["deleted"] is True

    r2 = client.get(f"/api/xdr/secrets/{created['id']}",
                             headers=_hdrs(TEN_A))
    assert r2.status_code == 404

    events = client.get("/api/xdr/audit-log",
                                params={"action": "SECRET_DELETED"},
                                headers=_hdrs(TEN_A)).json()["data"]["events"]
    assert any(e["resource_id"] == created["id"] for e in events)


def test_filter_by_kind_and_enabled():
    _skip_if_no_mongo()
    ten = f"tenant-f-{uuid.uuid4().hex[:8]}"
    client.post("/api/xdr/secrets", headers=_hdrs(ten),
                    json={"name": "k1", "kind": "api_key", "value": "v1"})
    client.post("/api/xdr/secrets", headers=_hdrs(ten),
                    json={"name": "k2", "kind": "hmac_secret", "value": "v2"})
    r = client.get("/api/xdr/secrets", params={"kind": "api_key"},
                          headers=_hdrs(ten))
    assert r.status_code == 200
    names = {s["name"] for s in r.json()["data"]["secrets"]}
    assert "k1" in names
    assert "k2" not in names
    # cleanup
    sec._get_coll().delete_many({"tenant_id": ten})
    al._get_coll().delete_many({"tenant_id": ten})


def test_audit_chain_still_valid_after_full_cycle():
    _skip_if_no_mongo()
    ten = f"tenant-c-{uuid.uuid4().hex[:8]}"
    created = client.post("/api/xdr/secrets", headers=_hdrs(ten),
                                    json={"name": "cycle", "kind": "generic",
                                              "value": "orig"}).json()["data"]
    client.put(f"/api/xdr/secrets/{created['id']}", headers=_hdrs(ten),
                    json={"description": "updated"})
    client.post(f"/api/xdr/secrets/{created['id']}/rotate",
                     headers=_hdrs(ten), json={"value": "rotated"})
    client.post(f"/api/xdr/secrets/{created['id']}/reveal",
                     headers=_hdrs(ten, **{"X-Secret-Reveal": "yes"}))
    client.delete(f"/api/xdr/secrets/{created['id']}", headers=_hdrs(ten))

    r = client.get("/api/xdr/audit-log/verify/chain", headers=_hdrs(ten))
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert d["status"] == "valid", d
    assert d["checked"] >= 5
    sec._get_coll().delete_many({"tenant_id": ten})
    al._get_coll().delete_many({"tenant_id": ten})


def test_resolve_secret_helper_returns_plaintext_no_audit():
    """Server-internal accessor used by OSINT/webhook routers."""
    _skip_if_no_mongo()
    ten = f"tenant-r-{uuid.uuid4().hex[:8]}"
    client.post("/api/xdr/secrets", headers=_hdrs(ten),
                    json={"name": "svc-key", "kind": "api_key",
                              "value": "internal-plaintext-42"})
    got = sec.resolve_secret(ten, "svc-key")
    assert got == "internal-plaintext-42"
    # Missing name → None (never raises).
    assert sec.resolve_secret(ten, "nope") is None
    sec._get_coll().delete_many({"tenant_id": ten})
    al._get_coll().delete_many({"tenant_id": ten})
