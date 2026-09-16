"""P0 · Collector API-key authentication (machine principal).

`require_permission` accepts two mutually exclusive principals:

    USER    — a verified JWT, resolved through `xdr_users` role assignments.
    MACHINE — `X-XDR-API-Key` + `X-Tenant-Id`, validated against the
              SHA-256 digests persisted in `xdr_api_keys`.

`xdr_api_keys` has always stored ONLY `hashlib.sha256(plaintext)`; there is
no plaintext column and therefore no plaintext comparison path to migrate
away from.  These tests assert that, and that every invalid machine
credential is denied.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

os.environ.setdefault("DB_NAME", "test_database")

from server import app  # noqa: E402

READ_PATH   = "/api/xdr/collectors"           # collectors.read
INGEST_PATH = "/api/xdr/ingest/telemetry"     # collectors.enroll
TENANT      = "p0f-keyauth-test"
OTHER_TENANT = "p0f-keyauth-other"

_keys = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]["xdr_api_keys"]


def _plaintext() -> str:
    return "nvx_" + secrets.token_hex(24)


def _mint(**overrides) -> str:
    """Insert a key document directly and return its plaintext."""
    raw = _plaintext()
    now = datetime.now(timezone.utc).isoformat()
    doc = {
        "id": f"key_{uuid.uuid4().hex[:20]}",
        "tenant_id": TENANT,
        "name": f"test-{uuid.uuid4().hex[:8]}",
        "prefix": raw[:12],
        "hash": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "scopes": ["collectors.read", "collectors.enroll"],
        "enabled": True,
        "revoked_at": None,
        "expires_at": None,
        "created_at": now,
        "updated_at": now,
        "last_used_at": None,
        "last_used_ip": None,
        "use_count": 0,
    }
    doc.update(overrides)
    _keys.insert_one(doc)
    return raw


@pytest.fixture(autouse=True, scope="module")
def _cleanup():
    yield
    _keys.delete_many({"tenant_id": {"$in": [TENANT, OTHER_TENANT]}})


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _hdrs(raw: str, tenant: str = TENANT) -> dict:
    return {"X-XDR-API-Key": raw, "X-Tenant-Id": tenant}


def _reason(resp) -> str:
    detail = resp.json().get("detail")
    return (detail or {}).get("reason") if isinstance(detail, dict) else str(detail)


# ── Storage guarantee ─────────────────────────────────────────────
def test_only_sha256_digests_are_persisted(client):
    raw = _mint()
    doc = _keys.find_one({"hash": hashlib.sha256(raw.encode()).hexdigest()})
    assert doc is not None
    assert doc["hash"] == hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert len(doc["hash"]) == 64
    # No field anywhere in the record may contain the plaintext.
    assert raw not in str({k: v for k, v in doc.items() if k != "prefix"})


def test_no_plaintext_comparison_path_in_rbac_source():
    with open("/app/backend/routers/xdr_rbac.py", encoding="utf8") as fh:
        src = fh.read()
    fn = src.split("def authenticate_api_key(", 1)[1].split("\n# ──", 1)[0]
    assert "hashlib.sha256" in fn, "key lookup is not digest-based"
    assert "hmac.compare_digest" in fn, "digest comparison is not constant-time"
    assert '"plaintext"' not in fn and "plaintext" not in fn, (
        "a plaintext compatibility path exists in the machine auth path")


# ── Happy path ────────────────────────────────────────────────────
def test_valid_key_authorizes_read(client):
    raw = _mint()
    r = client.get(READ_PATH, headers=_hdrs(raw))
    assert r.status_code == 200, r.text


def test_valid_key_reaches_ingest_handler(client):
    """`collectors.enroll` is granted, so the gate must pass and the
    request must reach body validation (400 empty batch)."""
    raw = _mint()
    r = client.post(INGEST_PATH, headers=_hdrs(raw), json={"envelopes": []})
    assert r.status_code == 400, r.text


def test_wildcard_scope_is_honoured(client):
    raw = _mint(scopes=["collectors.*"])
    assert client.get(READ_PATH, headers=_hdrs(raw)).status_code == 200


def test_global_wildcard_scope_is_honoured(client):
    raw = _mint(scopes=["*.*"])
    assert client.get(READ_PATH, headers=_hdrs(raw)).status_code == 200


def test_last_used_is_stamped(client):
    raw = _mint()
    digest = hashlib.sha256(raw.encode()).hexdigest()
    assert client.get(READ_PATH, headers=_hdrs(raw)).status_code == 200
    doc = _keys.find_one({"hash": digest})
    assert doc["last_used_at"] is not None
    assert doc["use_count"] == 1


# ── Fail-closed matrix ────────────────────────────────────────────
def test_missing_credential_is_rejected(client):
    r = client.get(READ_PATH, headers={"X-Tenant-Id": TENANT})
    assert r.status_code in (401, 403)


@pytest.mark.parametrize("bad", [
    "", "not-a-key", "nvx_", "nvx_short", "NVX_" + "a" * 48,
    "nvx_" + "A" * 48, "nvx_" + "z" * 48, "nvx_" + "a" * 47,
    "nvx_" + "a" * 49, "bearer nvx_" + "a" * 48,
])
def test_malformed_key_is_rejected(client, bad):
    r = client.get(READ_PATH, headers=_hdrs(bad))
    assert r.status_code == 401, r.text
    assert _reason(r) == "malformed-api-key"


def test_unknown_key_is_rejected(client):
    r = client.get(READ_PATH, headers=_hdrs(_plaintext()))
    assert r.status_code == 401
    assert _reason(r) == "unknown-api-key"


def test_missing_tenant_header_is_rejected(client):
    raw = _mint()
    r = client.get(READ_PATH, headers={"X-XDR-API-Key": raw})
    assert r.status_code == 401
    assert _reason(r) == "missing-tenant-header"


def test_revoked_key_is_rejected(client):
    raw = _mint(enabled=False,
                revoked_at=datetime.now(timezone.utc).isoformat())
    r = client.get(READ_PATH, headers=_hdrs(raw))
    assert r.status_code == 403
    assert _reason(r) == "api-key-revoked"


def test_disabled_key_is_rejected(client):
    raw = _mint(enabled=False)
    r = client.get(READ_PATH, headers=_hdrs(raw))
    assert r.status_code == 403
    assert _reason(r) == "api-key-disabled"


def test_expired_key_is_rejected(client):
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    raw = _mint(expires_at=past)
    r = client.get(READ_PATH, headers=_hdrs(raw))
    assert r.status_code == 403
    assert _reason(r) == "api-key-expired"


def test_unexpired_key_is_accepted(client):
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    raw = _mint(expires_at=future)
    assert client.get(READ_PATH, headers=_hdrs(raw)).status_code == 200


def test_malformed_expiry_never_means_never_expires(client):
    raw = _mint(expires_at="whenever")
    r = client.get(READ_PATH, headers=_hdrs(raw))
    assert r.status_code == 403
    assert _reason(r) == "api-key-expiry-malformed"


def test_wrong_tenant_header_is_rejected(client):
    raw = _mint()
    r = client.get(READ_PATH, headers=_hdrs(raw, OTHER_TENANT))
    assert r.status_code == 403
    assert _reason(r) == "api-key-tenant-mismatch"


def test_scope_not_granted_is_rejected(client):
    raw = _mint(scopes=["alerts.read"])
    r = client.get(READ_PATH, headers=_hdrs(raw))
    assert r.status_code == 403
    assert _reason(r) == "scope-not-granted"


def test_empty_scope_is_rejected(client):
    raw = _mint(scopes=[])
    r = client.get(READ_PATH, headers=_hdrs(raw))
    assert r.status_code == 403
    assert _reason(r) == "scope-not-granted"


def test_scope_gate_blocks_ingest_without_enroll(client):
    raw = _mint(scopes=["collectors.read"])
    r = client.post(INGEST_PATH, headers=_hdrs(raw), json={"envelopes": []})
    assert r.status_code == 403, r.text
    assert r.status_code not in (400, 422), "gate ran after body validation"


# ── The two principals must not blend ─────────────────────────────
def test_invalid_jwt_does_not_fall_through_to_key_auth(client):
    raw = _mint()
    r = client.get(READ_PATH, headers={**_hdrs(raw),
                                       "Authorization": "Bearer not-a-jwt"})
    assert r.status_code in (401, 403)
    assert _reason(r) == "ambiguous-credentials"


def test_both_credentials_present_is_rejected(client):
    raw = _mint()
    login = client.post("/api/auth/login", json={
        "email": os.environ["ADMIN_EMAIL"],
        "password": os.environ["ADMIN_PASSWORD"]})
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    r = client.get(READ_PATH, headers={**_hdrs(raw),
                                       "Authorization": f"Bearer {token}"})
    assert r.status_code in (401, 403)
    assert _reason(r) == "ambiguous-credentials"


def test_api_key_cannot_impersonate_a_user_principal(client):
    """A key grants only its own scopes — never a user's role set."""
    raw = _mint(scopes=["collectors.read"])
    r = client.get("/api/xdr/rbac/users", headers=_hdrs(raw))
    assert r.status_code == 403
    assert _reason(r) == "scope-not-granted"


def test_jwt_admin_path_still_works(client):
    login = client.post("/api/auth/login", json={
        "email": os.environ["ADMIN_EMAIL"],
        "password": os.environ["ADMIN_PASSWORD"]})
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    r = client.get(READ_PATH, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
