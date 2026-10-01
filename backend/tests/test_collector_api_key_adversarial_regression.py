"""Independent adversarial regression for the collector API-key auth path.

Runs against the LIVE preview backend (via REACT_APP_BACKEND_URL) — not TestClient —
to independently corroborate the in-process suite. Focus areas requested by the
review:

    - empty-string X-XDR-API-Key value
    - header-name case variations (x-xdr-api-key, X-XDR-Api-Key)
    - spoofed X-Principal-Id / X-Principal-Kind alongside a valid key
    - cross-tenant envelope: key bound to tenant A, ingest body tenant_id=tenant B
    - expires_at: null must be accepted (never-expires is intentional per spec)
    - JWT regression (admin login + gated GETs)
    - Anonymous fail-closed regression (with header spoofing)
"""
from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from datetime import datetime, timezone

import pytest
import requests
from pymongo import MongoClient

def _read_frontend_env():
    try:
        with open("/app/frontend/.env") as fh:
            for ln in fh:
                if ln.startswith("REACT_APP_BACKEND_URL="):
                    return ln.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return None

BASE = (os.environ.get("REACT_APP_BACKEND_URL") or _read_frontend_env() or "").rstrip("/")
assert BASE, "REACT_APP_BACKEND_URL not set"
DB   = MongoClient(os.environ["MONGO_URL"])[os.environ.get("DB_NAME", "test_database")]
KEYS = DB["xdr_api_keys"]

TENANT_A = "adv-regress-tenant-a"
TENANT_B = "adv-regress-tenant-b"

READ_PATH   = f"{BASE}/api/xdr/collectors"
INGEST_PATH = f"{BASE}/api/xdr/ingest/telemetry"
SECRETS_PATH = f"{BASE}/api/xdr/secrets"
APIKEYS_PATH = f"{BASE}/api/xdr/api-keys"
RULES_PATH   = f"{BASE}/api/xdr/rule-studio/rules"


def _plaintext() -> str:
    return "nvx_" + secrets.token_hex(24)


def _mint(tenant: str = TENANT_A, **overrides) -> str:
    raw = _plaintext()
    now = datetime.now(timezone.utc).isoformat()
    doc = {
        "id": f"key_{uuid.uuid4().hex[:20]}",
        "tenant_id": tenant,
        "name": f"adv-{uuid.uuid4().hex[:8]}",
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
    KEYS.insert_one(doc)
    return raw


@pytest.fixture(scope="module", autouse=True)
def _cleanup():
    yield
    KEYS.delete_many({"tenant_id": {"$in": [TENANT_A, TENANT_B]}})


@pytest.fixture(scope="module")
def admin_token():
    r = requests.post(f"{BASE}/api/auth/login", json={
        "email": os.environ["ADMIN_EMAIL"],
        "password": os.environ["ADMIN_PASSWORD"],
    }, timeout=15)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


# ── Adversarial: bypass probes ────────────────────────────────────
def test_empty_string_key_value_is_rejected():
    r = requests.get(READ_PATH, headers={"X-XDR-API-Key": "", "X-Tenant-Id": TENANT_A}, timeout=15)
    # Empty value should be treated as either missing credential or malformed key.
    assert r.status_code in (401, 403), r.text


def test_header_case_variation_lowercase_is_honoured():
    raw = _mint()
    r = requests.get(READ_PATH, headers={"x-xdr-api-key": raw, "x-tenant-id": TENANT_A}, timeout=15)
    assert r.status_code == 200, r.text


def test_header_case_variation_mixed_is_honoured():
    raw = _mint()
    r = requests.get(READ_PATH, headers={"X-Xdr-Api-Key": raw, "X-Tenant-ID": TENANT_A}, timeout=15)
    assert r.status_code == 200, r.text


def test_spoofed_principal_headers_with_valid_key_do_not_elevate():
    """Attacker adds X-Principal-* alongside a key with only collectors.read.
    Must still be 403 on a user-only endpoint (rbac/users)."""
    raw = _mint(scopes=["collectors.read"])
    r = requests.get(
        f"{BASE}/api/xdr/rbac/users",
        headers={
            "X-XDR-API-Key": raw,
            "X-Tenant-Id": TENANT_A,
            "X-Principal-Id": "admin@nivxray.com",
            "X-Principal-Kind": "user",
        }, timeout=15)
    assert r.status_code == 403, r.text


def test_cross_tenant_envelope_body_does_not_bypass_key_tenant_binding():
    """Key bound to tenant A, telemetry body claims tenant B → the gate uses
    the key's tenant, and the tenant header must equal the key's tenant.
    Attacker attempts: X-Tenant-Id = A (matches key), but body tenant_id = B."""
    raw = _mint(tenant=TENANT_A, scopes=["collectors.enroll"])
    body = {"envelopes": [{"tenant_id": TENANT_B, "source": "x", "events": []}]}
    r = requests.post(INGEST_PATH,
                      headers={"X-XDR-API-Key": raw, "X-Tenant-Id": TENANT_A},
                      json=body, timeout=15)
    # The gate should pass (auth OK) but downstream tenant-isolation must reject
    # cross-tenant envelopes, OR body validation must complain. Must not 200.
    assert r.status_code in (400, 403, 422), r.text
    # And with wrong header (B) but body A → auth denies with tenant mismatch.
    r2 = requests.post(INGEST_PATH,
                       headers={"X-XDR-API-Key": raw, "X-Tenant-Id": TENANT_B},
                       json={"envelopes": [{"tenant_id": TENANT_A, "source": "x", "events": []}]},
                       timeout=15)
    assert r2.status_code in (401, 403), r2.text


def test_expires_at_null_is_accepted_as_never_expires():
    raw = _mint(expires_at=None)
    r = requests.get(READ_PATH, headers={"X-XDR-API-Key": raw, "X-Tenant-Id": TENANT_A}, timeout=15)
    assert r.status_code == 200, r.text


def test_invalid_jwt_does_not_fall_through_when_key_also_present():
    raw = _mint()
    r = requests.get(READ_PATH, headers={
        "X-XDR-API-Key": raw, "X-Tenant-Id": TENANT_A,
        "Authorization": "Bearer garbage",
    }, timeout=15)
    assert r.status_code in (401, 403), r.text


# ── Anonymous fail-closed (P0-SEC regression) ─────────────────────
@pytest.mark.parametrize("path", [
    f"{BASE}/api/xdr/collectors",
    f"{BASE}/api/xdr/secrets",
    f"{BASE}/api/xdr/api-keys",
    f"{BASE}/api/xdr/rule-studio/rules",
])
def test_anonymous_is_rejected(path):
    r = requests.get(path, timeout=15)
    assert r.status_code in (401, 403), (path, r.status_code, r.text[:200])


@pytest.mark.parametrize("path", [
    f"{BASE}/api/xdr/collectors",
    f"{BASE}/api/xdr/secrets",
])
def test_anonymous_with_spoofed_principal_headers_is_rejected(path):
    r = requests.get(path, headers={
        "X-Tenant-Id": TENANT_A,
        "X-Principal-Id": "admin@nivxray.com",
        "X-Principal-Kind": "user",
    }, timeout=15)
    assert r.status_code in (401, 403), (path, r.status_code, r.text[:200])


def test_anonymous_ingest_denied_before_body_validation():
    r = requests.post(INGEST_PATH, json={"envelopes": []}, timeout=15)
    assert r.status_code in (401, 403), r.text
    # Must NOT be 400 empty-batch (which would prove auth was bypassed)
    assert r.status_code != 400, "gate ran after body validation for anonymous"


# ── JWT admin regression ──────────────────────────────────────────
@pytest.mark.parametrize("path", [
    "/api/xdr/collectors",
    "/api/xdr/secrets",
    "/api/xdr/api-keys",
    "/api/xdr/rule-studio/rules",
])
def test_admin_jwt_still_authorized(admin_token, path):
    r = requests.get(f"{BASE}{path}",
                     headers={"Authorization": f"Bearer {admin_token}"}, timeout=20)
    assert r.status_code == 200, (path, r.status_code, r.text[:200])
