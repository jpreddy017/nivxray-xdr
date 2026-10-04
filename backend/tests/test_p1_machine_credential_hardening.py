"""P1 machine-credential hardening — rate limiting + issuance confirmation.

Closes the two gaps recorded in memory/PREVIEW_COLLECTOR_PROOF.md before a
production ingest credential is issued:
  P1-a  no per-key / per-tenant / per-IP throttle on the machine auth path
  P1-b  key issuance derived the tenant from a header with no confirmation
"""
from __future__ import annotations

import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Depends, Request
from fastapi.testclient import TestClient

from routers import xdr_api_keys as ak
from routers import xdr_rbac as rb
from services import machine_rate_limit as mrl

TEN = f"p1-hardening-{uuid.uuid4().hex[:8]}"


def _skip_if_no_mongo():
    if ak._coll() is None or not os.environ.get("MONGO_URL"):
        pytest.skip("MONGO_URL not configured")


def _buckets():
    mrl._coll()
    return mrl._client[mrl._DB_NAME][mrl._COLLECTION]


# ── Minimal app exercising ONLY the machine path ──────────────────
app = FastAPI()


@app.get("/probe", dependencies=[Depends(rb.require_permission("collectors.enroll"))])
def probe(request: Request):
    return {"ok": True, "tenant": request.state.tenant_id}


client = TestClient(app)


def _mint(scopes=("collectors.enroll",), tenant=TEN):
    """Mint a key directly through the router's own storage contract."""
    plaintext = ak._gen_plaintext()
    kid = f"key_{uuid.uuid4().hex[:20]}"
    ak._coll().insert_one({
        "id": kid, "tenant_id": tenant, "name": kid,
        "prefix": ak._preview(plaintext), "hash": ak._hash(plaintext),
        "scopes": list(scopes), "enabled": True, "revoked_at": None,
        "expires_at": None, "use_count": 0})
    return kid, plaintext


@pytest.fixture(autouse=True)
def _clean_buckets():
    if not os.environ.get("MONGO_URL"):
        yield
        return
    _buckets().delete_many({})
    yield
    _buckets().delete_many({})
    if ak._coll() is not None:
        ak._coll().delete_many({"tenant_id": TEN})


# ══ P1-a · rate limiting ══════════════════════════════════════════
def test_valid_key_is_allowed_under_quota():
    _skip_if_no_mongo()
    _, key = _mint()
    r = client.get("/probe", headers={"X-XDR-API-Key": key, "X-Tenant-Id": TEN})
    assert r.status_code == 200, r.text
    assert r.json()["tenant"] == TEN


def test_per_key_quota_returns_429_with_retry_after(monkeypatch):
    _skip_if_no_mongo()
    monkeypatch.setitem(mrl.LIMITS, "key", 3)
    _, key = _mint()
    hdrs = {"X-XDR-API-Key": key, "X-Tenant-Id": TEN}
    codes = [client.get("/probe", headers=hdrs).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200], codes
    assert codes[3] == 429 and codes[4] == 429, codes
    r = client.get("/probe", headers=hdrs)
    assert r.json()["detail"]["code"] == "RATE_LIMITED"
    assert r.json()["detail"]["scope"] == "key"
    assert int(r.headers["Retry-After"]) >= 1
    assert r.headers["RateLimit-Remaining"] == "0"


def test_ip_quota_throttles_unknown_keys(monkeypatch):
    _skip_if_no_mongo()
    monkeypatch.setitem(mrl.LIMITS, "ip", 2)
    bogus = "nvx_" + "0" * 48
    hdrs = {"X-XDR-API-Key": bogus, "X-Tenant-Id": TEN}
    codes = [client.get("/probe", headers=hdrs).status_code for _ in range(4)]
    # Unknown key is 401, but the IP window still closes: brute force is capped.
    assert codes[:2] == [401, 401], codes
    assert codes[2] == 429 and codes[3] == 429, codes


def test_tenant_quota_is_shared_across_keys(monkeypatch):
    _skip_if_no_mongo()
    monkeypatch.setitem(mrl.LIMITS, "tenant", 2)
    _, key_a = _mint()
    _, key_b = _mint()
    a = client.get("/probe", headers={"X-XDR-API-Key": key_a, "X-Tenant-Id": TEN})
    b = client.get("/probe", headers={"X-XDR-API-Key": key_b, "X-Tenant-Id": TEN})
    c = client.get("/probe", headers={"X-XDR-API-Key": key_b, "X-Tenant-Id": TEN})
    assert (a.status_code, b.status_code) == (200, 200)
    assert c.status_code == 429
    assert c.json()["detail"]["scope"] == "tenant"


def test_limiter_fault_fails_closed(monkeypatch):
    _skip_if_no_mongo()
    _, key = _mint()

    def _boom(scope, subject):
        raise mrl.RateLimitUnavailable("store down")

    monkeypatch.setattr(mrl, "consume", _boom)
    r = client.get("/probe", headers={"X-XDR-API-Key": key, "X-Tenant-Id": TEN})
    assert r.status_code == 503
    assert r.json()["detail"]["code"] == "RATE_LIMITER_UNAVAILABLE"


def test_throttle_does_not_apply_to_missing_credential():
    _skip_if_no_mongo()
    r = client.get("/probe")
    assert r.status_code == 403
    assert r.json()["detail"]["reason"] == "unauthenticated"


# ══ P1-b · issuance confirmation ══════════════════════════════════
class _Req:
    """Minimal request stub — `_principal()` only reads headers/state."""

    def __init__(self, tenant):
        self.headers = {"X-Tenant-Id": tenant, "X-Principal-Id": "admin@nivxray.com"}
        self.state = type("S", (), {})()


def test_confirm_tenant_id_is_required():
    _skip_if_no_mongo()
    with pytest.raises(Exception):
        ak.CreateKeyBody(name="x")


def test_confirmation_mismatch_is_rejected():
    _skip_if_no_mongo()
    _mint()  # make TEN a known tenant
    body = ak.CreateKeyBody(name=f"k-{uuid.uuid4().hex[:6]}",
                            confirm_tenant_id="typo-tenant", scopes=[])
    with pytest.raises(Exception) as ex:
        ak.create_key(body, _Req(TEN))
    assert ex.value.detail["code"] == "TENANT_CONFIRMATION_MISMATCH"
    assert ex.value.status_code == 400


def test_unknown_tenant_needs_explicit_acknowledgement():
    _skip_if_no_mongo()
    ghost = f"ghost-{uuid.uuid4().hex[:8]}"
    body = ak.CreateKeyBody(name=f"k-{uuid.uuid4().hex[:6]}",
                            confirm_tenant_id=ghost, scopes=[])
    with pytest.raises(Exception) as ex:
        ak.create_key(body, _Req(ghost))
    assert ex.value.detail["code"] == "UNKNOWN_TENANT"

    ok = ak.CreateKeyBody(name=f"k-{uuid.uuid4().hex[:6]}",
                          confirm_tenant_id=ghost, allow_new_tenant=True,
                          scopes=[])
    res = ak.create_key(ok, _Req(ghost))
    assert res["data"]["tenant_id"] == ghost
    assert res["data"]["plaintext"].startswith("nvx_")
    ak._coll().delete_many({"tenant_id": ghost})


def test_matching_confirmation_on_known_tenant_succeeds():
    _skip_if_no_mongo()
    _mint()
    body = ak.CreateKeyBody(name=f"k-{uuid.uuid4().hex[:6]}",
                            confirm_tenant_id=TEN, scopes=["collectors.enroll"])
    res = ak.create_key(body, _Req(TEN))
    assert res["data"]["tenant_id"] == TEN
    assert "hash" not in res["data"]


def test_tenant_is_known_detects_existing_control_plane_object():
    _skip_if_no_mongo()
    assert ak._tenant_is_known(f"never-existed-{uuid.uuid4().hex}") is False
    _mint()
    assert ak._tenant_is_known(TEN) is True
