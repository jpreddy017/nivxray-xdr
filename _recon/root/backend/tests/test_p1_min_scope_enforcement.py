"""Owner-required proof: the ingest credential's MINIMUM scopes are actually
enforced by the backend.

A production ingest key will hold exactly `collectors.enroll` +
`collectors.read`. This suite proves that such a key:
  * CAN authenticate for those two permissions;
  * CANNOT reach anything else — create/update/delete/enable/disable/test/
    rotate collectors, mint or read API keys, read alerts, manage users,
    read secrets, run RBAC admin;
  * gets NO wildcard expansion, and a wildcard scope is never implied.
"""
from __future__ import annotations

import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from routers import xdr_api_keys as ak
from routers import xdr_rbac as rb
from services import machine_rate_limit as mrl

TEN = f"p1-minscope-{uuid.uuid4().hex[:8]}"
GRANTED = ["collectors.enroll", "collectors.read"]

# Everything the production ingest credential must NOT be able to do.
DENIED_PERMISSIONS = [
    "collectors.create", "collectors.update", "collectors.delete",
    "collectors.enable", "collectors.disable", "collectors.test",
    "collectors.rotate",
    "api_keys.create", "api_keys.read", "api_keys.revoke", "api_keys.rotate",
    "api_keys.delete",
    "alerts.read", "alerts.ack",
    "users.create", "users.read", "users.delete",
    "roles.create", "roles.read",
    "secrets.read", "secrets.create",
    "audit.read",
    "webhooks.create",
    "data_sources.create", "data_sources.delete",
]

app = FastAPI()


def _mount(permission: str):
    @app.get(f"/probe/{permission}",
             dependencies=[Depends(rb.require_permission(permission))])
    def _p(request: Request, _perm=permission):        # noqa: ANN001
        return {"ok": True, "permission": _perm}


for _perm in GRANTED + DENIED_PERMISSIONS:
    _mount(_perm)

client = TestClient(app)


def _skip_if_no_mongo():
    if ak._coll() is None or not os.environ.get("MONGO_URL"):
        pytest.skip("MONGO_URL not configured")


def _mint(scopes):
    plaintext = ak._gen_plaintext()
    kid = f"key_{uuid.uuid4().hex[:20]}"
    ak._coll().insert_one({
        "id": kid, "tenant_id": TEN, "name": kid,
        "prefix": ak._preview(plaintext), "hash": ak._hash(plaintext),
        "scopes": list(scopes), "enabled": True, "revoked_at": None,
        "expires_at": None, "use_count": 0})
    return kid, plaintext


@pytest.fixture(autouse=True)
def _clean():
    if not os.environ.get("MONGO_URL"):
        yield
        return
    mrl._coll().delete_many({})
    yield
    mrl._coll().delete_many({})
    ak._coll().delete_many({"tenant_id": TEN})


def _hdrs(key):
    return {"X-XDR-API-Key": key, "X-Tenant-Id": TEN}


def test_granted_permissions_are_allowed():
    _skip_if_no_mongo()
    _, key = _mint(GRANTED)
    for perm in GRANTED:
        r = client.get(f"/probe/{perm}", headers=_hdrs(key))
        assert r.status_code == 200, f"{perm} -> {r.status_code} {r.text}"


@pytest.mark.parametrize("perm", DENIED_PERMISSIONS)
def test_every_other_permission_is_denied(perm):
    _skip_if_no_mongo()
    _, key = _mint(GRANTED)
    r = client.get(f"/probe/{perm}", headers=_hdrs(key))
    assert r.status_code == 403, f"{perm} -> {r.status_code} {r.text}"
    d = r.json()["detail"]
    assert d["reason"] == "scope-not-granted"
    assert d["principal_kind"] == "api_key"


def test_effective_permission_set_is_exactly_the_two_granted():
    _skip_if_no_mongo()
    perms = rb._key_effective_permissions({"scopes": GRANTED})
    assert perms == set(GRANTED), perms


def test_no_wildcard_is_implied():
    _skip_if_no_mongo()
    perms = rb._key_effective_permissions({"scopes": GRANTED})
    assert not any(p.endswith(".*") or p == "*.*" for p in perms)
    # A key that never asked for it must not inherit the collectors wildcard.
    assert "collectors.create" not in perms
    assert "collectors.delete" not in perms


def test_empty_scopes_grant_nothing():
    _skip_if_no_mongo()
    _, key = _mint([])
    r = client.get("/probe/collectors.enroll", headers=_hdrs(key))
    assert r.status_code == 403
    assert r.json()["detail"]["reason"] == "scope-not-granted"


def test_key_never_inherits_a_user_role():
    _skip_if_no_mongo()
    # The machine path resolves permissions ONLY from the key document, so a
    # platform_admin role existing in the same tenant changes nothing.
    if rb._c_roles() is not None:
        rb._c_roles().insert_one({"tenant_id": TEN, "id": "platform_admin",
                                  "permissions": ["*.*"]})
    try:
        _, key = _mint(GRANTED)
        r = client.get("/probe/api_keys.create", headers=_hdrs(key))
        assert r.status_code == 403
        assert r.json()["detail"]["reason"] == "scope-not-granted"
    finally:
        if rb._c_roles() is not None:
            rb._c_roles().delete_many({"tenant_id": TEN})
