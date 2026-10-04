"""P0-SEC · the XDR RBAC bootstrap bypass must stay closed.

Regression guard for the 2026-09-09 production defect: ``require_permission``
resolved its principal from the client-supplied ``X-Tenant-Id`` /
``X-Principal-Id`` headers and returned ``True`` whenever ``users`` held no
document for that tenant.  ``_principal()`` defaults an anonymous caller to
tenant ``default``, and ``seed_admin()`` writes admins with no ``tenant_id``,
so the count was permanently 0 and every RBAC-gated route was open to
unauthenticated callers.

These tests are deliberately written against the ASGI app so they exercise the
real dependency graph — a unit test on ``check_access`` would not have caught
this, because ``check_access`` was never reached.
"""
from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DB_NAME", "test_database")

# Imported after the env defaults above are set.
from server import app
from tests._verified_session import register_tenants

client = TestClient(app)

#: The tenant this suite operates in. It is REGISTERED below rather than
#: assumed: the CI database is clean, and `default` is not registered there —
#: which is itself the rule under test (`TENANT_NOT_FOUND`), because tenancy
#: is an administrative act (`POST /api/xdr/tenants`) and never a side effect
#: of a request naming a tenant.
LEGITIMATE_TENANT = f"p0sec-{uuid.uuid4().hex[:8]}"

#: Every surface proven reachable anonymously in production on 2026-09-09.
GATED_GETS = [
    "/api/xdr/collectors",
    "/api/xdr/secrets",
    "/api/xdr/api-keys",
    "/api/xdr/rule-studio/rules",
]


def _rejected(status: int) -> bool:
    return status in (401, 403)


@pytest.mark.parametrize("path", GATED_GETS)
def test_anonymous_get_is_rejected(path):
    r = client.get(path)
    assert _rejected(r.status_code), f"{path} answered {r.status_code} anonymously"


@pytest.mark.parametrize("path", GATED_GETS)
@pytest.mark.parametrize("tenant", ["default", "attacker", ""])
def test_anonymous_get_with_spoofed_tenant_header_is_rejected(path, tenant):
    r = client.get(path, headers={"X-Tenant-Id": tenant,
                                  "X-Principal-Id": "system@ingest",
                                  "X-Principal-Kind": "system"})
    assert _rejected(r.status_code), (
        f"{path} answered {r.status_code} for spoofed tenant {tenant!r}")


def test_anonymous_telemetry_post_is_rejected_before_body_validation():
    """The exact request that reached the handler in production.

    An empty batch previously produced 400 "empty batch", proving the
    permission gate had already been passed.  It must now be refused by the
    dependency, so neither 400 (body) nor 422 (validation) may appear.
    """
    r = client.post("/api/xdr/ingest/telemetry", json={"envelopes": []})
    assert _rejected(r.status_code), f"answered {r.status_code}"
    assert r.status_code not in (400, 422), (
        "request reached body validation — the gate ran too late")


def test_anonymous_telemetry_post_with_wellformed_body_is_rejected():
    r = client.post(
        "/api/xdr/ingest/telemetry",
        headers={"X-Tenant-Id": "default"},
        json={"envelopes": [{
            "tenant_id": "default", "collector_id": "c1",
            "event_id": "e1", "received_at": "2026-09-09T00:00:00Z",
            "collection_method": "PUSH", "raw": {},
        }]})
    assert _rejected(r.status_code), f"answered {r.status_code}"


def test_invalid_bearer_token_is_rejected():
    for path in GATED_GETS:
        r = client.get(path, headers={"Authorization": "Bearer not-a-jwt"})
        assert _rejected(r.status_code), f"{path} answered {r.status_code}"


def test_authenticated_admin_still_authorized():
    """Regression: the fix must not lock the legitimate admin out.

    The administrator must NAME the tenant it is operating in. That is not a
    softening of this guard — it is the companion rule: there is no default
    tenant, so a cross-tenant principal that names nothing is refused
    (`TENANT_REQUIRED`), and the tenant it does name is then AUTHORIZED
    server-side for that principal. The header therefore remains an input to
    authorization and never an identity.

    Context-managed client so FastAPI startup runs (`validate_config()` +
    `init_database()`); the anonymous tests above deliberately run WITHOUT it,
    which also proves the gate fails closed when the datastore is unbound.
    """
    with TestClient(app) as c:
        login = c.post("/api/auth/login", json={
            "email": os.environ["ADMIN_EMAIL"],
            "password": os.environ["ADMIN_PASSWORD"]})
        assert login.status_code == 200, login.text
        token = login.json()["access_token"]
        register_tenants(LEGITIMATE_TENANT, label="p0sec")
        auth = {"Authorization": f"Bearer {token}",
                "X-Tenant-Id": LEGITIMATE_TENANT}
        for path in GATED_GETS:
            r = c.get(path, headers=auth)
            assert r.status_code == 200, f"{path} answered {r.status_code} for admin"


def test_admin_without_a_named_tenant_is_refused():
    """No default tenant · the companion half of the rule above.

    A verified administrator that names NO tenant must not silently land in
    `default`. Substituting a tenant is how a cross-tenant read becomes
    invisible, so the platform refuses instead.
    """
    with TestClient(app) as c:
        login = c.post("/api/auth/login", json={
            "email": os.environ["ADMIN_EMAIL"],
            "password": os.environ["ADMIN_PASSWORD"]})
        assert login.status_code == 200, login.text
        auth = {"Authorization": f"Bearer {login.json()['access_token']}"}
        r = c.get("/api/xdr/collectors", headers=auth)
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["code"] == "TENANT_REQUIRED", r.text


def test_bootstrap_bypass_pattern_is_absent_from_source():
    """The tenant-empty bypass must not come back in any form."""
    with open("/app/backend/routers/xdr_rbac.py", encoding="utf8") as fh:
        src = fh.read()
    dep = src.split("def require_permission(", 1)[1].split("\n    return _dep", 1)[0]
    assert 'count_documents({"tenant_id"' not in dep, (
        "tenant-empty count is being used for authorization again")
    assert "_principal(request)" not in dep, (
        "identity is being taken from request headers again")
    assert "_deps_current_user(creds)" in dep, (
        "the dependency no longer derives user identity from the verified JWT")
    # The machine-principal path must go through the validating helper, never
    # trust the raw header, and never be reachable alongside a bearer token.
    assert "authenticate_api_key(request, raw_key, permission)" in dep, (
        "collector API keys are no longer validated by authenticate_api_key")
    assert "ambiguous-credentials" in dep, (
        "a bearer token and an API key can be presented together again")
