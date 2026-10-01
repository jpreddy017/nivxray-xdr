"""XDR RBAC — negative enforcement, proven against VERIFIED SESSIONS.

MODERNIZED 2026-06 (owner decision: "the stale test must adapt to the
hardened security architecture").  The previous revision of this suite
established identity with the client-supplied `X-Tenant-Id` /
`X-Principal-Id` headers and relied on the tenant-empty *bootstrap
short-circuit*.  Both were the P0-SEC fail-open defect and were deleted
from `require_permission()` on 2026-09-09, so the suite could no longer
provision anything and reported 21 collection/fixture errors.

Nothing was restored to make these tests pass.  The suite now does what a
real client does: it authenticates, carries a JWT, and lets the server
resolve the tenant from the VERIFIED user record.

What is proven here:
  * unauthenticated                  → denied
  * tampered / non-JWT bearer        → denied
  * expired JWT                      → denied
  * authenticated but unauthorized   → deterministic 403 `ACCESS_DENIED`
                                       naming the exact permission
  * authenticated and authorized     → allowed (least privilege, not blanket)
  * tenant resolved SERVER-SIDE      → a header never establishes scope
  * cross-tenant request             → denied `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL`
  * wildcard role expansion          → `secrets.*` covers create+read, and
                                       still cannot reach `users.create`
  * every denial is audit-logged and the audit chain stays valid
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")
os.environ.setdefault("XDR_SECRETS_MASTER", "test-secrets-master-passphrase")
os.environ.setdefault("DB_NAME", "test_database")

import deps
from routers import xdr_audit_log as al
from routers import xdr_rbac as rb
from server import app

_SUFFIX = uuid.uuid4().hex[:6]
TEN = f"rbac-enf-{_SUFFIX}"
TEN_OTHER = f"rbac-oth-{_SUFFIX}"

#: Tenant-scoped principals, each authenticating with a real password.
SOC = f"soc-{_SUFFIX}@nivxray.enf"
VAULT = f"vault-{_SUFFIX}@nivxray.enf"
OUTSIDER = f"outsider-{_SUFFIX}@nivxray.enf"
PASSWORD = "Enf!Suite2026-verified-session"

_TOKENS: dict[str, str] = {}


def _auth(email_or_token: str, tenant: str | None = None) -> dict:
    """Authorization header for a verified session.

    `X-Tenant-Id` is sent where a cross-tenant principal must NAME the
    tenant it operates in.  It is an input to authorization and never an
    identity — that is exactly what several tests below prove.
    """
    token = _TOKENS.get(email_or_token, email_or_token)
    h = {"Authorization": f"Bearer {token}"}
    if tenant:
        h["X-Tenant-Id"] = tenant
    return h


def _skip_if_unusable():
    if rb._db() is None:
        pytest.skip("MONGO_URL not configured")


def _login(client: TestClient, email: str, password: str) -> str:
    r = client.post("/api/auth/login", json={"email": email,
                                             "password": password})
    assert r.status_code == 200, f"login failed for {email}: {r.text}"
    return r.json()["access_token"]


def _provision_session_user(email: str, tenant_id: str) -> None:
    """Create the AUTH record a verified session needs.

    Role is deliberately NOT `admin`: a platform administrator holds the
    documented cross-tenant break-glass authority and would prove nothing
    about permission enforcement.
    """
    users = deps.sync_collection("users")
    users.delete_many({"email": email})
    users.insert_one({
        "email": email,
        "password": deps.hash_password(PASSWORD),
        "role": "analyst",
        "tenant_id": tenant_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })


@pytest.fixture(scope="module", autouse=True)
def client():
    _skip_if_unusable()
    with TestClient(app) as c:
        # ── clean prior state for both tenants ────────────────────
        for coll in (rb._c_users, rb._c_roles, rb._c_groups, rb._c_assignments):
            if coll() is not None:
                coll().delete_many({"tenant_id": {"$in": [TEN, TEN_OTHER]}})
        if al._get_coll() is not None:
            al._get_coll().delete_many({"tenant_id": {"$in": [TEN, TEN_OTHER]}})

        # ── tenancy is an ADMINISTRATIVE act, never implied ───────
        # The registry fails closed on an unregistered tenant, so the two
        # suite tenants are registered here exactly as an operator would.
        from services import tenant_registry as tr
        org = tr.create_organization(slug=f"rbac-enf-org-{_SUFFIX}",
                                     display_name="RBAC Enforcement Suite",
                                     kind="CUSTOMER", created_by="test-suite")
        for tid in (TEN, TEN_OTHER):
            tr.adopt_legacy(tenant_id=tid, organization_id=org["id"],
                            slug=tid, display_name=tid,
                            created_by="test-suite")

        # ── the platform administrator drives provisioning ────────
        _TOKENS["admin"] = _login(c, os.environ["ADMIN_EMAIL"],
                                  os.environ["ADMIN_PASSWORD"])
        admin = _auth("admin", TEN)

        # A scoped role holding ONLY `lolbas.read` + `audit.read`.
        r = c.post("/api/xdr/rbac/roles", headers=admin,
                   json={"name": f"readonly_soc_{_SUFFIX}",
                         "display_name": "Read-Only SOC",
                         "description": "Test-only scoped role",
                         "permissions": ["lolbas.read", "audit.read"]})
        assert r.status_code == 200, r.text
        soc_role = r.json()["data"]["id"]

        r = c.post("/api/xdr/rbac/roles", headers=admin,
                   json={"name": f"vault_op_{_SUFFIX}",
                         "display_name": "Vault Ops",
                         "permissions": ["secrets.*"]})
        assert r.status_code == 200, r.text
        vault_role = r.json()["data"]["id"]

        for email, role_id in ((SOC, soc_role), (VAULT, vault_role)):
            _provision_session_user(email, TEN)
            r = c.post("/api/xdr/rbac/users", headers=admin,
                       json={"email": email, "display_name": email,
                             "initial_roles": [role_id]})
            assert r.status_code == 200, r.text
            _TOKENS[email] = _login(c, email, PASSWORD)

        # An administrator of a DIFFERENT tenant — the cross-tenant control.
        _provision_session_user(OUTSIDER, TEN_OTHER)
        r = c.post("/api/xdr/rbac/users", headers=_auth("admin", TEN_OTHER),
                   json={"email": OUTSIDER, "display_name": "Outsider",
                         "initial_roles": ["platform_admin"]})
        assert r.status_code == 200, r.text
        _TOKENS[OUTSIDER] = _login(c, OUTSIDER, PASSWORD)

        yield c


# ─────────────────────────────────────────────────────────────────
# Every entry is (method, path, body_or_none, permission_expected).
# Routes SOC legitimately owns (lolbas.read / audit.read) are covered
# by the positive tests instead.
# ─────────────────────────────────────────────────────────────────
DENIED_ROUTES = [
    ("POST",   "/api/xdr/secrets",
     {"name": "x", "kind": "api_key", "value": "v"}, "secrets.create"),
    ("GET",    "/api/xdr/secrets", None, "secrets.read"),
    ("DELETE", "/api/xdr/secrets/nope", None, "secrets.delete"),

    ("POST",   "/api/xdr/api-keys",
     {"name": "x", "scopes": ["lolbas.read"],
      "confirm_tenant_id": "acme", "allow_new_tenant": True},
     "api_keys.create"),
    ("GET",    "/api/xdr/api-keys", None, "api_keys.read"),

    ("POST",   "/api/xdr/webhooks",
     {"name": "x", "url": "https://example.test/x", "events": ["audit.*"]},
     "webhooks.create"),
    ("GET",    "/api/xdr/webhooks", None, "webhooks.read"),

    ("POST",   "/api/xdr/lolbas/sync?use_bundled_fallback=false",
     None, "lolbas.sync"),
    ("POST",   "/api/xdr/lolbas/rollback/nope", None, "lolbas.rollback"),
    ("POST",   "/api/xdr/lolbas/entries/Regsvr32.exe/disable",
     None, "lolbas.disable"),

    ("GET",    "/api/xdr/rbac/roles", None, "roles.read"),
    ("GET",    "/api/xdr/rbac/users", None, "users.read"),
    ("POST",   "/api/xdr/rbac/roles",
     {"name": "hack", "display_name": "H", "permissions": []},
     "roles.create"),

    ("POST",   "/api/xdr/audit-log/emit",
     {"action": "FORGED", "resource_kind": "test", "resource_id": "z"},
     "audit.write"),

    ("POST",   "/api/xdr/response-evidence",
     {"execution_id": "e1", "tenant_id": TEN,
      "invoker": {"kind": "user", "id": SOC},
      "action": {"action_id": "noop"}},
     "response.execute"),
]

_IDS = [f"{m}:{p}" for m, p, _, _ in DENIED_ROUTES]


def _call(client: TestClient, method: str, path: str, body, headers: dict):
    kwargs = {"headers": headers}
    if body is not None:
        kwargs["json"] = body
    return getattr(client, method.lower())(path, **kwargs)


# ── 1 · no credential at all ──────────────────────────────────────
@pytest.mark.parametrize("method,path,body,perm", DENIED_ROUTES, ids=_IDS)
def test_unauthenticated_is_denied(client, method, path, body, perm):
    r = _call(client, method, path, body, {})
    assert r.status_code in (401, 403), \
        f"{method} {path} answered {r.status_code} anonymously: {r.text}"


# ── 2 · a tampered / non-JWT bearer establishes nothing ───────────
def test_tampered_token_is_denied(client):
    real = _TOKENS[SOC]
    tampered = real[:-4] + ("aaaa" if not real.endswith("aaaa") else "bbbb")
    for token in ("not-a-jwt", tampered):
        r = client.get("/api/xdr/rbac/users",
                       headers={"Authorization": f"Bearer {token}"})
        assert r.status_code in (401, 403), r.text


# ── 3 · an expired JWT is not a session ───────────────────────────
def test_expired_token_is_denied(client):
    past = datetime.now(timezone.utc) - timedelta(hours=2)
    expired = jwt.encode({"sub": SOC, "iat": past,
                          "exp": past + timedelta(minutes=1)},
                         deps.JWT_SECRET, algorithm=deps.JWT_ALG)
    r = client.get("/api/xdr/lolbas/status",
                   headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code in (401, 403), r.text


# ── 4 · authenticated, evaluated, and denied on what it lacks ─────
@pytest.mark.parametrize("method,path,body,perm", DENIED_ROUTES, ids=_IDS)
def test_scoped_principal_is_denied(client, method, path, body, perm):
    r = _call(client, method, path, body, _auth(SOC))
    assert r.status_code == 403, (
        f"{method} {path} expected 403; got {r.status_code} · body={r.text}")
    detail = r.json().get("detail", {})
    assert isinstance(detail, dict), \
        f"denial detail must be structured dict, got: {detail}"
    assert detail.get("code") == "ACCESS_DENIED", detail
    assert detail.get("permission") == perm, detail


# ── 5 · least privilege, not blanket denial ───────────────────────
def test_scoped_principal_allowed_on_owned_reads(client):
    r = client.get("/api/xdr/lolbas/status", headers=_auth(SOC))
    assert r.status_code == 200, r.text
    r = client.get("/api/xdr/audit-log", headers=_auth(SOC))
    assert r.status_code == 200, r.text


# ── 6 · positive control · the platform administrator ─────────────
def test_admin_can_do_every_denied_action(client):
    for path in ("/api/xdr/rbac/users", "/api/xdr/rbac/roles",
                 "/api/xdr/api-keys", "/api/xdr/webhooks",
                 "/api/xdr/secrets"):
        r = client.get(path, headers=_auth("admin", TEN))
        assert r.status_code == 200, f"{path}: {r.text}"


# ── 7 · the tenant is resolved from the RECORD, never the header ──
def test_tenant_is_resolved_server_side_not_from_header(client):
    """SOC names a tenant it is not authorized for.

    The request must fail closed on tenancy — and the permission SOC
    genuinely holds must NOT rescue it.  Without any header the same call
    succeeds, because the server resolves TEN from the verified record.
    """
    r = client.get("/api/xdr/audit-log", headers=_auth(SOC, TEN_OTHER))
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] in (
        "TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL", "ACCESS_DENIED"), r.text

    r = client.get("/api/xdr/audit-log", headers=_auth(SOC))
    assert r.status_code == 200, r.text
    for e in r.json()["data"]["events"]:
        assert e.get("tenant_id") == TEN, \
            f"scope leak: {e.get('tenant_id')} returned for a {TEN} principal"


# ── 8 · cross-tenant, held by a principal with `*.*` elsewhere ────
def test_cross_tenant_request_is_denied(client):
    """OUTSIDER is a platform_admin **of TEN_OTHER**.  Holding `*.*` in
    its own tenant must not reach TEN."""
    r = client.get("/api/xdr/audit-log", headers=_auth(OUTSIDER, TEN))
    assert r.status_code == 403, r.text
    r = client.get("/api/xdr/rbac/users", headers=_auth(OUTSIDER, TEN))
    assert r.status_code == 403, r.text
    # …and in its own tenant it sees only its own tenant's users.
    r = client.get("/api/xdr/rbac/users", headers=_auth(OUTSIDER, TEN_OTHER))
    assert r.status_code == 200, r.text
    for u in r.json()["data"]["users"]:
        assert u["tenant_id"] == TEN_OTHER, u


# ── 9 · denials are evidence ──────────────────────────────────────
def test_access_denied_events_are_audit_logged(client):
    r = client.post("/api/xdr/rbac/roles", headers=_auth(SOC),
                    json={"name": f"hackx_{_SUFFIX}", "display_name": "H",
                          "permissions": []})
    assert r.status_code == 403, r.text
    r = client.get("/api/xdr/audit-log?action=ACCESS_DENIED",
                   headers=_auth("admin", TEN))
    assert r.status_code == 200, r.text
    events = r.json()["data"]["events"]
    assert any(e["principal_id"] == SOC
               and e.get("outcome") == "FAILURE"
               and e.get("resource_id") == "roles.create"
               for e in events), events


def test_audit_chain_remains_valid_after_denials(client):
    r = client.get("/api/xdr/audit-log/verify/chain",
                   headers=_auth("admin", TEN))
    assert r.status_code == 200, r.text
    assert r.json()["data"]["status"] == "valid", r.json()["data"]


# ── 10 · wildcard expansion widens the ACTION, never the RESOURCE ─
def test_wildcard_role_covers_every_action(client):
    r = client.post("/api/xdr/secrets", headers=_auth(VAULT),
                    json={"name": f"k-{uuid.uuid4().hex[:6]}",
                          "kind": "api_key", "value": "shh"})
    assert r.status_code == 200, r.text
    r = client.get("/api/xdr/secrets", headers=_auth(VAULT))
    assert r.status_code == 200, r.text
    r = client.post("/api/xdr/rbac/users", headers=_auth(VAULT),
                    json={"email": f"denied-{_SUFFIX}@nivxray.enf"})
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["permission"] == "users.create"
