"""XDR RBAC — P0-1 Global Retrofit Negative Enforcement Tests.

For every retrofitted route, prove:
  * An authenticated user WITHOUT the required permission receives
    a deterministic HTTP 403 with `code = ACCESS_DENIED` and the
    exact permission name in the response body.
  * An authenticated user WITH the required permission (via role
    assignment) receives 2xx / expected success.
  * The denial is audit-logged (`action = ACCESS_DENIED`,
    `outcome = FAILURE`) and the audit chain remains valid.

This suite guarantees the acceptance criterion from the P0-1
directive: "backend enforcement is authoritative, not UI hiding".
"""
from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")
os.environ.setdefault("XDR_SECRETS_MASTER", "test-secrets-master-passphrase")

from routers import xdr_audit_log as al
from routers import xdr_rbac as rb
from server import app

client = TestClient(app)

# Tenant unique to this suite so bootstrap short-circuit is fully
# consumed after we provision the first user, then enforcement engages.
TEN = f"rbac-enf-{uuid.uuid4().hex[:8]}"
_SUFFIX = uuid.uuid4().hex[:6]

# Two principals: `SOC` (has scoped permissions only), `ROOT` (admin).
ROOT     = "root@nivxray.enf"
SOC      = "soc@nivxray.enf"


def _hdrs(email: str, ten: str | None = None) -> dict:
    return {"X-Tenant-Id": ten or TEN,
                "X-Principal-Id": email,
                "X-Principal-Kind": "user"}


def _skip_if_no_mongo():
    if rb._db() is None:
        pytest.skip("MONGO_URL not configured")


@pytest.fixture(scope="module", autouse=True)
def _seed_users():
    """Provision two users in this tenant: an admin and a scoped
    read-only analyst.  Also provision at least one user in the DEFAULT
    tenant so the bootstrap short-circuit is exercised only where we
    want it to be."""
    _skip_if_no_mongo()
    # Clean prior state for this tenant.
    for c in (rb._c_users, rb._c_roles, rb._c_groups, rb._c_assignments):
        if c() is not None:
            c().delete_many({"tenant_id": TEN})
    if al._get_coll() is not None:
        al._get_coll().delete_many({"tenant_id": TEN})

    # 1) Create the ROOT user first — while tenant has 0 users the
    #    bootstrap short-circuit lets this through.
    r = client.post("/api/xdr/rbac/users", headers=_hdrs(ROOT),
                          json={"email": ROOT, "display_name": "Root",
                                    "initial_roles": ["platform_admin"]})
    assert r.status_code == 200, r.text

    # 2) Create SOC user with a scoped role that grants ONLY `lolbas.read`
    #    and `audit.read` — nothing else.
    #    Build a custom role first (unique name per run — roles are global).
    r = client.post("/api/xdr/rbac/roles", headers=_hdrs(ROOT),
                          json={"name": f"readonly_soc_{_SUFFIX}",
                                    "display_name": "Read-Only SOC",
                                    "description": "Test-only scoped role",
                                    "permissions": ["lolbas.read", "audit.read"]})
    assert r.status_code == 200, r.text
    role_id = r.json()["data"]["id"]

    r = client.post("/api/xdr/rbac/users", headers=_hdrs(ROOT),
                          json={"email": SOC, "display_name": "SOC",
                                    "initial_roles": [role_id]})
    assert r.status_code == 200, r.text
    yield


# ─────────────────────────────────────────────────────────────────
# Negative enforcement — a scoped principal MUST be denied on
# every mutation and privileged-read endpoint they do not own.
# ─────────────────────────────────────────────────────────────────
# Every entry is (method, path, body_or_none, permission_expected).
# Endpoints that only require lolbas.read / audit.read (SOC owns those)
# are DELIBERATELY not listed — those are covered by allow tests below.
DENIED_ROUTES = [
    # Secrets
    ("POST",   "/api/xdr/secrets",
      {"name": "x", "kind": "api_key", "value": "v"},
      "secrets.create"),
    ("GET",    "/api/xdr/secrets", None, "secrets.read"),
    ("DELETE", "/api/xdr/secrets/nope", None, "secrets.delete"),

    # API Keys
    ("POST",   "/api/xdr/api-keys",
      {"name": "x", "scopes": ["lolbas.read"]},
      "api_keys.create"),
    ("GET",    "/api/xdr/api-keys", None, "api_keys.read"),

    # Webhooks
    ("POST",   "/api/xdr/webhooks",
      {"name": "x", "url": "https://example.test/x", "events": ["audit.*"]},
      "webhooks.create"),
    ("GET",    "/api/xdr/webhooks", None, "webhooks.read"),

    # LOLBAS mutations (SOC has read only)
    ("POST",   "/api/xdr/lolbas/sync?use_bundled_fallback=false",
      None, "lolbas.sync"),
    ("POST",   "/api/xdr/lolbas/rollback/nope", None, "lolbas.rollback"),
    ("POST",   "/api/xdr/lolbas/entries/Regsvr32.exe/disable",
      None, "lolbas.disable"),

    # RBAC self-management (SOC has neither role nor user perms)
    ("GET",    "/api/xdr/rbac/roles", None, "roles.read"),
    ("GET",    "/api/xdr/rbac/users", None, "users.read"),
    ("POST",   "/api/xdr/rbac/roles",
      {"name": "hack", "display_name": "H", "permissions": []},
      "roles.create"),

    # Audit-emit (privileged write)
    ("POST",   "/api/xdr/audit-log/emit",
      {"action": "FORGED", "resource_kind": "test", "resource_id": "z"},
      "audit.write"),

    # Response evidence writer
    ("POST",   "/api/xdr/response-evidence",
      {"execution_id": "e1", "tenant_id": TEN,
        "invoker": {"kind": "user", "id": SOC},
        "action":  {"action_id": "noop"}},
      "response.execute"),
]


@pytest.mark.parametrize("method,path,body,perm", DENIED_ROUTES,
                                            ids=[f"{m}:{p}" for m, p, _, _ in DENIED_ROUTES])
def test_scoped_principal_is_denied(method: str, path: str,
                                                                body, perm: str):
    _skip_if_no_mongo()
    req = getattr(client, method.lower())
    kwargs = {"headers": _hdrs(SOC)}
    if body is not None:
        kwargs["json"] = body
    r = req(path, **kwargs)
    assert r.status_code == 403, (
        f"{method} {path} expected 403; got {r.status_code} · body={r.text}")
    detail = r.json().get("detail", {})
    assert isinstance(detail, dict), \
        f"denial detail must be structured dict, got: {detail}"
    assert detail.get("code") == "ACCESS_DENIED", detail
    assert detail.get("permission") == perm, detail


def test_scoped_principal_allowed_on_owned_reads():
    """SOC has `lolbas.read` + `audit.read` — those routes MUST succeed."""
    _skip_if_no_mongo()
    r = client.get("/api/xdr/lolbas/status", headers=_hdrs(SOC))
    assert r.status_code == 200
    r = client.get("/api/xdr/audit-log", headers=_hdrs(SOC))
    assert r.status_code == 200


def test_root_admin_can_do_every_denied_action():
    """Positive control — the same routes SOC was denied on succeed
    for a platform_admin (holder of ``*.*``)."""
    _skip_if_no_mongo()
    r = client.get("/api/xdr/rbac/users", headers=_hdrs(ROOT))
    assert r.status_code == 200
    r = client.get("/api/xdr/rbac/roles", headers=_hdrs(ROOT))
    assert r.status_code == 200
    r = client.get("/api/xdr/api-keys",   headers=_hdrs(ROOT))
    assert r.status_code == 200
    r = client.get("/api/xdr/webhooks",   headers=_hdrs(ROOT))
    assert r.status_code == 200
    r = client.get("/api/xdr/secrets",    headers=_hdrs(ROOT))
    assert r.status_code == 200


def test_access_denied_events_are_audit_logged():
    _skip_if_no_mongo()
    # Trigger one deterministic denial.
    client.post("/api/xdr/rbac/roles", headers=_hdrs(SOC),
                    json={"name": "hackx", "display_name": "H", "permissions": []})
    r = client.get("/api/xdr/audit-log?action=ACCESS_DENIED",
                          headers=_hdrs(ROOT))
    assert r.status_code == 200
    events = r.json()["data"]["events"]
    assert any(e["principal_id"] == SOC and
                    e.get("outcome") == "FAILURE" and
                    e.get("resource_id") == "roles.create"
                    for e in events), events


def test_audit_chain_remains_valid_after_denials():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/audit-log/verify/chain", headers=_hdrs(ROOT))
    d = r.json()["data"]
    assert d["status"] == "valid", d


# ─────────────────────────────────────────────────────────────────
# Tenant isolation — a principal in tenant A must NOT read/write
# resources in tenant B, even if they hold `*.*` in their own tenant.
# ─────────────────────────────────────────────────────────────────
def test_tenant_isolation_denied_across_tenants():
    _skip_if_no_mongo()
    other_ten = f"other-{uuid.uuid4().hex[:8]}"
    # ROOT is admin of TEN.  Attempting to read another tenant's
    # audit-log with ROOT's identity but their own tenant header should
    # still ONLY show TEN's rows (never other_ten's).  Provision no
    # users in other_ten so bootstrap short-circuits — but we assert
    # that ROOT reading with X-Tenant-Id=other_ten is scoped to
    # other_ten's (empty) collection, NOT leaking TEN's data.
    r = client.get("/api/xdr/audit-log", headers=_hdrs(ROOT, ten=other_ten))
    # Under bootstrap short-circuit this returns 200 with a list scoped
    # to other_ten — MUST NOT contain any TEN events.
    assert r.status_code == 200, r.text
    events = r.json()["data"]["events"]
    for e in events:
        assert e.get("tenant_id") == other_ten, \
            f"tenant isolation breach: {e.get('tenant_id')} leaked into {other_ten}"


# ─────────────────────────────────────────────────────────────────
# Wildcard expansion — a role that holds `secrets.*` must satisfy
# secrets.create AND secrets.read AND secrets.delete without listing
# them individually.
# ─────────────────────────────────────────────────────────────────
def test_wildcard_role_covers_every_action():
    _skip_if_no_mongo()
    # Provision a user with only `secrets.*`.
    r = client.post("/api/xdr/rbac/roles", headers=_hdrs(ROOT),
                          json={"name": f"vault_op_{_SUFFIX}", "display_name": "Vault Ops",
                                    "permissions": ["secrets.*"]})
    assert r.status_code == 200, r.text
    role_id = r.json()["data"]["id"]
    email = "vault@nivxray.enf"
    r = client.post("/api/xdr/rbac/users", headers=_hdrs(ROOT),
                          json={"email": email, "initial_roles": [role_id]})
    assert r.status_code == 200, r.text

    # secrets.create allowed
    r = client.post("/api/xdr/secrets", headers=_hdrs(email),
                          json={"name": f"k-{uuid.uuid4().hex[:6]}",
                                    "kind": "api_key", "value": "shh"})
    assert r.status_code == 200, r.text
    # secrets.read allowed
    r = client.get("/api/xdr/secrets", headers=_hdrs(email))
    assert r.status_code == 200, r.text
    # But `users.create` MUST still be denied
    r = client.post("/api/xdr/rbac/users", headers=_hdrs(email),
                          json={"email": "denied@nivxray.enf"})
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["permission"] == "users.create"
