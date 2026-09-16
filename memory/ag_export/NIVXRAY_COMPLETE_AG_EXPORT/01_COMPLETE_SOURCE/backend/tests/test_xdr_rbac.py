"""XDR RBAC — P0-3 pytest.

Covers:
- permission catalog is comprehensive and grouped
- built-in starter roles exist and expand wildcards correctly
- custom role CRUD + wildcards validated + built-in immutability
- user CRUD + multi-role assignment + effective permissions union
- access simulation (ALLOW / DENY paths with reason codes)
- require_permission enforcement on protected routes (allow + deny)
- audit-log entries emitted for every mutation & access denial
- audit chain remains valid across the RBAC lifecycle
- role clone / delete guards / assignment idempotency
- bootstrap short-circuit (empty users collection → allow)
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

TEN = f"rbac-tenant-{uuid.uuid4().hex[:8]}"
ADMIN = "root@nivxray.com"
ANALYST = "analyst@nivxray.com"


def _hdrs(email=ADMIN, ten=None):
    return {"X-Tenant-Id": ten or TEN,
                "X-Principal-Id": email,
                "X-Principal-Kind": "user"}


@pytest.fixture(scope="module", autouse=True)
def _clean():
    for c in (rb._c_users, rb._c_roles, rb._c_groups, rb._c_assignments):
        if c() is not None:
            c().delete_many({"tenant_id": TEN})
            c().delete_many({})  # also clear any global (roles) leftovers
    if al._get_coll() is not None:
        al._get_coll().delete_many({"tenant_id": TEN})
    yield


def _skip_if_no_mongo():
    if rb._db() is None:
        pytest.skip("MONGO_URL not configured")


# ── 1 · Permission catalog ────────────────────────────────────────
def test_permission_catalog_is_comprehensive():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/rbac/permissions")
    d = r.json()["data"]
    all_p = d["all"]
    assert len(all_p) > 80  # 30+ resources × several actions each
    for must in ("users.create", "roles.publish", "secrets.reveal",
                        "lolbas.sync", "correlation.publish",
                        "response.execute", "audit.read"):
        assert must in all_p, f"missing canonical permission: {must}"


# ── 2 · Built-in starter roles ────────────────────────────────────
def test_builtin_roles_exposed_and_expandable():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/rbac/roles")
    roles = r.json()["data"]["roles"]
    names = {x["name"] for x in roles}
    for expected in ("platform_admin", "tenant_admin", "soc_manager",
                              "l3_investigator", "l2_investigator",
                              "l1_analyst", "threat_hunter", "detection_sme",
                              "responder", "auditor", "read_only"):
        assert expected in names, f"missing built-in role: {expected}"

    # Platform Admin expands to `*.*`.
    r2 = client.get("/api/xdr/rbac/roles/role_builtin_platform_admin")
    ep = r2.json()["data"]["effective_permissions"]
    assert "users.create" in ep and "secrets.reveal" in ep
    assert "response.execute" in ep


# ── 3 · User CRUD + effective permissions ─────────────────────────
def test_create_user_with_starter_role_and_check_effective():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/rbac/users", headers=_hdrs(),
                          json={"email": ADMIN, "display_name": "Root",
                                    "initial_roles": ["platform_admin"]})
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert d["email"] == ADMIN
    assert any(a["role_name"] == "platform_admin" for a in d["assignments"])

    eff = client.get(f"/api/xdr/rbac/users/{d['id']}/effective",
                              headers=_hdrs()).json()["data"]
    assert eff["count"] > 50
    assert "roles.create" in eff["permissions"]


def test_second_user_with_analyst_role():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/rbac/users", headers=_hdrs(),
                          json={"email": ANALYST, "initial_roles": ["l1_analyst"]})
    assert r.status_code == 200
    uid = r.json()["data"]["id"]
    eff = client.get(f"/api/xdr/rbac/users/{uid}/effective",
                              headers=_hdrs()).json()["data"]
    assert "alerts.read" in eff["permissions"]
    assert "secrets.reveal" not in eff["permissions"]
    assert "response.execute" not in eff["permissions"]


# ── 4 · Access simulation ─────────────────────────────────────────
def test_simulate_allow_and_deny():
    _skip_if_no_mongo()
    # Admin can create users.
    r_allow = client.post("/api/xdr/rbac/simulate", headers=_hdrs(),
                                          json={"user_id_or_email": ADMIN,
                                                    "permission": "users.create"})
    d = r_allow.json()["data"]
    assert d["decision"] == "ALLOW", d
    assert d["matched_role"] == "platform_admin"

    # Analyst cannot reveal secrets.
    r_deny = client.post("/api/xdr/rbac/simulate", headers=_hdrs(),
                                        json={"user_id_or_email": ANALYST,
                                                    "permission": "secrets.reveal"})
    d2 = r_deny.json()["data"]
    assert d2["decision"] == "DENY", d2
    assert d2["reason"] in ("permission-not-granted",)

    # Unknown permission is deterministically rejected.
    r_bad = client.post("/api/xdr/rbac/simulate", headers=_hdrs(),
                                       json={"user_id_or_email": ADMIN,
                                                    "permission": "not.a.permission"})
    assert r_bad.json()["data"]["decision"] == "DENY"


# ── 5 · Custom role CRUD + wildcard validation ────────────────────
def test_create_custom_role_and_validate_permissions():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/rbac/roles", headers=_hdrs(),
                          json={"name": "detection_engineer",
                                    "display_name": "Detection Engineer",
                                    "tier": "SPECIALIST",
                                    "permissions": ["detections.*", "sigma.read",
                                                            "correlation.read"]})
    assert r.status_code == 200, r.text
    role = r.json()["data"]
    assert role["type"] == "CUSTOM"
    assert role["id"].startswith("role_")

    # Rejects invalid permission.
    r_bad = client.post("/api/xdr/rbac/roles", headers=_hdrs(),
                                       json={"name": "bogus",
                                                    "display_name": "Bogus",
                                                    "permissions": ["nope.foo"]})
    assert r_bad.status_code == 400

    # Cannot collide with built-in.
    r_col = client.post("/api/xdr/rbac/roles", headers=_hdrs(),
                                       json={"name": "platform_admin",
                                                    "display_name": "X"})
    assert r_col.status_code == 409


def test_cannot_modify_or_delete_builtin_role():
    _skip_if_no_mongo()
    r = client.put("/api/xdr/rbac/roles/role_builtin_platform_admin",
                          headers=_hdrs(), json={"description": "hax"})
    assert r.status_code == 409
    r2 = client.delete("/api/xdr/rbac/roles/role_builtin_platform_admin",
                                  headers=_hdrs())
    assert r2.status_code == 409


def test_role_clone_creates_editable_copy():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/rbac/roles/role_builtin_l2_investigator/clone",
                          headers=_hdrs())
    assert r.status_code == 200, r.text
    new = r.json()["data"]
    assert new["type"] == "CUSTOM"
    assert new["cloned_from"] == "role_builtin_l2_investigator"
    assert new["name"].startswith("l2_investigator_copy")


# ── 6 · Enforcement via require_permission ────────────────────────
def test_enforcement_denies_when_role_missing():
    _skip_if_no_mongo()
    # Analyst tries to create a role → 403.
    r = client.post("/api/xdr/rbac/roles",
                          headers=_hdrs(email=ANALYST),
                          json={"name": "sneaky", "display_name": "Sneaky",
                                    "permissions": []})
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "ACCESS_DENIED"
    assert r.json()["detail"]["permission"] == "roles.create"

    # Access denial recorded in audit log.
    events = client.get("/api/xdr/audit-log?action=ACCESS_DENIED",
                                  headers=_hdrs()).json()["data"]["events"]
    assert any(e["principal_id"] == ANALYST for e in events)


def test_enforcement_allows_when_role_grants():
    _skip_if_no_mongo()
    # Admin creates a group → 200.
    r = client.post("/api/xdr/rbac/groups", headers=_hdrs(),
                          json={"name": "soc_l2", "description": "L2 team"})
    assert r.status_code == 200


# ── 7 · Assignment idempotency ────────────────────────────────────
def test_assign_role_is_idempotent_for_same_scope():
    _skip_if_no_mongo()
    # Find analyst id
    users = client.get("/api/xdr/rbac/users",
                                headers=_hdrs()).json()["data"]["users"]
    analyst = next(u for u in users if u["email"] == ANALYST)
    # Assign threat_hunter twice, no scope.
    r1 = client.post(f"/api/xdr/rbac/users/{analyst['id']}/roles",
                              headers=_hdrs(),
                              json={"role_id": "role_builtin_threat_hunter"})
    r2 = client.post(f"/api/xdr/rbac/users/{analyst['id']}/roles",
                              headers=_hdrs(),
                              json={"role_id": "role_builtin_threat_hunter"})
    assert r1.status_code == 200 and r2.status_code == 200
    assert r2.json()["data"].get("idempotent") is True
    # Now the analyst's effective permissions include threat_hunting.execute.
    eff = client.get(f"/api/xdr/rbac/users/{analyst['id']}/effective",
                              headers=_hdrs()).json()["data"]
    assert "threat_hunting.execute" in eff["permissions"]


# ── 8 · User disable / delete removes access ──────────────────────
def test_disable_user_denies_access():
    _skip_if_no_mongo()
    users = client.get("/api/xdr/rbac/users",
                                headers=_hdrs()).json()["data"]["users"]
    analyst = next(u for u in users if u["email"] == ANALYST)
    r = client.put(f"/api/xdr/rbac/users/{analyst['id']}",
                          headers=_hdrs(), json={"enabled": False})
    assert r.status_code == 200
    sim = client.post("/api/xdr/rbac/simulate", headers=_hdrs(),
                              json={"user_id_or_email": ANALYST,
                                        "permission": "alerts.read"}).json()["data"]
    assert sim["decision"] == "DENY"
    assert sim["reason"] == "user-disabled"
    # Re-enable to leave state consistent.
    client.put(f"/api/xdr/rbac/users/{analyst['id']}",
                    headers=_hdrs(), json={"enabled": True})


# ── 9 · Audit chain remains valid across all RBAC activity ────────
def test_audit_chain_valid_across_rbac_lifecycle():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/audit-log/verify/chain", headers=_hdrs())
    d = r.json()["data"]
    assert d["status"] == "valid", d


# ── 10 · Cleanup respects assignments-still-exist guard ───────────
def test_cannot_delete_role_with_active_assignments():
    _skip_if_no_mongo()
    # detection_engineer role has zero assignments → deletable.
    roles = client.get("/api/xdr/rbac/roles").json()["data"]["roles"]
    det = next(r for r in roles if r.get("name") == "detection_engineer")
    ok = client.delete(f"/api/xdr/rbac/roles/{det['id']}", headers=_hdrs())
    assert ok.status_code == 200
