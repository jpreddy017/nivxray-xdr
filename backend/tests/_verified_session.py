"""Shared VERIFIED-SESSION helpers for the security-plane test suites.

Why this module exists
----------------------
Several suites (`test_xdr_audit_log`, `test_xdr_api_keys`, `test_xdr_secrets`,
`test_xdr_webhooks`, `test_xdr_rbac_enforcement`) were written when a client
could assert its own identity with `X-Principal-Id` and its own tenant with
`X-Tenant-Id`, and when `require_permission()` short-circuited for an empty
tenant. Both were the P0-SEC fail-open defect and are gone. The suites kept
failing not because the platform regressed but because they were still
speaking the pre-hardening dialect.

Nothing here weakens the server. It does exactly what a real client must do:

  * authenticate, and carry a bearer token,
  * register a tenant through the tenancy registry instead of inventing one
    in a header (there is no default tenant — an unnamed tenant is a denial),
  * NAME the tenant it operates in, which the server then AUTHORIZES for the
    principal (`authorize_requested_tenant`).

`X-Tenant-Id` therefore remains an *input to* authorization and never an
identity — several tests assert precisely that.
"""
from __future__ import annotations

import os
import uuid

from fastapi.testclient import TestClient


def admin_token(client: TestClient) -> str:
    """Log the seeded platform administrator in and return its JWT."""
    r = client.post("/api/auth/login", json={
        "email": os.environ["ADMIN_EMAIL"],
        "password": os.environ["ADMIN_PASSWORD"]})
    assert r.status_code == 200, f"admin login failed: {r.text}"
    return r.json()["access_token"]


def register_tenants(*tenant_ids: str, label: str = "test-suite") -> None:
    """Register suite tenants the way an operator would.

    The registry fails closed on an unregistered tenant, so a test that
    invents `tenant-a-1234` in a header must also declare it.
    """
    from services import tenant_registry as tr

    org = tr.create_organization(slug=f"{label}-org-{uuid.uuid4().hex[:6]}",
                                 display_name=f"{label} suite",
                                 kind="CUSTOMER", created_by=label)
    for tid in tenant_ids:
        tr.adopt_legacy(tenant_id=tid, organization_id=org["id"], slug=tid,
                        display_name=tid, created_by=label)


def authorize_tenants(email: str, *tenant_ids: str) -> None:
    """Grant a principal explicit authorization for suite tenants.

    `register_tenants()` makes a tenant exist; it does not make anyone
    authorized for it. `authorize_requested_tenant()` resolves WHERE a
    principal may act from exactly two server-side facts —
    `authority_scope == "PLATFORM"` or the explicit `tenant_ids[]` grant
    list — so the seeded administrator, which is created with neither,
    is correctly refused with TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL.

    This writes the narrower of the two facts: an explicit grant list, the
    same server-side state an operator's provisioning action produces. It
    deliberately does NOT set PLATFORM scope, which is an owner designation
    and would hand the suite cross-tenant breadth it has no need for.
    Registry validation and RBAC still run downstream, unchanged.
    """
    import deps

    deps.sync_collection("users").update_one(
        {"email": email},
        {"$addToSet": {"tenant_ids": {"$each": list(tenant_ids)}}},
    )


def provision_rbac_principal(tenant_id: str, email: str,
                             role_name: str = "platform_admin") -> None:
    """Provision the tenant-scoped RBAC record the API itself cannot bootstrap.

    `POST /api/xdr/rbac/users` is gated by `users.create`, which resolves
    through `check_access()` against the per-tenant `xdr_users` collection —
    so creating the FIRST principal in a tenant requires a principal that
    already exists in it. `deps.seed_admin()` writes only the authentication
    record in `users`, never the RBAC record, so an administrator in a fresh
    suite tenant is correctly refused with `user-not-provisioned`.

    This writes exactly the two documents `create_user()` writes — the
    `xdr_users` row and one role assignment — and nothing else. The server's
    permission resolution, tenant authorization, audit chain and scope checks
    all run unchanged afterwards; this supplies state, never a bypass.
    """
    import uuid as _uuid
    from datetime import datetime, timezone

    import routers.xdr_rbac as rb

    users, assignments = rb._c_users(), rb._c_assignments()
    if users is None or assignments is None:
        raise AssertionError(
            "RBAC store unavailable; provisioning would silently do nothing")
    if users.find_one({"tenant_id": tenant_id, "email": email}):
        return
    now = datetime.now(timezone.utc).isoformat()
    uid = f"usr_{_uuid.uuid4().hex[:20]}"
    users.insert_one({"id": uid, "tenant_id": tenant_id, "email": email,
                      "display_name": email, "groups": [], "enabled": True,
                      "created_at": now, "updated_at": now,
                      "last_login": None, "created_by": "test-suite"})
    role = rb._BUILTIN_ROLE_BY_NAME.get(role_name) or rb._role_by_id(role_name)
    if role is None:
        raise AssertionError(f"unknown role for provisioning: {role_name}")
    assignments.insert_one({"id": f"asg_{_uuid.uuid4().hex[:20]}",
                            "tenant_id": tenant_id, "user_id": uid,
                            "role_id": role["id"], "scope": {},
                            "created_at": now, "created_by": "test-suite"})


def hdrs(token: str, tenant: str | None = None, **extra: str) -> dict:
    """Authorization + the tenant the caller is REQUESTING (not claiming)."""
    h = {"Authorization": f"Bearer {token}"}
    if tenant:
        h["X-Tenant-Id"] = tenant
    h.update(extra)
    return h


#: A password shared by suite-provisioned principals. Preview database only.
SUITE_PASSWORD = "Suite!Verified2026-session"


def provision_session_user(email: str, tenant_id: str,
                           role: str = "analyst") -> None:
    """Create the AUTH record a non-admin principal needs to log in.

    `role` is deliberately NOT `admin`: a platform administrator holds the
    documented cross-tenant break-glass authority, so testing a denial with
    an admin token proves nothing about permission enforcement.
    """
    import deps

    users = deps.sync_collection("users")
    users.delete_many({"email": email})
    users.insert_one({
        "email": email,
        "password": deps.hash_password(SUITE_PASSWORD),
        "role": role,
        "tenant_id": tenant_id,
    })


def login(client: TestClient, email: str,
          password: str = SUITE_PASSWORD) -> str:
    r = client.post("/api/auth/login", json={"email": email,
                                             "password": password})
    assert r.status_code == 200, f"login failed for {email}: {r.text}"
    return r.json()["access_token"]
