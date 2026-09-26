"""A0.5 · TENANT / AUTHORIZATION SECURITY CLOSURE — acceptance suite.

Owner-authorized scope (2026-06):

    T-RISK-1  unresolved tenant    → literal "default"            FAIL CLOSED
    T-RISK-2  unresolved principal → literal "admin@nivxray.com"  FAIL CLOSED
    C1–C9     authoritative scope / console contracts
    12        tenant-scope acceptance tests
              + single-tenant, cross-tenant, incident pivot-lock,
                console permission matrix, client-manipulation,
                MACHINE-path and response-isolation regressions

Locked invariants asserted here:
    ScopeSelection is client intent. EffectiveScope is server truth.
    EffectiveScope = RequestedScope ∩ AuthorizedScope.
    Unresolved tenant fails closed. There is no default tenant.
    Absence of identity never increases privilege.
    Tenant groups organize scope; they never grant authority.
    Console destination does not grant console permission.
"""
from __future__ import annotations

import hashlib
import os
import uuid

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")
os.environ.setdefault("XDR_SECRETS_MASTER", "test-secrets-master-passphrase")

from routers import xdr_audit_log as al          # noqa: E402
from routers import xdr_rbac as rb               # noqa: E402
from server import app                           # noqa: E402
from services import session_context as sc       # noqa: E402

client = TestClient(app)

SUF = uuid.uuid4().hex[:8]
T_ACME = f"a05-acme-{SUF}"
T_CONTOSO = f"a05-contoso-{SUF}"
T_NORTHWIND = f"a05-northwind-{SUF}"

U_ADMIN = f"a05-admin-{SUF}@nivxray.test"
U_ACME = f"a05-acme-analyst-{SUF}@nivxray.test"
U_CONTOSO = f"a05-contoso-analyst-{SUF}@nivxray.test"
U_MULTI = f"a05-mdr-{SUF}@nivxray.test"
U_NOTENANT = f"a05-notenant-{SUF}@nivxray.test"
U_SOC = f"a05-soc-{SUF}@nivxray.test"
U_ADM = f"a05-adm-{SUF}@nivxray.test"
U_BOTH = f"a05-both-{SUF}@nivxray.test"
U_NEITHER = f"a05-neither-{SUF}@nivxray.test"

INC_ACME = f"inc_a05_acme_{SUF}"
INC_CONTOSO = f"inc_a05_contoso_{SUF}"


# ── fixtures ──────────────────────────────────────────────────────
@pytest.fixture(scope="module", autouse=True)
def _seed():
    if rb._db() is None:
        pytest.skip("MONGO_URL not configured")
    from deps import sync_collection
    users = sync_collection("users")
    cases = sync_collection("workspace_cases")

    def _user(email, role, tenant_id=None, tenant_ids=None):
        doc = {"email": email, "role": role}
        if tenant_id:
            doc["tenant_id"] = tenant_id
        if tenant_ids:
            doc["tenant_ids"] = tenant_ids
        users.update_one({"email": email}, {"$set": doc}, upsert=True)

    _user(U_ADMIN, "admin")
    _user(U_ACME, "analyst", T_ACME)
    _user(U_CONTOSO, "analyst", T_CONTOSO)
    _user(U_MULTI, "analyst", None, [T_ACME, T_CONTOSO])
    _user(U_NOTENANT, "analyst")
    for e in (U_SOC, U_ADM, U_BOTH, U_NEITHER):
        _user(e, "analyst", T_ACME)

    for iid, ten in ((INC_ACME, T_ACME), (INC_CONTOSO, T_CONTOSO)):
        cases.update_one({"id": iid}, {"$set": {
            "id": iid, "doc_type": "xdr_incident", "tenant_id": ten,
            "title": f"A0.5 fixture {ten}", "incident_state": "new"}},
            upsert=True)

    # RBAC provisioning in the ACME tenant: `users.read` for the plain
    # analyst, and one role per console-permission combination.
    for c in (rb._c_users, rb._c_roles, rb._c_assignments):
        if c() is None:
            pytest.skip("RBAC store unavailable")

    def _role(name, perms):
        rid = f"role_a05_{name}_{SUF}"
        rb._c_roles().update_one({"id": rid}, {"$set": {
            "id": rid, "name": f"a05_{name}_{SUF}",
            "display_name": name, "type": "CUSTOM",
            "permissions": perms, "enabled": True}}, upsert=True)
        return rid

    r_reader = _role("reader", ["users.read"])
    r_soc = _role("soc", ["users.read", "console.soc.access"])
    r_adm = _role("adm", ["users.read", "console.admin.access"])
    r_both = _role("both", ["users.read", "console.soc.access",
                            "console.admin.access"])
    r_wild = _role("wild", ["*.*"])

    def _provision(email, tenant, role_ids):
        uid = f"usr_a05_{hashlib.sha1(email.encode()).hexdigest()[:16]}"
        rb._c_users().update_one({"id": uid}, {"$set": {
            "id": uid, "tenant_id": tenant, "email": email,
            "display_name": email, "enabled": True}}, upsert=True)
        for r in role_ids:
            rb._c_assignments().update_one(
                {"tenant_id": tenant, "user_id": uid, "role_id": r},
                {"$set": {"id": f"asg_{uuid.uuid4().hex[:16]}",
                          "tenant_id": tenant, "user_id": uid,
                          "role_id": r, "scope": {}}}, upsert=True)
        return uid

    _provision(U_ACME, T_ACME, [r_reader])
    _provision(U_CONTOSO, T_CONTOSO, [r_reader])
    _provision(U_SOC, T_ACME, [r_soc])
    _provision(U_ADM, T_ACME, [r_adm])
    _provision(U_BOTH, T_ACME, [r_both])
    _provision(U_NEITHER, T_ACME, [r_wild])   # `*.*` must NOT grant consoles

    with client:
        yield

    users.delete_many({"email": {"$regex": f"a05-.*-{SUF}@nivxray.test"}})
    cases.delete_many({"id": {"$in": [INC_ACME, INC_CONTOSO]}})
    rb._c_users().delete_many({"tenant_id": {"$in": [T_ACME, T_CONTOSO]}})
    rb._c_roles().delete_many({"id": {"$regex": f"role_a05_.*_{SUF}"}})
    rb._c_assignments().delete_many({"tenant_id": {"$in": [T_ACME, T_CONTOSO]}})


def _tok(email: str) -> str:
    from deps import create_token
    return create_token(email)


def _auth(email: str, tenant: str | None = None) -> dict:
    h = {"Authorization": f"Bearer {_tok(email)}"}
    if tenant:
        h["X-Tenant-Id"] = tenant
    return h


def _detail(resp) -> dict:
    d = resp.json().get("detail")
    return d if isinstance(d, dict) else {"detail": d}


# ══════════════════════════════════════════════════════════════════
# T-RISK-1 · unresolved tenant must FAIL CLOSED, never become "default"
# ══════════════════════════════════════════════════════════════════
def test_trisk1_cross_tenant_principal_without_tenant_fails_closed():
    """Before: `_principal()` returned the literal tenant "default" and the
    route read/wrote another tenancy's RBAC records. After: 403."""
    r = client.get("/api/xdr/rbac/users", headers=_auth(U_ADMIN))
    assert r.status_code == 403, r.text
    d = _detail(r)
    assert d["code"] == "TENANT_REQUIRED"
    assert d["fail_closed"] is True
    assert d["risk"] == "T-RISK-1"
    assert d["basis"] == "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER"
    assert d["requested_tenant"] is None
    assert "data" not in r.json()        # no tenant's records were read


def test_trisk1_principal_with_no_tenant_scope_fails_closed():
    r = client.get("/api/xdr/rbac/users", headers=_auth(U_NOTENANT))
    # `require_permission` denies first (no tenant scope at all) — either
    # way the outcome is a denial, never tenant "default".
    assert r.status_code == 403, r.text
    assert "ACCESS_DENIED" in r.text


def test_trisk1_requested_tenant_outside_scope_is_denied():
    r = client.get("/api/xdr/rbac/users", headers=_auth(U_ACME, T_CONTOSO))
    assert r.status_code == 403, r.text
    assert _detail(r)["code"] == "TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL"


def test_trisk1_unit_no_default_tenant_anywhere():
    with pytest.raises(sc.ScopeDenied) as e:
        sc.authorize_requested_tenant(U_ADMIN, None)
    assert e.value.code == "TENANT_REQUIRED"
    with pytest.raises(sc.ScopeDenied):
        sc.authorize_requested_tenant(None, None)
    with pytest.raises(sc.ScopeDenied):
        sc.authorize_requested_tenant(U_NOTENANT, None)
    # and the legitimate paths still resolve
    assert sc.authorize_requested_tenant(U_ACME, None) == (
        T_ACME, "SINGLE_AUTHORIZED_TENANT")
    assert sc.authorize_requested_tenant(U_ADMIN, T_ACME) == (
        T_ACME, "EXPLICIT_REQUEST_TENANT")


def test_trisk1_denial_is_audited():
    if al._get_coll() is None:
        pytest.skip("audit store unavailable")
    before = al._get_coll().count_documents(
        {"resource_kind": "tenant_scope", "principal_id": U_ADMIN})
    client.get("/api/xdr/rbac/users", headers=_auth(U_ADMIN))
    after = al._get_coll().count_documents(
        {"resource_kind": "tenant_scope", "principal_id": U_ADMIN})
    assert after > before
    row = al._get_coll().find_one(
        {"resource_kind": "tenant_scope", "principal_id": U_ADMIN},
        sort=[("_id", -1)])
    assert row["outcome"] == "FAILURE"
    assert "T-RISK-1" in row["metadata"]["reason"]


# ══════════════════════════════════════════════════════════════════
# T-RISK-2 · unresolved principal must FAIL CLOSED, never become admin
# ══════════════════════════════════════════════════════════════════
def _bare_request(headers: dict):
    from starlette.requests import Request
    return Request({"type": "http", "method": "GET", "path": "/",
                    "headers": [(k.lower().encode(), v.encode())
                                for k, v in headers.items()],
                    "query_string": b"", "client": ("127.0.0.1", 1234)})


def test_trisk2_no_verified_principal_is_not_the_platform_admin():
    """Before: `_principal()` returned "admin@nivxray.com" for a caller with
    no identity at all. After: it raises ACCESS_DENIED / T-RISK-2."""
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as e:
        rb.resolve_principal(_bare_request({}))
    assert e.value.status_code == 403
    assert e.value.detail["risk"] == "T-RISK-2"
    assert "admin@nivxray.com" not in str(e.value.detail)


def test_trisk2_client_claimed_identity_is_not_an_identity():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as e:
        rb.resolve_principal(_bare_request({
            "X-Principal-Id": "admin@nivxray.com",
            "X-Principal-Kind": "user",
            "X-Tenant-Id": T_ACME}))
    assert e.value.detail["risk"] == "T-RISK-2"


def test_trisk2_forged_admin_header_cannot_impersonate():
    """A real analyst token plus a forged `X-Principal-Id: admin` must be
    attributed to the ANALYST — provenance can no longer be forged."""
    ten_pid = rb.resolve_principal(_bare_request({
        "Authorization": f"Bearer {_tok(U_ACME)}",
        "X-Principal-Id": U_ADMIN,
        "X-Principal-Kind": "user"}))
    assert ten_pid == (T_ACME, U_ACME, "user")


def test_trisk2_missing_principal_and_tenant_together_fail_closed():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as e:
        rb.resolve_principal(_bare_request({"X-Principal-Kind": "user"}))
    assert e.value.status_code == 403


def test_trisk2_absence_of_identity_never_increases_privilege():
    for hdrs in ({}, {"X-Tenant-Id": T_ACME},
                 {"X-Principal-Id": U_ADMIN},
                 {"X-Principal-Kind": "api_key"}):
        r = client.get("/api/xdr/rbac/users", headers=hdrs)
        assert r.status_code in (401, 403), (hdrs, r.status_code)
        assert "users" not in (r.json().get("data") or {})


# ══════════════════════════════════════════════════════════════════
# Single-tenant regression — legitimate behaviour unchanged
# ══════════════════════════════════════════════════════════════════
def test_single_tenant_analyst_without_header_still_works():
    r = client.get("/api/xdr/rbac/users", headers=_auth(U_ACME))
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True


def test_single_tenant_analyst_with_own_tenant_header_still_works():
    r = client.get("/api/xdr/rbac/users", headers=_auth(U_ACME, T_ACME))
    assert r.status_code == 200, r.text
    emails = [u["email"] for u in r.json()["data"]["users"]]
    assert U_ACME in emails
    assert U_CONTOSO not in emails


def test_cross_tenant_admin_with_explicit_tenant_still_works():
    r = client.get("/api/xdr/rbac/users", headers=_auth(U_ADMIN, T_ACME))
    assert r.status_code == 200, r.text
    assert all(u["tenant_id"] == T_ACME for u in r.json()["data"]["users"])


# ══════════════════════════════════════════════════════════════════
# C1 · GET /api/xdr/scope/authorized
# ══════════════════════════════════════════════════════════════════
def test_c1_authorized_scope_is_server_resolved():
    r = client.get("/api/xdr/scope/authorized", headers=_auth(U_ACME))
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert d["authority"] == "server"
    assert d["basis"] == "SINGLE_AUTHORIZED_TENANT"
    assert d["basis_label"] == "Only authorized tenant"
    assert d["cross_tenant_role"] is False
    assert [t["customer"] for t in d["tenants"]] == [T_ACME]


def test_c1_publishes_exactly_the_six_authoritative_bases():
    r = client.get("/api/xdr/scope/authorized", headers=_auth(U_ADMIN))
    assert r.status_code == 200
    assert r.json()["data"]["bases"] == list(sc.SCOPE_BASES)
    assert len(sc.SCOPE_BASES) == 6


def test_c1_requires_authentication():
    assert client.get("/api/xdr/scope/authorized").status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════
# C2 · POST /api/xdr/scope/select — EffectiveScope
# ══════════════════════════════════════════════════════════════════
def _select(email, body, tenant=None):
    return client.post("/api/xdr/scope/select", json=body,
                       headers=_auth(email, tenant))


def test_c2_explicit_authorized_tenant_resolves():
    r = _select(U_MULTI, {"kind": "tenant", "tenant_id": T_CONTOSO})
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert d["tenant_ids"] == [T_CONTOSO]
    assert d["basis"] == "EXPLICIT_REQUEST_TENANT"
    assert d["authority"] == "server"
    assert d["locked"] is False


def test_c2_unauthorized_tenant_request_never_returns_that_tenants_scope():
    r = _select(U_ACME, {"kind": "tenant", "tenant_id": T_CONTOSO})
    assert r.status_code == 403, r.text
    d = _detail(r)
    assert d["tenant_ids"] == []
    assert T_CONTOSO in d["denied_tenant_ids"]
    assert d["basis"] == "NOT_AUTHORIZED"


def test_c2_effective_scope_is_an_intersection_for_multi_tenant_analyst():
    r = _select(U_MULTI, {"kind": "all_authorized"})
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert sorted(d["tenant_ids"]) == sorted([T_ACME, T_CONTOSO])
    assert d["basis"] == "MULTIPLE_AUTHORIZED_TENANTS"
    assert d["cross_tenant"] is True


def test_c2_cross_tenant_role_reports_real_customers_not_a_tenant_table():
    r = _select(U_ADMIN, {"kind": "all_authorized"})
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert d["basis"] == "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER"
    assert d["cross_tenant"] is True
    assert T_ACME in d["tenant_ids"] and T_CONTOSO in d["tenant_ids"]


def test_c2_single_authorized_tenant_basis():
    r = _select(U_ACME, {"kind": "all_authorized"})
    d = r.json()["data"]
    assert d["tenant_ids"] == [T_ACME]
    assert d["basis"] == "SINGLE_AUTHORIZED_TENANT"
    assert d["cross_tenant"] is False


def test_c2_not_authorized_principal_is_denied():
    r = _select(U_NOTENANT, {"kind": "all_authorized"})
    assert r.status_code == 403
    assert _detail(r)["basis"] == "NOT_AUTHORIZED"


# ══════════════════════════════════════════════════════════════════
# Tenant groups (A0.5-6) — organize scope, never grant it
# ══════════════════════════════════════════════════════════════════
def test_group_membership_never_grants_tenant_authorization():
    r = _select(U_ACME, {"kind": "group", "group_id": "apac",
                         "group_tenant_ids": [T_ACME, T_CONTOSO,
                                              T_NORTHWIND]})
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert d["tenant_ids"] == [T_ACME]
    assert sorted(d["denied_tenant_ids"]) == sorted([T_CONTOSO, T_NORTHWIND])
    assert d["requested_count"] == 3
    assert d["effective_count"] == 1


def test_group_with_no_authorized_member_is_denied_and_explained():
    r = _select(U_ACME, {"kind": "group", "group_id": "emea",
                         "group_tenant_ids": [T_CONTOSO, T_NORTHWIND]})
    assert r.status_code == 403, r.text
    d = _detail(r)
    assert d["tenant_ids"] == []
    assert sorted(d["denied_tenant_ids"]) == sorted([T_CONTOSO, T_NORTHWIND])


def test_tenant_groups_are_declared_deferred_and_never_fabricated():
    r = client.get("/api/xdr/scope/authorized", headers=_auth(U_ADMIN))
    d = r.json()["data"]
    assert d["groups"] == []
    assert d["tenant_groups"]["state"] == "DEFERRED_NOT_YET_AUTHORITATIVE"
    for f in ("group_id", "tenant_ids", "authorized_tenant_ids",
              "denied_tenant_ids", "requested_count", "effective_count",
              "provenance", "version"):
        assert f in d["tenant_groups"]["fields"]


# ══════════════════════════════════════════════════════════════════
# A0.5-7 · incident-bound tenant lock (server-side)
# ══════════════════════════════════════════════════════════════════
def test_incident_inherited_tenant_is_locked():
    r = _select(U_MULTI, {"kind": "all_authorized",
                          "incident_id": INC_ACME})
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert d["tenant_ids"] == [T_ACME]
    assert d["basis"] == "INHERITED_FROM_INCIDENT"
    assert d["locked"] is True
    assert T_ACME in d["lock_reason"]
    assert d["resource"] == {"kind": "incident", "id": INC_ACME}


def test_incident_bound_scope_cannot_be_pivoted_client_side():
    """Open an ACME incident, then ask for Contoso while keeping the ACME
    incident context — the SERVER refuses, not a disabled dropdown."""
    r = _select(U_MULTI, {"kind": "tenant", "tenant_id": T_CONTOSO,
                          "incident_id": INC_ACME})
    assert r.status_code == 403, r.text
    d = _detail(r)
    assert "SCOPE_LOCKED_TO_INCIDENT" in d["reason"]
    assert d["locked"] is True
    assert d["tenant_ids"] == []


def test_incident_outside_scope_is_not_a_tenant_pivot():
    r = _select(U_ACME, {"kind": "all_authorized",
                         "incident_id": INC_CONTOSO})
    assert r.status_code == 403, r.text
    assert _detail(r)["reason"] == "INCIDENT_TENANT_OUT_OF_SCOPE"


def test_incident_resource_authorization_is_independent_of_scope_request():
    """Backend resource authorization rejects an incompatible
    tenant/resource pair regardless of any client scope state."""
    r = client.get(f"/api/incidents/{INC_CONTOSO}", headers=_auth(U_ACME))
    assert r.status_code == 404, r.text          # existence never disclosed
    r2 = client.get(f"/api/incidents/{INC_ACME}", headers=_auth(U_ACME))
    assert r2.status_code == 200, r2.text


# ══════════════════════════════════════════════════════════════════
# A0.5-5 · console authorization — 4 combinations, both directions
# ══════════════════════════════════════════════════════════════════
_console_app = FastAPI()
# The dependency under test is `require_console`. Two probe routes are
# mounted on the SAME app the rest of this suite drives, so the assertion
# is on a real HTTP authorization decision (API, not UI) and shares the
# application's event loop. They are registered by this test module only
# and never by `server.py`.
_probe = APIRouter(prefix="/api/_a05_probe")


@_probe.get("/console/soc",
            dependencies=[Depends(rb.require_console("soc"))])
def _probe_soc():
    return {"console": "soc"}


@_probe.get("/console/admin",
            dependencies=[Depends(rb.require_console("admin"))])
def _probe_admin():
    return {"console": "admin"}


app.include_router(_probe)

_CONSOLE_USERS = {"soc_only": (lambda: U_SOC, True, False),
                  "admin_only": (lambda: U_ADM, False, True),
                  "both": (lambda: U_BOTH, True, True),
                  "neither": (lambda: U_NEITHER, False, False)}


@pytest.mark.parametrize("who", list(_CONSOLE_USERS))
def test_console_permission_matrix_api_not_ui(who):
    get_email, soc, adm = _CONSOLE_USERS[who]
    email = get_email()
    r = client.get("/api/_a05_probe/console/soc", headers=_auth(email, T_ACME))
    assert (r.status_code == 200) is soc, (who, "soc", r.status_code, r.text)
    r = client.get("/api/_a05_probe/console/admin",
                   headers=_auth(email, T_ACME))
    assert (r.status_code == 200) is adm, (who, "admin", r.status_code, r.text)


@pytest.mark.parametrize("who", list(_CONSOLE_USERS))
def test_console_endpoint_reports_the_same_authority(who):
    get_email, soc, adm = _CONSOLE_USERS[who]
    r = client.get("/api/xdr/scope/console",
                   headers=_auth(get_email(), T_ACME))
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert d["soc"] is soc and d["admin"] is adm, (who, d)
    assert d["authority"] == "server"


def test_console_claim_grants_nothing():
    """A `console=` destination claim (query, header or cookie-shaped) must
    never manufacture the permission."""
    for extra in ({"X-Console": "admin"}, {"console": "admin"},
                  {"X-Nivx-Console": "admin"}):
        h = {**_auth(U_SOC, T_ACME), **extra}
        assert client.get("/api/_a05_probe/console/admin",
                          headers=h).status_code == 403, extra
    assert client.get("/api/_a05_probe/console/admin?console=admin",
                      headers=_auth(U_SOC, T_ACME)).status_code == 403


def test_neither_console_is_granted_by_a_wildcard():
    """`*.*` is broad administrative authority; it must not silently confer
    console entry. Administrator ⇏ SOC access."""
    assert rb._expand_wildcard("*.*").isdisjoint(
        {"console.soc.access", "console.admin.access"})
    assert rb._expand_wildcard("console.*") == set()
    assert rb._expand_wildcard("*.access") == set()
    # but a by-name grant works
    assert rb._expand_wildcard("console.soc.access") == {"console.soc.access"}
    assert rb._valid_permission("console.soc.access")
    assert "console.admin.access" in rb._all_permissions()


def test_console_permissions_are_independent_of_each_other():
    soc = rb.console_authorization({"email": U_SOC, "role": "analyst",
                                    "tenant_id": T_ACME})
    adm = rb.console_authorization({"email": U_ADM, "role": "analyst",
                                    "tenant_id": T_ACME})
    assert soc["soc"] and not soc["admin"]
    assert adm["admin"] and not adm["soc"]


def test_platform_admin_break_glass_is_declared_not_inferred():
    d = rb.console_authorization({"email": U_ADMIN, "role": "admin"})
    assert d["basis"] == "PLATFORM_ADMIN_BREAK_GLASS"
    assert d["soc"] and d["admin"]
    assert "not an inference" in d["note"]


# ══════════════════════════════════════════════════════════════════
# A0.5-9 · client-manipulation tests
# ══════════════════════════════════════════════════════════════════
_MANIPULATED = ["tenant_id", "customer_id", "scope", "scope_type",
                "tenant_group", "incident_id", "resource_id", "console",
                "role", "permission"]


@pytest.mark.parametrize("field", _MANIPULATED)
def test_client_cannot_manipulate_authority_via_body(field):
    body = {"kind": "all_authorized", field: T_CONTOSO}
    r = _select(U_ACME, body)
    assert r.status_code in (200, 403, 422), (field, r.status_code)
    if r.status_code == 200:
        assert r.json()["data"]["tenant_ids"] == [T_ACME], field
    else:
        assert T_CONTOSO not in (_detail(r).get("tenant_ids") or []), field


@pytest.mark.parametrize("field", _MANIPULATED)
def test_client_cannot_manipulate_authority_via_query_or_header(field):
    r = client.post(f"/api/xdr/scope/select?{field}={T_CONTOSO}",
                    json={"kind": "all_authorized"},
                    headers={**_auth(U_ACME), field: T_CONTOSO})
    assert r.status_code == 200, r.text
    assert r.json()["data"]["tenant_ids"] == [T_ACME]


def test_client_cached_effective_access_object_is_not_authority():
    """Replaying a previously-returned EffectiveScope for another tenant
    does not make it effective."""
    good = _select(U_MULTI, {"kind": "tenant",
                             "tenant_id": T_CONTOSO}).json()["data"]
    assert good["tenant_ids"] == [T_CONTOSO]
    replay = client.post("/api/xdr/scope/select",
                         json={**good, "kind": "tenant",
                               "tenant_id": T_CONTOSO},
                         headers=_auth(U_ACME))
    assert replay.status_code == 403
    assert _detail(replay)["tenant_ids"] == []


def test_forged_role_and_permission_claims_are_ignored():
    r = client.get("/api/xdr/rbac/users", headers={
        **_auth(U_ACME, T_ACME), "X-Role": "admin",
        "X-Permission": "*.*", "X-Principal-Kind": "api_key"})
    assert r.status_code == 200
    emails = [u["email"] for u in r.json()["data"]["users"]]
    assert U_CONTOSO not in emails


# ══════════════════════════════════════════════════════════════════
# MACHINE principal — a separate, preserved security contract
# ══════════════════════════════════════════════════════════════════
@pytest.fixture(scope="module")
def _api_key():
    if rb._c_api_keys() is None:
        pytest.skip("api key store unavailable")
    raw = "nvx_" + uuid.uuid4().hex + uuid.uuid4().hex[:16]
    kid = f"key_a05_{SUF}"
    rb._c_api_keys().update_one({"id": kid}, {"$set": {
        "id": kid, "hash": hashlib.sha256(raw.encode()).hexdigest(),
        "tenant_id": T_ACME, "enabled": True, "revoked_at": None,
        "expires_at": None, "scopes": ["users.read"]}}, upsert=True)
    yield raw
    rb._c_api_keys().delete_one({"id": kid})


def test_machine_principal_acts_only_in_its_bound_tenant(_api_key):
    r = client.get("/api/xdr/rbac/users", headers={
        "X-XDR-API-Key": _api_key, "X-Tenant-Id": T_ACME})
    assert r.status_code == 200, r.text
    assert all(u["tenant_id"] == T_ACME for u in r.json()["data"]["users"])


def test_machine_principal_cannot_name_another_tenant(_api_key):
    r = client.get("/api/xdr/rbac/users", headers={
        "X-XDR-API-Key": _api_key, "X-Tenant-Id": T_CONTOSO})
    assert r.status_code == 403, r.text
    assert _detail(r)["reason"] == "api-key-tenant-mismatch"


def test_machine_principal_without_tenant_header_is_denied(_api_key):
    r = client.get("/api/xdr/rbac/users",
                   headers={"X-XDR-API-Key": _api_key})
    assert r.status_code in (401, 403)
    assert _detail(r)["reason"] == "missing-tenant-header"


def test_machine_principal_has_no_console():
    assert sc.TENANT_GROUP_STATE  # contract loaded
    d = rb.console_authorization({"email": None})
    assert d["soc"] is False and d["admin"] is False


# ══════════════════════════════════════════════════════════════════
# C4 · every tenant-scoped row carries resolved tenant provenance
# ══════════════════════════════════════════════════════════════════
def test_c4_cross_tenant_rows_carry_tenant_provenance():
    r = client.get("/api/incidents?limit=25", headers=_auth(U_ADMIN))
    assert r.status_code == 200, r.text
    rows = r.json().get("items") or r.json().get("incidents") or []
    assert rows, "cross-tenant queue returned no rows to verify"
    for row in rows:
        assert row.get("tenant") or row.get("customer"), row


# ══════════════════════════════════════════════════════════════════
# A0.5-10 · response/tenant isolation regression (authority untouched)
# ══════════════════════════════════════════════════════════════════
def test_response_authority_states_are_unchanged():
    from routers import xdr_respond_boundary as rbd
    src = open(rbd.__file__).read()
    for token in ("REQUESTED", "APPROVED", "DISPATCHED"):
        assert token in src.upper()


def test_cross_tenant_response_request_cannot_target_another_tenant():
    """An analyst naming another tenant is refused by the tenant authority
    before any approval/dispatch can exist."""
    with pytest.raises(sc.ScopeDenied):
        sc.authorize_requested_tenant(U_ACME, T_CONTOSO)
    r = client.get("/api/xdr/respond/pending-approvals",
                   headers=_auth(U_ACME, T_CONTOSO))
    assert r.status_code != 200 or all(
        (x.get("tenant_id") in (None, T_ACME))
        for x in (r.json().get("data") or r.json().get("items") or []))


# ══════════════════════════════════════════════════════════════════
# Class guard — the T-RISK-1 / T-RISK-2 literals cannot reappear
# ══════════════════════════════════════════════════════════════════
#: Disclosed, owner-fenced sites that A0.5 deliberately did NOT change.
_DISCLOSED_RESIDUALS = {
    "xdr_respond_boundary.py": "T-RISK-3 · Response lane fenced by the owner",
    "xdr_cortex_wizard.py": "T-RISK-4 · vendor wizard body tenant",
    "xdr_vendor_wizard.py": "T-RISK-4 · vendor wizard body tenant",
    "xdr_mss.py": "T-RISK-5 · document labelling, not authorization",
    "incidents.py": "T-RISK-5 · document labelling, not authorization",
}


def test_no_router_reintroduces_the_default_tenant_fallback():
    import pathlib
    offenders = []
    for p in pathlib.Path(rb.__file__).parent.glob("*.py"):
        if p.name in _DISCLOSED_RESIDUALS:
            continue
        src = p.read_text()
        for needle in ('X-Tenant-Id") or "default"',
                       'tenant_id", None) or "default"',
                       'or "admin@nivxray.com"'):
            if needle in src:
                offenders.append((p.name, needle))
    assert offenders == [], offenders


def test_the_guard_is_not_vacuous():
    """A guard that matches nothing is worse than none: prove the pattern
    still matches at the disclosed residual sites."""
    import pathlib
    boundary = (pathlib.Path(rb.__file__).parent
                / "xdr_respond_boundary.py").read_text()
    assert 'or "default"' in boundary, (
        "T-RISK-3 residual disappeared — re-classify the guard")
