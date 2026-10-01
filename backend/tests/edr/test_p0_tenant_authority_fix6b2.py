"""P0 · TENANT AUTHORITY · FIX 6B-2 — grants-first + explicit PLATFORM scope.

What this proves
----------------
Tenant breadth used to come from a free-text role string
(`_CROSS_TENANT_ROLES = {admin, platform_admin, soc_manager, mssp_operator}`),
so `role` alone authorised every customer tenant. After Fix 6B-2:

    WHERE  = users.authority_scope == "PLATFORM"  (explicit designation)
             OR users.tenant_ids[]               (explicit grants)
    WHAT   = role / RBAC

PLATFORM is breadth, never a bypass: registry validation (Fix 5A) and RBAC
still run for both classes.

EVIDENCE LABELLING — TEST/SYNTHETIC. Stubbed principals and a stubbed
registry; no credential, no live account, no write.
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from routers import edr_session as es
from routers import edr_tenancy as et
from services import dashboard_lenses as dl
from services import session_context as sc
from services import tenant_registry as reg

TEN_A = "ten_a0000000000000000000000a"
TEN_B = "ten_b0000000000000000000000b"
TEN_C = "ten_c0000000000000000000000c"
TEN_ARCHIVED = "ten_d0000000000000000000000d"
TEN_ORPHAN = "ten_e0000000000000000000000e"
TEN_UNKNOWN = "ten_not_registered_00000000"

ORG = "org_a0000000000000000000000a"
ORG_SUSPENDED = "org_b0000000000000000000000b"

CUST_A = "admin@customer-a.test"            # CUSTOMER admin, grants [A]
CUST_AB = "soc@mssp.test"                   # CUSTOMER soc_manager, grants [A,B]
ADMIN_NO_GRANTS = "admin@nogrants.test"     # role admin, zero grants
SOC_NO_GRANTS = "soc@nogrants.test"         # role soc_manager, zero grants
MSSP_NO_GRANTS = "mssp@nogrants.test"       # role mssp_operator, zero grants
PLATFORM_P = "superadmin@nivxforge.test"    # authority_scope = PLATFORM
FAKE_PLATFORM = "fake@nivxforge.test"       # malformed authority_scope values

_USERS = {
    CUST_A: {"email": CUST_A, "role": "admin", "tenant_ids": [TEN_A]},
    CUST_AB: {"email": CUST_AB, "role": "soc_manager",
              "tenant_ids": [TEN_A, TEN_B]},
    ADMIN_NO_GRANTS: {"email": ADMIN_NO_GRANTS, "role": "admin"},
    SOC_NO_GRANTS: {"email": SOC_NO_GRANTS, "role": "soc_manager"},
    MSSP_NO_GRANTS: {"email": MSSP_NO_GRANTS, "role": "mssp_operator"},
    PLATFORM_P: {"email": PLATFORM_P, "role": "admin",
                 "authority_scope": "PLATFORM", "tenant_ids": [TEN_A]},
    FAKE_PLATFORM: {"email": FAKE_PLATFORM, "role": "platform_admin",
                    "authority_scope": "platform_admin",
                    "tenant_ids": [TEN_A]},
}

_REGISTRY = {
    TEN_A: {"id": TEN_A, "state": "ACTIVE", "organization_id": ORG},
    TEN_B: {"id": TEN_B, "state": "ACTIVE", "organization_id": ORG},
    TEN_C: {"id": TEN_C, "state": "ACTIVE", "organization_id": ORG},
    TEN_ARCHIVED: {"id": TEN_ARCHIVED, "state": "ARCHIVED",
                   "organization_id": ORG},
    TEN_ORPHAN: {"id": TEN_ORPHAN, "state": "ACTIVE",
                 "organization_id": ORG_SUSPENDED},
}
_ORGS = {ORG: {"id": ORG, "state": "ACTIVE"},
         ORG_SUSPENDED: {"id": ORG_SUSPENDED, "state": "SUSPENDED"}}


class _FakeUsers:
    def find_one(self, query, _proj=None):
        return _USERS.get(query.get("email"))


@pytest.fixture(autouse=True)
def _stubs(monkeypatch):
    """Real authority chain end to end; only its INPUTS are stubbed."""
    import deps
    monkeypatch.setattr(deps, "sync_collection",
                        lambda name: _FakeUsers() if name == "users" else None)
    monkeypatch.setattr(reg, "get_tenant", lambda t: _REGISTRY.get(t))
    monkeypatch.setattr(reg, "get_organization", lambda o: _ORGS.get(o))
    monkeypatch.setattr(reg, "list_tenants",
                        lambda **kw: list(_REGISTRY.values()))
    monkeypatch.setattr(reg, "list_organizations",
                        lambda **kw: list(_ORGS.values()))
    from routers import xdr_rbac
    monkeypatch.setattr(xdr_rbac, "_resolve_user_permissions",
                        lambda tenant, email: (set(), "stub:no_assignment"))
    yield


def _request(tenant=None):
    headers = [(b"x-tenant-id", tenant.encode())] if tenant else []
    return Request({"type": "http", "method": "GET",
                    "path": "/api/edr/endpoints", "headers": headers,
                    "query_string": b""})


def _resolve(email, tenant=None):
    role = (_USERS.get(email) or {}).get("role")
    return asyncio.run(et.edr_tenant(_request(tenant),
                                     {"email": email, "role": role}))


def _refusal(email, tenant=None):
    with pytest.raises(HTTPException) as ei:
        _resolve(email, tenant)
    return ei.value


# ── A–E · CUSTOMER scope is exactly the explicit grant list ───────
def test_a_customer_grants_a_reaches_a():
    assert _resolve(CUST_A, TEN_A) == TEN_A


def test_b_customer_grants_a_refused_b():
    e = _refusal(CUST_A, TEN_B)
    assert e.status_code == 403
    assert e.detail["code"] == et.UNAUTHORIZED_TENANT_CODE


def test_c_d_customer_grants_ab_reaches_both():
    assert _resolve(CUST_AB, TEN_A) == TEN_A
    assert _resolve(CUST_AB, TEN_B) == TEN_B


def test_e_customer_grants_ab_refused_c():
    assert _refusal(CUST_AB, TEN_C).status_code == 403


# ── F/G/H · a role name is no longer tenant authority ─────────────
@pytest.mark.parametrize("email", [ADMIN_NO_GRANTS, SOC_NO_GRANTS,
                                   MSSP_NO_GRANTS])
def test_f_g_h_role_without_grants_has_no_tenant_authority(email):
    scope = dl.resolve_tenant_scope(email)
    assert scope["authority_scope"] == "CUSTOMER"
    assert scope["all_tenants"] is False
    assert scope["tenant_ids"] == []
    # cannot auto-bind anything …
    assert _refusal(email).detail["code"] == "TENANT_NOT_RESOLVED"
    # … and cannot name a real tenant either
    assert _refusal(email, TEN_A).status_code == 403


def test_f_legacy_role_breadth_constant_is_no_longer_authority():
    assert not hasattr(dl, "_CROSS_TENANT_ROLES")
    src = dl.resolve_tenant_scope.__code__.co_consts
    assert "_LEGACY_ROLE_BREADTH_RETIRED" not in str(src)


# ── I/J/K · the browser cannot manufacture authority ──────────────
def test_i_hostile_x_tenant_id_cannot_escape_the_grant_set():
    for hostile in (TEN_C, TEN_UNKNOWN, "default", TEN_ARCHIVED):
        assert _refusal(CUST_A, hostile).status_code == 403


def test_j_query_tenant_is_not_read_by_the_authority_path():
    req = Request({"type": "http", "method": "GET",
                   "path": "/api/edr/endpoints", "headers": [],
                   "query_string": b"tenant=" + TEN_C.encode()})
    assert asyncio.run(et.edr_tenant(req, {"email": CUST_A,
                                           "role": "admin"})) == TEN_A


def test_k_backend_authority_reads_only_server_state():
    """No client-side store participates: the only inputs are the verified
    principal document and the X-Tenant-Id request value."""
    scope = dl.resolve_tenant_scope(CUST_A)
    assert scope["tenant_ids"] == [TEN_A]
    assert set(scope) == {"authorized", "authority_scope", "all_tenants",
                          "tenant_ids", "role"}


# ── L/M/N · registry validation still governs (Fix 5A intact) ─────
def test_l_granted_but_archived_tenant_is_refused():
    users = dict(_USERS[CUST_A], tenant_ids=[TEN_ARCHIVED])
    _USERS["tmp@archived.test"] = users | {"email": "tmp@archived.test"}
    try:
        e = _refusal("tmp@archived.test")
        assert e.detail["code"] == "TENANT_NOT_ACTIVE"
    finally:
        _USERS.pop("tmp@archived.test")


def test_m_granted_tenant_under_inactive_org_is_refused():
    _USERS["tmp@orphan.test"] = {"email": "tmp@orphan.test", "role": "analyst",
                                 "tenant_ids": [TEN_ORPHAN]}
    try:
        assert _refusal("tmp@orphan.test").detail["code"] == \
            "ORGANIZATION_NOT_ACTIVE"
    finally:
        _USERS.pop("tmp@orphan.test")


def test_n_registry_failure_fails_closed(monkeypatch):
    def _boom(_t):
        raise RuntimeError("mongo is gone")
    monkeypatch.setattr(reg, "get_tenant", _boom)
    e = _refusal(CUST_A)
    assert e.status_code == 503 and e.detail["code"] == reg.REGISTRY_UNAVAILABLE


# ── O/P · no requested tenant ─────────────────────────────────────
def test_o_single_grant_auto_binds():
    assert _resolve(CUST_A) == TEN_A
    _, basis = sc.authorize_requested_tenant(CUST_A)
    assert basis == "SINGLE_AUTHORIZED_TENANT"


def test_p_multiple_grants_require_explicit_tenant():
    e = _refusal(CUST_AB)
    assert e.detail["code"] == "TENANT_REQUIRED"
    assert e.detail["basis"] == "MULTIPLE_AUTHORIZED_TENANTS"


def test_p_platform_without_a_request_never_auto_binds():
    e = _refusal(PLATFORM_P)
    assert e.detail["code"] == "TENANT_REQUIRED"
    assert e.detail["requested_tenant"] is None
    assert "default" not in str(e.detail).lower().replace("default customer", "")


# ── Q–U · PLATFORM is breadth, not a bypass ───────────────────────
def test_q_r_platform_reaches_any_registered_active_tenant():
    assert _resolve(PLATFORM_P, TEN_A) == TEN_A
    assert _resolve(PLATFORM_P, TEN_B) == TEN_B
    assert _resolve(PLATFORM_P, TEN_C) == TEN_C   # not in its tenant_ids


def test_s_platform_cannot_reach_a_nonexistent_tenant():
    assert _refusal(PLATFORM_P, TEN_UNKNOWN).detail["code"] == \
        "TENANT_NOT_FOUND"


def test_t_platform_cannot_reach_an_inactive_tenant():
    assert _refusal(PLATFORM_P, TEN_ARCHIVED).detail["code"] == \
        "TENANT_NOT_ACTIVE"


def test_u_platform_cannot_reach_a_tenant_under_inactive_org():
    assert _refusal(PLATFORM_P, TEN_ORPHAN).detail["code"] == \
        "ORGANIZATION_NOT_ACTIVE"


# ── V · PLATFORM requires the explicit designation, nothing else ──
def test_v_role_alone_does_not_create_platform_scope():
    for email in (CUST_A, CUST_AB, ADMIN_NO_GRANTS, SOC_NO_GRANTS,
                  MSSP_NO_GRANTS, FAKE_PLATFORM):
        assert dl.resolve_tenant_scope(email)["authority_scope"] == "CUSTOMER"
    assert dl.resolve_tenant_scope(PLATFORM_P)["authority_scope"] == "PLATFORM"


@pytest.mark.parametrize("value", [None, "", "CUSTOMER", "platform",
                                   "platform_admin", True, 1, ["PLATFORM"],
                                   {"scope": "PLATFORM"}])
def test_v_malformed_authority_scope_is_customer(value):
    assert dl.authority_scope({"authority_scope": value}) == "CUSTOMER"
    assert dl.authority_scope({}) == "CUSTOMER"
    assert dl.authority_scope(None) == "CUSTOMER"


def test_v_platform_designation_is_the_only_accepted_form():
    assert dl.authority_scope({"authority_scope": "PLATFORM"}) == "PLATFORM"
    assert dl.authority_scope({"authority_scope": " PLATFORM "}) == "PLATFORM"


def test_v_fake_platform_principal_is_confined_to_its_grants():
    assert _resolve(FAKE_PLATFORM, TEN_A) == TEN_A
    assert _refusal(FAKE_PLATFORM, TEN_C).status_code == 403


# ── authorized_count · authority-derived, never the case corpus ───
def test_authorized_count_customer_is_grant_derived():
    out = sc.effective_scope(CUST_AB, kind="tenant", tenant_id=TEN_A)
    assert out["authorized_count"] == 2          # grants [A, B], both valid
    _USERS["tmp@mixed.test"] = {"email": "tmp@mixed.test", "role": "analyst",
                                "tenant_ids": [TEN_A, TEN_ARCHIVED]}
    try:
        out = sc.effective_scope("tmp@mixed.test", kind="tenant",
                                 tenant_id=TEN_A)
        assert out["authorized_count"] == 1      # archived grant excluded
    finally:
        _USERS.pop("tmp@mixed.test")


def test_authorized_count_platform_is_active_tenants_under_active_orgs():
    out = sc.effective_scope(PLATFORM_P, kind="tenant", tenant_id=TEN_A)
    assert out["authorized_count"] == 3          # A, B, C — not archived/orphan


def test_authorized_count_platform_fails_closed_on_registry_failure(
        monkeypatch):
    monkeypatch.setattr(reg, "list_tenants",
                        lambda **kw: (_ for _ in ()).throw(RuntimeError("x")))
    out = sc.effective_scope(PLATFORM_P, kind="tenant", tenant_id=TEN_A)
    assert out["authorized_count"] == 0


# ── W · a successful explicit switch is audited ───────────────────
def _fake_request(tenant, basis="EXPLICIT_REQUEST_TENANT", trace="trc_1"):
    req = _request(tenant)
    req.state.effective_tenant_id = tenant
    req.state.tenant_resolution_basis = basis
    req.state.trace_id = trace
    return req


def test_w_successful_switch_writes_one_audit_row(monkeypatch):
    rows = []
    monkeypatch.setattr(es, "emit_audit",
                        lambda **kw: rows.append(kw) or {"id": "aud_test"})
    monkeypatch.setattr(es, "_previous_context", lambda p: TEN_A)
    out = asyncio.run(es.set_active_tenant(_fake_request(TEN_B), TEN_B,
                                           {"email": PLATFORM_P,
                                            "role": "admin"}))
    assert out["switch_recorded"] is True
    assert out["previous_tenant_id"] == TEN_A
    assert len(rows) == 1
    row = rows[0]
    assert row["action"] == "TENANT_CONTEXT_SWITCHED"
    assert row["principal_id"] == PLATFORM_P
    assert row["tenant_id"] == TEN_B
    assert row["resource_kind"] == "tenant_context"
    assert row["outcome"] == "SUCCESS"
    assert row["before"] == {"tenant_id": TEN_A}
    assert row["after"] == {"tenant_id": TEN_B}
    assert row["correlation_id"] == "trc_1"
    assert row["metadata"]["authority_scope"] == "PLATFORM"
    assert row["metadata"]["basis"] == "EXPLICIT_REQUEST_TENANT"
    assert row["metadata"]["requested_tenant"] == TEN_B


def test_w_unknown_previous_context_is_stated_not_invented(monkeypatch):
    rows = []
    monkeypatch.setattr(es, "emit_audit",
                        lambda **kw: rows.append(kw) or {"id": "aud_test"})
    monkeypatch.setattr(es, "_previous_context", lambda p: None)
    out = asyncio.run(es.set_active_tenant(_fake_request(TEN_A), TEN_A,
                                           {"email": CUST_AB}))
    assert out["previous_tenant_id"] == es.PREVIOUS_UNKNOWN
    assert rows[0]["before"] == {"tenant_id": "NOT_AVAILABLE"}
    assert rows[0]["metadata"]["authority_scope"] == "CUSTOMER"


def test_w_repeating_the_same_context_is_not_a_switch(monkeypatch):
    rows = []
    monkeypatch.setattr(es, "emit_audit",
                        lambda **kw: rows.append(kw) or {"id": "aud_test"})
    monkeypatch.setattr(es, "_previous_context", lambda p: TEN_A)
    out = asyncio.run(es.set_active_tenant(_fake_request(TEN_A), TEN_A,
                                           {"email": CUST_A}))
    assert out["switch_recorded"] is False
    assert out["reason"] == "NO_CONTEXT_CHANGE"
    assert rows == []


# ── X · refusals keep their existing audit evidence ───────────────
def test_x_refused_switch_still_produces_refusal_audit(monkeypatch):
    """A non-privileged principal's refusal takes the Fix 2 non-disclosing
    path, which is the path that writes the ACCESS_DENIED/tenant_scope row."""
    seen = []
    from routers import xdr_rbac
    monkeypatch.setattr(xdr_rbac, "_audit_scope_denial",
                        lambda *a, **kw: seen.append(a))
    assert _refusal(CUST_AB, TEN_C).status_code == 403
    assert seen and seen[0][0] == TEN_C and seen[0][2] == "tenant_scope"
    assert "P0-FIX-2:non_disclosing:" in seen[0][3]
