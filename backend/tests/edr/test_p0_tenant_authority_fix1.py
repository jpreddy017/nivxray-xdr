"""P0 · TENANT AUTHORITY · FIX 1 — the EDR tenant dependency gate.

What this proves
----------------
`routers.edr_tenancy.edr_tenant()` used to answer only "is the named
tenant registered and ACTIVE?". Principal authorisation lived in an
OPTIONAL `edr_scope()` call that eight TENANT_SCOPED operations never
made, so on those routes a client-supplied `X-Tenant-Id` expanded
authority. Fix 1 makes authorisation happen by CONSTRUCTION inside the
dependency itself.

Two layers of proof:

  1. BEHAVIOUR — `edr_tenant()` is called directly with a stubbed
     principal, a stubbed authorisation scope and a stubbed registry, so
     the real `authorize_requested_tenant` → `tenant_registry.authoritative`
     chain is exercised with no Mongo, no network and no preview probe.
  2. STRUCTURE — the LIVE FastAPI route table is walked to prove every
     TENANT_SCOPED `/api/edr/*` operation (the eight G1 routes included)
     actually depends on `edr_tenant`, so none of them can obtain a
     tenant without passing through the authorisation above.

EVIDENCE LABELLING — TEST/SYNTHETIC. No credential, no HTTP request, no
write of any kind.
"""
from __future__ import annotations

import asyncio
import os

import pytest
from dotenv import load_dotenv
from fastapi import HTTPException
from starlette.requests import Request

load_dotenv("/app/backend/.env")

from routers import edr_tenancy as et                          # noqa: E402
from routers.edr_tenancy import (PRODUCT_METADATA,             # noqa: E402
                                 ROUTE_CLASSIFICATION,
                                 SENSOR_SCOPED, TENANT_SCOPED)
from services import session_context as sc                     # noqa: E402
from services import tenant_registry as reg                    # noqa: E402

TEN_A = "ten_aaaa000000000000000000aa"
TEN_B = "ten_bbbb000000000000000000bb"
TEN_ARCHIVED = "ten_cccc000000000000000000cc"
TEN_UNKNOWN = "ten_not_registered_0000000000"

SOLO = "solo@customer-a.test"          # exactly one authorized tenant
MULTI = "multi@customer-ab.test"       # two authorized tenants
ZERO = "zero@nothing.test"             # authorized principal, no tenant
CROSS = "vendor@nivxray.test"          # cross-tenant principal

_SCOPES = {
    SOLO:  {"authorized": True, "all_tenants": False, "tenant_ids": [TEN_A],
            "role": "l2_investigator"},
    MULTI: {"authorized": True, "all_tenants": False,
            "tenant_ids": [TEN_A, TEN_B], "role": "l3_investigator"},
    ZERO:  {"authorized": True, "all_tenants": False, "tenant_ids": [],
            "role": "l1_analyst"},
    CROSS: {"authorized": True, "all_tenants": True, "role": "platform_admin"},
}

ORG = "org_aaaa000000000000000000aa"

_REGISTRY = {TEN_A: {"id": TEN_A, "state": "ACTIVE", "organization_id": ORG},
             TEN_B: {"id": TEN_B, "state": "ACTIVE", "organization_id": ORG},
             TEN_ARCHIVED: {"id": TEN_ARCHIVED, "state": "ARCHIVED",
                            "organization_id": ORG}}
_ORGS = {ORG: {"id": ORG, "state": "ACTIVE"}}

# The eight operations the audit found registry-validated but NOT
# principal-authorized (gap G1).
G1_OPERATIONS = (
    ("GET", "/api/edr/detections"),
    ("GET", "/api/edr/campaign-story"),
    ("GET", "/api/edr/file-trajectory"),
    ("GET", "/api/edr/fleet-spread-index"),
    ("GET", "/api/edr/response/actions/{command_id}"),
    ("GET", "/api/edr/response/isolation-policy"),
    ("GET", "/api/edr/wave0/raw-events/stats"),
    ("GET", "/api/edr/wave0/raw-events/replay-candidates"),
)


#: P0-FIX-1B · the seven enrollment/onboarding operations that used to
#: resolve their tenant through the duplicate registry-only resolver
#: `routers.edr_enrollment._tenant`. That resolver is DELETED and these
#: routes now consume `edr_tenant`, so the set below must stay EMPTY.
SECOND_RESOLVER_OPERATIONS: tuple = ()

#: The formerly weak enrollment/onboarding operations (gap G1-B).
G1B_OPERATIONS = (
    ("GET", "/api/edr/onboarding/computers"),
    ("GET", "/api/edr/onboarding/computers/{endpoint_id}"),
    ("POST", "/api/edr/enrollment/tokens"),
    ("GET", "/api/edr/enrollment/tokens"),
    ("GET", "/api/edr/enrollment/endpoints"),
    ("POST", "/api/edr/enrollment/endpoints/{endpoint_id}/rotate"),
    ("POST", "/api/edr/enrollment/endpoints/{endpoint_id}/revoke"),
)


@pytest.fixture(autouse=True)
def _stubs(monkeypatch):
    """Real authority chain, stubbed inputs. No Mongo, no network."""
    monkeypatch.setattr(sc, "resolve_tenant_scope",
                        lambda email: dict(_SCOPES.get(email or "",
                                                       {"authorized": False})))
    monkeypatch.setattr(reg, "enforcing", lambda: True)
    monkeypatch.setattr(reg, "get_tenant", lambda t: _REGISTRY.get(t))
    monkeypatch.setattr(reg, "get_organization", lambda o: _ORGS.get(o))
    yield


def _request(tenant=None):
    headers = [(b"x-tenant-id", tenant.encode())] if tenant else []
    return Request({"type": "http", "method": "GET",
                    "path": "/api/edr/endpoints", "headers": headers,
                    "query_string": b""})


def _resolve(email, tenant=None):
    """Call the dependency exactly as FastAPI would."""
    req = _request(tenant)
    out = asyncio.run(et.edr_tenant(req, {"email": email}))
    return out, req


def _refusal(email, tenant=None):
    with pytest.raises(HTTPException) as e:
        _resolve(email, tenant)
    detail = e.value.detail
    return e.value.status_code, (detail or {}).get("code"), detail


# ══════════════════════════════════════════════════════════════════
# SINGLE-TENANT CUSTOMER
# ══════════════════════════════════════════════════════════════════

def test_f01_single_tenant_principal_needs_no_header():
    """The requirement: a single-customer user names nothing and works."""
    tenant, req = _resolve(SOLO)
    assert tenant == TEN_A
    assert req.state.effective_tenant_id == TEN_A
    assert req.state.tenant_resolution_basis == "SINGLE_AUTHORIZED_TENANT"


def test_f02_single_tenant_principal_may_name_its_own_tenant():
    tenant, req = _resolve(SOLO, TEN_A)
    assert tenant == TEN_A
    assert req.state.tenant_resolution_basis == "EXPLICIT_REQUEST_TENANT"


def test_f03_single_tenant_principal_naming_another_tenant_is_refused():
    """A request may NAME a tenant; it may never AUTHORISE one."""
    status, code, detail = _refusal(SOLO, TEN_B)
    assert status == 403
    assert code == "TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL"
    assert detail["fail_closed"] is True
    assert detail["requested_tenant"] == TEN_B


def test_f04_a_registered_active_tenant_is_still_refused_when_not_held():
    """Registry validity is not authority: TEN_B exists and is ACTIVE."""
    assert reg.get_tenant(TEN_B)["state"] == "ACTIVE"
    assert _refusal(SOLO, TEN_B)[1] == "TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL"


# ══════════════════════════════════════════════════════════════════
# MULTI-TENANT / CROSS-TENANT PRINCIPAL
# ══════════════════════════════════════════════════════════════════

def test_f05_multi_tenant_principal_must_name_a_tenant():
    status, code, detail = _refusal(MULTI)
    assert status == 403 and code == "TENANT_REQUIRED"
    assert detail["basis"] == "MULTIPLE_AUTHORIZED_TENANTS"


def test_f06_multi_tenant_principal_is_accepted_for_either_held_tenant():
    for ten in (TEN_A, TEN_B):
        tenant, req = _resolve(MULTI, ten)
        assert tenant == ten
        assert req.state.tenant_resolution_basis == "EXPLICIT_REQUEST_TENANT"


def test_f07_multi_tenant_principal_is_refused_an_unheld_tenant():
    assert _refusal(MULTI, TEN_ARCHIVED)[1] == \
        "TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL"


def test_f08_cross_tenant_principal_must_still_name_a_tenant():
    status, code, detail = _refusal(CROSS)
    assert status == 403 and code == "TENANT_REQUIRED"
    assert detail["basis"] == "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER"


def test_f09_cross_tenant_principal_is_narrowed_to_the_named_tenant():
    tenant, _ = _resolve(CROSS, TEN_B)
    assert tenant == TEN_B


# ══════════════════════════════════════════════════════════════════
# ZERO-TENANT / UNVERIFIED PRINCIPAL
# ══════════════════════════════════════════════════════════════════

def test_f10_zero_tenant_principal_is_refused_with_and_without_a_header():
    assert _refusal(ZERO)[1] == "TENANT_NOT_RESOLVED"
    assert _refusal(ZERO, TEN_A)[1] == "TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL"


def test_f11_an_unknown_principal_is_refused():
    assert _refusal("ghost@nowhere.test", TEN_A)[1] == "ACCESS_DENIED"


def test_f12_no_principal_at_all_is_refused():
    with pytest.raises(HTTPException) as e:
        asyncio.run(et.edr_tenant(_request(TEN_A), {}))
    assert e.value.status_code == 403
    assert e.value.detail["code"] == "ACCESS_DENIED"


# ══════════════════════════════════════════════════════════════════
# REGISTRY AUTHORITY STILL APPLIES — AND ONLY NARROWS
# ══════════════════════════════════════════════════════════════════

def test_f13_an_unregistered_tenant_is_refused_even_for_cross_tenant():
    status, code, _ = _refusal(CROSS, TEN_UNKNOWN)
    assert status == 403 and code == "TENANT_NOT_FOUND"


def test_f14_a_non_active_tenant_is_refused():
    status, code, _ = _refusal(CROSS, TEN_ARCHIVED)
    assert status == 403 and code == "TENANT_NOT_ACTIVE"


def test_f15_authorisation_runs_before_the_registry_lookup(monkeypatch):
    """An unheld tenant must never reach the registry: existence is not
    disclosed to a principal that is not authorised for it."""
    seen = []
    monkeypatch.setattr(reg, "get_tenant",
                        lambda t: (seen.append(t), _REGISTRY.get(t))[1])
    assert _refusal(SOLO, TEN_B)[1] == "TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL"
    assert seen == []
    _resolve(SOLO, TEN_A)
    assert seen == [TEN_A]


def test_f16_no_default_tenant_is_ever_substituted():
    for email in (SOLO, MULTI, CROSS, ZERO):
        try:
            tenant, _ = _resolve(email)
        except HTTPException:
            continue
        assert tenant != "default"
        assert tenant in _REGISTRY


# ══════════════════════════════════════════════════════════════════
# STRUCTURE · the eight G1 routes inherit the corrected authority
# ══════════════════════════════════════════════════════════════════

def _flat_dependencies(dependant):
    out = []
    for dep in dependant.dependencies:
        out.append(dep.call)
        out.extend(_flat_dependencies(dep))
    return out


def _live_routes():
    from server import app
    table = {}
    for route in app.routes:
        path = getattr(route, "path", None)
        dependant = getattr(route, "dependant", None)
        if not path or dependant is None:
            continue
        for method in (getattr(route, "methods", None) or ()):
            table[(method, path)] = route
    return table


@pytest.fixture(scope="module")
def routes():
    return _live_routes()


def test_f17_every_g1_operation_exists_and_is_tenant_scoped(routes):
    for op in G1_OPERATIONS:
        assert op in ROUTE_CLASSIFICATION, op
        assert ROUTE_CLASSIFICATION[op] == TENANT_SCOPED, op
        assert op in routes, op


def test_f18_every_g1_operation_is_forced_through_edr_tenant(routes):
    """The structural proof: the bypass is closed at the dependency."""
    for op in G1_OPERATIONS:
        deps = _flat_dependencies(routes[op].dependant)
        assert et.edr_tenant in deps, op


def test_f19_every_tenant_scoped_edr_operation_is_forced_through_it(routes):
    """EVERY TENANT_SCOPED operation resolves its tenant through the one
    canonical dependency. `SECOND_RESOLVER_OPERATIONS` is now empty: after
    Fix 1B there is no second tenant-authorization path."""
    missing = []
    for op, kind in ROUTE_CLASSIFICATION.items():
        if kind != TENANT_SCOPED or op not in routes:
            continue
        if et.edr_tenant not in _flat_dependencies(routes[op].dependant):
            missing.append(op)
    assert sorted(missing) == sorted(SECOND_RESOLVER_OPERATIONS), missing


def test_f19b_the_duplicate_resolver_no_longer_exists():
    """Fix 1B eliminated the second implementation rather than hardening a
    copy of it: there is ONE principal→tenant authority on the EDR plane."""
    from routers import edr_enrollment as ee
    from routers import edr_onboarding as eo
    assert not hasattr(ee, "_tenant")
    assert not hasattr(eo, "_tenant")
    assert ee.edr_tenant is et.edr_tenant
    assert eo.edr_tenant is et.edr_tenant
    assert SECOND_RESOLVER_OPERATIONS == ()


def test_f19c_the_seven_g1b_operations_are_forced_through_edr_tenant(routes):
    from deps import get_current_user
    for op in G1B_OPERATIONS:
        assert ROUTE_CLASSIFICATION.get(op) == TENANT_SCOPED, op
        assert op in routes, op
        deps = _flat_dependencies(routes[op].dependant)
        assert et.edr_tenant in deps, op
        assert get_current_user in deps, op


def test_f19d_the_users_customer_compat_fallback_is_gone():
    """`users["customer"]` could previously SELECT the tenant when the
    header was absent. It must not appear on this authorization path."""
    import inspect
    from routers import edr_enrollment as ee
    from routers import edr_onboarding as eo
    for mod in (ee, eo, et):
        src = inspect.getsource(mod)
        assert '"customer"' not in src, mod.__name__
        assert "get('customer')" not in src, mod.__name__
    et_src = inspect.getsource(et.edr_tenant)
    assert "authorize_requested_tenant" in et_src
    assert "compat_default" not in et_src


def test_f19e_the_sensor_plane_still_derives_tenant_from_its_session():
    """SENSOR_SCOPED behaviour is untouched: the agent's tenant comes from
    its authenticated enrolment/agent credential, never from a header."""
    import inspect
    from routers import edr_enrollment as ee
    src = inspect.getsource(ee._agent_tenant)
    assert "X-Tenant-Id" not in src
    assert "headers" not in src
    assert "authoritative" in src
    assert callable(et.sensor_tenant)
    assert "No request header is consulted" in (et.sensor_tenant.__doc__ or "")


def test_f20_the_dependency_itself_now_requires_a_verified_principal(routes):
    from deps import get_current_user
    for op in G1_OPERATIONS:
        deps = _flat_dependencies(routes[op].dependant)
        assert get_current_user in deps, op
    # and the authority helper is the shared server-side one
    assert et.authorize_requested_tenant is sc.authorize_requested_tenant


def test_f21_sensor_and_metadata_routes_are_left_alone(routes):
    for op, kind in ROUTE_CLASSIFICATION.items():
        if kind not in (SENSOR_SCOPED, PRODUCT_METADATA) or op not in routes:
            continue
        assert et.edr_tenant not in _flat_dependencies(routes[op].dependant), op


def test_f22_edr_scope_remains_available_for_defense_in_depth():
    assert callable(et.edr_scope)
    assert "narrows" in (et.edr_scope.__doc__ or "")
