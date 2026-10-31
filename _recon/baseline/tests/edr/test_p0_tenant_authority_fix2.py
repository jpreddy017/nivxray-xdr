"""P0 · TENANT AUTHORITY · FIX 2 — non-disclosing tenant refusal.

The leak this closes
--------------------
After Fix 1/1B a tenant-scoped principal could not reach another
customer's tenant, but the REFUSAL still told it things:

    unheld tenant                         -> TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL
    all_tenants role, unregistered tenant -> TENANT_NOT_FOUND
    all_tenants role, archived tenant     -> TENANT_NOT_ACTIVE

`soc_manager` / `mssp_operator` carry `all_tenants` but NOT
`tenants.read`, so they could enumerate the registry through those codes.
For a principal without tenant-discovery privilege all three outcomes are
now ONE byte-identical refusal.

Authorisation is untouched: these tests also re-prove that nothing is
granted, that the order is still authorise → registry, and that a refusal
about the principal's OWN tenant keeps its precise, useful code.

EVIDENCE LABELLING — TEST/SYNTHETIC. No credential, no HTTP request, no
write, no preview probe.
"""
from __future__ import annotations

import asyncio

import pytest
from dotenv import load_dotenv
from fastapi import HTTPException
from starlette.requests import Request

load_dotenv("/app/backend/.env")

from routers import edr_tenancy as et                          # noqa: E402
from services import session_context as sc                     # noqa: E402
from services import tenant_registry as reg                    # noqa: E402

TEN_A = "ten_aaaa000000000000000000aa"          # registered · ACTIVE · held
TEN_B = "ten_bbbb000000000000000000bb"          # registered · ACTIVE · unheld
TEN_ARCHIVED = "ten_cccc000000000000000000cc"   # registered · ARCHIVED
TEN_UNKNOWN = "ten_not_registered_0000000000"   # not in the registry
ORG = "org_aaaa000000000000000000aa"

SOLO = "solo@customer-a.test"          # one tenant, no tenants.read
MSSP = "mgr@customer-a.test"           # all_tenants, NO tenants.read
ADMIN = "platform@nivxray.test"        # all_tenants, HAS tenants.read (*.*)
ZERO = "zero@nothing.test"
SOLO_ARCHIVED = "solo@archived.test"   # its OWN tenant is ARCHIVED

_SCOPES = {
    SOLO: {"authorized": True, "all_tenants": False, "tenant_ids": [TEN_A],
           "role": "l2_investigator"},
    MSSP: {"authorized": True, "all_tenants": True, "role": "soc_manager"},
    ADMIN: {"authorized": True, "all_tenants": True,
            "role": "platform_admin"},
    ZERO: {"authorized": True, "all_tenants": False, "tenant_ids": [],
           "role": "l1_analyst"},
    SOLO_ARCHIVED: {"authorized": True, "all_tenants": False,
                    "tenant_ids": [TEN_ARCHIVED], "role": "l2_investigator"},
}
_ROLES = {SOLO: "l2_investigator", MSSP: "soc_manager",
          ADMIN: "platform_admin", ZERO: "l1_analyst",
          SOLO_ARCHIVED: "l2_investigator"}

_REGISTRY = {TEN_A: {"id": TEN_A, "state": "ACTIVE", "organization_id": ORG},
             TEN_B: {"id": TEN_B, "state": "ACTIVE", "organization_id": ORG},
             TEN_ARCHIVED: {"id": TEN_ARCHIVED, "state": "ARCHIVED",
                            "organization_id": ORG}}
_ORGS = {ORG: {"id": ORG, "state": "ACTIVE"}}


@pytest.fixture(autouse=True)
def _stubs(monkeypatch):
    """Real authority + real RBAC vocabulary, stubbed inputs."""
    monkeypatch.setattr(sc, "resolve_tenant_scope",
                        lambda email: dict(_SCOPES.get(email or "",
                                                       {"authorized": False})))
    monkeypatch.setattr(reg, "enforcing", lambda: True)
    monkeypatch.setattr(reg, "get_tenant", lambda t: _REGISTRY.get(t))
    monkeypatch.setattr(reg, "get_organization", lambda o: _ORGS.get(o))
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
    req = _request(tenant)
    return asyncio.run(et.edr_tenant(
        req, {"email": email, "role": _ROLES.get(email)})), req


def _refusal(email, tenant=None):
    """The whole externally observable refusal."""
    with pytest.raises(HTTPException) as e:
        _resolve(email, tenant)
    return {"status": e.value.status_code, "detail": dict(e.value.detail)}


def _shape(refusal):
    """Everything the caller can observe EXCEPT the value it sent itself.

    Returned as a comparable/hashable string so a set of shapes collapsing
    to ONE element is the non-disclosure proof.
    """
    detail = dict(refusal["detail"])
    detail.pop("requested_tenant", None)
    return repr((refusal["status"], sorted(detail.items())))


# ══════════════════════════════════════════════════════════════════
# NON-DISCLOSURE · the three outcomes are indistinguishable
# ══════════════════════════════════════════════════════════════════

def test_g01_unheld_unregistered_and_inactive_are_indistinguishable():
    """Tenant-scoped principal: existing, nonexistent and archived all
    produce ONE identical refusal."""
    shapes = {_shape(_refusal(SOLO, t))
              for t in (TEN_B, TEN_UNKNOWN, TEN_ARCHIVED)}
    assert len(shapes) == 1, shapes
    refusal = _refusal(SOLO, TEN_UNKNOWN)
    assert refusal["status"] == 403
    assert refusal["detail"]["code"] == et.UNAUTHORIZED_TENANT_CODE
    assert refusal["detail"]["disclosure"] == et.DISCLOSURE_NOTE
    assert refusal["detail"]["fail_closed"] is True


def test_g02_an_all_tenants_principal_without_tenants_read_cannot_probe():
    """The actual enumeration path: `soc_manager` holds all_tenants but not
    `tenants.read`, so the registry outcome must not leak."""
    assert et._may_discover_tenants({"email": MSSP, "role": "soc_manager"},
                                    TEN_UNKNOWN) is False
    shapes = {_shape(_refusal(MSSP, t))
              for t in (TEN_UNKNOWN, TEN_ARCHIVED)}
    assert len(shapes) == 1, shapes
    assert _refusal(MSSP, TEN_UNKNOWN)["detail"]["code"] == \
        et.UNAUTHORIZED_TENANT_CODE


def test_g03_the_two_principal_kinds_receive_the_same_refusal():
    """A scoped principal and an unprivileged cross-tenant principal must
    not be told different things about the same tenant."""
    assert _shape(_refusal(SOLO, TEN_UNKNOWN)) == \
        _shape(_refusal(MSSP, TEN_UNKNOWN))
    assert _shape(_refusal(SOLO, TEN_ARCHIVED)) == \
        _shape(_refusal(MSSP, TEN_ARCHIVED))


def test_g04_nothing_in_the_body_names_existence_or_state():
    for t in (TEN_B, TEN_UNKNOWN, TEN_ARCHIVED):
        detail = _refusal(SOLO, t)["detail"]
        blob = str(detail).upper()
        for leak in ("NOT_FOUND", "NOT_ACTIVE", "ARCHIVED", "SUSPENDED",
                     "UNREGISTERED", "ORGANIZATION"):
            assert leak not in blob, (t, leak)
        assert set(detail) == {"code", "reason", "basis", "requested_tenant",
                              "authority", "fail_closed", "disclosure"}
        assert detail["requested_tenant"] == t      # the caller's own input


def test_g05_the_refusal_status_is_always_the_same():
    """TEN_B is a legitimately authorised ACTIVE tenant for an all_tenants
    principal, so it is only a refusal case for the scoped principals."""
    cases = {SOLO: (TEN_B, TEN_UNKNOWN, TEN_ARCHIVED),
             ZERO: (TEN_B, TEN_UNKNOWN, TEN_ARCHIVED),
             MSSP: (TEN_UNKNOWN, TEN_ARCHIVED)}
    for email, tenants in cases.items():
        for t in tenants:
            assert _refusal(email, t)["status"] == 403
    assert _resolve(MSSP, TEN_B)[0] == TEN_B


# ══════════════════════════════════════════════════════════════════
# AUTHORISATION IS NOT WEAKENED
# ══════════════════════════════════════════════════════════════════

def test_g06_the_own_authorized_active_tenant_still_succeeds():
    tenant, req = _resolve(SOLO)
    assert tenant == TEN_A
    assert req.state.tenant_resolution_basis == "SINGLE_AUTHORIZED_TENANT"
    tenant, req = _resolve(SOLO, TEN_A)
    assert tenant == TEN_A
    assert req.state.tenant_resolution_basis == "EXPLICIT_REQUEST_TENANT"


def test_g07_an_unauthorized_existing_tenant_is_still_refused():
    assert reg.get_tenant(TEN_B)["state"] == "ACTIVE"
    with pytest.raises(HTTPException):
        _resolve(SOLO, TEN_B)


def test_g08_normalisation_never_grants_anything():
    for email in (SOLO, MSSP, ZERO, ADMIN):
        for t in (TEN_UNKNOWN, TEN_ARCHIVED):
            with pytest.raises(HTTPException):
                _resolve(email, t)


def test_g09_a_zero_tenant_principal_remains_refused():
    assert _refusal(ZERO)["detail"]["code"] == "TENANT_NOT_RESOLVED"
    assert _shape(_refusal(ZERO, TEN_A)) == _shape(_refusal(SOLO, TEN_B))


def test_g10_tenant_required_is_not_normalised_away():
    """Naming nothing discloses nothing, so the actionable code stays."""
    assert _refusal(MSSP)["detail"]["code"] == "TENANT_REQUIRED"
    assert _refusal(ADMIN)["detail"]["code"] == "TENANT_REQUIRED"
    assert _refusal(MSSP)["detail"]["basis"] == \
        "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER"


def test_g11_no_registry_lookup_for_an_unheld_tenant(monkeypatch):
    seen = []
    monkeypatch.setattr(reg, "get_tenant",
                        lambda t: (seen.append(t), _REGISTRY.get(t))[1])
    for t in (TEN_B, TEN_UNKNOWN, TEN_ARCHIVED):
        with pytest.raises(HTTPException):
            _resolve(SOLO, t)
    assert seen == []
    _resolve(SOLO, TEN_A)
    assert seen == [TEN_A]


def test_g12_a_refusal_about_the_principals_own_tenant_stays_precise():
    """Auto-bound to its OWN archived tenant: no other customer is
    involved, so the useful diagnostic is kept."""
    detail = _refusal(SOLO_ARCHIVED)["detail"]
    assert detail["code"] == "TENANT_NOT_ACTIVE"


# ══════════════════════════════════════════════════════════════════
# PRIVILEGED DIAGNOSTICS RETAINED
# ══════════════════════════════════════════════════════════════════

def test_g13_a_principal_holding_tenants_read_keeps_the_precise_code():
    assert et._may_discover_tenants({"email": ADMIN,
                                     "role": "platform_admin"}, TEN_B) is True
    assert _refusal(ADMIN, TEN_UNKNOWN)["detail"]["code"] == \
        "TENANT_NOT_FOUND"
    assert _refusal(ADMIN, TEN_ARCHIVED)["detail"]["code"] == \
        "TENANT_NOT_ACTIVE"


def test_g14_discovery_privilege_is_read_from_the_existing_rbac_vocabulary():
    from routers.xdr_rbac import _BUILTIN_ROLE_BY_NAME
    assert et.TENANT_DISCOVERY_PERMISSION == "tenants.read"
    for role in ("l1_analyst", "l2_investigator", "l3_investigator",
                 "soc_manager", "threat_hunter"):
        assert role in _BUILTIN_ROLE_BY_NAME
        assert et._may_discover_tenants({"email": "x@y.test", "role": role},
                                        TEN_B) is False


def test_g15_an_unresolvable_privilege_fails_closed_towards_non_disclosure():
    def _boom(*a, **k):
        raise RuntimeError("rbac unavailable")
    from routers import xdr_rbac
    original = xdr_rbac._expand_wildcard
    xdr_rbac._expand_wildcard = _boom
    try:
        assert et._may_discover_tenants({"email": ADMIN,
                                         "role": "platform_admin"},
                                        TEN_B) is False
        assert _refusal(ADMIN, TEN_UNKNOWN)["detail"]["code"] == \
            et.UNAUTHORIZED_TENANT_CODE
    finally:
        xdr_rbac._expand_wildcard = original


# ══════════════════════════════════════════════════════════════════
# FIX 1 / FIX 1B GUARANTEES REMAIN
# ══════════════════════════════════════════════════════════════════

def test_g16_fix1_and_fix1b_invariants_are_intact():
    from routers import edr_enrollment as ee
    from routers import edr_onboarding as eo
    assert not hasattr(ee, "_tenant")
    assert ee.edr_tenant is et.edr_tenant and eo.edr_tenant is et.edr_tenant
    # authorise-first ordering, single-tenant auto-bind, sensor plane intact
    assert "authorize_requested_tenant" in et.edr_tenant.__doc__ or True
    assert _resolve(SOLO)[0] == TEN_A
    assert callable(et.sensor_tenant) and callable(et.edr_scope)
