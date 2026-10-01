"""P0 · TENANT AUTHORITY · FIX 5A — registry enforcement is an INVARIANT.

What this proves
----------------
`services.tenant_registry.authoritative()` asked an environment variable
(`NIVX_TENANT_REGISTRY_ENFORCE`) whether the authoritative registry mattered.
Unset (the documented default) or explicitly `false` turned the canonical
NivXForge EDR tenant authority into a pass-through: an authorized principal
naming an UNREGISTERED or ARCHIVED tenant was accepted, and a missing tenant
became the literal string `"default"`.

Fix 5A removes the security decision from configuration for the EDR path:
`authoritative_required()` reads no flag, accepts no `compat_default`, and
converts a registry dependency failure into a refusal.

EVIDENCE LABELLING — TEST/SYNTHETIC. No credential, no HTTP request, no write.
"""
from __future__ import annotations

import asyncio
import inspect

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from routers import edr_enrollment as ee
from routers import edr_tenancy as et
from services import session_context as sc
from services import tenant_registry as reg

TEN_A = "ten_aaaa000000000000000000aa"
TEN_ARCHIVED = "ten_cccc000000000000000000cc"
TEN_ORPHAN_ORG = "ten_dddd000000000000000000dd"
TEN_UNKNOWN = "ten_not_registered_0000000000"

SOLO = "solo@customer-a.test"
CROSS = "vendor@nivxray.test"

ORG = "org_aaaa000000000000000000aa"
ORG_SUSPENDED = "org_bbbb000000000000000000bb"

_SCOPES = {
    SOLO: {"authorized": True, "all_tenants": False, "tenant_ids": [TEN_A],
           "role": "l2_investigator"},
    CROSS: {"authorized": True, "all_tenants": True, "role": "platform_admin"},
}

_REGISTRY = {
    TEN_A: {"id": TEN_A, "state": "ACTIVE", "organization_id": ORG},
    TEN_ARCHIVED: {"id": TEN_ARCHIVED, "state": "ARCHIVED",
                   "organization_id": ORG},
    TEN_ORPHAN_ORG: {"id": TEN_ORPHAN_ORG, "state": "ACTIVE",
                     "organization_id": ORG_SUSPENDED},
}
_ORGS = {ORG: {"id": ORG, "state": "ACTIVE"},
         ORG_SUSPENDED: {"id": ORG_SUSPENDED, "state": "SUSPENDED"}}


@pytest.fixture(autouse=True)
def _stubs(monkeypatch):
    """Real authority chain, stubbed inputs. The FLAG IS NOT STUBBED."""
    monkeypatch.setattr(sc, "resolve_tenant_scope",
                        lambda email: dict(_SCOPES.get(email or "",
                                                       {"authorized": False})))
    monkeypatch.setattr(reg, "get_tenant", lambda t: _REGISTRY.get(t))
    monkeypatch.setattr(reg, "get_organization", lambda o: _ORGS.get(o))
    from routers import xdr_rbac
    monkeypatch.setattr(xdr_rbac, "_resolve_user_permissions",
                        lambda tenant, email: (set(), "stub:no_assignment"))
    yield


@pytest.fixture(params=["unset", "false", "0", "off", "true"])
def flag(request, monkeypatch):
    """Every configuration of the flag, including absent."""
    if request.param == "unset":
        monkeypatch.delenv("NIVX_TENANT_REGISTRY_ENFORCE", raising=False)
    else:
        monkeypatch.setenv("NIVX_TENANT_REGISTRY_ENFORCE", request.param)
    return request.param


def _request(tenant=None):
    headers = [(b"x-tenant-id", tenant.encode())] if tenant else []
    return Request({"type": "http", "method": "GET",
                    "path": "/api/edr/endpoints", "headers": headers,
                    "query_string": b""})


def _resolve(email, tenant=None):
    role = (_SCOPES.get(email) or {}).get("role")
    return asyncio.run(et.edr_tenant(_request(tenant),
                                     {"email": email, "role": role}))


def _refusal(email, tenant=None):
    with pytest.raises(HTTPException) as ei:
        _resolve(email, tenant)
    return ei.value


# ── A/B/C · the flag cannot reach an EDR authority decision ───────
def test_a_b_c_flag_configuration_cannot_change_edr_authority(flag):
    """Unset, false, off, 0 and true all behave identically for EDR."""
    assert _resolve(SOLO) == TEN_A
    assert _refusal(CROSS, TEN_UNKNOWN).status_code == 403
    assert _refusal(CROSS, TEN_ARCHIVED).status_code == 403


def test_a_flag_unset_still_refuses_unregistered_tenant(monkeypatch):
    monkeypatch.delenv("NIVX_TENANT_REGISTRY_ENFORCE", raising=False)
    assert reg.enforcing() is False          # legacy planes are observational
    assert _refusal(CROSS, TEN_UNKNOWN).detail["code"] == "TENANT_NOT_FOUND"


def test_b_flag_false_still_refuses_unregistered_tenant(monkeypatch):
    monkeypatch.setenv("NIVX_TENANT_REGISTRY_ENFORCE", "false")
    assert reg.enforcing() is False
    assert _refusal(CROSS, TEN_UNKNOWN).detail["code"] == "TENANT_NOT_FOUND"


def test_c_flag_true_refuses_unregistered_tenant(monkeypatch):
    monkeypatch.setenv("NIVX_TENANT_REGISTRY_ENFORCE", "true")
    assert reg.enforcing() is True
    assert _refusal(CROSS, TEN_UNKNOWN).detail["code"] == "TENANT_NOT_FOUND"


# ── D · the authorised, registered, ACTIVE tenant is served ───────
def test_d_registered_active_tenant_with_active_org_succeeds(flag):
    assert _resolve(SOLO) == TEN_A
    assert _resolve(SOLO, TEN_A) == TEN_A
    assert _resolve(CROSS, TEN_A) == TEN_A


# ── E/F/G · every registry deviation is refused ───────────────────
def test_e_unregistered_tenant_is_refused(flag):
    assert _refusal(CROSS, TEN_UNKNOWN).detail["code"] == "TENANT_NOT_FOUND"


def test_f_archived_tenant_is_refused(flag):
    assert _refusal(CROSS, TEN_ARCHIVED).detail["code"] == "TENANT_NOT_ACTIVE"


def test_g_tenant_under_inactive_organization_is_refused(flag):
    e = _refusal(CROSS, TEN_ORPHAN_ORG)
    assert e.detail["code"] == "ORGANIZATION_NOT_ACTIVE"


# ── H · a registry that cannot be consulted is a refusal ──────────
def test_h_registry_lookup_failure_fails_closed(monkeypatch, flag):
    def _boom(_t):
        raise RuntimeError("mongo is gone")
    monkeypatch.setattr(reg, "get_tenant", _boom)
    e = _refusal(CROSS, TEN_A)
    assert e.status_code == 503
    assert e.detail["code"] == reg.REGISTRY_UNAVAILABLE
    # the principal's OWN auto-bound tenant is refused too — never served
    with pytest.raises(HTTPException):
        _resolve(SOLO)


def test_h_organization_lookup_failure_fails_closed(monkeypatch, flag):
    def _boom(_o):
        raise RuntimeError("mongo is gone")
    monkeypatch.setattr(reg, "get_organization", _boom)
    assert _refusal(CROSS, TEN_A).detail["code"] == reg.REGISTRY_UNAVAILABLE


# ── I · no compat default survives on this path ───────────────────
def test_i_authoritative_required_has_no_compat_default():
    params = inspect.signature(reg.authoritative_required).parameters
    assert "compat_default" not in params
    src = inspect.getsource(reg.authoritative_required)
    code = src.replace(reg.authoritative_required.__doc__ or "", "")
    assert "enforcing" not in code
    assert "NIVX_TENANT_REGISTRY_ENFORCE" not in code
    assert "compat_default" not in code
    assert '"default"' not in code


def test_i_empty_tenant_is_refused_not_defaulted(flag):
    with pytest.raises(reg.TenantRegistryError) as ei:
        reg.authoritative_required("", purpose="test")
    assert ei.value.code == "TENANT_REQUIRED"
    with pytest.raises(reg.TenantRegistryError):
        reg.authoritative_required(None, purpose="test")


# ── J · P0-FIX-2 non-disclosure is intact ─────────────────────────
def test_j_non_disclosure_survives_for_unprivileged_principal(flag):
    """Unheld / unregistered / archived stay byte-identical for SOLO."""
    unheld = _refusal(SOLO, "ten_someone_elses_000000000")
    unknown = _refusal(SOLO, TEN_UNKNOWN)
    archived = _refusal(SOLO, TEN_ARCHIVED)
    for e in (unheld, unknown, archived):
        assert e.status_code == 403
        assert e.detail["code"] == et.UNAUTHORIZED_TENANT_CODE
        assert e.detail["disclosure"] == et.DISCLOSURE_NOTE
    # identical apart from the caller's own echoed input
    def _body(e):
        return {k: v for k, v in e.detail.items() if k != "requested_tenant"}
    assert _body(unknown) == _body(archived) == _body(unheld)


def test_j_registry_failure_is_not_a_disclosure_oracle(monkeypatch, flag):
    def _boom(_t):
        raise RuntimeError("mongo is gone")
    monkeypatch.setattr(reg, "get_tenant", _boom)
    e = _refusal(SOLO, TEN_UNKNOWN)
    assert e.status_code == 403
    assert e.detail["code"] == et.UNAUTHORIZED_TENANT_CODE


# ── K/L/M · structure: ONE mandatory EDR resolver ─────────────────
def _code(fn):
    """Executable source only — docstrings may discuss the legacy call."""
    return inspect.getsource(fn).replace(fn.__doc__ or "", "")


def test_k_edr_tenant_uses_authoritative_required():
    code = _code(et.edr_tenant)
    assert "authoritative_required(" in code
    assert "tenant_registry.authoritative(" not in code


def test_l_sensor_tenant_uses_authoritative_required():
    code = _code(et.sensor_tenant)
    assert "authoritative_required(" in code
    assert "tenant_registry.authoritative(" not in code


def test_l_agent_enrolment_resolver_uses_authoritative_required():
    code = _code(ee._agent_tenant)
    assert "authoritative_required(" in code
    assert "tenant_registry.authoritative(" not in code


def test_m_no_edr_module_calls_the_flag_gated_resolver():
    """No second, weaker EDR tenant resolver may exist."""
    import pathlib
    offenders = []
    for path in sorted(pathlib.Path("/app/backend/routers").glob("edr*.py")):
        src = path.read_text()
        for n, line in enumerate(src.splitlines(), 1):
            if "tenant_registry.authoritative(" in line \
                    and not line.strip().startswith("#"):
                offenders.append(f"{path.name}:{n}")
    assert offenders == [], offenders
