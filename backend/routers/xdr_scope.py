"""XDR · authoritative TENANT SCOPE contracts (A0.5-3).

    ScopeSelection is CLIENT INTENT.  EffectiveScope is SERVER TRUTH.
    EffectiveScope = RequestedScope ∩ AuthorizedScope

The browser REQUESTS a scope; this router DETERMINES it. Nothing here is a
new authority: every fact is read from the existing tenant authority
(`services.dashboard_lenses.resolve_tenant_scope` / `_scope`) through
`services.session_context`, which also owns the six authoritative
resolution bases. No second resolver, no second state machine.

Unresolved tenant/scope FAILS CLOSED. There is no default tenant.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import get_current_user as _deps_current_user
from routers.xdr_rbac import console_authorization
from services import session_context as sc

router = APIRouter(prefix="/api/xdr/scope", tags=["xdr-scope"])


class ScopeSelection(BaseModel):
    """What the UI requests. Never authority."""
    kind: str = Field(default="all_authorized",
                      pattern=r"^(tenant|group|all_authorized)$")
    tenant_id: str | None = None
    group_id: str | None = None
    #: Tenant groups are not persisted in this build (A0.5-6). A caller may
    #: name candidate members; they are intersected with the authorized set
    #: and never treated as a grant.
    group_tenant_ids: list[str] = Field(default_factory=list)
    incident_id: str | None = None


@router.get("/authorized")
def authorized_scope(user=Depends(_deps_current_user)):
    """C1 · the scopes this principal may enter, server-resolved."""
    email = (user or {}).get("email")
    if not email:
        raise HTTPException(status_code=403, detail={
            "code": "ACCESS_DENIED", "reason": "unauthenticated",
            "fail_closed": True})
    ctx = sc.tenant_context(email)
    eff = sc.effective_scope(email)
    return {"ok": True, "data": {
        "principal": ctx["principal"],
        "tenants": ctx["customers"],
        "authorized_count": eff["authorized_count"],
        "cross_tenant_role": bool(ctx["tenant_scope"]["all_tenants"]),
        "basis": eff["basis"],
        "basis_label": eff["basis_label"],
        "bases": list(sc.SCOPE_BASES),
        "authority": "server",
        "default_scope": eff,
        # Contract shape only — never fabricated from the case corpus.
        "groups": [],
        "tenant_groups": sc.TENANT_GROUP_CONTRACT,
        "favorites": [],
        "recent": [],
        "note": ("favorites/recent are not persisted in this build; they are "
                 "reported empty rather than invented"),
    }}


@router.post("/select")
def select_scope(body: ScopeSelection, user=Depends(_deps_current_user)):
    """C2 · resolve a requested scope into the authoritative EffectiveScope.

    Returns the INTERSECTION with the authorized set and names every
    denial. A denied or unresolvable scope is a 403, never a substitution.
    """
    email = (user or {}).get("email")
    if not email:
        raise HTTPException(status_code=403, detail={
            "code": "ACCESS_DENIED", "reason": "unauthenticated",
            "fail_closed": True})
    eff = sc.effective_scope(email, kind=body.kind,
                             tenant_id=body.tenant_id,
                             group_tenant_ids=body.group_tenant_ids,
                             incident_id=body.incident_id)
    if not eff.get("authorized"):
        raise HTTPException(status_code=403, detail={
            "code": "SCOPE_NOT_AUTHORIZED", "fail_closed": True, **eff})
    return {"ok": True, "data": eff}


@router.get("/console")
def console_access(user=Depends(_deps_current_user)):
    """A0.5-5 · which consoles the verified principal may enter, and why.

    `console.soc.access` and `console.admin.access` are independent; this
    endpoint reports authority and grants nothing.
    """
    return {"ok": True, "data": console_authorization(user)}
