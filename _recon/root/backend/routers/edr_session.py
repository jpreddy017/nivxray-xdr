"""NivXForge EDR · explicit customer-context switch (P0-FIX-6B-2).

Authorization for a tenant-bound request already happens on EVERY route
through `edr_tenant()`. What did NOT exist was a record of the *transition*:
a multi-customer CUSTOMER principal or the PLATFORM Super Admin moved between
customers by changing a browser value, and the server recorded nothing.

This route adds the attribution, not the authority. It depends on
`edr_tenant`, so the identical chain runs first —

    verified principal
      → authorize_requested_tenant()          (grants / PLATFORM scope)
      → tenant_registry.authoritative_required()  (registered · ACTIVE · ACTIVE org)
      → the tenant this request acts in

— and a refusal is produced by that dependency with the Fix 2 non-disclosure
semantics intact (refusals are already audited as
`ACCESS_DENIED`/`tenant_scope`). Only a SUCCESS reaches this handler, where it
is written to the existing append-only `xdr_audit_log` chain as
`TENANT_CONTEXT_SWITCHED`. No new audit store, no new authority.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Request
from pymongo import DESCENDING

from deps import get_current_user, sync_collection
from routers.edr_tenancy import edr_tenant
from routers.xdr_audit_log import emit_audit
from services.dashboard_lenses import resolve_tenant_scope

router = APIRouter(prefix="/edr/session", tags=["nivxforge-edr-session"])

SWITCH_ACTION = "TENANT_CONTEXT_SWITCHED"
#: The server keeps no session-side "current tenant"; the previous context is
#: read back from the audit chain itself. When the chain holds nothing for
#: this principal, that is stated rather than invented.
PREVIOUS_UNKNOWN = "NOT_AVAILABLE"


def _previous_context(principal: str) -> Optional[str]:
    coll = sync_collection("xdr_audit_log")
    if coll is None:
        return None
    last = coll.find_one({"principal_id": principal, "action": SWITCH_ACTION},
                         sort=[("at", DESCENDING)])
    return ((last or {}).get("after") or {}).get("tenant_id")


@router.post("/active-tenant")
async def set_active_tenant(
        request: Request,
        tenant: str = Depends(edr_tenant),
        user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Record the customer context this principal is now operating in.

    The tenant comes from `X-Tenant-Id` via `edr_tenant`, so it is already
    authorized, registered, ACTIVE and inside an ACTIVE organization. A repeat
    of the SAME context is not a switch and writes no second audit row.
    """
    principal = (user or {}).get("email") or (user or {}).get("sub")
    scope = resolve_tenant_scope(principal)
    basis = getattr(request.state, "tenant_resolution_basis", None)
    previous = _previous_context(principal)

    if previous == tenant:
        return {"ok": True, "tenant_id": tenant, "basis": basis,
                "authority_scope": scope.get("authority_scope"),
                "authority": "server", "switch_recorded": False,
                "reason": "NO_CONTEXT_CHANGE"}

    event = emit_audit(
        tenant_id=tenant,
        principal_id=str(principal),
        principal_kind="user",
        action=SWITCH_ACTION,
        resource_kind="tenant_context",
        resource_id=tenant,
        outcome="SUCCESS",
        before={"tenant_id": previous or PREVIOUS_UNKNOWN},
        after={"tenant_id": tenant},
        correlation_id=getattr(request.state, "trace_id", None),
        source="nivxforge-edr",
        metadata={"authority_scope": scope.get("authority_scope"),
                  "basis": basis,
                  "requested_tenant": request.headers.get("X-Tenant-Id"),
                  "role": scope.get("role")})
    return {"ok": True, "tenant_id": tenant, "basis": basis,
            "authority_scope": scope.get("authority_scope"),
            "authority": "server", "switch_recorded": True,
            "previous_tenant_id": previous or PREVIOUS_UNKNOWN,
            "audit_ref": event.get("id")}
