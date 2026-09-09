"""Attack Story Timeline router — POST /api/iue/timeline.

Accepts a batch of Lane A / Lane B / Lane C T2 wire fragments and
returns ONE deterministic reconstructed timeline projection.

Pure projection · no correlation · no inference (owner directive).

Authentication is required (SEC-001 preserved).  Tenancy is inherited
from each lane wire's ``intake_decision.tenant_id``; the router does
not cross-fuse across tenants — a callable helper enforces the invariant.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import get_current_user


router = APIRouter(prefix="/iue/timeline", tags=["iue-timeline"])


class TimelineFuseBody(BaseModel):
    """Batch input for the fuse endpoint.  Each ``lanes[i]`` element
    is a T2 wire dict returned by ``/api/iue/lane-a|b|c/analyze``.
    """
    lanes: List[Dict[str, Any]] = Field(default_factory=list,
                                          description="List of Lane A/B/C wire fragments")


def _reject_cross_tenant(user: Dict[str, Any],
                           lanes: List[Dict[str, Any]]) -> Optional[str]:
    """Return an error string if any lane wire targets a tenant
    different from the caller's identity.  This is the timeline's
    tenant firewall — never fuse evidence across tenants.
    """
    caller_tid = (user or {}).get("tenant_id") \
                    or (user or {}).get("email") \
                    or (user or {}).get("sub")
    if not caller_tid:
        return "caller tenant not resolvable"
    for i, w in enumerate(lanes):
        if not isinstance(w, dict):
            continue
        wire_tid = (w.get("intake_decision") or {}).get("tenant_id") or ""
        if wire_tid and wire_tid != caller_tid:
            return (f"lane[{i}] tenant_id={wire_tid!r} differs from "
                     f"caller tenant_id={caller_tid!r}")
    return None


@router.post("/fuse")
async def fuse(body: TimelineFuseBody,
                user=Depends(get_current_user)):
    """Fuse multiple Lane A/B/C wires into one deterministic timeline."""
    if not body.lanes:
        raise HTTPException(status_code=400,
                              detail={"error": "no_lanes"})
    err = _reject_cross_tenant(user, body.lanes)
    if err:
        raise HTTPException(status_code=403,
                              detail={"error": "cross_tenant_fuse_forbidden",
                                       "reason": err})
    from services.iue.timeline import fuse as _fuse
    return _fuse(body.lanes)
