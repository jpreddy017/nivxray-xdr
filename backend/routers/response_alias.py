"""P0-H · Response route consistency alias.

Sprint 1 · owner-locked closure rule.

The 360° audit found the analyst-facing Response Fabric endpoints
mounted at the internally-consistent but externally-confusing path
    /api/admin/content-supply-chain/response/{...}
instead of the documented intent
    /api/response/{...}

The historical mounting was correct for the content-supply-chain
admin surface, but the response-actions endpoint is analyst-facing
and should live at the intended path.

Rather than move the implementation (risk: breaking every frontend
caller and every audit link in the run history), this module adds
a PARALLEL alias router that exposes the same three endpoints at
the intended `/api/response/*` path.  The handlers delegate to the
existing implementations — one code path, two mount points during
the transition.

When frontend + docs have moved to the new path, the legacy path
can be retired by a future cleanup gate.  For P0-H the acceptance
criterion is that BOTH paths respond identically.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from deps import db
from routers.content_supply_chain import (
    require_admin, response_actions as _legacy_response_actions,
    response_fabric as _legacy_response_fabric,
    response_recompute as _legacy_response_recompute,
)


router = APIRouter(prefix="/response", tags=["response"])


@router.get("/actions")
async def response_actions_alias(user=Depends(require_admin)):
    """Alias for `/api/admin/content-supply-chain/response/actions`.
    Owner-locked P0-H route-consistency fix."""
    return await _legacy_response_actions(user=user)


@router.get("/{incident_id}")
async def response_fabric_alias(incident_id: str,
                                 user=Depends(require_admin)):
    """Alias for `/api/admin/content-supply-chain/response/{id}`."""
    return await _legacy_response_fabric(incident_id, user=user)


@router.post("/{incident_id}/recompute")
async def response_recompute_alias(incident_id: str,
                                    user=Depends(require_admin)):
    """Alias for `/api/admin/content-supply-chain/response/{id}/recompute`."""
    return await _legacy_response_recompute(incident_id, user=user)
