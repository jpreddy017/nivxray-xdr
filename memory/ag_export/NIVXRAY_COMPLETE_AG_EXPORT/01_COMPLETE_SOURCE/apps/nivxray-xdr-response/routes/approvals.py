"""Approval decision routes.

POST /api/respond/approve/{execution_id}  — resumes a WAITING_APPROVAL execution.
POST /api/respond/reject/{execution_id}   — terminates a WAITING_APPROVAL execution.

Both mutate the EXISTING execution row — the client never re-submits
the request body.  Immutable: once approved OR rejected, the same row
cannot be approved again (returns HTTP 409).
"""
from __future__ import annotations

from typing   import Any, Dict, Optional
from fastapi  import APIRouter, HTTPException, Request
from pydantic import BaseModel

from framework.executor import Executor, ExecutorError


router = APIRouter(tags=["approvals"])


class ApprovalBody(BaseModel):
    approved_by:  str
    approval_ref: Optional[str] = None
    reason:       Optional[str] = None


class RejectionBody(BaseModel):
    rejected_by: str
    reason:      Optional[str] = None


@router.post("/approve/{execution_id}")
async def approve(execution_id: str, body: ApprovalBody, request: Request):
    ex: Executor = request.app.state.executor
    try:
        return await ex.approve(execution_id,
                                     approved_by=body.approved_by,
                                     approval_ref=body.approval_ref,
                                     reason=body.reason)
    except ExecutorError as e:
        raise HTTPException(status_code=e.code,
                                 detail={"error": e.error, **e.detail})


@router.post("/reject/{execution_id}")
def reject(execution_id: str, body: RejectionBody, request: Request):
    ex: Executor = request.app.state.executor
    try:
        return ex.reject(execution_id,
                            rejected_by=body.rejected_by,
                            reason=body.reason)
    except ExecutorError as e:
        raise HTTPException(status_code=e.code,
                                 detail={"error": e.error, **e.detail})


@router.get("/pending-approvals")
def pending_approvals(request: Request, tenant_id: Optional[str] = None):
    """List every execution parked in WAITING_APPROVAL.  Optional
    ``tenant_id`` filter — the caller MUST supply their own tenant
    scoping upstream; this endpoint enforces filtering as a defensive
    second layer."""
    from framework.execution_store import STATE_WAITING_APPROVAL
    rows = request.app.state.store.list_state(STATE_WAITING_APPROVAL, limit=500)
    if tenant_id:
        rows = [r for r in rows if r["tenant_id"] == tenant_id]
    return {"count": len(rows),
             "rows":  [Executor._response_from_row(r) for r in rows]}
