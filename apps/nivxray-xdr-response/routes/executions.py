"""Executions read + reversal routes."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException, Request

router = APIRouter(tags=["executions"])


@router.get("/executions/{execution_id}")
def get_execution(execution_id: str, request: Request, tenant_id: str,
                     invoker_kind: str, invoker_id: str):
    """Fetch a prior execution by (tenant, invoker_kind, invoker_id, execution_id).
    All four are required — an execution_id alone is not unique across invokers."""
    row = request.app.state.idempotency.find(tenant_id, invoker_kind,
                                                    invoker_id, execution_id)
    if not row:
        raise HTTPException(404, detail={"error": "execution_not_found"})
    return row["response"]
