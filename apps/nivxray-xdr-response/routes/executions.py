"""Executions read route."""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, HTTPException, Request

from framework.executor import Executor

router = APIRouter(tags=["executions"])


@router.get("/executions/{execution_id}")
def get_execution(execution_id: str, request: Request,
                     tenant_id: Optional[str] = None,
                     invoker_kind: Optional[str] = None,
                     invoker_id: Optional[str] = None):
    """Fetch a prior execution.  If ``tenant_id`` + ``invoker_kind`` +
    ``invoker_id`` are provided, uses the full idempotency key (strict
    tenant isolation).  Otherwise falls back to execution_id lookup —
    used by approval routes where the client only carries an id."""
    store = request.app.state.store
    if tenant_id and invoker_kind and invoker_id:
        row = store.find(tenant_id, invoker_kind, invoker_id, execution_id)
    else:
        row = store.find_by_execution_id(execution_id)
    if not row:
        raise HTTPException(404, detail={"error": "execution_not_found"})
    return Executor._response_from_row(row)
