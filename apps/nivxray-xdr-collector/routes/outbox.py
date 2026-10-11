"""
Outbox management routes · Phase B.5.

Read-only + replay endpoints for operators.  Never exposes envelope
credentials (they are stored on the connector, not the outbox).
"""
from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Request


from framework.tenant_scope import tenant_scope

router = APIRouter(tags=["outbox"])


def _outbox(request: Request):
    ob = getattr(request.app.state, "runtime", None)
    return ob.outbox if ob else None


@router.get("/outbox/health")
def outbox_health(request: Request):
    """Ingest + outbox operational health.  This is the single
    endpoint the UI shows on the Integrations dashboard."""
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        raise HTTPException(503, detail={"error": "runtime_not_ready"})
    metrics = runtime.outbox.metrics(tenant_id=tenant_scope(request))
    # Process-wide delivery/worker counters are not tenant measurements.
    return {"state": "not_available", "delivery_health": {},
            "ingest": {"state": "not_available"}, "outbox": metrics,
            "worker": {"state": "not_available"}}


@router.get("/outbox")
def list_outbox(request: Request,
                    status: Optional[str] = Query(default=None),
                    connector_id: Optional[str] = Query(default=None),
                    limit: int = Query(default=100, ge=1, le=1000)):
    ob = _outbox(request)
    if not ob:
        raise HTTPException(503, detail={"error": "runtime_not_ready"})
    rows = ob.list(status=status, connector_id=connector_id, limit=limit,
                   tenant_id=tenant_scope(request))
    return {"envelopes": [{
        "id":              r.id,
        "tenant_id":       r.tenant_id,
        "connector_id":    r.connector_id,
        "source":          r.source,
        "source_event_id": r.source_event_id,
        "status":          r.status,
        "attempts":        r.attempts,
        "next_attempt_at": r.next_attempt_at,
        "last_error":      r.last_error,
        "failure_detail":  r.failure_detail,
        "created_at":      r.created_at,
        "updated_at":      r.updated_at,
    } for r in rows], "count": len(rows)}


@router.get("/outbox/{rid}")
def get_outbox(rid: str, request: Request):
    ob = _outbox(request)
    if not ob:
        raise HTTPException(503, detail={"error": "runtime_not_ready"})
    row = ob.by_id(rid, tenant_id=tenant_scope(request))
    if not row:
        raise HTTPException(404, detail={"error": "envelope_not_found"})
    return {
        "id":               row.id,
        "tenant_id":        row.tenant_id,
        "connector_id":     row.connector_id,
        "source":           row.source,
        "source_event_id":  row.source_event_id,
        "collection_method": row.collection_method,
        "parser_version":   row.parser_version,
        "status":           row.status,
        "attempts":         row.attempts,
        "next_attempt_at":  row.next_attempt_at,
        "last_error":       row.last_error,
        "failure_detail":   row.failure_detail,
        "created_at":       row.created_at,
        "updated_at":       row.updated_at,
        "raw":              row.raw,
        "canonical":        row.canonical,
    }


@router.post("/outbox/{rid}/replay")
def replay_outbox(rid: str, request: Request):
    ob = _outbox(request)
    if not ob:
        raise HTTPException(503, detail={"error": "runtime_not_ready"})
    if ob.by_id(rid, tenant_id=tenant_scope(request)) is None:
        raise HTTPException(404, detail={"error": "envelope_not_found"})
    ok = ob.replay_dead(rid, tenant_id=tenant_scope(request))
    if not ok:
        raise HTTPException(400, detail={"error": "not_dead_letter_or_missing"})
    return {"ok": True, "requeued": rid}


@router.post("/outbox/drain-once")
async def drain_once(request: Request):
    """Operator/test-plane endpoint: force one delivery-worker tick."""
    tenant_scope(request)
    # The worker tick drains every tenant. No tenant-scoped grant authorizes it.
    raise HTTPException(403, detail={"code": "GLOBAL_COLLECTOR_OPERATION_DENIED"})
