"""G1-R5 · Delivery reconciliation endpoint.

Deliberately a SEPARATE router from D21 routing visibility
(`routers/xdr_ingest_routing.py`), which holds a hard architectural contract:
that surface exposes GET only, so no endpoint on it can alter a routing
decision. This reconciliation call is semantically a read — it writes nothing
and re-decides nothing — but it takes a BODY, because a bounded population of
up to 500 delivery identities does not belong in a URL. Keeping it in its own
router preserves the D21 contract literally instead of weakening it.

Tenant authority, scope resolution and the read-only note are reused from the
D21 module rather than redefined, so there is exactly one implementation of
"which tenants may this principal see".
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from routers.xdr_ingest_routing import TenantScope, _db, _ensure_indexes
from routers.xdr_ingest_routing import _scope as _routing_scope
from services import delivery_reconciliation

router = APIRouter(prefix="/api/xdr/ingest/routing",
                   tags=["xdr-ingest-routing"])


class ReconcileIdentity(BaseModel):
    """One collector delivery, identified by what the collector already holds."""
    ref: str | None = None
    delivery_key: str | None = None
    source_event_id: str | None = None
    collector_id: str | None = None
    connector_id: str | None = None
    payload_digest: str | None = None
    endpoint_outcome: str | None = None


class ReconcileRequest(BaseModel):
    identities: list[ReconcileIdentity]


@router.post("/reconcile")
async def reconcile_deliveries(
        body: ReconcileRequest,
        scope: TenantScope = Depends(_routing_scope)) -> dict[str, Any]:
    """What did the authoritative plane ACTUALLY do with these deliveries?

    READ-ONLY. It reads the idempotency claim, the raw row, the canonical
    evidence, the refusal record and the B4 retained raw that the ingest
    boundary already wrote, and reports one accounting bucket per delivery. It
    exists because HTTP 2xx at the collector proves acceptance by the
    destination and NOT canonical ingestion: an accepted batch can still
    contain a routing refusal, a B4 retention or a duplicate suppression.
    """
    if _db() is None:
        raise HTTPException(503, detail={
            "code": "TELEMETRY_STORE_UNAVAILABLE",
            "reason": "the telemetry store is not bound"})
    _ensure_indexes()
    tenant_ids = None if scope.all_tenants else list(scope.tenant_ids)
    try:
        result = delivery_reconciliation.reconcile(
            _db(), tenant_ids, [i.model_dump() for i in body.identities])
    except delivery_reconciliation.ReconciliationRequestInvalid as ex:
        raise HTTPException(400, detail={
            "code": "RECONCILIATION_REQUEST_INVALID",
            "reason": str(ex),
            "max_identities": delivery_reconciliation.MAX_IDENTITIES})
    return {"tenant_scope": scope.describe(), **result}
