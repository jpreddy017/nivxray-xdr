"""Durable delivery receipts · the collector-facing authority surface.

WHY A SEPARATE SURFACE FROM `/ingest/routing/reconcile`
    That endpoint answers the same question for a HUMAN analyst: it resolves
    tenant scope from a verified console session and may be cross-tenant. A
    collector has no session and no scope navigator — it holds one
    tenant-pinned machine credential. Permanent, automatic reconciliation
    therefore needs a MACHINE surface, and it must be impossible for it to
    widen scope. Both share ONE implementation of the accounting
    (`services.delivery_reconciliation`), so there is exactly one definition
    of what the authoritative plane did with a delivery.

WHAT IT IS
    READ-ONLY. It writes nothing, re-decides nothing and creates no authority.
    It reports, per delivery identity, what the ingest boundary already wrote:
    the idempotency claim, the canonical evidence, the B4 retained raw and the
    routing refusal.

FAIL CLOSED
    · `collectors.enroll` is required (the same permission delivery needs);
    · the tenant is the CREDENTIAL's tenant, resolved by the existing tenant
      authority — never a client header claim, and never cross-tenant;
    · the named collector must exist AND belong to that tenant;
    · every identity must belong to that same collector;
    · a request that cannot be bound to one tenant + one collector is refused
      rather than answered narrowly.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from routers.xdr_ingest import _principal as _machine_principal
from routers.xdr_rbac import require_permission
from services import delivery_reconciliation

router = APIRouter(prefix="/api/xdr/ingest/delivery",
                   tags=["xdr-ingest-delivery"])

COLLECTORS_COLLECTION = "xdr_collectors"

RECEIPT_CONTRACT = "nivx.delivery.receipt/1"


def _db():
    from routers.xdr_ingest_routing import _db as _routing_db
    return _routing_db()


class ReceiptIdentity(BaseModel):
    """One delivery, identified by what the endpoint already holds."""
    ref: str | None = None
    delivery_key: str | None = None
    source_event_id: str | None = None
    collector_id: str | None = None
    connector_id: str | None = None
    payload_digest: str | None = None
    endpoint_outcome: str | None = None


class ReceiptRequest(BaseModel):
    collector_id: str = Field(min_length=1, max_length=128)
    identities: list[ReceiptIdentity]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.post("/receipts",
             dependencies=[Depends(require_permission("collectors.enroll"))])
async def delivery_receipts(body: ReceiptRequest,
                            request: Request) -> dict[str, Any]:
    """The authoritative disposition of a bounded population of deliveries.

    This is the receipt the endpoint needs before it may call anything
    delivered: HTTP 2xx proves the destination accepted a batch, not that
    this delivery was committed and evidenced.
    """
    db = _db()
    if db is None:
        raise HTTPException(503, detail={
            "code": "TELEMETRY_STORE_UNAVAILABLE",
            "reason": "the telemetry store is not bound"})
    tenant, principal, principal_kind = _machine_principal(request)

    collector = db[COLLECTORS_COLLECTION].find_one({"id": body.collector_id})
    if not collector:
        raise HTTPException(404, detail={
            "code": "COLLECTOR_NOT_FOUND",
            "reason": "no such collector"})
    if collector.get("tenant_id") != tenant:
        raise HTTPException(403, detail={
            "code": "TENANT_ISOLATION_VIOLATION",
            "reason": ("the named collector does not belong to the "
                       "authenticated tenant"),
            "credential_tenant": tenant})

    identities: list[dict[str, Any]] = []
    for ident in body.identities:
        row = ident.model_dump()
        claimed = row.get("collector_id")
        if claimed and claimed != body.collector_id:
            raise HTTPException(403, detail={
                "code": "COLLECTOR_IDENTITY_MISMATCH",
                "reason": ("every identity in one receipt request must belong "
                           "to the named collector"),
                "collector_id": body.collector_id,
                "identity_collector_id": claimed})
        row["collector_id"] = body.collector_id
        identities.append(row)

    try:
        result = delivery_reconciliation.reconcile(db, [tenant], identities)
    except delivery_reconciliation.ReconciliationRequestInvalid as ex:
        raise HTTPException(400, detail={
            "code": "RECEIPT_REQUEST_INVALID",
            "reason": str(ex),
            "max_identities": delivery_reconciliation.MAX_IDENTITIES}) from None

    return {
        "contract": RECEIPT_CONTRACT,
        # The binding the endpoint verifies every row against. A receipt that
        # cannot be bound to this tenant and this collector must never be
        # converted into a local success.
        "authority": {
            "tenant_id": tenant,
            "collector_id": body.collector_id,
            "principal_kind": principal_kind,
            "principal_id": principal,
            "at": _now(),
            "read_only": True,
            "basis": "AUTHORITATIVE_RECONCILIATION",
        },
        **result,
    }
