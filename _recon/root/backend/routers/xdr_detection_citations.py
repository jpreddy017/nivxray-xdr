"""D8 · read-only detection citations.

One GET. It returns the citations **as persisted by the detection engine** and
does not recompute, reconstruct or guess anything at read time — if the
pipeline did not record a condition, this endpoint will not invent it.

PARALLEL-WORK BOUNDARY (owner instruction, 2026-09-14): no authentication,
JWT/tenant-binding, RBAC, collector-security or response-security code is
modified here. This module only CONSUMES two existing, unmodified
dependencies:

  · ``require_permission("detections.read")`` — the existing RBAC gate.
  · ``deps.get_current_user``                 — the existing verified-JWT
                                                identity.

Authorization scope is taken from the AUTHENTICATED principal record, never
from a caller-supplied ``X-Tenant-Id``. A ``tenant`` query parameter is
accepted only from a cross-tenant ``admin`` role, and even then it is a
FILTER applied inside an already-authorized scope — it can never widen it.

This is a preview inspection surface: JWT principals only. A machine API key
has no reason to read citations, and ``get_current_user`` will reject one.
"""
from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pymongo import MongoClient

from deps import get_current_user
from routers.xdr_rbac import require_permission

router = APIRouter(prefix="/api/xdr/detections", tags=["xdr-detections"])

_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME = os.environ.get("DB_NAME") or "test_database"
_client = MongoClient(_MONGO_URL) if _MONGO_URL else None
COLLECTION = "xdr_detection_matches"


def _c():
    return _client[_DB_NAME][COLLECTION] if _client is not None else None


def _scope(user: dict[str, Any], tenant: str | None) -> dict[str, Any]:
    """Resolve the authorized query scope from the AUTHENTICATED user."""
    role = (user or {}).get("role")
    if role == "admin":
        # Cross-tenant role. `tenant` narrows the result set; it cannot
        # grant anything, because the role already spans every tenant.
        return {"tenant_id": tenant} if tenant else {}
    own = (user or {}).get("tenant_id")
    if not own:
        raise HTTPException(403, detail={
            "code": "ACCESS_DENIED",
            "reason": "principal has no tenant scope"})
    if tenant and tenant != own:
        # Asking for someone else's tenant is refused outright rather than
        # silently downgraded to your own, so a probe cannot be mistaken
        # for an empty result.
        raise HTTPException(403, detail={
            "code": "TENANT_ISOLATION_VIOLATION",
            "reason": "a tenant-scoped principal may only read its own "
                      "tenant's citations",
            "authorized_tenant": own,
            "requested_tenant": tenant})
    return {"tenant_id": own}


def _shape(doc: dict[str, Any]) -> dict[str, Any]:
    """Project the PERSISTED record. No recomputation, no defaults."""
    return {
        "rule_id":              doc.get("rule_id"),
        "rule_version":         doc.get("rule_version"),
        "rule_name":            doc.get("rule_name"),
        "engine_id":            doc.get("engine_id"),
        "rule_result":          doc.get("rule_result"),
        "canonical_event_id":   doc.get("canonical_event_id"),
        "evidence_ref":         doc.get("evidence_ref"),
        "raw_ref":              doc.get("raw_ref"),
        "trace_id":             doc.get("trace_id"),
        "tenant_id":            doc.get("tenant_id"),
        "trust_state":          doc.get("trust_state"),
        "source":               doc.get("source"),
        "severity":             doc.get("severity"),
        "confidence":           doc.get("confidence"),
        "mitre_attack":         doc.get("mitre_attack") or [],
        "declaration_state":    doc.get("declaration_state"),
        "citation_completeness": doc.get("citation_completeness"),
        "evaluated_conditions": doc.get("evaluated_conditions") or [],
        "matched_conditions":   doc.get("matched_conditions") or [],
        "unmatched_conditions": doc.get("unmatched_conditions") or [],
        "telemetry_requirements": doc.get("telemetry_requirements") or [],
        "evaluated_at":         doc.get("evaluated_at"),
    }


@router.get("/{event_id}/citations",
            dependencies=[Depends(require_permission("detections.read"))])
async def get_citations(event_id: str,
                        tenant: str | None = Query(default=None),
                        user: dict = Depends(get_current_user)):
    """Citations persisted for one canonical event. Read-only."""
    if _c() is None:
        raise HTTPException(503, detail="storage unavailable")
    q = {**_scope(user, tenant), "canonical_event_id": event_id}
    docs = list(_c().find(q, {"_id": 0}))
    if not docs:
        # A citation that exists in another tenant is indistinguishable from
        # one that does not exist at all — the response must not reveal which.
        raise HTTPException(404, detail={
            "code": "NOT_FOUND",
            "reason": "no citations are recorded for this canonical event "
                      "within the authorized scope",
            "canonical_event_id": event_id})
    return {"ok": True, "data": {
        "canonical_event_id": event_id,
        "count": len(docs),
        "citations": [_shape(d) for d in docs],
        "note": ("Returned verbatim as persisted at evaluation time. "
                 "Nothing is recomputed at read time: an absent condition "
                 "means the engine did not record one."),
    }}
