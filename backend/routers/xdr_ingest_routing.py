"""D21 · Routing visibility — a READ-ONLY window over decisions already made.

This router creates NO authority. Every field it returns was decided at the
authenticated ingest boundary (D15) and persisted there:

    accepted deliveries → ``xdr_canonical_evidence.provenance.routing``
                           (the decision travels with the evidence it produced)
    refused deliveries  → ``xdr_ingest_routing_blocks.routing``
                           (a refusal produces no evidence, so it is kept apart)

Nothing is recomputed here, nothing is re-decided, and there is no endpoint
that can alter routing: the module exposes GET only. If a value was never
observed it is reported as ``null`` with the reason, never back-filled from a
neighbouring field.

Tenant scope is derived from the AUTHENTICATED principal only
(``deps.get_current_user`` → ``services.dashboard_lenses.resolve_tenant_scope``,
the same authority the incident plane uses). ``X-Tenant-Id`` is ignored
outright on this surface, and ``?tenant_id=`` is honoured only for a
cross-tenant role — a tenant-scoped principal that asks for another tenant is
answered with its own scope and told that the request was ignored.
"""
from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pymongo import DESCENDING, MongoClient

from deps import get_current_user
from services import raw_forensic_retention as raw_retention
from services import source_routing
from services.dashboard_lenses import resolve_tenant_scope

router = APIRouter(prefix="/api/xdr/ingest/routing", tags=["xdr-ingest-routing"])

_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME = os.environ.get("DB_NAME") or "test_database"
_client = MongoClient(_MONGO_URL) if _MONGO_URL else None

_EVIDENCE = "xdr_canonical_evidence"
_BLOCKS = "xdr_ingest_routing_blocks"
#: B4 · retained forensic raw for AUTHORIZED deliveries refused before
#: interpretation. Explicitly NOT canonical evidence.
_RETAINED = raw_retention.COLLECTION

_READ_ONLY_NOTE = (
    "read-only projection of decisions made at the authenticated ingest "
    "boundary; this surface is not a routing authority and cannot alter a "
    "decision")
_INDEXED = False


def _db():
    return _client[_DB_NAME] if _client is not None else None


def _ensure_indexes() -> None:
    global _INDEXED
    if _INDEXED or _db() is None:
        return
    _db()[_BLOCKS].create_index([("tenant_id", 1), ("at", DESCENDING)])
    _db()[_EVIDENCE].create_index(
        [("tenant_id", 1), ("ingest_time", DESCENDING)])
    _db()[_RETAINED].create_index(
        [("tenant_id", 1), ("first_seen_at", DESCENDING)])
    # G1-R5 · reconciliation looks a refusal up by the delivery identity the
    # collector holds, so that lookup gets an index too.
    _db()[_BLOCKS].create_index([("tenant_id", 1), ("source_event_id", 1)])
    _db()[_RETAINED].create_index([("tenant_id", 1), ("source_event_id", 1)])
    _INDEXED = True


# ── tenant scope · from the authenticated principal, never a header ──
class TenantScope:
    def __init__(self, scope: dict[str, Any], requested: str | None):
        self.all_tenants = bool(scope.get("all_tenants"))
        self.tenant_ids: list[str] = list(scope.get("tenant_ids") or [])
        self.role = scope.get("role")
        self.requested = requested
        self.requested_honoured = False
        self.requested_ignored_reason: str | None = None
        if requested:
            if self.all_tenants:
                self.requested_honoured = True
                self.tenant_ids = [requested]
                self.all_tenants = False
            elif requested in self.tenant_ids:
                self.requested_honoured = True
                self.tenant_ids = [requested]
            else:
                self.requested_ignored_reason = (
                    "the authenticated principal is not authorized for the "
                    "requested tenant; its own scope was used instead")

    def filter(self) -> dict[str, Any]:
        if self.all_tenants:
            return {}
        if not self.tenant_ids:
            return {"tenant_id": {"$in": []}}
        return {"tenant_id": {"$in": self.tenant_ids}}

    def describe(self) -> dict[str, Any]:
        return {
            "basis": ("CROSS_TENANT_ROLE" if self.all_tenants
                      else "AUTHENTICATED_PRINCIPAL_TENANT"),
            "role": self.role,
            "tenant_ids": None if self.all_tenants else self.tenant_ids,
            "requested_tenant_id": self.requested,
            "requested_tenant_id_honoured": self.requested_honoured,
            "requested_tenant_id_ignored_reason": self.requested_ignored_reason,
            "header_note": ("X-Tenant-Id is ignored on this surface; scope "
                            "comes from the verified session only"),
        }


async def _scope(user: dict = Depends(get_current_user),
                 tenant_id: str | None = Query(
                     None, description="cross-tenant roles only; ignored for "
                                       "a tenant-scoped principal")
                 ) -> TenantScope:
    return TenantScope(resolve_tenant_scope((user or {}).get("email")),
                       tenant_id)


# ── row projection ───────────────────────────────────────────────
def _relationship(routing: dict[str, Any]) -> str:
    authorized = routing.get("collector_authorized_sources")
    resolved = routing.get("declared_source_resolved")
    if authorized is None:
        return "NOT_APPLICABLE_NO_AUTHENTICATED_COLLECTOR"
    if not routing.get("declared_source"):
        return "NO_DECLARATION_MADE"
    if resolved is None:
        return "DECLARED_SOURCE_NOT_IN_CATALOG"
    return ("DECLARED_SOURCE_IN_COLLECTOR_ALLOWLIST" if resolved in authorized
            else "DECLARED_SOURCE_NOT_IN_COLLECTOR_ALLOWLIST")


def _routing_fields(routing: dict[str, Any]) -> dict[str, Any]:
    return {
        "routing_result": routing.get("routing_result"),
        "routing_authority": routing.get("routing_authority"),
        "declared_source": routing.get("declared_source"),
        "declared_source_resolved": routing.get("declared_source_resolved"),
        "collector_authorized_sources": routing.get(
            "collector_authorized_sources"),
        "authorization_relationship": _relationship(routing),
        "selected_dsm_id": routing.get("selected_dsm_id"),
        "content_compatible": routing.get("content_compatible"),
        "content_recognized_as": routing.get("content_recognized_as"),
        "declared_format_recognized": routing.get(
            "declared_format_recognized"),
        "raw_retention_eligible": routing.get("raw_retention_eligible"),
        "reason_code": routing.get("mismatch_reason"),
        "reason": routing.get("reason"),
    }


def _accepted_row(doc: dict[str, Any]) -> dict[str, Any]:
    prov = doc.get("provenance") or {}
    routing = prov.get("routing") or {}
    ingest = prov.get("ingest") or {}
    stamps = prov.get("timestamps") or {}
    received = (stamps.get("nivx_received_at") or {}).get("value")
    return {
        "delivery": "ACCEPTED",
        "at": received or doc.get("ingest_time"),
        "at_basis": ("provenance.timestamps.nivx_received_at" if received
                     else "canonical.ingest_time"),
        "tenant_id": doc.get("tenant_id"),
        "collector_id": ingest.get("collector_id") or prov.get("collector_id"),
        "collector_id_basis": ingest.get("collector_id_source")
        or "canonical provenance",
        "payload_shape": ingest.get("payload_shape"),
        "declared_payload_format": ingest.get("declared_payload_format"),
        "collection_method": ingest.get("collection_method"),
        "source_event_id": None,
        "source_event_id_basis": (
            "NOT_CARRIED_INTO_CANONICAL_EVIDENCE — the collector's own event "
            "id is not persisted on the evidence row; the evidence ref and "
            "trace id identify this delivery"),
        "trace_id": prov.get("trace_id"),
        "evidence_ref": f"{_EVIDENCE}/{doc.get('event_id')}",
        "evidence_ref_absent_reason": None,
        "raw_envelope_ref": ingest.get("raw_envelope_ref"),
        "payload_keys": None,
        "payload_excerpt": None,
        "retained_raw_id": None,
        "raw_retention": {
            "state": "NOT_APPLICABLE",
            "reason": ("this delivery was ACCEPTED, so its raw row and "
                       "canonical evidence exist on the normal path")},
        **_routing_fields(routing),
    }


def _blocked_row(doc: dict[str, Any]) -> dict[str, Any]:
    routing = doc.get("routing") or {}
    result = routing.get("routing_result") or "BLOCKED"
    return {
        "delivery": result,
        "at": doc.get("nivx_received_at") or doc.get("at"),
        "at_basis": ("ingest handler receipt instant" if
                     doc.get("nivx_received_at") else "block record written_at"),
        "tenant_id": doc.get("tenant_id"),
        "collector_id": doc.get("collector_id"),
        "collector_id_basis": ("authenticated collector, verified against "
                               "xdr_collectors.tenant_id"),
        "payload_shape": doc.get("payload_shape"),
        "declared_payload_format": doc.get("declared_payload_format"),
        "collection_method": doc.get("collection_method"),
        "source_event_id": doc.get("source_event_id"),
        "source_event_id_basis": "collector-supplied envelope.source_event_id",
        "trace_id": doc.get("trace_id"),
        "evidence_ref": None,
        "evidence_ref_absent_reason": doc.get("honesty_note"),
        "raw_envelope_ref": None,
        "payload_keys": doc.get("payload_keys"),
        "payload_excerpt": doc.get("payload_excerpt"),
        #: B4 · the bridge to the verbatim evidence behind this refusal.
        "retained_raw_id": doc.get("retained_raw_id"),
        "raw_retention": doc.get("raw_retention") or {
            "state": "NOT_RECORDED",
            "reason": ("this refusal predates B4 raw forensic retention, so "
                       "no raw record was kept for it")},
        **_routing_fields(routing),
    }


# ── filters · allow-listed, built server-side ────────────────────
_LIMIT_MAX = 200


def _apply_filters(base: dict[str, Any], prefix: str, *, reason_code,
                   declared_source, selected_dsm_id,
                   routing_authority, since, until,
                   time_field: str) -> dict[str, Any]:
    q = dict(base)
    if reason_code:
        q[f"{prefix}mismatch_reason"] = reason_code
    if declared_source:
        q[f"{prefix}declared_source_resolved"] = declared_source
    if selected_dsm_id:
        q[f"{prefix}selected_dsm_id"] = selected_dsm_id
    if routing_authority:
        q[f"{prefix}routing_authority"] = routing_authority
    window: dict[str, Any] = {}
    if since:
        window["$gte"] = since
    if until:
        window["$lte"] = until
    if window:
        q[time_field] = window
    return q


@router.get("/deliveries")
async def list_deliveries(
        scope: TenantScope = Depends(_scope),
        result: str | None = Query(None, description="ACCEPTED | BLOCKED | "
                                                     "NOT_EVALUATED"),
        reason_code: str | None = None,
        collector_id: str | None = None,
        declared_source: str | None = None,
        selected_dsm_id: str | None = None,
        routing_authority: str | None = None,
        since: str | None = Query(None, description="ISO-8601 lower bound"),
        until: str | None = Query(None, description="ISO-8601 upper bound"),
        limit: int = Query(50, ge=1, le=_LIMIT_MAX),
) -> dict[str, Any]:
    """Last-N routing decisions for the authenticated scope, newest first."""
    if _db() is None:
        return {"rows": [], "count": 0,
                "unavailable": "telemetry store unavailable",
                "read_only_note": _READ_ONLY_NOTE}
    _ensure_indexes()
    tf = scope.filter()
    want = (result or "").strip().upper() or None
    rows: list[dict[str, Any]] = []

    if want in (None, "ACCEPTED"):
        q = _apply_filters({**tf, "provenance.routing": {"$exists": True},
                            "provenance.routing.routing_result": "ACCEPTED"},
                           "provenance.routing.",
                           reason_code=reason_code,
                           declared_source=declared_source,
                           selected_dsm_id=selected_dsm_id,
                           routing_authority=routing_authority,
                           since=since, until=until,
                           time_field="ingest_time")
        if collector_id:
            q["provenance.ingest.collector_id"] = collector_id
        rows += [_accepted_row(d) for d in
                 _db()[_EVIDENCE].find(q).sort("ingest_time",
                                               DESCENDING).limit(limit)]

    if want in (None, "BLOCKED", "NOT_EVALUATED"):
        q = _apply_filters({**tf}, "routing.",
                           reason_code=reason_code,
                           declared_source=declared_source,
                           selected_dsm_id=selected_dsm_id,
                           routing_authority=routing_authority,
                           since=since, until=until, time_field="at")
        if collector_id:
            q["collector_id"] = collector_id
        if want:
            q["routing.routing_result"] = want
        rows += [_blocked_row(d) for d in
                 _db()[_BLOCKS].find(q).sort("at", DESCENDING).limit(limit)]

    rows.sort(key=lambda r: str(r.get("at") or ""), reverse=True)
    rows = rows[:limit]
    return {
        "tenant_scope": scope.describe(),
        "filters_applied": {"result": want, "reason_code": reason_code,
                            "collector_id": collector_id,
                            "declared_source": declared_source,
                            "selected_dsm_id": selected_dsm_id,
                            "routing_authority": routing_authority,
                            "since": since, "until": until, "limit": limit},
        "count": len(rows),
        "rows": rows,
        "sources": {"accepted": f"{_EVIDENCE}.provenance.routing",
                    "refused": f"{_BLOCKS}.routing"},
        "read_only_note": _READ_ONLY_NOTE,
    }


@router.get("/retained-raw")
async def list_retained_raw(
        scope: TenantScope = Depends(_scope),
        reason_code: str | None = Query(
            None, description="SOURCE_RECORD_NOT_SUPPORTED | "
                              "SOURCE_FORMAT_MISMATCH | "
                              "SOURCE_DSM_UNAVAILABLE"),
        collector_id: str | None = None,
        declared_source: str | None = None,
        event_id: str | None = Query(None, description="Windows EventID, "
                                                       "when one was "
                                                       "extractable"),
        channel: str | None = None,
        since: str | None = Query(None, description="ISO-8601 lower bound"),
        until: str | None = Query(None, description="ISO-8601 upper bound"),
        limit: int = Query(50, ge=1, le=_LIMIT_MAX),
        offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """B4 · retained forensic raw for the authenticated scope, metadata only.

    Bounded and paginated, and never a global enumeration: the tenant filter
    comes from the verified session, so a principal can only ever see its own
    tenants' evidence. The verbatim raw is NOT in this response — fetch a
    record by its `retained_raw_id` to read it.
    """
    if _db() is None:
        return {"rows": [], "count": 0,
                "unavailable": "telemetry store unavailable",
                "read_only_note": _READ_ONLY_NOTE}
    _ensure_indexes()
    q: dict[str, Any] = {**scope.filter()}
    if reason_code:
        q["disposition.mismatch_reason"] = reason_code
    if collector_id:
        q["collector_id"] = collector_id
    if declared_source:
        q["declared_source_resolved"] = declared_source
    if event_id:
        q["record_hints.event_id"] = str(event_id)
    if channel:
        q["record_hints.channel"] = channel
    window: dict[str, Any] = {}
    if since:
        window["$gte"] = since
    if until:
        window["$lte"] = until
    if window:
        q["first_seen_at"] = window

    cursor = (_db()[_RETAINED].find(q)
              .sort("first_seen_at", DESCENDING)
              .skip(offset).limit(limit))
    rows = [raw_retention.metadata_row(d) for d in cursor]
    return {
        "tenant_scope": scope.describe(),
        "filters_applied": {"reason_code": reason_code,
                            "collector_id": collector_id,
                            "declared_source": declared_source,
                            "event_id": event_id, "channel": channel,
                            "since": since, "until": until,
                            "limit": limit, "offset": offset},
        "count": len(rows),
        "total": _db()[_RETAINED].count_documents(q),
        "rows": rows,
        "source": _RETAINED,
        "evidence_contract": {
            "retained_raw_is_canonical_evidence": False,
            "invariant": ("RAW RETAINED != PARSED != NORMALIZED != "
                          "EVALUATED != DETECTED"),
        },
        "read_only_note": _READ_ONLY_NOTE,
    }


@router.get("/retained-raw/{retained_raw_id}")
async def get_retained_raw(retained_raw_id: str,
                           scope: TenantScope = Depends(_scope)
                           ) -> dict[str, Any]:
    """B4 · one retained forensic record, verbatim raw included.

    Fails closed on tenant isolation: a record belonging to another tenant is
    answered exactly like a record that does not exist, so the surface never
    confirms the existence of evidence outside the caller's authority.
    """
    if _db() is None:
        raise HTTPException(503, detail="telemetry store unavailable")
    _ensure_indexes()
    doc = _db()[_RETAINED].find_one({"id": retained_raw_id,
                                     **scope.filter()})
    if not doc:
        raise HTTPException(404, detail={
            "code": "RETAINED_RAW_NOT_FOUND",
            "reason": ("no retained raw record with this id exists inside "
                       "the authenticated tenant scope"),
            "tenant_scope": scope.describe()})
    return {"tenant_scope": scope.describe(),
            "row": raw_retention.full_row(doc),
            "read_only_note": _READ_ONLY_NOTE}


@router.get("/summary")
async def routing_summary(
        scope: TenantScope = Depends(_scope),
        since: str | None = None,
        until: str | None = None,
) -> dict[str, Any]:
    """Counts for the authenticated scope. Accepted and refused are counted
    from the two places they actually live — never inferred from each other."""
    if _db() is None:
        return {"unavailable": "telemetry store unavailable",
                "read_only_note": _READ_ONLY_NOTE}
    _ensure_indexes()
    tf = scope.filter()
    window: dict[str, Any] = {}
    if since:
        window["$gte"] = since
    if until:
        window["$lte"] = until

    acc_q: dict[str, Any] = {**tf,
                             "provenance.routing.routing_result": "ACCEPTED"}
    blk_q: dict[str, Any] = {**tf}
    if window:
        acc_q["ingest_time"] = window
        blk_q["at"] = window

    def _group(coll: str, q: dict[str, Any], field: str) -> dict[str, int]:
        pipeline = [{"$match": q}, {"$group": {"_id": f"${field}",
                                               "n": {"$sum": 1}}},
                    {"$sort": {"n": -1}}, {"$limit": 50}]
        return {str(r["_id"]): r["n"] for r in
                _db()[coll].aggregate(pipeline) if r["_id"] is not None}

    return {
        "tenant_scope": scope.describe(),
        "window": {"since": since, "until": until},
        "accepted": {
            "total": _db()[_EVIDENCE].count_documents(acc_q),
            "by_declared_source": _group(
                _EVIDENCE, acc_q, "provenance.routing.declared_source_resolved"),
            "by_selected_dsm": _group(
                _EVIDENCE, acc_q, "provenance.routing.selected_dsm_id"),
            "by_routing_authority": _group(
                _EVIDENCE, acc_q, "provenance.routing.routing_authority"),
        },
        "refused": {
            "total": _db()[_BLOCKS].count_documents(blk_q),
            "by_reason_code": _group(_BLOCKS, blk_q,
                                     "routing.mismatch_reason"),
            "by_result": _group(_BLOCKS, blk_q, "routing.routing_result"),
            "by_collector": _group(_BLOCKS, blk_q, "collector_id"),
        },
        "honesty_note": (
            "a refused delivery produced no raw row and no canonical "
            "evidence, so refusals are counted from the refusal record and "
            "never subtracted from accepted counts"),
        "read_only_note": _READ_ONLY_NOTE,
    }


@router.get("/catalog")
async def routing_catalog(scope: TenantScope = Depends(_scope)
                          ) -> dict[str, Any]:
    """The declarable source catalog and the refusal vocabulary, verbatim
    from the ingest authority module — restated here, never redefined."""
    return {"tenant_scope": scope.describe(),
            **source_routing.catalog(),
            "read_only_note": _READ_ONLY_NOTE}
