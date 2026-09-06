"""
XDR Ingest Telemetry — P0-8 · Evidence-Backed CONNECTED gate.

This is the ONLY code path that may transition a collector to
``CONNECTED``.  It exists specifically so the state machine cannot be
lied to by the admin surface, a test button, or a UI toggle.

Contract (owner-locked):
    Collector receives raw event
       ↓
    Parser succeeds
       ↓
    Normalization succeeds
       ↓
    POST /api/xdr/ingest/telemetry  (this endpoint)
       ↓  atomic counter increment
       ↓  transition to CONNECTED IFF received > 0 AND parsed > 0
       ↓                            AND normalized > 0
       ↓  (any failure demotes to PARSE_ERROR / DEGRADED honestly)

Bearer-key protection (in addition to the P0-1 RBAC dependency):
The forwarder (nivxray-xdr-collector) authenticates with a scoped
API key that carries ``collectors.enroll`` — enforced via
``require_permission``.

Storage: updates in place on ``xdr_collectors`` and ``xdr_data_sources``.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from pymongo import MongoClient

from routers.xdr_audit_log import emit_audit
from routers.xdr_rbac import require_permission

router = APIRouter(prefix="/api/xdr/ingest", tags=["xdr-ingest"])


# ── Mongo binding ─────────────────────────────────────────────────
_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME   = os.environ.get("DB_NAME") or "test_database"
_client    = MongoClient(_MONGO_URL) if _MONGO_URL else None


def _db():
    return _client[_DB_NAME] if _client is not None else None


def _c_collectors():
    return _db()["xdr_collectors"] if _db() is not None else None


def _c_data_sources():
    return _db()["xdr_data_sources"] if _db() is not None else None


def _c_events():
    return _db()["xdr_canonical_events"] if _db() is not None else None


def _principal(req: Request) -> tuple[str, str, str]:
    ten = (req.headers.get("X-Tenant-Id")
                or getattr(req.state, "tenant_id", None) or "default")
    pid = (req.headers.get("X-Principal-Id")
                or getattr(req.state, "principal_id", None) or "system@ingest")
    pkd = (req.headers.get("X-Principal-Kind")
                or getattr(req.state, "principal_kind", None) or "system")
    return ten, pid, pkd


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Model ─────────────────────────────────────────────────────────
class CanonicalEnvelope(BaseModel):
    """One telemetry unit forwarded by the collector service.  Fields
    match the ``framework.base.Envelope`` shape in nivxray-xdr-collector
    (INGEST_CONTRACT.md §2.1) plus the parser/normalization outcome so
    this endpoint can update counters truthfully."""
    tenant_id:            str
    collector_id:         str                           # required — anchors state
    data_source_id:       str | None  = None
    source_event_id:      str | None  = None
    collection_method:    str                           # syslog/webhook/rest/…
    canonical_schema:     str | None  = None
    raw:                  dict[str, Any] = Field(default_factory=dict)
    normalized:           dict[str, Any] | None = None
    parser_ok:            bool = True
    normalized_ok:        bool = True
    received_at:          str | None  = None
    # ── collector provenance (contract §2.1) ─────────────────────
    source:               str | None  = None            # human label of origin
    connector_id:         str | None  = None            # transport instance
    parser_version:       str | None  = None
    event_type:           str | None  = None
    source_timestamp:     str | None  = None
    collection_timestamp: str | None  = None
    # The collector's best-effort extraction.  Provenance, NOT authority
    # — the core re-parses ``raw`` itself (contract §2.1).
    canonical:            dict[str, Any] | None = None

    def normalized_view(self) -> dict[str, Any] | None:
        return self.normalized if self.normalized is not None else self.canonical


class TelemetryBatch(BaseModel):
    """The canonical/public ingest body — INGEST_CONTRACT.md §2.1:
    ``{"envelopes": [...]}``.  A bare JSON list is still accepted for
    backward compatibility and normalised to this shape immediately."""
    envelopes: list[CanonicalEnvelope]


class ReasoningOutcome(BaseModel):
    """Honest per-envelope record of what the core reasoning chain did.
    ``NOT_ATTEMPTED`` and ``NO_DSM`` are real answers, not failures to
    hide: they mean the payload format has no authoritative parser."""
    source_event_id:  str | None = None
    trace_id:         str
    status:           str                    # REASONED | NO_DSM | BLOCKED | FAILED
    blocker:          str | None = None
    detection:        str | None = None
    detections_matched: int = 0
    verdict:          str | None = None
    verdict_score:    int | None = None
    incident_created: bool = False
    incident_id:      str | None = None
    incident_reason:  str | None = None
    observation_id:   str | None = None
    error:            str | None = None


class TelemetryReceipt(BaseModel):
    accepted:             int
    parse_errors:         int
    normalize_errors:     int
    collector_state:      str
    collector_state_reason: str
    # ── P1.10 · live reasoning ───────────────────────────────────
    reasoned:             int = 0
    observations_created: int = 0
    incidents_promoted:   list[str] = Field(default_factory=list)
    reasoning:            list[ReasoningOutcome] = Field(default_factory=list)


# ── P1.10 · Live reasoning stage ──────────────────────────────────
# The collector's job ends at delivery.  From here the event travels the
# EXISTING authoritative chain — canonical evidence → detection → IUE →
# ICE → VEEE → gated incident materialisation.  No second engine is
# created, and no incident is fabricated: `materialise_incident` refuses
# any verdict below its gate and that refusal is reported verbatim.
_REASONING_AUDIT = "xdr_live_reasoning_audit"


def _raw_event_for_pipeline(e: CanonicalEnvelope) -> dict[str, Any]:
    """Assemble the raw event the DSM registry resolves against.  The
    verbatim line is the authority; the collector's parse rides along as
    provenance only."""
    raw = e.raw or {}
    return {
        "tenant_id":            e.tenant_id,
        "line":                 raw.get("line") or raw.get("message") or "",
        "payload_format":       raw.get("payload_format")
                                or (e.canonical or {}).get("payload_format"),
        "source":               e.source,
        "connector_id":         e.connector_id,
        "collector_id":         e.collector_id,
        "collection_method":    e.collection_method,
        "parser_version":       e.parser_version,
        "collection_timestamp": e.collection_timestamp,
        "raw":                  raw,
    }


async def _run_reasoning(envelopes: list[CanonicalEnvelope],
                             tenant_id: str) -> dict[str, Any]:
    """Drive each envelope through the existing reasoning chain.

    The counter/state contract of this endpoint is locked and must not
    depend on the reasoning fabric: if the async DB binding is absent
    (e.g. a TestClient that never ran startup) the receipt still returns
    truthfully, with the reason recorded rather than swallowed.
    """
    try:
        return await _reason_batch(envelopes, tenant_id)
    except Exception as ex:                                       # noqa: BLE001
        return {"reasoned": 0, "observations_created": 0,
                "incidents_promoted": [],
                "reasoning": [ReasoningOutcome(
                    trace_id="none", status="NOT_ATTEMPTED",
                    blocker="reasoning_unavailable",
                    error=f"{type(ex).__name__}: {ex}"[:300])]}


async def _reason_batch(envelopes: list[CanonicalEnvelope],
                            tenant_id: str) -> dict[str, Any]:
    from deps import db as _adb
    from detection_content.xdr_pipeline import process_event_through_pipeline
    from v2.ingestion.telemetry_bridge import (
        link_observations_to_incident, persist_live_observation)

    outcomes: list[ReasoningOutcome] = []
    promoted: list[str] = []
    observations = 0
    reasoned = 0

    for idx, e in enumerate(envelopes):
        trace_id = f"live_{uuid.uuid4().hex[:16]}"
        raw_event = _raw_event_for_pipeline(e)
        if not raw_event["line"]:
            outcomes.append(ReasoningOutcome(
                source_event_id=e.source_event_id, trace_id=trace_id,
                status="NOT_ATTEMPTED",
                blocker="no_verbatim_line",
                error="envelope carries no raw line to re-parse"))
            continue
        try:
            result = await process_event_through_pipeline(
                _adb, raw_event, trace_id,
                integration_id=e.data_source_id or e.connector_id or "unmapped",
                collector_id=e.collector_id,
                tenant_id=e.tenant_id or tenant_id)
        except Exception as ex:                                   # noqa: BLE001
            outcomes.append(ReasoningOutcome(
                source_event_id=e.source_event_id, trace_id=trace_id,
                status="FAILED", error=f"{type(ex).__name__}: {ex}"[:300]))
            continue

        canonical = result.get("canonical")
        if canonical is None:
            outcomes.append(ReasoningOutcome(
                source_event_id=e.source_event_id, trace_id=trace_id,
                status="NO_DSM" if result.get("blocker") == "dsm" else "BLOCKED",
                blocker=result.get("blocker")))
            continue

        obs_id = await persist_live_observation(
            _adb, canonical, envelope=e.model_dump(),
            tenant_id=e.tenant_id or tenant_id, sequence=idx)
        if obs_id:
            observations += 1

        detection = result.get("detection") or {}
        verdict   = result.get("verdict") or {}
        incident  = result.get("incident") or {}
        created   = bool(incident.get("created"))
        if created:
            promoted.append(incident.get("incident_id"))
            await link_observations_to_incident(
                _adb, trace_id=trace_id,
                incident_id=incident["incident_id"])
        reasoned += 1
        outcomes.append(ReasoningOutcome(
            source_event_id=e.source_event_id, trace_id=trace_id,
            status="REASONED", blocker=result.get("blocker"),
            detection=detection.get("status"),
            detections_matched=len(detection.get("detections") or []),
            verdict=verdict.get("label"),
            verdict_score=verdict.get("score"),
            incident_created=created,
            incident_id=incident.get("incident_id"),
            incident_reason=incident.get("reason"),
            observation_id=obs_id))

    await _adb[_REASONING_AUDIT].insert_one({
        "tenant_id":   tenant_id,
        "at":          _now(),
        "envelopes":   len(envelopes),
        "reasoned":    reasoned,
        "observations_created": observations,
        "incidents_promoted":   promoted,
        "outcomes":    [o.model_dump() for o in outcomes],
    })
    return {"reasoned": reasoned,
            "observations_created": observations,
            "incidents_promoted": promoted,
            "reasoning": outcomes}


# ── Endpoint ──────────────────────────────────────────────────────
@router.post("/telemetry",
                       response_model=TelemetryReceipt,
                       dependencies=[Depends(require_permission("collectors.enroll"))])
async def ingest_telemetry(
        body: TelemetryBatch | list[CanonicalEnvelope],
        request: Request):
    """Bulk ingest for a single collector.  Every envelope in the
    batch MUST reference the same ``collector_id`` — this endpoint
    rejects batches that mix collectors so a state transition is
    always tied to a single evidence-backed source.

    Body: ``{"envelopes": [...]}`` (canonical) or a bare JSON list
    (backward compatibility).  Both normalise to ``TelemetryBatch``.
    """
    batch = body if isinstance(body, TelemetryBatch) else TelemetryBatch(envelopes=body)
    envelopes = batch.envelopes
    if not envelopes:
        raise HTTPException(400, detail="empty batch")
    if _c_collectors() is None:
        raise HTTPException(503, detail="storage unavailable")

    ten_hdr, pid, pkd = _principal(request)

    # Tenant isolation is proved BEFORE anything else is looked up: a
    # caller must never learn whether a collector exists in another
    # tenant, and a batch must never mix tenants.
    body_tenants = {e.tenant_id for e in envelopes}
    if len(body_tenants) != 1:
        raise HTTPException(403, detail={
            "code": "TENANT_ISOLATION_VIOLATION",
            "reason": "one batch must reference exactly one tenant_id",
            "header_tenant": ten_hdr,
            "envelope_tenants": sorted(body_tenants)})
    body_ten = next(iter(body_tenants))
    if body_ten != ten_hdr:
        raise HTTPException(403, detail={
            "code": "TENANT_ISOLATION_VIOLATION",
            "header_tenant": ten_hdr,
            "envelope_tenant": body_ten})

    collector_ids = {e.collector_id for e in envelopes}
    if len(collector_ids) != 1:
        raise HTTPException(400, detail={
            "code": "MIXED_COLLECTORS",
            "reason": "one batch must reference exactly one collector_id"})
    cid = next(iter(collector_ids))

    # Locate the collector and enforce cross-tenant isolation: the
    # ``tenant_id`` from every envelope must match the collector's
    # tenant_id on disk.  This is the strictest guard against a
    # rogue caller injecting telemetry into another tenant.
    coll_doc = _c_collectors().find_one({"id": cid})
    if not coll_doc:
        raise HTTPException(404, detail="collector not found")
    owner_ten = coll_doc.get("tenant_id")
    for e in envelopes:
        if e.tenant_id != owner_ten:
            raise HTTPException(403, detail={
                "code": "TENANT_ISOLATION_VIOLATION",
                "collector_tenant": owner_ten,
                "envelope_tenant":  e.tenant_id})
    # Header tenant must ALSO match — the forwarder identity is
    # tenant-bound; a caller can never masquerade as another tenant.
    if ten_hdr != owner_ten:
        raise HTTPException(403, detail={
            "code": "TENANT_ISOLATION_VIOLATION",
            "header_tenant":   ten_hdr,
            "collector_tenant": owner_ten})

    accepted = parse_err = norm_err = 0
    now = _now()
    persisted_ids: list[str] = []
    for e in envelopes:
        if e.parser_ok and e.normalized_ok:
            accepted += 1
        elif not e.parser_ok:
            parse_err += 1
        elif not e.normalized_ok:
            norm_err += 1
        # Persist the canonical event (minimal projection — this is
        # not the SSOT; the authoritative event fabric is elsewhere).
        # Retention/rotation is handled by an out-of-band sweeper.
        rec = {
            "tenant_id":       e.tenant_id,
            "collector_id":    e.collector_id,
            "data_source_id":  e.data_source_id,
            "source_event_id": e.source_event_id,
            "collection_method": e.collection_method,
            "canonical_schema": e.canonical_schema,
            "raw":             e.raw,
            "normalized":      e.normalized_view(),
            "parser_ok":       e.parser_ok,
            "normalized_ok":   e.normalized_ok,
            "received_at":     e.received_at or e.collection_timestamp or now,
            "ingested_at":     now,
            "source":          e.source,
            "connector_id":    e.connector_id,
            "parser_version":  e.parser_version,
            "event_type":      e.event_type,
            "source_timestamp": e.source_timestamp,
        }
        if _c_events() is not None:
            r = _c_events().insert_one(rec)
            persisted_ids.append(str(r.inserted_id))

    # Update counters atomically.
    inc = {"events_received": len(envelopes),
              "events_parsed":   len(envelopes) - parse_err,
              "events_normalized": accepted,
              "events_error":    parse_err + norm_err}
    _c_collectors().update_one(
        {"_id": coll_doc["_id"]},
        {"$inc": inc, "$set": {"last_event_at": now, "updated_at": now}})

    # Recompute state honestly from the counters we just wrote.
    updated = _c_collectors().find_one({"_id": coll_doc["_id"]})
    received   = int(updated.get("events_received")   or 0)
    parsed     = int(updated.get("events_parsed")     or 0)
    normalized = int(updated.get("events_normalized") or 0)
    err_count  = int(updated.get("events_error")      or 0)
    prev_state = coll_doc.get("state", "ADOPTED")

    new_state: str
    reason:    str
    if not updated.get("enabled", True):
        new_state, reason = "DISABLED", "collector is disabled"
    elif received == 0:
        new_state, reason = prev_state, "no telemetry yet"
    elif parsed == 0 and received > 0:
        new_state, reason = "PARSE_ERROR", "parser failed on every event"
    elif normalized == 0 and parsed > 0:
        new_state, reason = "PARSE_ERROR", "normalization failed on every event"
    elif err_count > 0 and normalized > 0:
        # Some errors but also real successful telemetry — DEGRADED
        # is honest.  If the error ratio drops the next batch will
        # push us back to CONNECTED.
        error_ratio = err_count / max(received, 1)
        if error_ratio > 0.10:
            new_state, reason = "DEGRADED", (
                f"error ratio {error_ratio:.2%} above 10%")
        else:
            new_state, reason = "CONNECTED", (
                f"telemetry received/parsed/normalized: "
                f"{received}/{parsed}/{normalized}")
    elif received > 0 and parsed > 0 and normalized > 0:
        new_state, reason = "CONNECTED", (
            f"telemetry received/parsed/normalized: "
            f"{received}/{parsed}/{normalized}")
    else:
        new_state, reason = prev_state, "no state change"

    state_changed = new_state != prev_state
    if state_changed:
        _c_collectors().update_one(
            {"_id": coll_doc["_id"]},
            {"$set": {"state": new_state, "state_reason": reason,
                           "state_evidence": {
                               "at": now, "by": pid,
                               "received":   received,
                               "parsed":     parsed,
                               "normalized": normalized,
                               "errors":     err_count}}})
        emit_audit(
            tenant_id=owner_ten, principal_id=pid, principal_kind=pkd,
            action="COLLECTOR_STATE_CHANGED", resource_kind="collector",
            resource_id=cid,
            before={"state": prev_state},
            after={"state": new_state, "reason": reason},
            metadata={"evidence": {
                "received": received, "parsed": parsed,
                "normalized": normalized, "errors": err_count}},
        )

    # Bubble counters up to the linked data source (best-effort — a
    # collector can serve many sources; we increment the first-mapped
    # source when an envelope carries data_source_id).
    if _c_data_sources() is not None:
        by_ds: dict[str, dict[str, int]] = {}
        for e in envelopes:
            if not e.data_source_id:
                continue
            b = by_ds.setdefault(e.data_source_id,
                                                {"r": 0, "p": 0, "n": 0, "err": 0})
            b["r"] += 1
            if e.parser_ok:                 b["p"] += 1
            if e.parser_ok and e.normalized_ok: b["n"] += 1
            if not e.parser_ok or not e.normalized_ok: b["err"] += 1
        for ds_id, b in by_ds.items():
            _c_data_sources().update_one(
                {"id": ds_id, "tenant_id": owner_ten},
                {"$inc": {"events_received":   b["r"],
                                "events_parsed":     b["p"],
                                "events_normalized": b["n"],
                                "events_error":      b["err"]},
                  "$set": {"last_telemetry_at": now, "updated_at": now}},
            )

    return TelemetryReceipt(accepted=accepted, parse_errors=parse_err,
                                              normalize_errors=norm_err,
                                              collector_state=new_state,
                                              collector_state_reason=reason,
                                              **(await _run_reasoning(
                                                  envelopes, owner_ten)))
