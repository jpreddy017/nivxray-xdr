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

from detection_content.telemetry import evtx_xml
from routers.xdr_audit_log import emit_audit
from routers.xdr_rbac import require_permission, verified_actor
from services import ingest_idempotency as idem
from services import ingest_provenance as ing_prov
from services import source_routing
from services import tenant_registry

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


def _c_routing_blocks():
    """D15 · refused routing decisions. Evidence that a delivery was
    blocked and why — kept apart from canonical evidence, which a blocked
    delivery never produces."""
    return _db()["xdr_ingest_routing_blocks"] if _db() is not None else None


def _principal(req: Request) -> tuple[str, str, str]:
    # The tenant still comes from the authenticated delivery (the API key sets
    # `request.state.tenant_id`); the registry only adds "and it must be a
    # registered, ACTIVE tenant". Telemetry never establishes tenancy.
    raw = (req.headers.get("X-Tenant-Id")
                or getattr(req.state, "tenant_id", None) or "")
    try:
        ten = tenant_registry.authoritative(raw, purpose="xdr.ingest")
    except tenant_registry.TenantRegistryError as e:
        raise HTTPException(status_code=e.http, detail=e.detail()) from None
    # B3 · audit attribution comes from VERIFIED authentication only. The
    # machine principal is stamped on request.state by authenticate_api_key();
    # a client-supplied X-Principal-Id / X-Principal-Kind is parked as a
    # non-authoritative claim by verified_actor() and never becomes the actor.
    v_pid, v_pkd = verified_actor(req)
    pid = v_pid or "system@ingest"
    pkd = v_pkd or "system"
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
    #: D15 · what THIS delivery declares itself to be. The authenticated
    #: collector must declare it, the declaration must be inside the
    #: collector's server-side authorized set, and content may only validate
    #: it. Absent -> DECLARATION_REQUIRED; content is never used to guess.
    declared_source:      str | None  = None
    canonical_schema:     str | None  = None
    raw:                  dict[str, Any] = Field(default_factory=dict)
    normalized:           dict[str, Any] | None = None
    #: W2 · PROCESSING OUTCOME — MEASURED, NEVER ASSUMED.
    #: These used to default to ``True``, so a collector that said nothing
    #: about its own parsing was counted as a successful parse and a
    #: successful normalization. That made `events_parsed` /
    #: `events_normalized` — the LOCKED evidence behind the CONNECTED gate —
    #: describe an assumption instead of processing.
    #: ``None`` now means the collector DID NOT DECLARE an outcome. It is
    #: counted as unmeasured: never as success, never as an error.
    parser_ok:            bool | None = None
    normalized_ok:        bool | None = None
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

    # ── W2 · measured processing outcome ─────────────────────────
    #: The core does not re-guess the collector's parser. It measures the
    #: one thing it can observe first-hand — whether this delivery actually
    #: carries a normalized view — and otherwise reports the collector's
    #: own declaration, or UNMEASURED when there is none.
    def measured_normalized(self) -> bool | None:
        view = self.normalized_view()
        if isinstance(view, dict) and view:
            return True
        if self.normalized_ok is False:
            return False
        if self.normalized_ok is True:
            # The collector claims success but delivered no normalized view.
            # The observation wins: there is nothing normalized here.
            return False
        return None

    def measured_parsed(self) -> bool | None:
        if self.parser_ok is not None:
            return self.parser_ok
        return None

    def outcome_provenance(self) -> dict[str, Any]:
        return {
            "parser_ok_declared":     self.parser_ok,
            "normalized_ok_declared": self.normalized_ok,
            "parser_ok_basis": ("COLLECTOR_DECLARED" if self.parser_ok is not None
                                else "NOT_DECLARED"),
            "normalized_ok_basis": (
                "CORE_OBSERVED_NORMALIZED_VIEW"
                if isinstance(self.normalized_view(), dict)
                and self.normalized_view() else
                "COLLECTOR_DECLARED" if self.normalized_ok is not None
                else "NOT_DECLARED"),
        }


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
    status:           str      # REASONED | NO_DSM | BLOCKED | FAILED | DUPLICATE
    #: Set on a recognised retry: how many times this delivery has arrived
    #: and the identity that proved it is the same event.
    duplicate_of_trace_id: str | None = None
    delivery_count:   int | None = None
    dedupe_key:       str | None = None
    blocker:          str | None = None
    #: D4 · set when this envelope's auditd record was stitched into another
    #: envelope's canonical event instead of becoming its own.
    stitched_into_source_event_id: str | None = None
    stitch_audit_id:  str | None = None
    stitch_record_type: str | None = None
    #: D15 · the routing decision that produced (or refused) this outcome.
    declared_source:  str | None = None
    selected_dsm_id:  str | None = None
    routing_result:   str | None = None
    mismatch_reason:  str | None = None
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
    #: W2 · deliveries whose parsing / normalization outcome was NOT
    #: measured. They are not accepted and they are not errors — they are
    #: unknown, and they are reported as unknown.
    parse_unmeasured:     int = 0
    normalize_unmeasured: int = 0
    collector_state:      str
    collector_state_reason: str
    # ── P0 · delivery idempotency ────────────────────────────────
    #: Envelopes recognised as a retry of an already-processed delivery.
    #: They create no raw row, no canonical event, no detection and no
    #: incident — the original chain is reported back instead.
    duplicates:           int = 0
    #: Envelopes whose raw row already existed from an incomplete earlier
    #: attempt: reasoning was resumed WITHOUT re-persisting the raw row.
    resumed:              int = 0
    #: D15 · envelopes refused by declared-source routing. They create no
    #: raw row, no canonical event, no detection and no incident, and they
    #: never count toward the CONNECTED gate.
    routing_blocked:      int = 0
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


#: D13 · the single reserved key under which NivX transport metadata rides
#: on a DOCUMENT-shaped event.  One namespace, so nothing the source sent
#: can be shadowed and nothing the source sends can impersonate provenance.
TRANSPORT_NS = "_nivx"

SHAPE_LINE = "LINE"
SHAPE_DOCUMENT = "DOCUMENT"


class IngestShapeCollision(Exception):
    """A source document already carries the reserved transport key.

    Fail closed. Overwriting it would let NivX metadata destroy source
    evidence; honouring it would let source content impersonate NivX
    provenance. Neither is acceptable, so the delivery is refused with the
    reason recorded.
    """

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(
            f"source document carries the reserved transport key {key!r}: "
            "refusing to overwrite source evidence or to let source "
            "content impersonate NivX provenance")


#: Everything a LINE envelope is allowed to contain.  A collector that
#: delivers a verbatim line sends only the line and, optionally, the format
#: it believes it to be.  Anything ELSE in `raw` means the payload is a
#: source document whose own fields happen to include `message`.
_LINE_ONLY_KEYS = frozenset({"line", "message", "payload_format"})


def _payload_shape(e: CanonicalEnvelope) -> str:
    """LINE when the collector delivered a verbatim line, DOCUMENT when it
    delivered structured JSON.

    The distinction is STRUCTURAL, never a guess about content:

    * `raw.line` present  -> LINE. A delivered line is explicit.
    * `raw.message` present and `raw` carries nothing else of its own
      -> LINE. This is the older line-collector shape and it is preserved.
    * anything else with keys -> DOCUMENT. A Windows export carrying its own
      `message` field is a document, and treating it as a line would hand it
      to whichever line DSM recognised the text.
    * an empty envelope -> LINE, so its honest NO_DSM answer is unchanged.
    """
    raw = e.raw or {}
    if not isinstance(raw, dict) or not raw:
        return SHAPE_LINE
    if isinstance(raw.get("line"), str) and raw["line"].strip():
        return SHAPE_LINE
    if isinstance(raw.get("message"), str) and raw["message"].strip() \
            and not (set(raw) - _LINE_ONLY_KEYS):
        return SHAPE_LINE
    return SHAPE_DOCUMENT


def _document_for_pipeline(e: CanonicalEnvelope) -> dict[str, Any]:
    """D13 · a JSON-document envelope, shaped as the DSM registry expects.

    The document is handed over exactly as the source emitted it, because
    `supports()` and every document parser read source fields at the top
    level.  NivX's own metadata rides under `_nivx` where it cannot shadow
    a source field.

    One field is deliberately withheld: a source-supplied `tenant_id`. The
    authenticated tenant is the only authority on ownership, and a document
    that could name its own tenant would be a tenant-boundary bypass. The
    claimed value is preserved under `_nivx` as a claim, so no evidence is
    lost — it is simply not believed.
    """
    doc = dict(e.raw or {})
    if TRANSPORT_NS in doc:
        raise IngestShapeCollision(TRANSPORT_NS)
    # ── W2-1 · a rendered Windows Event Log record is decoded ONCE ─────
    # The native Windows adapter delivers `EvtRender(EvtRenderEventXml)`
    # output verbatim. Without this step the XML reaches every DSM's
    # `supports()` as an opaque string, no DSM claims it, and a channel
    # that is genuinely RECEIVING reports NO_DSM forever. The verbatim XML
    # stays in the document and stays the authority; the decode only adds
    # the fields the XML already contained, and its outcome is recorded so
    # "not a Windows record" can never be confused with "a Windows record
    # we could not read".
    evtx_decode: dict[str, Any] | None = None
    try:
        _decoded = evtx_xml.decode_document(doc)
    except evtx_xml.EvtxXmlDecodeError as exc:
        evtx_decode = {"decoded": False, "code": exc.code,
                       "reason": exc.message,
                       "decoder_id": evtx_xml.DECODER_ID}
    else:
        if _decoded is not None:
            doc = _decoded
            evtx_decode = {"decoded": True,
                           "decoder_id": evtx_xml.DECODER_ID}
    withheld: dict[str, Any] = {}
    if "tenant_id" in doc:
        withheld["tenant_id"] = doc.pop("tenant_id")
    doc[TRANSPORT_NS] = {
        "payload_shape":           SHAPE_DOCUMENT,
        "tenant_id":               e.tenant_id,
        "collector_id":            e.collector_id,
        "connector_id":            e.connector_id,
        "data_source_id":          e.data_source_id,
        "source":                  e.source,
        "collection_method":       e.collection_method,
        "parser_version":          e.parser_version,
        "collection_timestamp":    e.collection_timestamp,
        "source_timestamp":        e.source_timestamp,
        "received_at":             e.received_at,
        "declared_payload_format": (e.raw or {}).get("payload_format")
                                   or (e.canonical or {}).get(
                                       "payload_format"),
        "source_fields_withheld":  withheld or None,
        "evtx_decode":             evtx_decode,
        "withheld_reason": (
            "a source-supplied tenant_id is recorded as a claim and never "
            "used: the authenticated tenant is the only authority on "
            "ownership" if withheld else None),
    }
    return doc


def _raw_event_for_pipeline(e: CanonicalEnvelope) -> dict[str, Any]:
    """Assemble the raw event the DSM registry resolves against.  The
    verbatim line is the authority; the collector's parse rides along as
    provenance only."""
    if _payload_shape(e) == SHAPE_DOCUMENT:
        return _document_for_pipeline(e)
    raw = e.raw or {}
    line = raw.get("line") or raw.get("message") or ""
    return {
        "tenant_id":            e.tenant_id,
        "line":                 line,
        # Some DSMs (linux-auditd) key their parser on `message`.  Without
        # this the auditd DSM would claim the event in `supports()` and then
        # its own parser would reject it as UNRECOGNIZED_AUDITD.  The value
        # is the SAME verbatim line — nothing is invented.
        "message":              line,
        "payload_format":       raw.get("payload_format")
                                or (e.canonical or {}).get("payload_format"),
        "source":               e.source,
        "connector_id":         e.connector_id,
        "collector_id":         e.collector_id,
        "collection_method":    e.collection_method,
        "parser_version":       e.parser_version,
        "collection_timestamp": e.collection_timestamp,
        # D11 · carried verbatim so the canonical provenance can cite the
        # collector's own claims instead of re-deriving them.
        "source_timestamp":     e.source_timestamp,
        "received_at":          e.received_at,
        "raw":                  raw,
    }


def _ingest_provenance_for(e: CanonicalEnvelope, *, nivx_received_at: str,
                           tenant_id: str, raw_ref: dict[str, Any] | None
                           ) -> dict[str, Any]:
    """D11 · one envelope's ingest provenance: when each transport boundary
    saw it, and who says so.  No boundary is ever filled from another."""
    env = e.model_dump()
    return {
        "timestamps": ing_prov.transport_stamps(
            env, nivx_received_at=nivx_received_at,
            path_kind=ing_prov.COLLECTOR_DELIVERED),
        "identity": ing_prov.identity_block(
            env, path_kind=ing_prov.COLLECTOR_DELIVERED,
            tenant_id=tenant_id,
            tenant_id_source=("envelope.tenant_id, verified equal to header "
                              "X-Tenant-Id and to xdr_collectors.tenant_id"),
            collector_id=e.collector_id, raw_ref=raw_ref,
            payload_shape=_payload_shape(e)),
    }


async def _run_reasoning(envelopes: list[CanonicalEnvelope],
                             tenant_id: str,
                             keys: list[str] | None = None,
                             *,
                             nivx_received_at: str | None = None,
                             raw_refs: list[dict[str, Any] | None] | None = None,
                             routings: list[dict[str, Any]] | None = None
                             ) -> dict[str, Any]:
    """Drive each envelope through the existing reasoning chain.

    The counter/state contract of this endpoint is locked and must not
    depend on the reasoning fabric: if the async DB binding is absent
    (e.g. a TestClient that never ran startup) the receipt still returns
    truthfully, with the reason recorded rather than swallowed.
    """
    if not envelopes:
        return {"reasoned": 0, "observations_created": 0,
                "incidents_promoted": [], "reasoning": []}
    try:
        return await _reason_batch(envelopes, tenant_id, keys,
                                   nivx_received_at=nivx_received_at,
                                   raw_refs=raw_refs, routings=routings)
    except Exception as ex:                                       # noqa: BLE001
        # No claim is released.  The raw rows are already persisted, so the
        # claims stay at RAW_PERSISTED and the collector's retry RESUMES from
        # there once the lease expires — it never re-persists a raw row.
        return {"reasoned": 0, "observations_created": 0,
                "incidents_promoted": [],
                "reasoning": [ReasoningOutcome(
                    trace_id="none", status="NOT_ATTEMPTED",
                    blocker="reasoning_unavailable",
                    error=f"{type(ex).__name__}: {ex}"[:300])]}


async def _reason_batch(envelopes: list[CanonicalEnvelope],
                            tenant_id: str,
                            keys: list[str] | None = None,
                            *,
                            nivx_received_at: str | None = None,
                            raw_refs: list[dict[str, Any] | None] | None = None,
                            routings: list[dict[str, Any]] | None = None
                            ) -> dict[str, Any]:
    from deps import db as _adb
    from detection_content.telemetry.auditd_stitcher import (
        plan_stitch, record_type as aud_record_type)
    from detection_content.xdr_pipeline import process_event_through_pipeline
    from v2.ingestion.telemetry_bridge import (
        link_observations_to_incident,
        persist_live_observation,
    )

    outcomes: list[ReasoningOutcome] = []
    promoted: list[str] = []
    observations = 0
    reasoned = 0

    # ── D4 · auditd record stitching ─────────────────────────────────
    # auditd emits SYSCALL + EXECVE + PROCTITLE for ONE execution. Planned
    # here, before the pipeline, so one real execution becomes ONE canonical
    # event instead of three that contradict each other. Index-aligned to
    # `envelopes` so the per-envelope idempotency accounting below is
    # untouched: every index still gets exactly one settled outcome.
    # NOTE: no tenant-verification or authentication logic is touched; the
    # plan is partitioned BY the tenant those checks already established.
    _lines = [(e.raw or {}).get("line") or (e.raw or {}).get("message") or ""
              for e in envelopes]
    _plan = plan_stitch(_lines,
                        [e.tenant_id for e in envelopes],
                        [e.collector_id for e in envelopes])

    for idx, e in enumerate(envelopes):
        key = keys[idx] if keys and idx < len(keys) else None
        _routing = (routings[idx] if routings and idx < len(routings)
                    else None)
        trace_id = f"live_{uuid.uuid4().hex[:16]}"
        # D11 · the receipt instant is the ingest handler's own measurement,
        # taken before any work began. If this call was made without one
        # (tests, internal replay) the boundary stays MISSING — the current
        # clock is NOT substituted for a receipt we did not witness.
        _prov = _ingest_provenance_for(
            e, nivx_received_at=nivx_received_at, tenant_id=e.tenant_id
            or tenant_id,
            raw_ref=(raw_refs[idx] if raw_refs and idx < len(raw_refs)
                     else None)) if nivx_received_at else None
        raw_event: dict[str, Any] | None = None
        try:
            raw_event = _raw_event_for_pipeline(e)
        except IngestShapeCollision as ce:
            # D13 · fail closed. Transport metadata must never overwrite
            # source evidence, and source content must never impersonate
            # NivX provenance.
            outcomes.append(ReasoningOutcome(
                source_event_id=e.source_event_id, trace_id=trace_id,
                status="BLOCKED", blocker="ingest_shape",
                error=str(ce)[:300]))
            if key:
                idem.complete(key, trace_id=trace_id, outcome="BLOCKED")
            continue

        # A stitched member contributed its record to the group's canonical
        # event. It is settled honestly as STITCHED_INTO — never silently
        # dropped, and never re-parsed into a second contradictory event.
        if _plan["roles"].get(idx) == "MEMBER":
            _p = _plan["primary_of"][idx]
            outcomes.append(ReasoningOutcome(
                source_event_id=e.source_event_id, trace_id=trace_id,
                status="STITCHED_INTO",
                blocker=None,
                error=None,
                dedupe_key=key,
                stitched_into_source_event_id=envelopes[_p].source_event_id,
                stitch_audit_id=_plan["stitched"][_p]["_audit_identity"],
                stitch_record_type=aud_record_type(_lines[idx])))
            if key:
                idem.complete(key, trace_id=trace_id,
                              outcome="STITCHED_INTO")
            continue

        # The primary carries the stitched view: the merged key/value record
        # plus its own verbatim line, so the parser still sees real auditd
        # text and every contributing record travels with it.
        _st = _plan["stitched"].get(idx)
        if _st and len(_st["_contributing_records"]) > 1:
            raw_event = {**raw_event, **_st,
                         "line": _st["_primary_line"],
                         "message": _st["_primary_line"]}

        if not raw_event.get("line") and TRANSPORT_NS not in raw_event:
            outcomes.append(ReasoningOutcome(
                source_event_id=e.source_event_id, trace_id=trace_id,
                status="NOT_ATTEMPTED",
                blocker="no_verbatim_line",
                error="envelope carries neither a raw line nor a JSON "
                      "document to re-parse"))
            if key:
                idem.complete(key, trace_id=trace_id,
                              outcome="NOT_ATTEMPTED")
            continue
        try:
            result = await process_event_through_pipeline(
                _adb, raw_event, trace_id,
                integration_id=e.data_source_id or e.connector_id or "unmapped",
                collector_id=e.collector_id,
                tenant_id=e.tenant_id or tenant_id,
                ingest_provenance=_prov,
                routing=_routing)
        except Exception as ex:                                   # noqa: BLE001
            outcomes.append(ReasoningOutcome(
                source_event_id=e.source_event_id, trace_id=trace_id,
                status="FAILED", error=f"{type(ex).__name__}: {ex}"[:300],
                dedupe_key=key))
            # The pipeline may already have persisted canonical evidence
            # before it failed, and we cannot know.  The claim is therefore
            # NEVER released: auto-retry is refused so a second
            # raw/canonical chain can never exist.  The record is flagged so
            # an operator can requeue it deliberately.
            if key:
                idem.needs_review(
                    key, f"pipeline fault: {type(ex).__name__}: {ex}",
                    trace_id=trace_id)
            continue

        canonical = result.get("canonical")
        if canonical is None:
            outcomes.append(ReasoningOutcome(
                source_event_id=e.source_event_id, trace_id=trace_id,
                status="NO_DSM" if result.get("blocker") == "dsm" else "BLOCKED",
                blocker=result.get("blocker"), dedupe_key=key))
            # Deterministically blocked payload — terminal, so a retry does
            # not re-persist the same raw row.
            if key:
                idem.complete(
                    key, trace_id=trace_id,
                    outcome="NO_DSM" if result.get("blocker") == "dsm"
                    else "BLOCKED")
            continue

        try:
            obs_id = await persist_live_observation(
                _adb, canonical, envelope=e.model_dump(),
                tenant_id=e.tenant_id or tenant_id, sequence=idx)
        except Exception as ex:                                   # noqa: BLE001
            # Canonical evidence EXISTS at this point.  Same rule: never
            # release, flag for review.
            outcomes.append(ReasoningOutcome(
                source_event_id=e.source_event_id, trace_id=trace_id,
                status="FAILED", error=f"{type(ex).__name__}: {ex}"[:300],
                dedupe_key=key))
            if key:
                idem.needs_review(
                    key, f"post-canonical fault: {type(ex).__name__}: {ex}",
                    trace_id=trace_id)
            continue
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
            declared_source=(_routing or {}).get("declared_source"),
            selected_dsm_id=(_routing or {}).get("selected_dsm_id"),
            routing_result=(_routing or {}).get("routing_result"),
            detection=detection.get("status"),
            detections_matched=len(detection.get("detections") or []),
            verdict=verdict.get("label"),
            verdict_score=verdict.get("score"),
            incident_created=created,
            incident_id=incident.get("incident_id"),
            incident_reason=incident.get("reason"),
            observation_id=obs_id,
            dedupe_key=key))
        if key:
            idem.complete(
                key, trace_id=trace_id,
                canonical_event_id=canonical.get("event_id"),
                observation_id=obs_id,
                incident_id=incident.get("incident_id"),
                incident_created=created, outcome="PROCESSED")

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


# ── D15 · declared source routing gate ───────────────────────────
def route_batch(envelopes: list[CanonicalEnvelope], *,
                authorized: list[str], tenant_id: str,
                collector_id: str, nivx_received_at: str | None = None
                ) -> tuple[list[tuple[CanonicalEnvelope, dict[str, Any]]],
                           list[ReasoningOutcome], list[dict[str, Any]]]:
    """``(routed, blocked_outcomes, block_rows)`` — the ingestion authority.

        authenticated collector identity
          → the collector's server-side authorized source set
          → this delivery's EXPLICIT declaration
          → declaration / allowlist validation
          → DSM selection
          → content compatibility validation
          → canonical evidence

    Content may only VALIDATE the declaration. There is no registry-order
    fall-through and no content-inferred fallback, so a refused delivery
    gets NO raw row, NO idempotency claim, NO canonical evidence, no
    detection and no incident — and never counts toward the CONNECTED gate.
    The refusal itself is kept as evidence.
    """
    from detection_content.xdr_pipeline import DSM_REGISTRY

    routed: list[tuple[CanonicalEnvelope, dict[str, Any]]] = []
    blocked: list[ReasoningOutcome] = []
    rows: list[dict[str, Any]] = []
    for e in envelopes:
        try:
            probe = _raw_event_for_pipeline(e)
        except IngestShapeCollision as ce:
            # D13 already refuses this payload. Routing never ran, and it is
            # not reported as though it had.
            routed.append((e, source_routing.not_evaluated(
                declared=e.declared_source, authorized=authorized,
                reason=f"refused before routing: {ce}"[:400])))
            continue
        decision, _dsm = source_routing.route(
            declared=e.declared_source, authorized=authorized,
            raw_event=probe, registry=DSM_REGISTRY)
        if decision["routing_result"] == source_routing.ACCEPTED:
            routed.append((e, decision))
            continue
        btrace = f"blocked_{uuid.uuid4().hex[:16]}"
        blocked.append(ReasoningOutcome(
            source_event_id=e.source_event_id, trace_id=btrace,
            status="BLOCKED", blocker="source_routing",
            declared_source=decision.get("declared_source"),
            selected_dsm_id=decision.get("selected_dsm_id"),
            routing_result=decision.get("routing_result"),
            mismatch_reason=decision.get("mismatch_reason"),
            error=str(decision.get("reason"))[:300]))
        raw = e.raw if isinstance(e.raw, dict) else {}
        rows.append({
            "tenant_id":        tenant_id,
            "collector_id":     collector_id,
            "source_event_id":  e.source_event_id,
            "trace_id":         btrace,
            "at":               _now(),
            "nivx_received_at": nivx_received_at,
            "collection_method": e.collection_method,
            "payload_shape":    _payload_shape(e),
            "declared_payload_format": raw.get("payload_format"),
            # Mismatch evidence, bounded on purpose: the payload's own field
            # names and a short excerpt prove the disagreement without
            # copying an unbounded body into a control record.
            "payload_keys":     sorted(str(k) for k in raw),
            "payload_excerpt":  str(raw.get("line")
                                    or raw.get("message") or "")[:300],
            "routing":          decision,
            "honesty_note": (
                "no raw row, no idempotency claim and no canonical evidence "
                "exist for this delivery; it does not count toward the "
                "CONNECTED gate"),
        })
    return routed, blocked, rows


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
    # D11 · the ONE real NivX receipt instant for this delivery, taken before
    # any lookup, validation or persistence. Every later stage measures its
    # own boundary; none of them may stand in for this one.
    nivx_received_at = _now()
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

    # ── D15 · declared source routing · FAIL CLOSED ───────────────
    authorized = source_routing.authorized_sources(coll_doc)
    routed, routing_blocked, block_rows = route_batch(
        envelopes, authorized=authorized, tenant_id=owner_ten,
        collector_id=cid, nivx_received_at=nivx_received_at)
    if block_rows and _c_routing_blocks() is not None:
        _c_routing_blocks().insert_many(block_rows)

    # ── P0 · delivery idempotency ─────────────────────────────────
    # Partition the batch BEFORE anything is persisted.  A recognised retry
    # produces no raw row, no canonical event, no detection and no incident;
    # the original provenance chain is reported back instead.
    fresh: list[CanonicalEnvelope] = []
    fresh_keys: list[str] = []
    #: D15 · index-aligned routing decision for every envelope that will be
    #: reasoned, so the decision travels with the evidence it produced.
    fresh_routings: list[dict[str, Any]] = []
    dup_outcomes: list[ReasoningOutcome] = []
    dup_incident_ids: list[str] = []
    #: Envelopes whose raw row already exists from a previous, incomplete
    #: attempt — reasoning is resumed WITHOUT re-persisting the raw row.
    resume: list[CanonicalEnvelope] = []
    resume_keys: list[str] = []
    resume_routings: list[dict[str, Any]] = []
    #: D11 · the raw row that proves each resumed envelope, taken from the
    #: idempotency claim rather than re-derived.
    resume_raw_refs: list[dict[str, Any] | None] = []
    try:
        idents = [(e, route_dec,
                   idem.event_identity(e.tenant_id, e.collector_id,
                                       e.source, e.source_event_id, e.raw))
                  for e, route_dec in routed]
        claims = [(e, route_dec, ident, *idem.claim(ident))
                  for e, route_dec, ident in idents]
    except idem.IdempotencyUnavailable as ex:
        raise HTTPException(503, detail={
            "code": "INGEST_IDEMPOTENCY_UNAVAILABLE",
            "reason": str(ex),
            "retryable": True,
            "honesty_note": ("Telemetry is never processed through "
                                    "raw → detection → incident without "
                                    "exactly-once protection.")})

    for e, route_dec, ident, decision, rec in claims:
        if decision in ("DUPLICATE", "DUPLICATE_NEEDS_REVIEW", "IN_FLIGHT"):
            rec = rec or {}
            why = {
                "DUPLICATE": ("retry of an already-processed delivery — no "
                                    "second raw/canonical/detection/incident "
                                    "chain was created"),
                "DUPLICATE_NEEDS_REVIEW": (
                    "a previous attempt persisted evidence but did not finish "
                    "reasoning; auto-retry is refused so no second "
                    "raw/canonical chain can be produced — the claim is "
                    "flagged for operator review"),
                "IN_FLIGHT": ("a concurrent copy of this same delivery is "
                                    "already being processed — no second chain "
                                    "was started"),
            }[decision]
            dup_outcomes.append(ReasoningOutcome(
                source_event_id=e.source_event_id,
                trace_id=rec.get("trace_id") or "none",
                status=decision,
                blocker="duplicate_delivery",
                incident_created=False,
                incident_id=rec.get("incident_id"),
                incident_reason=why,
                observation_id=rec.get("observation_id"),
                duplicate_of_trace_id=rec.get("trace_id"),
                delivery_count=rec.get("delivery_count"),
                dedupe_key=ident["key"]))
            if decision == "DUPLICATE" and rec.get("incident_id"):
                dup_incident_ids.append(rec["incident_id"])
            continue
        if decision == "RESUME_FROM_RAW":
            resume.append(e)
            resume_keys.append(ident["key"])
            resume_routings.append(route_dec)
            _rid = (rec or {}).get("raw_row_id")
            resume_raw_refs.append(
                {"collection": "xdr_canonical_events", "id": _rid,
                 "state": "PERSISTED_BY_EARLIER_ATTEMPT"} if _rid else
                {"state": "MISSING",
                 "reason": ("the idempotency claim recorded RAW_PERSISTED but "
                            "carried no raw_row_id")})
            continue
        # FRESH or RESUME_FULL — nothing was ever persisted for this claim.
        fresh.append(e)
        fresh_keys.append(ident["key"])
        fresh_routings.append(route_dec)

    # Retry provenance on the ORIGINAL incident: the same event was seen
    # again.  Additive counters only — no state, priority or verdict change.
    if dup_incident_ids and _db() is not None:
        _db()["workspace_cases"].update_many(
            {"id": {"$in": dup_incident_ids}},
            {"$inc": {"duplicate_delivery_count": 1},
             "$set": {"last_duplicate_delivery_at": _now()}})

    accepted = parse_err = norm_err = 0
    parse_unmeasured = norm_unmeasured = 0
    now = _now()
    persisted_ids: list[str] = []
    #: D11 · index-aligned to `fresh`, so reasoning can cite the exact raw row.
    fresh_raw_refs: list[dict[str, Any] | None] = []
    for e, _claim_key in zip(fresh, fresh_keys):
        p_ok = e.measured_parsed()
        n_ok = e.measured_normalized()
        if p_ok is None:
            parse_unmeasured += 1
        if n_ok is None:
            norm_unmeasured += 1
        if p_ok is True and n_ok is True:
            accepted += 1
        elif p_ok is False:
            parse_err += 1
        elif n_ok is False:
            norm_err += 1
        # p_ok/n_ok None with no failure -> counted ONLY as unmeasured.
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
            "parser_ok":       p_ok,
            "normalized_ok":   n_ok,
            "processing_outcome": e.outcome_provenance(),
            "received_at":     e.received_at or e.collection_timestamp or now,
            "ingested_at":     now,
            "source":          e.source,
            "connector_id":    e.connector_id,
            "parser_version":  e.parser_version,
            "event_type":      e.event_type,
            "source_timestamp": e.source_timestamp,
        }
        # D11 · `received_at` above keeps its compatibility fallback chain, so
        # nothing that reads it breaks — but the substitution is now declared
        # instead of being indistinguishable from a collector measurement.
        if e.received_at:
            rec["received_at_source"] = "collector:envelope.received_at"
            rec["received_at_substituted"] = False
        elif e.collection_timestamp:
            rec["received_at_source"] = \
                "collector:envelope.collection_timestamp"
            rec["received_at_substituted"] = True
        else:
            rec["received_at_source"] = \
                "ingest:http receipt POST /api/xdr/ingest/telemetry"
            rec["received_at_substituted"] = True
        rec["nivx_received_at"] = nivx_received_at
        if _c_events() is not None:
            r = _c_events().insert_one(rec)
            persisted_ids.append(str(r.inserted_id))
            fresh_raw_refs.append({"collection": "xdr_canonical_events",
                                   "id": str(r.inserted_id),
                                   "state": "PERSISTED_BY_THIS_REQUEST"})
            # The raw row now exists.  Record it BEFORE reasoning so a retry
            # after a crash resumes instead of re-persisting it.  A failure
            # here is fatal for the request: losing this marker is what would
            # permit a duplicate raw row.
            try:
                idem.mark_raw_persisted(_claim_key, str(r.inserted_id))
            except idem.IdempotencyUnavailable as ex:
                raise HTTPException(503, detail={
                    "code": "INGEST_IDEMPOTENCY_UNAVAILABLE",
                    "reason": str(ex),
                    "retryable": True,
                    "stage": "raw_persisted_marker"})
        else:
            fresh_raw_refs.append(
                {"state": "MISSING",
                 "reason": "the raw event store was unavailable for this "
                           "delivery"})

    # Update counters atomically.  `events_received/parsed/normalized` are
    # the LOCKED evidence for the CONNECTED gate and count UNIQUE telemetry
    # only — a retry is recorded honestly in its own `events_duplicate`
    # counter so the state machine cannot be inflated by redelivery.
    #: `events_parsed` counted `len(fresh) - parse_err`, which credited every
    #: undeclared delivery as parsed. It now counts only MEASURED successes,
    #: and the undeclared ones are reported in their own counters so the
    #: CONNECTED gate can never be satisfied by an assumption.
    measured_parsed_ok = sum(1 for e in fresh if e.measured_parsed() is True)
    inc = {"events_received": len(fresh),
              "events_parsed":   measured_parsed_ok,
              "events_normalized": accepted,
              "events_error":    parse_err + norm_err,
              "events_parse_unmeasured": parse_unmeasured,
              "events_normalize_unmeasured": norm_unmeasured,
              "events_duplicate": len(dup_outcomes),
              # D15 · refused by declared-source routing. Counted apart so a
              # blocked delivery can never look like telemetry.
              "events_routing_blocked": len(routing_blocked)}
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
        for e in fresh:
            if not e.data_source_id:
                continue
            b = by_ds.setdefault(e.data_source_id,
                                                {"r": 0, "p": 0, "n": 0, "err": 0,
                                                 "unm": 0})
            b["r"] += 1
            p_ok, n_ok = e.measured_parsed(), e.measured_normalized()
            if p_ok is True:                        b["p"] += 1
            if p_ok is True and n_ok is True:       b["n"] += 1
            if p_ok is False or n_ok is False:      b["err"] += 1
            if p_ok is None or n_ok is None:        b["unm"] += 1
        for ds_id, b in by_ds.items():
            _c_data_sources().update_one(
                {"id": ds_id, "tenant_id": owner_ten},
                {"$inc": {"events_received":   b["r"],
                                "events_parsed":     b["p"],
                                "events_normalized": b["n"],
                                "events_error":      b["err"],
                                "events_unmeasured": b["unm"]},
                  "$set": {"last_telemetry_at": now, "updated_at": now}},
            )

    # Fresh envelopes and resumed ones are reasoned together; only the fresh
    # ones had a raw row written in this request.
    reasoning = await _run_reasoning(fresh + resume, owner_ten,
                                     fresh_keys + resume_keys,
                                     nivx_received_at=nivx_received_at,
                                     raw_refs=fresh_raw_refs + resume_raw_refs,
                                     routings=fresh_routings
                                     + resume_routings)
    reasoning["reasoning"] = list(reasoning.get("reasoning") or []) \
        + dup_outcomes + routing_blocked
    return TelemetryReceipt(accepted=accepted, parse_errors=parse_err,
                                              normalize_errors=norm_err,
                                              parse_unmeasured=parse_unmeasured,
                                              normalize_unmeasured=norm_unmeasured,
                                              collector_state=new_state,
                                              collector_state_reason=reason,
                                              duplicates=len(dup_outcomes),
                                              resumed=len(resume),
                                              routing_blocked=len(
                                                  routing_blocked),
                                              **reasoning)
