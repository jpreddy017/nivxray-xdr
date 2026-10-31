"""B4 · Raw forensic retention — evidence survives a refusal.

The G1 Windows Security RCA could name the MECHANISM of 24 refusals but not
the EventID of a single one of them, because a refused delivery kept only its
payload key names and an excerpt sampled from `raw["line"]` / `raw["message"]`
— fields a Windows record does not have. The evidence was authenticated,
tenant-authorized, declared, and then discarded.

This module is the correction, and nothing more:

    an event from an AUTHENTICATED, TENANT-AUTHORIZED, DECLARED source that
    reaches NivXRay remains durably inspectable as RAW FORENSIC EVIDENCE even
    when its record type has no parser, normalizer or detection support.

The one invariant that makes retention safe:

    RAW RETAINED  ≠  PARSED  ≠  NORMALIZED  ≠  EVALUATED  ≠  DETECTED

A retained record therefore asserts NOTHING beyond "this arrived, from this
authorized source, and here it is verbatim". It is not canonical evidence, it
carries no verdict, it is not benign, and it never counts toward a CONNECTED
gate or a detection decision.

What it does NOT do:

  * it does not widen authorization — `DECLARATION_REQUIRED`,
    `UNSUPPORTED_SOURCE` and `SOURCE_NOT_AUTHORIZED` are authority failures
    and retain nothing, so an unauthorized caller can never buy durable
    storage in a tenant by being refused;
  * it does not consume the ingest idempotency claim. A record refused for
    missing coverage must be able to enter the normal pipeline later, once
    that coverage exists — consuming the claim would make the same delivery
    look like a DUPLICATE forever;
  * it does not replace the raw payload with a parsed convenience view. The
    extracted `event_id` / `channel` / `provider` fields are ADDITIVE hints
    for retrieval; `raw` is the verbatim authority;
  * it does not manufacture a single timestamp. Every clock it has is kept
    under its own name, and a clock it never observed is absent.

Idempotency INSIDE the retention namespace is enforced on the delivery's own
identity (`services.ingest_idempotency.event_identity`), so a channel that
re-delivers the same unsupported record a thousand times leaves ONE retained
forensic row with a delivery counter — never a thousand copies.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from pymongo import ASCENDING, DESCENDING, MongoClient, errors

log = logging.getLogger("nivxray.b4.raw_retention")

COLLECTION = "xdr_ingest_raw_retained"

#: What a retained row explicitly does NOT claim. Written onto every row so
#: no reader can mistake retention for processing.
DISPOSITION_NOT_EVALUATED = "RAW_RETAINED_NOT_EVALUATED"

_HONESTY_NOTE = (
    "raw forensic evidence retained for an AUTHORIZED, DECLARED delivery "
    "that was refused before interpretation; it was NOT parsed, NOT "
    "normalized, NOT detected, NOT canonicalized and is NOT asserted to be "
    "benign — absence of a verdict is absence of evaluation")

_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME = os.environ.get("DB_NAME") or "test_database"
_client = MongoClient(_MONGO_URL) if _MONGO_URL else None
_INDEXED: set[str] = set()


class RetentionUnavailable(Exception):
    """The retained-raw store could not accept the evidence."""


def _db(db_name: str | None = None):
    if _client is None:
        return None
    return _client[db_name or _DB_NAME]


def _coll(db_name: str | None = None):
    db = _db(db_name)
    if db is None:
        return None
    c = db[COLLECTION]
    key = f"{db.name}.{COLLECTION}"
    if key not in _INDEXED:
        try:
            c.create_index([("tenant_id", ASCENDING),
                            ("retained_identity_key", ASCENDING)],
                           unique=True, name="ux_retained_identity")
            c.create_index([("tenant_id", ASCENDING),
                            ("first_seen_at", DESCENDING)])
            c.create_index([("tenant_id", ASCENDING), ("id", ASCENDING)],
                           unique=True, name="ux_retained_id")
            c.create_index([("tenant_id", ASCENDING),
                            ("disposition.mismatch_reason", ASCENDING)])
        except errors.PyMongoError as exc:                  # pragma: no cover
            log.warning("retained-raw index creation failed: %s", exc)
        _INDEXED.add(key)
    return c


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(value: Any) -> str:
    material = json.dumps(value, sort_keys=True, default=str,
                          separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _raw_format(raw: dict[str, Any]) -> str:
    """How the evidence arrived. Structural, never a guess about content."""
    if not isinstance(raw, dict):
        return "OPAQUE"
    for key in ("xml", "event_xml", "raw_xml"):
        if isinstance(raw.get(key), str) and raw[key].strip():
            return "WINDOWS_RENDERED_EVTX_XML"
    if isinstance(raw.get("line"), str):
        return "VERBATIM_LINE"
    return "DOCUMENT"


def _windows_hints(raw: dict[str, Any]) -> dict[str, Any]:
    """Additive retrieval hints extracted from the record, or nulls.

    These exist so an investigator can FIND the record ("which EventIDs did
    we refuse?") — the closed gap the Security RCA hit. They never replace
    `raw`, and a field the record did not carry stays `None`.
    """
    hints: dict[str, Any] = {"event_id": None, "event_record_id": None,
                             "channel": None, "provider": None,
                             "time_created": None,
                             "extraction": "NOT_A_WINDOWS_RECORD"}
    try:
        from detection_content.telemetry import evtx_xml
        view = evtx_xml.decoded_view(raw)
    except Exception:                                       # noqa: BLE001
        view = None
    if not isinstance(view, dict):
        hints["extraction"] = "UNREADABLE"
        return hints
    system = view.get("System") if isinstance(view.get("System"),
                                              dict) else {}
    eid = view.get("EventID") or view.get("event_id") or system.get("EventID")
    if eid is None:
        hints["extraction"] = "NO_EVENT_ID_PRESENT"
        return hints
    hints.update({
        "event_id": str(eid),
        "event_record_id": (str(system.get("EventRecordID"))
                            if system.get("EventRecordID") is not None
                            else None),
        "channel": (view.get("channel") or view.get("Channel")
                    or system.get("Channel")),
        "provider": (view.get("provider") or view.get("Provider")
                     or system.get("Provider")),
        "time_created": (view.get("TimeCreated")
                         or system.get("TimeCreated")),
        "extraction": "DECODED_FROM_RETAINED_RAW",
    })
    return hints


def retain(*, tenant_id: str, collector_id: str, envelope: Any,
           decision: dict[str, Any], identity: dict[str, Any],
           trace_id: str, nivx_received_at: str | None,
           db_name: str | None = None) -> dict[str, Any]:
    """Retain one refused-but-authorized delivery. Idempotent per identity.

    Returns the retention reference to publish on the refusal record. Never
    raises: a retention failure is reported as a FAILED state, because the
    delivery was already refused and pretending it was retained would be the
    same silent evidence loss this module exists to end.
    """
    c = _coll(db_name)
    if c is None:
        return {"state": "UNAVAILABLE", "retained_raw_id": None,
                "reason": "retained-raw store unavailable"}

    raw = envelope.raw if isinstance(getattr(envelope, "raw", None),
                                     dict) else {}
    key = identity.get("key")
    now = _now()
    rid = f"rr_{uuid.uuid4().hex[:24]}"
    hints = _windows_hints(raw)

    doc = {
        "id": rid,
        # ── authority chain, exactly as it was proved at the boundary ──
        "tenant_id": tenant_id,
        "collector_id": collector_id,
        "connector_id": getattr(envelope, "connector_id", None),
        "authority_basis": ("authenticated collector, verified against "
                            "xdr_collectors.tenant_id; declaration inside "
                            "the collector's server-side allowlist"),
        # ── event identity ──
        "retained_identity_key": key,
        "payload_digest": identity.get("payload_digest"),
        "source_event_id": getattr(envelope, "source_event_id", None),
        "source": getattr(envelope, "source", None),
        "declared_source": decision.get("declared_source"),
        "declared_source_resolved": decision.get("declared_source_resolved"),
        "selected_dsm_id": decision.get("selected_dsm_id"),
        "collection_method": getattr(envelope, "collection_method", None),
        # ── the evidence itself, verbatim ──
        "raw": raw,
        "raw_format": _raw_format(raw),
        "raw_keys": sorted(str(k) for k in raw),
        "raw_sha256": _digest(raw),
        "record_hints": hints,
        "record_hints_note": ("additive retrieval hints decoded from the "
                              "retained raw; `raw` remains the authority"),
        # ── clocks · each under its own name, never merged ──
        "clocks": {
            "activity_time_declared_by_source": hints.get("time_created"),
            "source_timestamp": getattr(envelope, "source_timestamp", None),
            "collection_timestamp": getattr(envelope,
                                            "collection_timestamp", None),
            "collector_received_at": getattr(envelope, "received_at", None),
            "nivx_received_at": nivx_received_at,
            "retained_at": now,
            "note": ("a clock NivXRay did not observe is absent; no single "
                     "timestamp is manufactured from the others"),
        },
        # ── provenance ──
        "provenance": {
            "trace_id": trace_id,
            "routing": decision,
            "parser_version_declared_by_collector": getattr(
                envelope, "parser_version", None),
            "event_type_declared_by_collector": getattr(envelope,
                                                        "event_type", None),
        },
        # ── disposition · what this row does NOT claim ──
        "disposition": {
            "state": DISPOSITION_NOT_EVALUATED,
            "routing_result": decision.get("routing_result"),
            "mismatch_reason": decision.get("mismatch_reason"),
            "parsed": False,
            "normalized": False,
            "detection_evaluated": False,
            "canonical_evidence_created": False,
            "verdict": None,
            "benign_assertion": False,
            "counts_toward_connected_gate": False,
            "ingest_idempotency_claim_consumed": False,
            "reprocessable_when_coverage_exists": True,
        },
        "honesty_note": _HONESTY_NOTE,
        "first_seen_at": now,
    }

    try:
        existing = c.find_one_and_update(
            {"tenant_id": tenant_id, "retained_identity_key": key},
            {"$setOnInsert": doc,
             "$inc": {"delivery_count": 1},
             "$set": {"last_seen_at": now}},
            upsert=True, return_document=False)
    except errors.PyMongoError as exc:
        log.error("B4 retained-raw write FAILED · tenant=%s key=%s: %s",
                  tenant_id, key, exc)
        return {"state": "FAILED", "retained_raw_id": None,
                "reason": f"{type(exc).__name__}: {str(exc)[:200]}"}

    if existing is None:
        return {"state": "RETAINED", "retained_raw_id": rid,
                "collection": COLLECTION, "delivery_count": 1,
                "disposition": DISPOSITION_NOT_EVALUATED}
    return {"state": "ALREADY_RETAINED",
            "retained_raw_id": existing.get("id"),
            "collection": COLLECTION,
            "delivery_count": int(existing.get("delivery_count") or 1) + 1,
            "disposition": DISPOSITION_NOT_EVALUATED}
    return {"state": "ALREADY_RETAINED",
            "retained_raw_id": existing.get("id"),
            "collection": COLLECTION,
            "delivery_count": int(existing.get("delivery_count") or 1) + 1,
            "disposition": DISPOSITION_NOT_EVALUATED}


def metadata_row(doc: dict[str, Any]) -> dict[str, Any]:
    """Bounded, metadata-only projection for list responses."""
    return {
        "retained_raw_id": doc.get("id"),
        "tenant_id": doc.get("tenant_id"),
        "collector_id": doc.get("collector_id"),
        "connector_id": doc.get("connector_id"),
        "source_event_id": doc.get("source_event_id"),
        "declared_source": doc.get("declared_source"),
        "declared_source_resolved": doc.get("declared_source_resolved"),
        "selected_dsm_id": doc.get("selected_dsm_id"),
        "mismatch_reason": (doc.get("disposition") or {}).get(
            "mismatch_reason"),
        "raw_format": doc.get("raw_format"),
        "raw_keys": doc.get("raw_keys"),
        "raw_sha256": doc.get("raw_sha256"),
        "record_hints": doc.get("record_hints"),
        "clocks": doc.get("clocks"),
        "trace_id": (doc.get("provenance") or {}).get("trace_id"),
        "disposition": doc.get("disposition"),
        "first_seen_at": doc.get("first_seen_at"),
        "last_seen_at": doc.get("last_seen_at"),
        "delivery_count": doc.get("delivery_count"),
        "raw_included": False,
        "raw_note": ("fetch the record by its retained_raw_id to read the "
                     "verbatim raw evidence"),
    }


def full_row(doc: dict[str, Any]) -> dict[str, Any]:
    """The authoritative retained record, verbatim raw included."""
    row = metadata_row(doc)
    row.update({
        "raw": doc.get("raw"),
        "raw_included": True,
        "raw_note": "verbatim as delivered; nothing normalized or rewritten",
        "retained_identity_key": doc.get("retained_identity_key"),
        "payload_digest": doc.get("payload_digest"),
        "authority_basis": doc.get("authority_basis"),
        "provenance": doc.get("provenance"),
        "honesty_note": doc.get("honesty_note"),
    })
    return row
