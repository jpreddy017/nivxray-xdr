"""P0 · Collector delivery idempotency.

A collector that forwards telemetry at-least-once WILL replay an envelope
after a timeout, a 5xx or a process restart.  Before this module a replay
produced a second raw row, a second canonical event, a second detection and —
for non-endpoint sources — a second incident for the SAME real-world event.

This is deliberately a SEPARATE mechanism from incident campaign
consolidation (`detection_content.xdr_incident._consolidate`):

    idempotency   answers "is this the same DELIVERY of one event?"
    consolidation answers "do these DISTINCT events belong to one campaign?"

Identity (immutable, derived only from fields the collector already sends):

    tenant_id | collector_id | source | source_event_id | sha256(raw payload)

* `tenant_id` and `collector_id` keep tenants and collectors separate — the
  same `source_event_id` from a different tenant or collector is a DIFFERENT
  event.
* `source_event_id` keeps genuinely repeated security activity separate: the
  same payload with a new id is a NEW event and is never suppressed.
* The payload digest covers the semantic event only (`raw`), never the
  volatile transport fields (`collection_timestamp`, `received_at`), so a
  retry is recognised even though its transport metadata moved on.  Including
  it also means a collector that reuses one `source_event_id` for two
  different payloads never has an event silently dropped.

The claim is an atomic `insert_one` against a UNIQUE index, so it is correct
across concurrent workers and survives a process restart — no timing
heuristic, no in-memory cache.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

from pymongo import ASCENDING, MongoClient
from pymongo.errors import DuplicateKeyError

COLLECTION = "xdr_ingest_dedupe"

_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME = os.environ.get("DB_NAME") or "test_database"
_client = MongoClient(_MONGO_URL) if _MONGO_URL else None
_index_ready = False


def _coll():
    global _index_ready
    if _client is None:
        return None
    c = _client[_DB_NAME][COLLECTION]
    if not _index_ready:
        c.create_index([("key", ASCENDING)], unique=True, name="uniq_event_key")
        c.create_index([("tenant_id", ASCENDING), ("collector_id", ASCENDING)],
                       name="tenant_collector")
        _index_ready = True
    return c


def _digest(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str,
                   separators=(",", ":")).encode("utf-8")).hexdigest()


def event_identity(tenant_id: str, collector_id: str, source: str | None,
                   source_event_id: str | None, raw: Any) -> dict:
    """Immutable identity of ONE collector delivery."""
    payload_digest = _digest(raw if raw is not None else {})
    sei = source_event_id if source_event_id else "__no_source_event_id__"
    material = "\x1f".join([
        str(tenant_id or ""), str(collector_id or ""), str(source or ""),
        str(sei), payload_digest,
    ])
    return {
        "key": hashlib.sha256(material.encode("utf-8")).hexdigest(),
        "tenant_id": tenant_id,
        "collector_id": collector_id,
        "source": source,
        "source_event_id": source_event_id,
        "payload_digest": payload_digest,
        "has_source_event_id": bool(source_event_id),
    }


def claim(identity: dict) -> tuple[str, dict | None]:
    """Atomically claim this delivery.

    Returns ``("FRESH", record)`` for a first delivery, ``("DUPLICATE",
    existing_record)`` for a retry, or ``("UNAVAILABLE", None)`` when the
    store is unbound (the caller then processes normally rather than dropping
    telemetry — availability of ingest outranks de-duplication).
    """
    c = _coll()
    if c is None:
        return "UNAVAILABLE", None
    now = datetime.now(timezone.utc).isoformat()
    doc = {**identity, "status": "CLAIMED", "first_seen_at": now,
           "last_seen_at": now, "delivery_count": 1, "retry_count": 0,
           "trace_id": None, "canonical_event_id": None,
           "observation_id": None, "incident_id": None,
           "incident_created": None}
    try:
        c.insert_one(dict(doc))
        return "FRESH", doc
    except DuplicateKeyError:
        existing = c.find_one_and_update(
            {"key": identity["key"]},
            {"$set": {"last_seen_at": now},
             "$inc": {"delivery_count": 1, "retry_count": 1}},
            return_document=True)
        return "DUPLICATE", existing


def record_outcome(key: str, *, trace_id: str | None = None,
                   canonical_event_id: str | None = None,
                   observation_id: str | None = None,
                   incident_id: str | None = None,
                   incident_created: bool | None = None,
                   status: str = "PROCESSED") -> None:
    """Bind the resulting provenance chain to the claim so a later retry can
    point at the ORIGINAL event instead of producing a new one."""
    c = _coll()
    if c is None:
        return
    patch = {"status": status,
             "processed_at": datetime.now(timezone.utc).isoformat()}
    for k, v in (("trace_id", trace_id),
                 ("canonical_event_id", canonical_event_id),
                 ("observation_id", observation_id),
                 ("incident_id", incident_id),
                 ("incident_created", incident_created)):
        if v is not None:
            patch[k] = v
    c.update_one({"key": key}, {"$set": patch})


def release(key: str) -> None:
    """Drop a claim whose processing never completed, so the collector's next
    retry is treated as a first delivery rather than silently swallowed."""
    c = _coll()
    if c is not None:
        c.delete_one({"key": key, "status": "CLAIMED"})
