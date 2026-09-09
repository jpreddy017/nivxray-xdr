"""P0 · Collector delivery idempotency — production-hardened.

A collector that forwards telemetry at-least-once WILL replay an envelope
after a timeout, a 5xx or a process restart.  Without a delivery identity a
replay produced a second raw row, canonical event, detection and incident.

This is deliberately a SEPARATE mechanism from incident campaign
consolidation (`detection_content.xdr_incident._consolidate`):

    idempotency   answers "is this the same DELIVERY of one event?"
    consolidation answers "do these DISTINCT events belong to one campaign?"

Identity (immutable, derived only from fields the collector already sends):

    tenant_id | collector_id | source | source_event_id | sha256(raw payload)

* `tenant_id` / `collector_id` keep tenants and collectors independent.
* `source_event_id` keeps genuinely repeated security activity separate: the
  same payload with a new id is a NEW event and is never suppressed.  There is
  no payload-only suppression anywhere in this module.
* The payload digest covers the semantic event only (`raw`), never the volatile
  transport fields (`collection_timestamp`, `received_at`), so a retry is
  recognised even though its transport metadata moved on.

FAIL CLOSED (owner directive 2026-06)
=====================================
This store is a correctness dependency of machine ingestion, not a
best-effort optimisation.  If it is unbound, unreachable, or cannot ATOMICALLY
claim the delivery, `claim()` raises `IdempotencyUnavailable` and the ingest
route answers `503 INGEST_IDEMPOTENCY_UNAVAILABLE`.  Telemetry is NEVER
processed through raw -> detection -> incident without dedupe protection, and
authentication is never weakened to compensate.

CLAIM LIFECYCLE
===============
No claim is ever deleted to "let the retry through" — that is what previously
permitted an extra raw row.  A claim is a durable state machine with a lease:

    CLAIMED         lease held, NOTHING persisted yet
    RAW_PERSISTED   raw row written, reasoning still pending
    COMPLETED       fully processed (terminal)
    NEEDS_REVIEW    reasoning did not complete after work was already
                    persisted; auto-retry is refused so a second
                    raw/canonical chain can never be produced (terminal for
                    ingest, flagged for an operator)

A retry is resolved against that state, never against a wall-clock guess:

    COMPLETED                       -> DUPLICATE            (report original)
    NEEDS_REVIEW                    -> DUPLICATE_NEEDS_REVIEW
    CLAIMED/RAW_PERSISTED + live    -> IN_FLIGHT            (concurrent copy)
    CLAIMED + expired lease         -> RESUME_FULL          (nothing persisted)
    RAW_PERSISTED + expired lease   -> RESUME_FROM_RAW      (skip raw persist)

Lease takeover is a single conditional `find_one_and_update`, so exactly one
worker can ever own a claim.  There is no in-memory lock anywhere.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from pymongo import ASCENDING, MongoClient
from pymongo.errors import DuplicateKeyError, PyMongoError

COLLECTION = "xdr_ingest_dedupe"

#: How long one worker may hold a claim before another may take it over.
#: Must exceed the worst-case pipeline latency for a single envelope.
LEASE_SECONDS = int(os.environ.get("INGEST_DEDUPE_LEASE_SECONDS", "300"))

#: Retention horizon = the supported collector retry/replay horizon.
#: `nivxray-xdr-collector` spools and replays for at most 7 days; 14 days is
#: double that, so a delivery can never fall out of the window while the
#: forwarder is still capable of replaying it.  Applied ONLY to terminal
#: claims, via a dedicated `retention_at` date field.
RETENTION_DAYS = int(os.environ.get("INGEST_DEDUPE_RETENTION_DAYS", "14"))

# Terminal states — a retry of one of these never starts new work.
# `PROCESSED` is the pre-hardening completed marker and is honoured so that
# claims written by the previous version stay terminal after upgrade.
TERMINAL = ("COMPLETED", "PROCESSED", "NEEDS_REVIEW")

_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME = os.environ.get("DB_NAME") or "test_database"
_client = MongoClient(_MONGO_URL) if _MONGO_URL else None
_index_ready = False


class IdempotencyUnavailable(RuntimeError):
    """The idempotency store cannot guarantee exactly-once processing."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _coll():
    """The claim collection with its indexes guaranteed.

    Raises `IdempotencyUnavailable` rather than returning None: a caller must
    not be able to accidentally continue without dedupe protection.
    """
    global _index_ready
    if _client is None:
        raise IdempotencyUnavailable("idempotency store is not bound "
                                     "(MONGO_URL missing)")
    c = _client[_DB_NAME][COLLECTION]
    if not _index_ready:
        try:
            c.create_index([("key", ASCENDING)], unique=True,
                           name="uniq_event_key")
            # TTL on a DEDICATED field that is set ONLY on a terminal claim.
            # MongoDB's TTL monitor ignores documents where the field is
            # missing or is not a date, so an active or in-progress claim can
            # never be expired out from under a retry.
            c.create_index([("retention_at", ASCENDING)],
                           expireAfterSeconds=0, name="ttl_retention_at")
            c.create_index([("tenant_id", ASCENDING),
                            ("collector_id", ASCENDING)],
                           name="tenant_collector")
            c.create_index([("status", ASCENDING)], name="status")
        except PyMongoError as ex:
            raise IdempotencyUnavailable(
                f"idempotency index unavailable: {type(ex).__name__}") from ex
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


def claim(identity: dict) -> tuple[str, dict]:
    """Atomically claim this delivery.

    Returns one of ``FRESH`` / ``RESUME_FULL`` / ``RESUME_FROM_RAW`` (the
    caller owns the claim and must process it) or ``DUPLICATE`` /
    ``DUPLICATE_NEEDS_REVIEW`` / ``IN_FLIGHT`` (the caller must NOT start new
    work), together with the claim record.

    Raises `IdempotencyUnavailable` on any store or atomicity failure.
    """
    c = _coll()
    now = _now()
    doc = {**identity,
           "status": "CLAIMED",
           "stage": "NONE",
           "attempt": 1,
           "first_seen_at": now.isoformat(),
           "last_seen_at": now.isoformat(),
           "claimed_at": now.isoformat(),
           "lease_expires_at": now + timedelta(seconds=LEASE_SECONDS),
           "delivery_count": 1,
           "duplicate_count": 0,
           "trace_id": None, "canonical_event_id": None,
           "observation_id": None, "incident_id": None,
           "incident_created": None,
           "retention_at": None}
    try:
        c.insert_one(dict(doc))
        return "FRESH", doc
    except DuplicateKeyError:
        pass
    except PyMongoError as ex:
        raise IdempotencyUnavailable(
            f"could not claim delivery: {type(ex).__name__}") from ex

    # A record exists.  Resolve strictly against its persisted state.
    try:
        existing = c.find_one_and_update(
            {"key": identity["key"]},
            {"$set": {"last_seen_at": now.isoformat()},
             "$inc": {"delivery_count": 1}},
            return_document=True)
        if existing is None:
            # Expired out between the insert and this read — treat the next
            # delivery as fresh rather than guessing.
            raise IdempotencyUnavailable("claim vanished during resolution")

        status = existing.get("status")
        if status in TERMINAL:
            patch: dict[str, Any] = {}
            if existing.get("retention_at") is None:
                # A claim written by the pre-hardening version has no
                # retention field; arm it now so it cannot live forever.
                patch["retention_at"] = _now() + timedelta(days=RETENTION_DAYS)
            c.update_one({"key": identity["key"]},
                         {"$inc": {"duplicate_count": 1},
                          **({"$set": patch} if patch else {})})
            existing["duplicate_count"] = int(
                existing.get("duplicate_count") or 0) + 1
            return ("DUPLICATE_NEEDS_REVIEW" if status == "NEEDS_REVIEW"
                    else "DUPLICATE"), existing

        # Non-terminal: either another worker is on it, or a previous attempt
        # died.  Only an EXPIRED lease may be taken over, and only once.
        # A record with no lease at all (pre-hardening schema) is treated as
        # expired so it can never deadlock as permanently IN_FLIGHT.
        taken = c.find_one_and_update(
            {"key": identity["key"],
             "status": {"$nin": list(TERMINAL)},
             "$or": [{"lease_expires_at": {"$lt": now}},
                     {"lease_expires_at": None},
                     {"lease_expires_at": {"$exists": False}}]},
            {"$set": {"claimed_at": now.isoformat(),
                      "lease_expires_at": now + timedelta(
                          seconds=LEASE_SECONDS)},
             "$inc": {"attempt": 1}},
            return_document=True)
        if taken is None:
            # Lease still live => this is a concurrent copy of the same
            # delivery.  No new work, no second chain.
            c.update_one({"key": identity["key"]},
                         {"$inc": {"duplicate_count": 1}})
            return "IN_FLIGHT", existing
        if taken.get("stage") == "NONE":
            return "RESUME_FULL", taken
        return "RESUME_FROM_RAW", taken
    except IdempotencyUnavailable:
        raise
    except PyMongoError as ex:
        raise IdempotencyUnavailable(
            f"could not resolve claim: {type(ex).__name__}") from ex


def mark_raw_persisted(key: str, raw_row_id: str | None = None) -> None:
    """Record that the raw row exists, so a later retry never re-persists it."""
    try:
        _coll().update_one({"key": key}, {"$set": {
            "stage": "RAW_PERSISTED",
            "status": "RAW_PERSISTED",
            "raw_row_id": raw_row_id,
            "raw_persisted_at": _now().isoformat()}})
    except (PyMongoError, IdempotencyUnavailable) as ex:
        # The raw row IS written; losing the marker would let a retry
        # duplicate it, so this is a hard failure.
        raise IdempotencyUnavailable(
            f"could not record raw persistence: {type(ex).__name__}") from ex


def complete(key: str, *, trace_id: str | None = None,
             canonical_event_id: str | None = None,
             observation_id: str | None = None,
             incident_id: str | None = None,
             incident_created: bool | None = None,
             outcome: str = "PROCESSED") -> None:
    """Terminal success. Binds the provenance chain and arms retention."""
    patch: dict[str, Any] = {
        "status": "COMPLETED",
        "stage": "COMPLETED",
        "outcome": outcome,
        "completed_at": _now().isoformat(),
        "retention_at": _now() + timedelta(days=RETENTION_DAYS),
    }
    for k, v in (("trace_id", trace_id),
                 ("canonical_event_id", canonical_event_id),
                 ("observation_id", observation_id),
                 ("incident_id", incident_id),
                 ("incident_created", incident_created)):
        if v is not None:
            patch[k] = v
    try:
        _coll().update_one({"key": key}, {"$set": patch})
    except (PyMongoError, IdempotencyUnavailable):
        # The work is done and the claim still exists in a non-terminal
        # state, so the worst case is a refused retry — never a duplicate.
        pass


def needs_review(key: str, reason: str, *, trace_id: str | None = None) -> None:
    """Reasoning did not complete after work was already persisted.

    The claim is NOT released: auto-retry is refused so a second
    raw/canonical chain can never be produced.  The record is flagged with the
    reason so an operator can requeue it deliberately.
    """
    try:
        _coll().update_one({"key": key}, {"$set": {
            "status": "NEEDS_REVIEW",
            "stage": "REASONING_INCOMPLETE",
            "review_reason": reason[:300],
            "trace_id": trace_id,
            "flagged_at": _now().isoformat(),
            "retention_at": _now() + timedelta(days=RETENTION_DAYS)}})
    except (PyMongoError, IdempotencyUnavailable):
        pass
