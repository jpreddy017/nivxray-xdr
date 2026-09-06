"""The immutable raw-event substrate — directive §5, owner decision 3A.

The architectural correction on record: `v2_shadow_observations` is useful
but is NOT a sufficient EDR substrate, because a normalized observation
has already lost the bytes we would need to re-reason after fixing a
parser. So raw telemetry lands here first, verbatim, and **nothing
downstream is permitted to overwrite it**.

Append-only is enforced three ways, not one:

  1. `append()` uses an idempotent insert keyed on a unique index. A
     re-delivery is recorded as a duplicate, never as a second event.
  2. There is no update function in this module. None. A caller who wants
     to change a raw event has to go around the API, which is auditable.
  3. Derived state (parser/normalizer/detection/analysis/verdict versions
     and `replay_generation`) is written to `derivations`, an APPENDED
     list. Re-reasoning adds a derivation; it never mutates the previous
     one, so the history of what we believed and when survives.

Consequence, which is the whole point: after a parser fix we can select
every raw event the old parser failed on and re-reason it, and the record
will honestly show both the original PARSER_FAILED derivation and the new
successful one.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

COLLECTION = "edr_raw_events"


class Derivation(BaseModel):
    """One pass of the pipeline over this raw event. Appended, never
    replaced."""
    model_config = ConfigDict(extra="forbid")

    replay_generation: int = 0
    derived_at: str
    parser_name: Optional[str] = None
    parser_version: Optional[str] = None
    parser_state: str = "OK"           # OK | PARTIAL | FAILED
    parser_notes: list[str] = Field(default_factory=list)
    normalizer_version: Optional[str] = None
    detection_content_version: Optional[str] = None
    analysis_version: Optional[str] = None
    verdict_version: Optional[str] = None
    event_id: Optional[str] = None
    evidence_ids: list[str] = Field(default_factory=list)
    outcome: Optional[str] = None
    reason: Optional[str] = None


class RawEndpointEvent(BaseModel):
    """The immutable original. `payload` is byte-faithful."""
    model_config = ConfigDict(extra="forbid")

    raw_id: str
    tenant_id: str
    source: str = Field(description="collector id / sensor id / adapter")
    source_kind: str = Field(default="unknown",
                             description="sensor | collector | adapter | api")
    sensor_version: Optional[str] = None

    endpoint_ref: Optional[str] = Field(
        default=None,
        description="Best-effort endpoint hint AT INGEST. Not authoritative "
                    "identity — resolution happens downstream and may "
                    "legitimately fail.")
    payload: str = Field(description="Verbatim payload, byte-for-byte.")
    payload_sha256: str
    payload_encoding: str = "utf-8"

    event_time: Optional[str] = Field(
        default=None, description="When it happened ON the endpoint. May be "
                                  "absent; that is not an error.")
    ingest_time: str = Field(description="When we learned about it.")
    received_from_ip: Optional[str] = None

    dedup_key: str = Field(
        description="Digest of the verbatim payload + tenant + source. A "
                    "replay of the same bytes cannot inflate anything.")

    telemetry_quality: str = "HEALTHY"
    trust_state: str = Field(
        default="UNAUTHENTICATED",
        description="AUTHENTICATED | UNAUTHENTICATED | REJECTED. A REJECTED "
                    "payload is retained as a SECURITY SIGNAL and must "
                    "never enter the authoritative evidence pipeline.")
    authentication: Optional[dict] = Field(
        default=None,
        description="AuthenticatedEndpoint.provenance() — the authenticated "
                    "endpoint_id, credential_id, session_id, auth_method and "
                    "device_iid that produced this exact event. This is what "
                    "lets every downstream trajectory, story and response "
                    "authorisation be attributable rather than assumed. Null "
                    "means the event predates authenticated transport.")

    derivations: list[Derivation] = Field(default_factory=list)
    duplicate_count: int = 0

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def digest(tenant_id: str, source: str, payload: str) -> str:
        return hashlib.sha256(
            f"{tenant_id}\x1f{source}\x1f{payload}".encode()).hexdigest()

    @classmethod
    def build(cls, *, tenant_id: str, source: str, payload: str,
              source_kind: str = "unknown",
              sensor_version: str | None = None,
              endpoint_ref: str | None = None,
              event_time: str | None = None,
              received_from_ip: str | None = None,
              trust_state: str = "UNAUTHENTICATED") -> "RawEndpointEvent":
        dedup = cls.digest(tenant_id, source, payload)
        return cls(
            raw_id=f"raw_{dedup[:24]}", tenant_id=tenant_id, source=source,
            source_kind=source_kind, sensor_version=sensor_version,
            endpoint_ref=endpoint_ref, payload=payload,
            payload_sha256=hashlib.sha256(payload.encode()).hexdigest(),
            event_time=event_time, ingest_time=cls.now(),
            received_from_ip=received_from_ip, dedup_key=dedup,
            trust_state=trust_state)


async def ensure_indexes(db: Any) -> None:
    await db[COLLECTION].create_index(
        [("tenant_id", 1), ("dedup_key", 1)], unique=True,
        name="uniq_tenant_dedup")
    await db[COLLECTION].create_index([("tenant_id", 1), ("ingest_time", -1)])
    await db[COLLECTION].create_index([("tenant_id", 1), ("endpoint_ref", 1)])
    await db[COLLECTION].create_index(
        [("tenant_id", 1), ("derivations.parser_state", 1)])


async def append(db: Any, event: RawEndpointEvent) -> dict[str, Any]:
    """Idempotent append. Returns what actually happened, honestly.

    A byte-identical re-delivery increments `duplicate_count` and returns
    `stored=False`. It does NOT overwrite, and it does not silently
    succeed as if it were new.
    """
    doc = event.model_dump()
    existing = await db[COLLECTION].find_one_and_update(
        {"tenant_id": event.tenant_id, "dedup_key": event.dedup_key},
        {"$inc": {"duplicate_count": 1}},
        projection={"raw_id": 1, "duplicate_count": 1})
    if existing:
        return {"stored": False, "duplicate": True,
                "raw_id": existing["raw_id"],
                "duplicate_count": (existing.get("duplicate_count", 0) + 1),
                "reason": "byte-identical payload already retained; the "
                          "original is immutable and was not modified"}
    await db[COLLECTION].insert_one(doc)
    return {"stored": True, "duplicate": False, "raw_id": event.raw_id}


async def add_derivation(db: Any, *, tenant_id: str, raw_id: str,
                         derivation: Derivation) -> dict[str, Any]:
    """Append one pipeline pass. The raw payload is untouched by design —
    this only ever `$push`es."""
    res = await db[COLLECTION].update_one(
        {"tenant_id": tenant_id, "raw_id": raw_id},
        {"$push": {"derivations": derivation.model_dump()}})
    return {"raw_id": raw_id, "appended": bool(res.modified_count),
            "replay_generation": derivation.replay_generation}


async def get(db: Any, *, tenant_id: str, raw_id: str
              ) -> Optional[dict[str, Any]]:
    return await db[COLLECTION].find_one(
        {"tenant_id": tenant_id, "raw_id": raw_id}, {"_id": 0})


async def replay_candidates(db: Any, *, tenant_id: str,
                            parser_state: str | None = None,
                            parser_version_below: str | None = None,
                            limit: int = 500) -> list[dict[str, Any]]:
    """Select raw events worth re-reasoning after an engine improvement.

    This is the mechanism that makes directive §5 real: because the bytes
    were never overwritten, a parser fix can be applied retroactively to
    exactly the events it would have changed.
    """
    q: dict[str, Any] = {"tenant_id": tenant_id}
    if parser_state:
        q["derivations.parser_state"] = parser_state
    if parser_version_below:
        q["derivations.parser_version"] = {"$lt": parser_version_below}
    cur = db[COLLECTION].find(q, {"_id": 0}).sort("ingest_time", 1).limit(limit)
    return await cur.to_list(length=limit)


async def next_generation(db: Any, *, tenant_id: str, raw_id: str) -> int:
    doc = await get(db, tenant_id=tenant_id, raw_id=raw_id)
    if not doc:
        return 0
    gens = [d.get("replay_generation", 0) for d in doc.get("derivations", [])]
    return (max(gens) + 1) if gens else 0


async def stats(db: Any, *, tenant_id: str) -> dict[str, Any]:
    coll = db[COLLECTION]
    total = await coll.count_documents({"tenant_id": tenant_id})
    failed = await coll.count_documents(
        {"tenant_id": tenant_id, "derivations.parser_state": "FAILED"})
    undervied = await coll.count_documents(
        {"tenant_id": tenant_id, "derivations": {"$size": 0}})
    rejected = await coll.count_documents(
        {"tenant_id": tenant_id, "trust_state": "REJECTED"})
    return {
        "collection": COLLECTION,
        "append_only": True,
        "total_raw_events": total,
        "parser_failed": failed,
        "never_derived": undervied,
        "rejected_untrusted": rejected,
        "honesty_note": (
            "parser_failed events are RETAINED and replayable. A parser "
            "failure is not an absence of an event. rejected_untrusted "
            "payloads are security signals and are never treated as "
            "endpoint evidence."),
    }
