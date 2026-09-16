"""v2/artifact_store/store.py · Persistence + query helpers.

Idempotency contract
--------------------
Given `(sha256, kind)` uniquely identifies an artifact, every writer
uses upsert semantics keyed on `artifact_iid`. Two ingest runs that
see the same command line produce ONE row, with `related_case_ids` /
`related_observation_iids` / `related_entity_iids` grown by set-union
and the chain-of-custody log grown by append. Nothing is ever
overwritten — the store is append-only per DFIR requirements.
"""
from __future__ import annotations
from typing import Any
from motor.motor_asyncio import AsyncIOMotorDatabase

from v2.case_engine.schema import COLLECTIONS
from .schema import (
    Artifact, CustodyEvent, CustodyAction,
    build_artifact_iid, compute_sha256, now_iso,
    ARTIFACT_SCHEMA_VERSION,
)

_C = COLLECTIONS["artifacts"]  # "v2_artifact_store"


# ─── Writes ──────────────────────────────────────────────────────────

async def create_or_update(
    db: AsyncIOMotorDatabase,
    *,
    kind: str,
    value: str = "",
    sha256: str | None = None,
    mime_type: str = "text/plain",
    size: int | None = None,
    acquisition_time: str = "",
    source: str = "manual",
    provenance: dict[str, Any] | None = None,
    case_id: str | None = None,
    entity_iid: str | None = None,
    observation_iid: str | None = None,
    actor: str = "system",
) -> Artifact:
    """Idempotent upsert of an Artifact.

    The (sha256, kind) tuple is the identity — two calls with the same
    payload return the SAME `artifact_iid` and merge related-ID lists.
    """
    if sha256 is None:
        sha256 = compute_sha256(value)
    sha256 = sha256.lower()
    if size is None:
        size = len(value.encode("utf-8")) if value else 0
    artifact_iid = build_artifact_iid(sha256, kind)
    ts = now_iso()

    # First-write payload — everything under $setOnInsert is applied
    # only if the row doesn't exist. Subsequent calls only merge lists.
    on_insert: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "artifact_iid":   artifact_iid,
        "sha256":         sha256,
        "kind":           kind,
        "value":          value,
        "mime_type":      mime_type,
        "size":           size,
        "acquisition_time": acquisition_time or ts,
        "created_at":     ts,
        "source":         source,
        "provenance":     provenance or {},
    }

    # Additive-only merges — never touch identity or content fields.
    add_to_set: dict[str, Any] = {}
    if case_id:        add_to_set["related_case_ids"] = case_id
    if entity_iid:     add_to_set["related_entity_iids"] = entity_iid
    if observation_iid:add_to_set["related_observation_iids"] = observation_iid

    update: dict[str, Any] = {"$setOnInsert": on_insert}
    if add_to_set:
        update["$addToSet"] = add_to_set

    await db[_C].update_one({"artifact_iid": artifact_iid}, update, upsert=True)

    # Append a single custody event describing this write. We log every
    # ingest so the chain of custody reflects every touch, even
    # idempotent re-writes.
    action: CustodyAction = "ingested"
    detail_parts = [f"source={source}"]
    if case_id:         detail_parts.append(f"case={case_id}")
    if observation_iid: detail_parts.append(f"observation={observation_iid}")
    if entity_iid:      detail_parts.append(f"entity={entity_iid}")
    custody = CustodyEvent(
        ts=ts, actor=actor, action=action,
        detail=" · ".join(detail_parts),
    ).model_dump()
    await db[_C].update_one(
        {"artifact_iid": artifact_iid},
        {"$push": {"chain_of_custody": custody}},
    )

    doc = await db[_C].find_one({"artifact_iid": artifact_iid})
    return _to_model(doc)


async def append_custody(
    db: AsyncIOMotorDatabase, *,
    artifact_iid: str, actor: str, action: CustodyAction, detail: str = "",
) -> Artifact | None:
    """Append a chain-of-custody entry. Returns the refreshed artifact."""
    entry = CustodyEvent(ts=now_iso(), actor=actor, action=action,
                         detail=detail).model_dump()
    res = await db[_C].update_one(
        {"artifact_iid": artifact_iid},
        {"$push": {"chain_of_custody": entry}},
    )
    if res.matched_count == 0:
        return None
    return _to_model(await db[_C].find_one({"artifact_iid": artifact_iid}))


async def link_observation(
    db: AsyncIOMotorDatabase, artifact_iid: str, observation_iid: str,
    actor: str = "system",
) -> Artifact | None:
    return await _link(db, artifact_iid, "related_observation_iids",
                       observation_iid, actor, f"observation={observation_iid}")


async def link_entity(
    db: AsyncIOMotorDatabase, artifact_iid: str, entity_iid: str,
    actor: str = "system",
) -> Artifact | None:
    return await _link(db, artifact_iid, "related_entity_iids",
                       entity_iid, actor, f"entity={entity_iid}")


async def link_case(
    db: AsyncIOMotorDatabase, artifact_iid: str, case_id: str,
    actor: str = "system",
) -> Artifact | None:
    return await _link(db, artifact_iid, "related_case_ids",
                       case_id, actor, f"case={case_id}")


async def _link(
    db: AsyncIOMotorDatabase, artifact_iid: str, field: str,
    value: str, actor: str, detail: str,
) -> Artifact | None:
    res = await db[_C].update_one(
        {"artifact_iid": artifact_iid},
        {"$addToSet": {field: value}},
    )
    if res.matched_count == 0:
        return None
    await append_custody(db, artifact_iid=artifact_iid, actor=actor,
                         action="linked", detail=detail)
    return _to_model(await db[_C].find_one({"artifact_iid": artifact_iid}))


# ─── Reads ───────────────────────────────────────────────────────────

async def get_by_iid(db: AsyncIOMotorDatabase, artifact_iid: str) -> Artifact | None:
    doc = await db[_C].find_one({"artifact_iid": artifact_iid})
    return _to_model(doc) if doc else None


async def get_by_sha(db: AsyncIOMotorDatabase, sha256: str, kind: str | None = None) -> Artifact | None:
    q: dict[str, Any] = {"sha256": sha256.lower()}
    if kind:
        q["kind"] = kind
    doc = await db[_C].find_one(q)
    return _to_model(doc) if doc else None


async def list_by_case(
    db: AsyncIOMotorDatabase, case_id: str, *,
    kind: str | None = None, limit: int = 500,
) -> list[Artifact]:
    q: dict[str, Any] = {"related_case_ids": case_id}
    if kind:
        q["kind"] = kind
    cursor = db[_C].find(q).sort("created_at", 1).limit(limit)
    return [_to_model(doc) async for doc in cursor]


# ─── Internal helpers ────────────────────────────────────────────────

def _to_model(doc: dict | None) -> Artifact | None:
    if not doc:
        return None
    doc.pop("_id", None)
    return Artifact.model_validate(doc)
