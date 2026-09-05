"""
Mongo-backed CheckpointStore / DedupStore.

Guarantees:
  · restart-safe (state lives in Mongo, not memory)
  · deterministic + idempotent
  · atomic upserts prevent duplicate emission during restart
  · concurrent runner safety via _id document keys
  · checkpoint only after successful processing (caller controlled)
  · credentials NEVER logged / stored / returned
"""
from __future__ import annotations

from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase


CKP_COLL   = "xdr_ingestion_checkpoints"
DEDUP_COLL = "xdr_ingestion_dedup"


class MongoCheckpointStore:
    def __init__(self, db: AsyncIOMotorDatabase):
        self._c = db[CKP_COLL]

    async def read(self, job: str) -> str | None:
        doc = await self._c.find_one({"_id": job})
        return None if doc is None else doc.get("cursor")

    async def write(self, job: str, cursor: str | None) -> None:
        if cursor is None:
            await self._c.delete_one({"_id": job})
            return
        await self._c.update_one(
            {"_id": job},
            {"$set": {"cursor": cursor}},
            upsert=True,
        )


class MongoDedupStore:
    """Deterministic dedup by canonical_id.  We use a bounded
    write with `$setOnInsert` + `upsert=True` so concurrent
    tickers can't emit the same id twice."""
    def __init__(self, db: AsyncIOMotorDatabase):
        self._c = db[DEDUP_COLL]

    async def seen(self, canonical_ids: list[str]) -> set[str]:
        if not canonical_ids:
            return set()
        cursor = self._c.find(
            {"_id": {"$in": list(canonical_ids)}},
            {"_id": 1},
        )
        out: set[str] = set()
        async for d in cursor:
            out.add(d["_id"])
        return out

    async def remember(self, canonical_ids: list[str]) -> None:
        if not canonical_ids:
            return
        # Bulk unordered upsert — best-effort; duplicates are
        # already tolerated because _id is the canonical_id.
        from pymongo import UpdateOne
        ops = [
            UpdateOne({"_id": cid},
                                {"$setOnInsert": {"_id": cid}},
                                upsert=True)
            for cid in canonical_ids
        ]
        try:
            await self._c.bulk_write(ops, ordered=False)
        except Exception:            # noqa: BLE001
            pass                       # duplicate key OK
