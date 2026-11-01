"""Exercise stale-owner fencing against disposable, localhost-only Mongo jobs.

Run from repository root: python tools/edr/check_queue_lease_ownership.py
No production connection or application environment file is used.
"""
from __future__ import annotations

import asyncio
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorClient

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "queue_under_test", ROOT / "backend/edr_plane/processing_queue.py")
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


async def main():
    client = AsyncIOMotorClient("mongodb://127.0.0.1:27017",
                               serverSelectionTimeoutMS=3000)
    name = "nivx_queue_ownership_" + uuid4().hex
    db = client[name]
    clock = q._now
    now = datetime.now(timezone.utc)
    q._now = lambda: now

    async def transition(action, raw_id, attempts, tenant="fixture"):
        args = dict(tenant_id=tenant, raw_id=raw_id, attempts=attempts)
        if action == "done":
            return await q.mark_done(db, **args)
        return await q.mark_retry(db, **args, error="synthetic failure")

    async def row(raw_id):
        return await db[q.COLLECTION].find_one(
            {"tenant_id": "fixture", "raw_id": raw_id})

    try:
        await q.ensure_indexes(db)
        # A was assigned the job; its lease expires; B atomically reclaims it.
        # Neither late success nor late failure from A may alter B's work.
        for action in ("done", "retry"):
            raw_id = "reassigned_" + action
            await q.enqueue(db, tenant_id="fixture", raw_id=raw_id)
            a = await q.claim(db, lease_seconds=1)
            now += timedelta(seconds=2)
            b = await q.claim(db, lease_seconds=60)
            assert b["raw_id"] == raw_id and b["attempts"] == a["attempts"] + 1
            before = await row(raw_id)
            assert not await transition(action, raw_id, a["attempts"])
            assert await row(raw_id) == before
            assert not await transition(action, raw_id, b["attempts"], "other")
            assert await row(raw_id) == before
            assert await transition(action, raw_id, b["attempts"])
            assert (await row(raw_id))["state"] == (q.DONE if action == "done" else q.RETRY)
            # Complete the delayed retry before testing the next independent case.
            if action == "retry":
                assert await q.claim(db) is None
                now += timedelta(seconds=31)
                c = await q.claim(db)
                assert c["attempts"] == b["attempts"] + 1
                assert await q.mark_done(db, tenant_id="fixture", raw_id=raw_id,
                                         attempts=c["attempts"])

        # An expired owner cannot transition even if nobody has reclaimed yet.
        for action in ("done", "retry"):
            raw_id = "expired_" + action
            await q.enqueue(db, tenant_id="fixture", raw_id=raw_id)
            a = await q.claim(db, lease_seconds=1)
            now += timedelta(seconds=1)  # exact expiry is no longer live
            before = await row(raw_id)
            assert not await transition(action, raw_id, a["attempts"])
            assert await row(raw_id) == before
            b = await q.claim(db)
            assert b["raw_id"] == raw_id
            assert await q.mark_done(db, tenant_id="fixture", raw_id=raw_id,
                                     attempts=b["attempts"])

        # State and generation jointly guard a completed job against late retry.
        assert not await q.mark_retry(db, tenant_id="fixture", raw_id=raw_id,
                                      attempts=b["attempts"], error="late failure")
        print("PASS: reassigned success/failure fenced; current owner accepted; "
              "tenant isolation; exact-expiry rejection; retry readiness; "
              "reclaimed completion; completed-state protection")
    finally:
        q._now = clock
        await client.drop_database(name)
        client.close()


if __name__ == "__main__":
    asyncio.run(main())
