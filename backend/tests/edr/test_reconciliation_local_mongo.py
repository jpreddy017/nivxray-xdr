"""Opt-in local MongoDB recovery tests; synthetic databases are retained."""
import asyncio
import os
import uuid
from datetime import datetime, timezone
import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient
from edr_plane import processing_queue as q
from edr_plane.reconciliation import CURSORS, RAW, reconcile_page

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(os.environ.get("NIVX_LOCAL_RECONCILIATION_TEST") != "1",
                      reason="explicit local MongoDB test opt-in required"),
]

def local_db():
    client = AsyncIOMotorClient("mongodb://127.0.0.1:27017",
                               serverSelectionTimeoutMS=2000)
    db = client["nivx_reconcile_" + uuid.uuid4().hex]
    print("RETAINED_TEST_DATABASE", db.name)
    return client, db

def raw(i, **extra):
    return {"tenant_id": "tenant-" + str(i % 2), "raw_id": "raw-" + str(i),
            "processing_contract": q.PROCESSING_CONTRACT,
            "trust_state": "AUTHENTICATED",
            "ingest_time": "2020-01-01T00:00:00+00:00", **extra}

async def test_more_than_500_old_records_restart_and_arrivals():
    client, db = local_db()
    try:
        await q.ensure_indexes(db)
        await db[RAW].insert_many([raw(i) for i in range(600)])
        for i in range(500):
            await q.enqueue(db, tenant_id=raw(i)["tenant_id"], raw_id=raw(i)["raw_id"])
        await db[RAW].insert_many([
            raw(900, processing_contract="legacy"),
            raw(901, trust_state="UNAUTHENTICATED")])
        a = await q.reconcile_missing_jobs(db)
        assert a == {"scanned": 500, "created": 0, "already_present": 500}
        await db[RAW].insert_one(raw(600))
        # New client: progress must not depend on process-local memory.
        other = AsyncIOMotorClient("mongodb://127.0.0.1:27017")
        try:
            b = await q.reconcile_missing_jobs(other[db.name])
        finally:
            other.close()
        assert b == {"scanned": 100, "created": 100, "already_present": 0}
        assert await db[q.COLLECTION].count_documents({}) == 600
        await q.reconcile_missing_jobs(db)
        c = await q.reconcile_missing_jobs(db)
        assert c["created"] == 1
        assert await db[q.COLLECTION].count_documents({}) == 601
        assert await db[q.COLLECTION].count_documents({"raw_id": {"$in": ["raw-900", "raw-901"]}}) == 0
        assert await db[RAW].count_documents({}) == 603
    finally:
        client.close()

async def test_failure_mid_page_replays_without_losing_progress():
    client, db = local_db()
    try:
        await q.ensure_indexes(db)
        await db[RAW].insert_many([raw(i) for i in range(8)])
        calls = 0
        async def fail_after_write(db, **kw):
            nonlocal calls
            result = await q.enqueue(db, **kw)
            calls += 1
            if calls == 3:
                raise RuntimeError("simulated crash after durable enqueue")
            return result
        with pytest.raises(RuntimeError):
            await reconcile_page(db, enqueue=fail_after_write,
                                 contract=q.PROCESSING_CONTRACT, limit=5)
        state = await db[CURSORS].find_one({"_id": q.PROCESSING_CONTRACT})
        assert state["after"] is None
        a = await q.reconcile_missing_jobs(db, limit=5)
        assert a["already_present"] == 3 and a["created"] == 2
        await q.reconcile_missing_jobs(db, limit=5)
        assert await db[q.COLLECTION].count_documents({}) == 8
        assert await db[RAW].count_documents({}) == 8
    finally:
        client.close()

async def test_concurrent_scanners_preserve_unique_jobs_and_tenants():
    client, db = local_db()
    try:
        await q.ensure_indexes(db)
        await db[RAW].insert_many([raw(i) for i in range(120)])
        await db[RAW].insert_one(raw(0, tenant_id="another-tenant"))
        for _ in range(8):
            await asyncio.gather(*[
                q.reconcile_missing_jobs(db, limit=20) for _ in range(8)])
        assert await db[q.COLLECTION].count_documents({}) == 121
        assert await db[q.COLLECTION].count_documents({"raw_id": "raw-0"}) == 2
        assert await db[q.COLLECTION].count_documents({"state": q.PENDING, "attempts": 0}) == 121
    finally:
        client.close()

async def test_late_record_behind_cursor_is_found_on_next_sweep():
    client, db = local_db()
    try:
        await q.ensure_indexes(db)
        await db[RAW].insert_many([raw(i) for i in range(4)])
        await q.reconcile_missing_jobs(db, limit=2)
        old_id = ObjectId.from_datetime(datetime(2000, 1, 1, tzinfo=timezone.utc))
        await db[RAW].insert_one(raw(99, _id=old_id))
        for _ in range(5):
            await q.reconcile_missing_jobs(db, limit=2)
        assert await db[q.COLLECTION].count_documents({}) == 5
        assert await db[RAW].count_documents({}) == 5
    finally:
        client.close()
