"""Real-Mongo regression for atomic queue claims; uses disposable local fixtures.

Run from the repository root with Motor/PyMongo installed:
    python tools/edr/check_queue_claim_indexes.py
Never reads application environment files or connects to production.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorClient


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "queue_under_test", ROOT / "backend/edr_plane/processing_queue.py"
)
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


def stages(value):
    if isinstance(value, dict):
        if "stage" in value:
            yield value["stage"]
        for child in value.values():
            yield from stages(child)
    elif isinstance(value, list):
        for child in value:
            yield from stages(child)


async def main():
    client = AsyncIOMotorClient(
        "mongodb://127.0.0.1:27017", serverSelectionTimeoutMS=3000
    )
    name = "nivx_queue_regression_" + uuid4().hex
    db = client[name]
    clock = q._now
    now = datetime.now(timezone.utc)
    q._now = lambda: now
    captured = {}

    class Capture:
        async def find_one_and_update(self, query, update, **kwargs):
            captured.update(query=query, update=update, kwargs=kwargs)

    try:
        await q.claim({q.COLLECTION: Capture()})
        coll = db[q.COLLECTION]
        old = now - timedelta(days=30)
        await coll.insert_many([
            dict(tenant_id="fixture", raw_id=str(i),
                 state=q.DONE if i < 10000 else q.PENDING,
                 created_at=old + timedelta(milliseconds=i),
                 available_at=old + timedelta(milliseconds=i),
                 lease_until=None, attempts=0)
            for i in range(50000)
        ])
        # Historical indexes: establish the measured regression, then exercise
        # the actual startup index function and the actual claim query/update.
        await coll.create_index([("tenant_id", 1), ("raw_id", 1)],
                                unique=True, name="uniq_tenant_raw")
        await coll.create_index([("state", 1), ("available_at", 1),
                                 ("created_at", 1)], name="claimable_work")
        await coll.create_index([("state", 1), ("lease_until", 1)],
                                name="expired_leases")
        command = dict(findAndModify=q.COLLECTION,
                       query=captured["query"], update=captured["update"],
                       sort=dict(captured["kwargs"]["sort"]), new=True)
        before = await db.command("explain", command, verbosity="executionStats")
        await q.ensure_indexes(db)
        await q.ensure_indexes(db)  # redeploy is idempotent
        after = await db.command("explain", command, verbosity="executionStats")
        report = {}
        for label, result in (("before", before), ("after", after)):
            stats = result["executionStats"]
            report[label] = {key: stats[key] for key in
                             ("executionTimeMillis", "totalKeysExamined",
                              "totalDocsExamined")}
            report[label]["stages"] = list(stages(result["queryPlanner"]["winningPlan"]))
        assert report["before"]["totalDocsExamined"] >= 40000, report
        assert report["after"]["totalDocsExamined"] <= 10, report
        assert report["after"]["totalKeysExamined"] <= 10, report
        assert "SORT" not in report["after"]["stages"], report
        first = await q.claim(db)
        assert first["raw_id"] == "10000" and first["attempts"] == 1
        assert first["state"] == q.PROCESSING

        # This collection contains synthetic documents only. Replace them with
        # a small adversarial fixture to verify readiness, FIFO and leases.
        await coll.delete_many({})
        def job(raw_id, state, age, available=-1, lease=None):
            return dict(tenant_id="fixture", raw_id=raw_id, state=state,
                        created_at=now - timedelta(seconds=age), attempts=0,
                        available_at=now + timedelta(seconds=available),
                        lease_until=(now + timedelta(seconds=lease)
                                     if lease is not None else None))
        await coll.insert_many([
            job("done", q.DONE, 1000),
            job("future_pending", q.PENDING, 900, available=300),
            job("future_retry", q.RETRY, 800, available=300),
            job("active_lease", q.PROCESSING, 700, lease=300),
            job("expired_lease", q.PROCESSING, 600, lease=-1),
            job("ready_retry", q.RETRY, 500),
            job("ready_pending", q.PENDING, 400),
        ])
        ordered = [await q.claim(db) for _ in range(3)]
        assert [row["raw_id"] for row in ordered] == [
            "expired_lease", "ready_retry", "ready_pending"]
        assert await q.claim(db) is None
        await coll.insert_many([job("parallel_" + str(i), q.PENDING, 100 - i)
                                for i in range(16)])
        claimed = await asyncio.gather(*(q.claim(db) for _ in range(24)))
        ids = [row["raw_id"] for row in claimed if row]
        assert len(ids) == len(set(ids)) == 16, ids
        assert await coll.count_documents({"raw_id": {"$in": [
            "future_pending", "future_retry", "active_lease"]},
            "attempts": 0}) == 3
        assert await q.mark_done(db, tenant_id="fixture", raw_id="ready_pending")
        assert await q.mark_retry(db, tenant_id="fixture", raw_id="ready_retry",
                                  error="fixture retry", retry_after_seconds=30)
        assert await q.claim(db) is None
        print(json.dumps(report, indent=2))
        print("PASS: atomic query plan, FIFO, retry readiness, lease recovery, "
              "24 concurrent claims, completion, retry delay, repeat startup")
    finally:
        q._now = clock
        await client.drop_database(name)
        client.close()


if __name__ == "__main__":
    asyncio.run(main())
