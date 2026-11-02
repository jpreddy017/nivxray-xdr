"""Local Mongo regressions; synthetic databases are retained for audit."""
import asyncio
import os
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from detection_content.xdr_incident import _consolidate, INCIDENT_COLLECTION

pytestmark = pytest.mark.skipif(
    os.getenv("NIVX_LOCAL_INCIDENT_TEST") != "1",
    reason="explicit isolated local Mongo opt-in required",
)


def seed(tenant="tenant_a", score=0):
    return {
        "id": "inc_shared", "doc_type": "xdr_incident", "tenant_id": tenant,
        "incident_state": "OPEN", "provenance": "PROVENANCE_UNKNOWN",
        "endpoint_campaign": {
            "endpoint_id": "ep_probe",
            "last_activity_at": datetime.now(timezone.utc).isoformat(),
            "max_score": score, "rule_ids": [], "detections": [],
        },
    }


def args(i=0):
    canonical = {
        "event_id": f"event_{i}",
        "additional_fields": {"endpoint_id": "ep_probe"},
    }
    detection = {"detections": [{
        "rule_id": f"rule_{i}", "name": f"Synthetic rule {i}",
        "severity": "high",
    }]}
    verdict = {"label": "SUSPICIOUS", "score": 60 + i}
    return canonical, detection, verdict, f"trace_{i}", "tenant_a", "SUSPICIOUS", 60 + i


class WrappedDB:
    def __init__(self, collection):
        self.collection = collection

    def __getitem__(self, name):
        assert name == INCIDENT_COLLECTION
        return self.collection


async def database():
    from motor.motor_asyncio import AsyncIOMotorClient
    client = AsyncIOMotorClient("mongodb://127.0.0.1:27017", serverSelectionTimeoutMS=3000)
    name = "nivx_incident_" + uuid.uuid4().hex
    print("RETAINED_TEST_DATABASE", name)
    return client, client[name]


@pytest.mark.asyncio
async def test_concurrent_observations_preserve_union_and_maximum():
    client, db = await database()
    col = db[INCIDENT_COLLECTION]
    await col.insert_one(seed())
    barrier = asyncio.Event()
    class ConcurrentRead:
        reads = 0
        async def find_one(self, *a, **kw):
            row = await col.find_one(*a, **kw)
            self.reads += 1
            if self.reads <= 8:
                if self.reads == 8:
                    barrier.set()
                await asyncio.wait_for(barrier.wait(), 5)
            return row
        async def update_one(self, *a, **kw):
            return await col.update_one(*a, **kw)
    try:
        wrapped = WrappedDB(ConcurrentRead())
        results = await asyncio.gather(*[_consolidate(wrapped, *args(i)) for i in range(8)])
        row = await col.find_one({"tenant_id": "tenant_a"})
        camp = row["endpoint_campaign"]
        assert all(r["consolidated"] for r in results)
        assert set(camp["rule_ids"]) == {f"rule_{i}" for i in range(8)}
        assert camp["max_score"] == 67
        assert row["verdict_card"]["confidence"] == 67
        assert len(camp["detections"]) == 8
        assert len(row["incident_state_history"]) == 8
    finally:
        client.close()


@pytest.mark.asyncio
async def test_write_does_not_cross_tenant_with_same_public_incident_id():
    client, db = await database()
    col = db[INCIDENT_COLLECTION]
    await col.insert_one(seed("tenant_b", 99))
    await col.insert_one(seed("tenant_a", 99))
    try:
        await _consolidate(db, *args())
        other = await col.find_one({"tenant_id": "tenant_b"})
        own = await col.find_one({"tenant_id": "tenant_a"})
        assert other["endpoint_campaign"]["detections"] == []
        assert len(own["endpoint_campaign"]["detections"]) == 1
    finally:
        client.close()


@pytest.mark.asyncio
async def test_concurrent_closure_is_not_overwritten_or_enriched():
    client, db = await database()
    col = db[INCIDENT_COLLECTION]
    await col.insert_one(seed())
    class CloseBeforeWrite:
        closed = False
        async def find_one(self, *a, **kw):
            return await col.find_one(*a, **kw)
        async def update_one(self, *a, **kw):
            if not self.closed:
                self.closed = True
                await col.update_one({"tenant_id": "tenant_a"}, {"$set": {"incident_state": "CLOSED"}})
            return await col.update_one(*a, **kw)
    try:
        assert await _consolidate(WrappedDB(CloseBeforeWrite()), *args()) is None
        row = await col.find_one({"tenant_id": "tenant_a"})
        assert row["incident_state"] == "CLOSED"
        assert row["endpoint_campaign"]["detections"] == []
    finally:
        client.close()


@pytest.mark.asyncio
async def test_contention_exhaustion_is_failure_not_false_success():
    client, db = await database()
    col = db[INCIDENT_COLLECTION]
    await col.insert_one(seed())
    class AlwaysConflicts:
        writes = 0
        async def find_one(self, *a, **kw):
            return await col.find_one(*a, **kw)
        async def update_one(self, *a, **kw):
            self.writes += 1
            return SimpleNamespace(matched_count=0)
    wrapper = AlwaysConflicts()
    try:
        with pytest.raises(RuntimeError, match="contention limit"):
            await _consolidate(WrappedDB(wrapper), *args())
        assert wrapper.writes == 16
        assert (await col.find_one({}))["endpoint_campaign"]["detections"] == []
    finally:
        client.close()
