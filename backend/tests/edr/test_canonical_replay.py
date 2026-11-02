import asyncio
import os
import uuid
from unittest.mock import AsyncMock
import pytest
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import DuplicateKeyError
from detection_content.canonical_replay import persist_canonical
from edr_plane.canonical_bridge import CANONICAL_EVENT_ID_AUTHORITY

def inputs(tenant="t", event="event"):
    canonical = {"tenant_id": tenant, "event_id": event,
                 "ingest_time": "original",
                 "provenance": {"trust_state": "AUTHENTICATED"}}
    raw = {"activity": "PROCESS", "pid": 12, "_authenticated_ingest": {
        "canonical_event_id": event,
        "canonical_event_id_authority": CANONICAL_EVENT_ID_AUTHORITY}}
    return canonical, raw

@pytest.mark.asyncio
@pytest.mark.parametrize("pattern", [None, {"other": 1}])
async def test_unrelated_collision_propagates(pattern):
    c, raw = inputs()
    coll = AsyncMock()
    coll.insert_one.side_effect = DuplicateKeyError("collision", 11000, {"keyPattern": pattern})
    with pytest.raises(DuplicateKeyError):
        await persist_canonical(coll, c, raw)
    coll.find_one.assert_not_awaited()

@pytest.mark.asyncio
async def test_missing_winner_propagates():
    c, raw = inputs()
    coll = AsyncMock()
    coll.insert_one.side_effect = DuplicateKeyError("collision", 11000, {"keyPattern": {"_id": 1}})
    coll.find_one.return_value = None
    with pytest.raises(DuplicateKeyError):
        await persist_canonical(coll, c, raw)

@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["no-envelope", "wrong-authority", "untrusted"])
async def test_unprotected_call_preserves_legacy_insert(change):
    c, raw = inputs()
    if change == "no-envelope":
        raw.pop("_authenticated_ingest")
    elif change == "wrong-authority":
        raw["_authenticated_ingest"]["canonical_event_id_authority"] = "untrusted"
    else:
        c["provenance"]["trust_state"] = "UNKNOWN"
    coll = AsyncMock()
    coll.insert_one.return_value.inserted_id = "legacy-id"
    out, record_id = await persist_canonical(coll, c, raw)
    assert out == c and record_id == "legacy-id"
    assert "processing_receipt" not in coll.insert_one.call_args.args[0]

local = pytest.mark.skipif(os.environ.get("NIVX_LOCAL_CANONICAL_TEST") != "1",
                          reason="explicit local MongoDB test opt-in required")

@local
@pytest.mark.asyncio
async def test_concurrent_retry_preserves_first_record_and_tenant_generation():
    client = AsyncIOMotorClient("mongodb://127.0.0.1:27017", serverSelectionTimeoutMS=2000)
    db = client["nivx_canonical_" + uuid.uuid4().hex]
    print("RETAINED_TEST_DATABASE", db.name)
    coll = db["xdr_canonical_evidence"]
    try:
        c, raw = inputs()
        results = await asyncio.gather(*[persist_canonical(coll, c, raw) for _ in range(20)])
        assert all(r == results[0] for r in results)
        later, identity = await persist_canonical(coll, {**c, "ingest_time": "later"}, raw)
        assert later["ingest_time"] == "original"
        assert await coll.count_documents({}) == 1
        with pytest.raises(ValueError, match="conflicting input"):
            await persist_canonical(coll, c, {**raw, "pid": 99})
        assert await coll.count_documents({}) == 1
        for tenant, event in [("other", "event"), ("t", "event-generation-2")]:
            other_c, other_raw = inputs(tenant, event)
            await persist_canonical(coll, other_c, other_raw)
        assert await coll.count_documents({}) == 3
    finally:
        client.close()

@local
@pytest.mark.asyncio
async def test_actual_pipeline_detection_failure_retry_keeps_one_canonical(monkeypatch):
    from detection_content import xdr_pipeline as pipeline
    client = AsyncIOMotorClient("mongodb://127.0.0.1:27017", serverSelectionTimeoutMS=2000)
    db = client["nivx_pipeline_canonical_" + uuid.uuid4().hex]
    print("RETAINED_TEST_DATABASE", db.name)
    event_id = "cev_synthetic_0"
    raw = {
        "activity": "PROCESS", "pid": 12, "ppid": 1,
        "observed_at": "2026-11-02T00:00:00+00:00",
        "start_time": "2026-11-01T00:00:00+00:00",
        "image_path": "/bin/echo", "image": "echo", "command_line": "echo audit",
        "endpoint_id": "ep-audit", "hostname": "audit",
        "_authenticated_ingest": {
            "canonical_event_id": event_id,
            "canonical_event_id_authority": CANONICAL_EVENT_ID_AUTHORITY,
            "source_kind": "ENDPOINT_SENSOR", "sensor_version": "synthetic-test",
            "trust_state": "AUTHENTICATED", "raw_id": "raw_synthetic",
            "replay_generation": 0, "authenticated_endpoint_id": "ep-audit"}}
    monkeypatch.setattr(pipeline, "evaluate_detection",
                        lambda canonical: {"status": "EXECUTION_FAILED", "error": "injected"})
    try:
        first = await pipeline.process_event_through_pipeline(
            db, raw, trace_id="raw_synthetic", integration_id="nivxforge-linux-sensor",
            collector_id="ep-audit", tenant_id="tenant-audit")
        second = await pipeline.process_event_through_pipeline(
            db, raw, trace_id="raw_synthetic", integration_id="nivxforge-linux-sensor",
            collector_id="ep-audit", tenant_id="tenant-audit")
        assert first["blocker"] == second["blocker"] == "detection"
        assert await db[pipeline.CANONICAL_COLLECTION].count_documents({}) == 1
        assert first["canonical"] == second["canonical"]
        assert first["canonical"]["processing_receipt"]["contract"] == "endpoint_canonical_replay_v1"
    finally:
        client.close()
