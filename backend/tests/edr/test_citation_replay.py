import asyncio
import os
import uuid
from unittest.mock import AsyncMock
import pytest
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import DuplicateKeyError
from detection_content.citation_replay import persist_citations
from edr_plane.canonical_bridge import CANONICAL_EVENT_ID_AUTHORITY

ROW = {"tenant_id": "t", "canonical_event_id": "e", "rule_id": "r",
       "rule_version": "1", "engine_id": "engine", "evaluated_at": "first",
       "matched_conditions": [{"field": "pid", "value": 12}]}

@pytest.mark.asyncio
@pytest.mark.parametrize("pattern", [None, {"unrelated": 1}])
async def test_unrelated_collision_propagates(pattern):
    coll = AsyncMock()
    coll.insert_one.side_effect = DuplicateKeyError("collision", 11000, {"keyPattern": pattern})
    with pytest.raises(DuplicateKeyError):
        await persist_citations(coll, [ROW], protected=True)
    coll.find_one.assert_not_awaited()

@pytest.mark.asyncio
async def test_missing_winner_propagates():
    coll = AsyncMock()
    coll.insert_one.side_effect = DuplicateKeyError("collision", 11000, {"keyPattern": {"_id": 1}})
    coll.find_one.return_value = None
    with pytest.raises(DuplicateKeyError):
        await persist_citations(coll, [ROW], protected=True)

@pytest.mark.asyncio
async def test_legacy_caller_uses_existing_bulk_insert():
    coll = AsyncMock()
    await persist_citations(coll, [ROW])
    coll.insert_many.assert_awaited_once_with([ROW])
    coll.insert_one.assert_not_awaited()

@pytest.mark.asyncio
async def test_protected_missing_identity_is_rejected():
    coll = AsyncMock()
    with pytest.raises(ValueError):
        await persist_citations(coll, [{**ROW, "tenant_id": None}], protected=True)
    coll.insert_one.assert_not_awaited()

local = pytest.mark.skipif(os.environ.get("NIVX_LOCAL_CITATION_TEST") != "1",
                          reason="explicit local MongoDB opt-in required")
def local_db():
    client = AsyncIOMotorClient("mongodb://127.0.0.1:27017", serverSelectionTimeoutMS=2000)
    db = client["nivx_citation_" + uuid.uuid4().hex]
    print("RETAINED_TEST_DATABASE", db.name)
    return client, db

@local
@pytest.mark.asyncio
async def test_real_rule_citation_persists_with_matching_source_values():
    """Exercise real parsing, rules and persistence in a fresh synthetic DB."""
    from detection_content.xdr_pipeline import process_event_through_pipeline
    from detection_content.library.models import resolve_field
    client, db = local_db()
    raw = {"activity": "PROCESS", "collection_method": "PROC_POLL",
           "pid": 12001, "image": "/usr/bin/bash",
           "command_line": "/bin/bash /tmp/payload.sh",
           "observed_at": "2026-11-04T07:00:00+00:00"}
    try:
        result = await process_event_through_pipeline(
            db, raw, trace_id="synthetic-citation-acceptance",
            integration_id="nivxforge-linux-sensor",
            collector_id="ep-synthetic-citation", tenant_id="tenant-synthetic")
        assert not result.get("blocker")
        row = await db.xdr_detection_matches.find_one({
            "tenant_id": "tenant-synthetic", "rule_id": "EDR-LNX-002",
            "declaration_state": "DECLARED"})
        assert row and row["rule_result"] == "MATCH"
        assert row["rule_version"] and row["engine_id"] and row["evaluated_at"]
        source = await db.xdr_canonical_evidence.find_one({
            "tenant_id": "tenant-synthetic", "event_id": row["canonical_event_id"]})
        assert source and row["matched_conditions"]
        assert row["evidence_ref"].endswith(source["event_id"])
        for condition in row["matched_conditions"]:
            observed, state = resolve_field(source, condition["canonical_field"])
            assert state == "PRESENT"
            assert observed == condition["observed_value"]
            assert condition["evidence_ref"] == row["evidence_ref"]
    finally:
        client.close()

@local
@pytest.mark.asyncio
async def test_concurrent_replay_timestamp_conflict_and_scope():
    client, db = local_db()
    coll = db["citations"]
    try:
        await asyncio.gather(*[persist_citations(coll, [ROW], protected=True) for _ in range(20)])
        await persist_citations(coll, [{**ROW, "evaluated_at": "later"}], protected=True)
        assert await coll.count_documents({}) == 1
        assert (await coll.find_one({}))["evaluated_at"] == "first"
        with pytest.raises(ValueError, match="conflicting input"):
            await persist_citations(coll, [{**ROW, "matched_conditions": []}], protected=True)
        for delta in [{"tenant_id": "other"}, {"canonical_event_id": "other"}, {"rule_version": "2"}]:
            await persist_citations(coll, [{**ROW, **delta}], protected=True)
        assert await coll.count_documents({}) == 4
    finally:
        client.close()

@local
@pytest.mark.asyncio
async def test_actual_pipeline_retry_after_citation_write(monkeypatch):
    from detection_content import xdr_pipeline as p
    client, db = local_db()
    raw = {"activity": "PROCESS", "collection_method": "PROC_POLL",
           "pid": 12, "image": "echo", "command_line": "echo synthetic",
           "observed_at": "2026-11-02T00:00:00+00:00",
           "_authenticated_ingest": {
               "canonical_event_id": "cev_synthetic_0",
               "canonical_event_id_authority": CANONICAL_EVENT_ID_AUTHORITY,
               "source_kind": "ENDPOINT_SENSOR", "trust_state": "AUTHENTICATED",
               "raw_id": "raw_synthetic", "replay_generation": 0,
               "authenticated_endpoint_id": "ep-audit"}}
    monkeypatch.setattr(p, "evaluate_detection", lambda c: {
        "status": "RULE_MATCH", "matched": True, "engine_id": "synthetic",
        "rule_id": "synthetic", "detections": [{
            "rule_id": "synthetic", "rule_version": "1", "name": "synthetic",
            "severity": "low", "citation": {"matched_conditions": [{"pid": 12}]}}]})
    monkeypatch.setattr(p, "iue_understand", lambda *a: {
        "iue_id": "synthetic", "entities": [], "capability_tags": [],
        "severity_hint": "low", "confidence": "high", "engine_id": "synthetic"})
    monkeypatch.setattr(p, "ice_correlate", AsyncMock(side_effect=RuntimeError("injected after citations")))
    try:
        for _ in range(2):
            with pytest.raises(RuntimeError, match="injected after citations"):
                await p.process_event_through_pipeline(db, raw, trace_id="raw_synthetic",
                    integration_id="nivxforge-linux-sensor", collector_id="ep-audit", tenant_id="t")
        assert await db[p.CANONICAL_COLLECTION].count_documents({}) == 1
        assert await db[p.DETECTION_MATCH_COLLECTION].count_documents({}) == 1
    finally:
        client.close()

@local
@pytest.mark.asyncio
async def test_partial_multi_citation_write_can_resume():
    client, db = local_db()
    coll = db["citations"]
    class Interrupted:
        def __init__(self):
            self.calls = 0
        async def insert_one(self, doc):
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("injected mid-list failure")
            return await coll.insert_one(doc)
        async def find_one(self, query):
            return await coll.find_one(query)
    rows = [ROW, {**ROW, "rule_id": "second-rule"}]
    try:
        with pytest.raises(RuntimeError, match="mid-list"):
            await persist_citations(Interrupted(), rows, protected=True)
        assert await coll.count_documents({}) == 1
        await persist_citations(coll, rows, protected=True)
        assert await coll.count_documents({}) == 2
    finally:
        client.close()
