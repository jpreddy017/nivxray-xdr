import asyncio
import os
import uuid
from unittest.mock import AsyncMock
import pytest
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import DuplicateKeyError
from detection_content import xdr_ice as ice
from detection_content.correlation_replay import persist_match

RULE = {"rule_id": "synthetic-rule", "enabled": True,
        "operators": [{"type": "EVENT_MATCH"}],
        "conditions": [{"match": {"signal_kind": "detection"}}]}
DOC = {"match_id": "legacy-random", "source_event_id": "event",
       "rule_id": "rule", "severity_hint": None, "attack_techniques": []}
async def persist(coll):
    return await persist_match(coll, DOC, tenant_id="tenant", rule=RULE,
                               signal={"source_event_id": "event"},
                               engine_version="1")

@pytest.mark.asyncio
@pytest.mark.parametrize("pattern", [{"unrelated": 1}, None])
async def test_unrelated_or_unidentified_collision_propagates(pattern):
    coll = AsyncMock()
    coll.insert_one.side_effect = DuplicateKeyError(
        "collision", 11000, {"keyPattern": pattern})
    with pytest.raises(DuplicateKeyError):
        await persist(coll)
    coll.find_one.assert_not_awaited()

@pytest.mark.asyncio
async def test_missing_winner_propagates_collision():
    coll = AsyncMock()
    coll.insert_one.side_effect = DuplicateKeyError(
        "collision", 11000, {"keyPattern": {"_id": 1}})
    coll.find_one.return_value = None
    with pytest.raises(DuplicateKeyError):
        await persist(coll)

@pytest.mark.asyncio
async def test_database_failure_is_not_reported_as_success():
    coll = AsyncMock()
    coll.insert_one.side_effect = RuntimeError("database unavailable")
    with pytest.raises(RuntimeError):
        await persist(coll)

@pytest.mark.asyncio
async def test_missing_tenant_explicitly_declares_unprotected_legacy_write():
    coll = AsyncMock()
    result = await persist_match(coll, DOC, tenant_id=None, rule=RULE,
                                 signal={}, engine_version="1")
    assert result["replay_protection"] == "UNAVAILABLE_IDENTITY"
    assert "tenant_id" not in result
    assert result["match_id"] == DOC["match_id"]

local = pytest.mark.skipif(os.environ.get("NIVX_LOCAL_CORRELATION_TEST") != "1",
                          reason="explicit local MongoDB test opt-in required")

def local_db():
    client = AsyncIOMotorClient("mongodb://127.0.0.1:27017",
                               serverSelectionTimeoutMS=2000)
    db = client["nivx_correlation_" + uuid.uuid4().hex]
    print("RETAINED_TEST_DATABASE", db.name)
    return client, db

@local
@pytest.mark.asyncio
async def test_actual_correlate_concurrent_replay_tenant_event_rule_isolation():
    client, db = local_db()
    try:
        await db[ice.CORRELATION_RULES_COLLECTION].insert_one(dict(RULE))
        event = {"event_id": "event", "tenant_id": "tenant"}
        results = await asyncio.gather(*[
            ice.correlate(db, event, {}, "trace") for _ in range(20)])
        first = results[0]["matches"][0]
        assert all(r["matches"][0] == first for r in results)
        assert await db[ice.CORRELATION_MATCHES_COLLECTION].count_documents({}) == 1
        await ice.correlate(db, {**event, "tenant_id": "other"}, {}, "trace")
        await ice.correlate(db, {**event, "event_id": "another-event"}, {}, "trace")
        await db[ice.CORRELATION_RULES_COLLECTION].update_one(
            {"rule_id": RULE["rule_id"]}, {"$set": {"version": "2"}})
        await ice.correlate(db, event, {}, "trace")
        assert await db[ice.CORRELATION_MATCHES_COLLECTION].count_documents({}) == 4
    finally:
        client.close()

@local
@pytest.mark.asyncio
async def test_conflicting_event_content_is_rejected_without_overwriting():
    client, db = local_db()
    try:
        await db[ice.CORRELATION_RULES_COLLECTION].insert_one(dict(RULE))
        event = {"event_id": "event", "tenant_id": "tenant",
                 "host": {"hostname": "original"}}
        first = await ice.correlate(db, event, {}, "trace")
        with pytest.raises(ValueError, match="conflicting input"):
            await ice.correlate(db, {**event, "host": {"hostname": "changed"}}, {}, "trace")
        assert await db[ice.CORRELATION_MATCHES_COLLECTION].count_documents({}) == 1
        original = await db[ice.CORRELATION_MATCHES_COLLECTION].find_one({})
        assert original["match_id"] == first["matches"][0]["match_id"]
    finally:
        client.close()
