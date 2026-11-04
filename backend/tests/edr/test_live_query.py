"""Live Query · one question, answered by the endpoint or not at all.

Disposable database. The distinctions that matter: an answer of NO MATCHES is
an answer; an old sensor is not an empty machine; an unanswered query claims
nothing; and a redelivered answer must not replace the first.
"""
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from motor.motor_asyncio import AsyncIOMotorClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from edr_plane import response as resp      # noqa: E402
from services.edr import live_query as lq   # noqa: E402

OWNER, OUTSIDER = "fx-lq-owner", "fx-lq-outsider"
EP, EP_OTHER = "ep_lqfixture_aaaaaaaaaa", "ep_lqfixture_bbbbbbbbbb"
WHO = "analyst@fixture.test"


@pytest_asyncio.fixture()
async def db():
    name = f"nivx_livequery_fixture_{uuid.uuid4().hex[:10]}"
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    d = client[name]
    await d["edr_endpoints"].insert_many([
        {"tenant_id": OWNER, "endpoint_id": EP, "hostname": "lq-a",
         "enrollment_state": "ENROLLED"},
        {"tenant_id": OUTSIDER, "endpoint_id": EP_OTHER, "hostname": "lq-b",
         "enrollment_state": "ENROLLED"},
    ])
    await resp.ensure_indexes(d)
    yield d
    await client.drop_database(name)


async def _ask(d, nm="mongod", tenant=OWNER, endpoint=EP):
    return await lq.run(d, tenant_id=tenant, endpoint_id=endpoint,
                        process_name=nm, requested_by=WHO)


@pytest.mark.asyncio
async def test_the_question_and_target_travel_with_the_query(db):
    q = await _ask(db)
    assert q["query_id"].startswith("cmd_")
    assert q["status"] == lq.QUEUED
    assert q["question"] == lq.QUESTION
    assert q["process_name"] == "mongod"
    assert q["endpoint_id"] == EP
    assert q["match_count"] is None
    assert "says nothing about what is running" in q["honesty_note"]


@pytest.mark.asyncio
async def test_a_name_longer_than_comm_says_what_was_actually_compared(db):
    # Linux truncates /proc/<pid>/comm to 15 characters. A 16+ character name
    # cannot be matched exactly, and the answer must not imply that it was.
    q = await _ask(db, "nivxforge_sensor.py")
    assert q["name_compared"] == "nivxforge_sensor"[:15]
    assert q["name_truncated"] is True
    assert "truncates /proc/<pid>/comm to 15" in q["match_basis"]

    short = await _ask(db, "mongod")
    assert short["name_truncated"] is False
    assert "exact match" in short["match_basis"]


@pytest.mark.asyncio
async def test_an_empty_name_asks_the_endpoint_nothing(db):
    with pytest.raises(lq.QueryError) as e:
        await _ask(db, "   ")
    assert e.value.code == "EMPTY_PROCESS_NAME"
    assert await db[resp.COLLECTION].count_documents({"action": lq.ACTION}) == 0


@pytest.mark.asyncio
async def test_matches_carry_pid_name_path_and_collection_time(db):
    q = await _ask(db)
    await resp.claim_pending(db, tenant_id=OWNER, endpoint_id=EP)
    await resp.record_result(
        db, tenant_id=OWNER, endpoint_id=EP, command_id=q["query_id"],
        outcome="EXECUTED", detail="1 of 24 running processes matched 'mongod'",
        evidence={"collected_at": "2026-11-03T15:30:00.123456+00:00",
                  "match_count": 1, "processes_examined": 24,
                  "sensor_version": "0.2.0",
                  "rows": [{"pid": 291, "name": "mongod",
                            "path": "/usr/bin/mongod"}]})
    out = await lq.get_query(db, tenant_id=OWNER, query_id=q["query_id"])
    assert out["status"] == lq.COMPLETED_WITH_MATCHES
    assert out["collected_at"].endswith("+00:00")
    assert out["match_count"] == 1
    assert out["processes_examined"] == 24
    assert out["rows"][0] == {"pid": 291, "name": "mongod",
                              "path": "/usr/bin/mongod"}


@pytest.mark.asyncio
async def test_zero_matches_is_an_answer_not_a_failure(db):
    q = await _ask(db, "definitelynot")
    await resp.claim_pending(db, tenant_id=OWNER, endpoint_id=EP)
    await resp.record_result(
        db, tenant_id=OWNER, endpoint_id=EP, command_id=q["query_id"],
        outcome="EXECUTED", detail="0 of 24 running processes matched",
        evidence={"collected_at": "2026-11-03T15:31:00+00:00",
                  "match_count": 0, "processes_examined": 24, "rows": []})
    out = await lq.get_query(db, tenant_id=OWNER, query_id=q["query_id"])
    assert out["status"] == lq.COMPLETED_NO_MATCHES
    assert out["status"] not in (lq.FAILED, lq.TIMED_OUT)
    assert "That is an answer" in out["status_meaning"]
    # it still proves the endpoint was read
    assert out["processes_examined"] == 24
    assert out["collected_at"] is not None


@pytest.mark.asyncio
async def test_unsupported_sensor_failure_and_timeout_stay_apart(db):
    unsupported = await _ask(db)
    await resp.claim_pending(db, tenant_id=OWNER, endpoint_id=EP)
    await resp.record_result(
        db, tenant_id=OWNER, endpoint_id=EP, command_id=unsupported["query_id"],
        outcome="CAPABILITY_UNAVAILABLE",
        detail="unknown action LIVE_QUERY_PROCESS_NAME", evidence={})
    u = await lq.get_query(db, tenant_id=OWNER,
                           query_id=unsupported["query_id"])
    assert u["status"] == lq.CAPABILITY_UNAVAILABLE
    assert u["match_count"] is None and u["rows"] == []
    assert "stored telemetry was NOT used" in u["status_meaning"]

    broken = await _ask(db)
    await resp.claim_pending(db, tenant_id=OWNER, endpoint_id=EP)
    await resp.record_result(
        db, tenant_id=OWNER, endpoint_id=EP, command_id=broken["query_id"],
        outcome="FAILED", detail="/proc is not readable on this endpoint",
        evidence={"match_count": 0, "rows": []})
    f = await lq.get_query(db, tenant_id=OWNER, query_id=broken["query_id"])
    assert f["status"] == lq.FAILED
    assert f["status"] != lq.COMPLETED_NO_MATCHES

    silent = await _ask(db)
    await resp.claim_pending(db, tenant_id=OWNER, endpoint_id=EP)
    doc = await db[resp.COLLECTION].find_one(
        {"command_id": silent["query_id"]})
    late = datetime.now(timezone.utc) + timedelta(
        seconds=lq.TIMEOUT_SECONDS + 30)
    assert lq._status(doc, late) == lq.TIMED_OUT
    assert "nothing is claimed about what is running" in \
        lq.STATUS_MEANING[lq.TIMED_OUT]


@pytest.mark.asyncio
async def test_redelivery_preserves_the_original_answer(db):
    q = await _ask(db)
    await resp.claim_pending(db, tenant_id=OWNER, endpoint_id=EP)
    await resp.record_result(
        db, tenant_id=OWNER, endpoint_id=EP, command_id=q["query_id"],
        outcome="EXECUTED", detail="1 match",
        evidence={"collected_at": "2026-11-03T15:30:00+00:00",
                  "match_count": 1,
                  "rows": [{"pid": 291, "name": "mongod"}]})
    again = await resp.record_result(
        db, tenant_id=OWNER, endpoint_id=EP, command_id=q["query_id"],
        outcome="EXECUTED", detail="RETRY — nothing",
        evidence={"match_count": 0, "rows": []})
    assert again["idempotent_replay"] is True
    out = await lq.get_query(db, tenant_id=OWNER, query_id=q["query_id"])
    assert out["match_count"] == 1
    assert len(out["rows"]) == 1
    assert await db[resp.COLLECTION].count_documents(
        {"command_id": q["query_id"]}) == 1


@pytest.mark.asyncio
async def test_another_customer_can_neither_list_nor_read_the_query(db):
    q = await _ask(db)
    assert await lq.get_query(db, tenant_id=OUTSIDER,
                              query_id=q["query_id"]) is None
    assert (await lq.list_queries(db, tenant_id=OUTSIDER))["queries"] == []
    mine = await lq.list_queries(db, tenant_id=OWNER)
    assert [r["query_id"] for r in mine["queries"]] == [q["query_id"]]
    assert await resp.claim_pending(db, tenant_id=OUTSIDER,
                                    endpoint_id=EP_OTHER) == []


@pytest.mark.asyncio
async def test_both_entry_points_address_one_query(db):
    q = await _ask(db)
    listed = await lq.list_queries(db, tenant_id=OWNER, endpoint_id=EP)
    assert [r["query_id"] for r in listed["queries"]] == [q["query_id"]]
    assert listed["question"] == lq.QUESTION
    assert (await lq.list_queries(db, tenant_id=OWNER,
                                  endpoint_id="ep_nope"))["queries"] == []


@pytest.mark.asyncio
async def test_each_request_is_its_own_collection(db):
    # "Now" changes, so a second ask is a second command rather than a cached
    # answer handed back.
    first = await _ask(db)
    second = await _ask(db)
    assert first["query_id"] != second["query_id"]
    assert await db[resp.COLLECTION].count_documents(
        {"action": lq.ACTION, "tenant_id": OWNER}) == 2
