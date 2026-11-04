"""Forensic snapshots · the distinctions that make a snapshot trustworthy.

Runs on a DISPOSABLE database. The states that matter are the ones an analyst
would otherwise confuse: a capture that ran and found nothing is not a failure;
a sensor too old to collect is not an empty machine; an unanswered job is not a
statement about the endpoint; and a redelivered result must not destroy the
original capture.
"""
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from motor.motor_asyncio import AsyncIOMotorClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from edr_plane import response as resp            # noqa: E402
from services.edr import forensic_snapshots as fs  # noqa: E402

OWNER, OUTSIDER = "fx-snap-owner", "fx-snap-outsider"
EP = "ep_snapfixture_aaaaaaaaaa"
EP_OTHER = "ep_snapfixture_bbbbbbbbbb"
WHO = "analyst@fixture.test"


@pytest_asyncio.fixture()
async def db():
    name = f"nivx_snapshot_fixture_{uuid.uuid4().hex[:10]}"
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    d = client[name]
    await d["edr_endpoints"].insert_many([
        {"tenant_id": OWNER, "endpoint_id": EP, "hostname": "snap-a",
         "enrollment_state": "ENROLLED"},
        {"tenant_id": OUTSIDER, "endpoint_id": EP_OTHER, "hostname": "snap-b",
         "enrollment_state": "ENROLLED"},
    ])
    await resp.ensure_indexes(d)
    yield d
    await client.drop_database(name)


async def _request(d, tenant=OWNER, endpoint=EP):
    return await fs.request(d, tenant_id=tenant, endpoint_id=endpoint,
                            requested_by=WHO)


async def _claim(d, tenant=OWNER, endpoint=EP):
    return await resp.claim_pending(d, tenant_id=tenant, endpoint_id=endpoint)


@pytest.mark.asyncio
async def test_a_request_is_queued_and_claims_nothing_about_the_endpoint(db):
    job = await _request(db)
    assert job["job_id"].startswith("cmd_")
    assert job["status"] == fs.QUEUED
    assert job["requested_by"] == WHO
    assert job["row_count"] is None
    assert "says nothing about what is running" in job["honesty_note"]


@pytest.mark.asyncio
async def test_claimed_but_unanswered_reads_as_running_then_timed_out(db):
    job = await _request(db)
    claimed = await _claim(db)
    assert [c["command_id"] for c in claimed] == [job["job_id"]]
    assert claimed[0]["action"] == fs.ACTION

    live = await fs.get_job(db, tenant_id=OWNER, job_id=job["job_id"])
    assert live["status"] == fs.RUNNING
    assert live["command_state"] == "DISPATCHED"

    # Past the window, an unanswered job is TIMED_OUT — not "running forever",
    # and not an empty result.
    late = datetime.now(timezone.utc) + timedelta(
        seconds=fs.TIMEOUT_SECONDS + 30)
    doc = await db[resp.COLLECTION].find_one({"command_id": job["job_id"]})
    assert fs._status(doc, late) == fs.TIMED_OUT
    assert "nothing is claimed about the endpoint" in fs.STATUS_MEANING[fs.TIMED_OUT]


@pytest.mark.asyncio
async def test_a_capture_with_rows_reports_capture_times_and_rows(db):
    job = await _request(db)
    await _claim(db)
    await resp.record_result(
        db, tenant_id=OWNER, endpoint_id=EP, command_id=job["job_id"],
        outcome="EXECUTED", detail="2 process rows captured",
        evidence={"capture_started_at": "2026-11-03T15:02:52.623079+00:00",
                  "capture_finished_at": "2026-11-03T15:02:52.623852+00:00",
                  "row_count": 2, "sensor_version": "0.2.0",
                  "rows": [{"pid": 1, "name": "entrypoint.sh",
                            "path": "/usr/bin/bash"},
                           {"pid": 10, "name": "uvicorn", "path": None,
                            "path_unavailable": "PermissionError"}]})
    out = await fs.get_job(db, tenant_id=OWNER, job_id=job["job_id"])
    assert out["status"] == fs.COMPLETED_WITH_ROWS
    assert out["capture_started_at"].endswith("+00:00")
    assert out["capture_finished_at"] > out["capture_started_at"]
    assert out["row_count"] == 2
    assert out["rows"][0] == {"pid": 1, "name": "entrypoint.sh",
                              "path": "/usr/bin/bash"}
    # a row whose path could not be read says so instead of showing nothing
    assert out["rows"][1]["path_unavailable"] == "PermissionError"


@pytest.mark.asyncio
async def test_zero_rows_is_an_empty_result_not_a_failure(db):
    job = await _request(db)
    await _claim(db)
    await resp.record_result(
        db, tenant_id=OWNER, endpoint_id=EP, command_id=job["job_id"],
        outcome="EXECUTED", detail="0 process rows captured",
        evidence={"capture_started_at": "2026-11-03T15:10:00+00:00",
                  "capture_finished_at": "2026-11-03T15:10:00+00:00",
                  "row_count": 0, "rows": []})
    out = await fs.get_job(db, tenant_id=OWNER, job_id=job["job_id"])
    assert out["status"] == fs.COMPLETED_ZERO_ROWS
    assert out["status"] != fs.FAILED
    assert "not a failure, and not a timeout" in out["status_meaning"]
    assert out["capture_finished_at"] is not None


@pytest.mark.asyncio
async def test_an_older_sensor_reports_the_capability_missing(db):
    # The sensor build predates on-demand collection: it must say so, and the
    # platform must NOT answer from stored telemetry in its place.
    job = await _request(db)
    await _claim(db)
    await resp.record_result(
        db, tenant_id=OWNER, endpoint_id=EP, command_id=job["job_id"],
        outcome="CAPABILITY_UNAVAILABLE",
        detail="unknown action COLLECT_PROCESS_SNAPSHOT", evidence={})
    out = await fs.get_job(db, tenant_id=OWNER, job_id=job["job_id"])
    assert out["status"] == fs.CAPABILITY_UNAVAILABLE
    assert out["row_count"] is None
    assert out["rows"] == []
    assert "history was NOT used" in out["status_meaning"]


@pytest.mark.asyncio
async def test_a_failed_capture_is_distinct_from_an_empty_one(db):
    job = await _request(db)
    await _claim(db)
    await resp.record_result(
        db, tenant_id=OWNER, endpoint_id=EP, command_id=job["job_id"],
        outcome="FAILED", detail="/proc is not readable on this endpoint",
        evidence={"row_count": 0, "rows": []})
    out = await fs.get_job(db, tenant_id=OWNER, job_id=job["job_id"])
    assert out["status"] == fs.FAILED
    assert out["status"] != fs.COMPLETED_ZERO_ROWS


@pytest.mark.asyncio
async def test_redelivery_preserves_the_original_job_and_result(db):
    job = await _request(db)
    await _claim(db)
    first = await resp.record_result(
        db, tenant_id=OWNER, endpoint_id=EP, command_id=job["job_id"],
        outcome="EXECUTED", detail="24 process rows captured",
        evidence={"row_count": 24, "rows": [{"pid": 1, "name": "init",
                                             "path": "/usr/bin/bash"}],
                  "capture_started_at": "2026-11-03T15:02:52.623079+00:00"})
    # The sensor never saw the 200 and sends the same result again.
    again = await resp.record_result(
        db, tenant_id=OWNER, endpoint_id=EP, command_id=job["job_id"],
        outcome="EXECUTED", detail="RETRY — different text",
        evidence={"row_count": 0, "rows": []})
    assert again["idempotent_replay"] is True
    assert again["sensor_result"]["detail"] == first["sensor_result"]["detail"]
    out = await fs.get_job(db, tenant_id=OWNER, job_id=job["job_id"])
    assert out["row_count"] == 24
    assert out["status"] == fs.COMPLETED_WITH_ROWS
    assert len(out["rows"]) == 1
    assert await db[resp.COLLECTION].count_documents(
        {"command_id": job["job_id"]}) == 1


@pytest.mark.asyncio
async def test_another_customer_can_neither_list_nor_read_the_job(db):
    job = await _request(db)
    await _claim(db)
    await resp.record_result(
        db, tenant_id=OWNER, endpoint_id=EP, command_id=job["job_id"],
        outcome="EXECUTED", detail="1 row",
        evidence={"row_count": 1, "rows": [{"pid": 1, "name": "init"}]})

    # by id
    assert await fs.get_job(db, tenant_id=OUTSIDER,
                            job_id=job["job_id"]) is None
    # by listing
    theirs = await fs.list_jobs(db, tenant_id=OUTSIDER)
    assert theirs["jobs"] == []
    mine = await fs.list_jobs(db, tenant_id=OWNER)
    assert [j["job_id"] for j in mine["jobs"]] == [job["job_id"]]
    # and the sensor side: another endpoint cannot claim this command
    assert await resp.claim_pending(db, tenant_id=OUTSIDER,
                                    endpoint_id=EP_OTHER) == []


@pytest.mark.asyncio
async def test_both_entry_points_address_one_job(db):
    # "From the computer" and "from the dashboard" are the same record: the
    # job id returned by the request is the one history lists.
    job = await _request(db)
    listed = await fs.list_jobs(db, tenant_id=OWNER, endpoint_id=EP)
    assert [j["job_id"] for j in listed["jobs"]] == [job["job_id"]]
    assert listed["jobs"][0]["endpoint_id"] == EP
    # and filtering by another endpoint does not surface it
    other = await fs.list_jobs(db, tenant_id=OWNER, endpoint_id="ep_nope")
    assert other["jobs"] == []


@pytest.mark.asyncio
async def test_a_snapshot_is_never_sent_to_an_unenrolled_endpoint(db):
    with pytest.raises(resp.ResponseError) as e:
        await fs.request(db, tenant_id=OWNER, endpoint_id="ep_never_enrolled",
                         requested_by=WHO)
    assert e.value.code == "ENDPOINT_NOT_ENROLLED"


@pytest.mark.asyncio
async def test_the_result_lists_what_it_covers_and_what_it_does_not(db):
    # Cisco's Orbital snapshot returns loaded modules, logged-in users, open
    # ports, wireless networks and shell history. This one returns processes.
    # The difference is listed, not left to be inferred from an absence.
    job = await _request(db)
    await _claim(db)
    await resp.record_result(
        db, tenant_id=OWNER, endpoint_id=EP, command_id=job["job_id"],
        outcome="EXECUTED", detail="3 process rows captured",
        evidence={"row_count": 3, "rows": [{"pid": 1, "name": "init"}]})
    out = await fs.get_job(db, tenant_id=OWNER, job_id=job["job_id"])
    by_name = {s["section"]: s for s in out["sections"]}
    assert by_name["Running processes"]["state"] == "COLLECTED"
    assert by_name["Running processes"]["rows"] == 3
    for absent in ("Logged-in users", "Open network ports", "Loaded modules",
                   "Wireless networks", "Shell history", "Memory image"):
        assert by_name[absent]["state"] == "NOT_COLLECTED"
        assert by_name[absent]["rows"] is None
    assert "kept until the database is cleared" in out["retention_note"]
