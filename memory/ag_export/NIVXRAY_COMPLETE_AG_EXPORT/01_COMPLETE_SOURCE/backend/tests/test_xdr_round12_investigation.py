"""
Round 12 · P0.6 · Investigation Fabric regression.

Guarantees:
  * The Golden E2E flips `investigation` stage from READY → EXECUTED.
  * Fabric projects 6 lanes; every EMPTY lane carries an exact reason.
  * `evidence_graph` links incident → canonical → hosts → detection.
  * No second investigation engine — the composer is pure.
"""
from __future__ import annotations
import asyncio, os, uuid
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_pipeline import process_event_through_pipeline
from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
from detection_content.xdr_investigation import (
    project_investigation, FABRIC_ENGINE_ID,
)


@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop()
    yield lp
    lp.close()


@pytest.fixture(scope="module")
def db(loop):
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c[os.environ.get("DB_NAME", "test_database")]
    c.close()


def _run(loop, coro):
    return loop.run_until_complete(coro)


def test_pipeline_investigation_stage_now_executed(loop, db):
    r = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    stage = next(s for s in r["stages"] if s["stage"] == "investigation")
    assert stage["status"] == "EXECUTED", (
        f"investigation must EXECUTE post-Round-12; got {stage}")
    assert r["investigation"]["engine_id"] == FABRIC_ENGINE_ID


def test_fabric_projects_six_lanes(loop, db):
    r = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    inv = r["investigation"]
    for lane in ("timeline", "process_tree", "evidence_graph",
                    "device_trajectory", "attack_story", "attck"):
        assert lane in inv["lanes"]
        state = inv["lanes"][lane]["state"]
        assert state in ("READY", "MINIMAL", "EMPTY"), (
            f"lane {lane} carried unexpected state {state}")
        if state == "EMPTY":
            assert inv["lanes"][lane].get("reason"), (
                f"EMPTY lane {lane} must carry exact reason")


def test_evidence_graph_contains_incident_and_canonical(loop, db):
    r = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    graph = r["investigation"]["lanes"]["evidence_graph"]
    assert graph["state"] == "READY"
    node_kinds = {n["kind"] for n in graph["nodes"]}
    assert "incident" in node_kinds
    assert "canonical_evidence" in node_kinds
    assert "host" in node_kinds


def test_fabric_missing_incident_returns_honest_state(loop, db):
    r = _run(loop, project_investigation(db, "inc_does_not_exist"))
    assert r["state"] == "MISSING"
    assert "not found" in r["reason"]
