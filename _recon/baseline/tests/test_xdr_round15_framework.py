"""Round 15 · P0.7.2 · Framework Mapping Fabric regression."""
from __future__ import annotations
import asyncio, os, uuid
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_pipeline import process_event_through_pipeline
from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
from detection_content.xdr_framework_mapping import (
    resolve_mappings, framework_registry, FABRIC_ID,
)


@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop(); yield lp; lp.close()


@pytest.fixture(scope="module")
def db(loop):
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c[os.environ.get("DB_NAME", "test_database")]; c.close()


def _run(loop, coro): return loop.run_until_complete(coro)


def _fresh(loop, db):
    return _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))


def test_registry_lists_five_frameworks():
    ids = {f["framework_id"] for f in framework_registry()}
    assert {"mitre_attack", "mitre_d3fend",
              "nist_ir",     "nist_csf_2", "owasp"} <= ids


def test_framework_stage_executes(loop, db):
    r = _fresh(loop, db)
    stage = next(s for s in r["stages"]
                     if s["stage"] == "framework_mapping")
    assert stage["status"] == "EXECUTED"
    fw = r["framework"]
    assert fw["state"] == "READY"
    assert fw["engine_id"] == FABRIC_ID


def test_framework_mappings_are_idempotent(loop, db):
    r = _fresh(loop, db)
    inc_id = r["incident"]["incident_id"]
    before = _run(loop, db["xdr_framework_mappings"].count_documents(
        {"incident_id": inc_id}))
    # Recompute + resolve again.
    _run(loop, resolve_mappings(db, inc_id))
    _run(loop, resolve_mappings(db, inc_id))
    after = _run(loop, db["xdr_framework_mappings"].count_documents(
        {"incident_id": inc_id}))
    assert before == after, (
        f"framework mappings must not duplicate on re-resolve "
        f"(before={before} after={after})")


def test_owasp_reports_not_applicable_for_network_alert(loop, db):
    r = _fresh(loop, db)
    fw = r["framework"]
    owasp = fw["mappings"].get("owasp") or []
    assert owasp, "owasp entry must exist (even if NOT_APPLICABLE)"
    assert any(m["status"] == "NOT_APPLICABLE" for m in owasp), (
        "network_alert incident must honestly report OWASP NOT_APPLICABLE")


def test_nist_ir_reports_detection_and_analysis(loop, db):
    r = _fresh(loop, db)
    fw = r["framework"]
    nist = fw["mappings"].get("nist_ir") or []
    active = [m for m in nist if m["status"] == "ACTIVE"]
    assert active and active[0]["object_id"] == "DETECTION_AND_ANALYSIS"


def test_csf_reports_detect_and_respond(loop, db):
    r = _fresh(loop, db)
    fw = r["framework"]
    csf = [m for m in (fw["mappings"].get("nist_csf_2") or [])
              if m["status"] == "ACTIVE"]
    ids = {m["object_id"] for m in csf}
    assert "DE" in ids   # DETECT always
    assert "RS" in ids   # RESPOND — action succeeded


def test_mapping_carries_provenance_and_source_refs(loop, db):
    r = _fresh(loop, db)
    fw = r["framework"]
    for fw_list in fw["mappings"].values():
        for m in fw_list:
            if m["status"] != "ACTIVE":
                continue
            assert "mapping_method" in m
            assert m["mapping_method"] in (
                "DIRECT_EVIDENCE", "DETECTION_RULE",
                "INTELLIGENCE_DERIVED", "CORRELATION_DERIVED",
                "INVESTIGATION_DERIVED", "KNOWLEDGE_MAPPING",
            )
            assert "source_refs" in m
            assert "provenance" in m
