"""
Round 18.6 · Analyst Annotations Fabric
────────────────────────────────────────

Validates:
  * CRUD lifecycle: create → update → retire, with full audit trail.
  * The deterministic composer output is NEVER rewritten by an
    annotation — annotations sit in a separate `analyst_annotations`
    block with `origin = ANALYST`.
  * Retire is soft-delete: document persists with `retired_at` set.
  * Section + kind validation rejects garbage.
"""
from __future__ import annotations
import asyncio, os, uuid
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content import xdr_analyst_annotations as ann
from detection_content.xdr_executive_summary import compose


@pytest.fixture(scope="module", autouse=True)
def _init_deps_db():
    from deps import validate_config, init_database
    validate_config(); init_database()
    yield


@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop(); yield lp; lp.close()


@pytest.fixture(scope="module")
def db(loop):
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c[os.environ.get("DB_NAME", "test_database")]; c.close()


def _run(loop, coro): return loop.run_until_complete(coro)


@pytest.fixture()
def incident_id():
    return "inc_ann_test_" + uuid.uuid4().hex[:10]


# ── Validation ─────────────────────────────────────────────────

def test_create_rejects_unknown_section(loop, db, incident_id):
    with pytest.raises(ValueError):
        _run(loop, ann.create(db, incident_id, section="garbage",
                                        kind="note", payload={}, author="a@x"))


def test_create_rejects_unknown_kind(loop, db, incident_id):
    with pytest.raises(ValueError):
        _run(loop, ann.create(db, incident_id, section="executive",
                                        kind="fabricate", payload={}, author="a@x"))


# ── CRUD lifecycle ─────────────────────────────────────────────

def test_create_annotation_persists_shape(loop, db, incident_id):
    doc = _run(loop, ann.create(db, incident_id,
                                            section="executive", kind="finding",
                                            payload={"text": "beacon interval ~60s"},
                                            author="analyst@nivxray"))
    assert doc["id"].startswith("ann-")
    assert doc["origin"] == "ANALYST"
    assert doc["section"] == "executive"
    assert doc["kind"] == "finding"
    assert doc["payload"]["text"] == "beacon interval ~60s"
    assert doc["superseded_by"] is None
    assert doc["retired_at"] is None
    assert doc["created_at"] == doc["updated_at"]
    assert doc["history"] == []


def test_update_appends_previous_payload_to_history(loop, db, incident_id):
    created = _run(loop, ann.create(db, incident_id,
                                                    section="technical", kind="note",
                                                    payload={"note": "initial"},
                                                    author="a1@x"))
    updated = _run(loop, ann.update(db, incident_id, created["id"],
                                                    payload={"note": "revised"},
                                                    author="a2@x"))
    assert updated["payload"]["note"] == "revised"
    assert updated["author"] == "a2@x"
    assert len(updated["history"]) == 1
    assert updated["history"][0]["payload"] == {"note": "initial"}
    assert updated["history"][0]["author"] == "a1@x"
    assert updated["updated_at"] != created["updated_at"]


def test_retire_is_soft_delete(loop, db, incident_id):
    created = _run(loop, ann.create(db, incident_id,
                                                    section="recommendations",
                                                    kind="custom_reco",
                                                    payload={"text": "verify vendor"},
                                                    author="analyst@x"))
    retired = _run(loop, ann.retire(db, incident_id, created["id"],
                                                    author="analyst@x",
                                                    reason="not applicable"))
    assert retired["retired_at"] is not None
    assert retired["retired_by"] == "analyst@x"
    assert retired["retired_reason"] == "not applicable"
    # Still findable via include_retired
    all_docs = _run(loop, ann.list_for_incident(
        db, incident_id, include_retired=True))
    ids = [d["id"] for d in all_docs]
    assert created["id"] in ids


def test_update_after_retire_returns_none(loop, db, incident_id):
    created = _run(loop, ann.create(db, incident_id,
                                                    section="supporting_evidence",
                                                    kind="finding",
                                                    payload={"claim": "x"},
                                                    author="a@x"))
    _run(loop, ann.retire(db, incident_id, created["id"], author="a@x"))
    r = _run(loop, ann.update(db, incident_id, created["id"],
                                        payload={"claim": "y"}, author="a@x"))
    assert r is None


def test_list_excludes_retired_by_default(loop, db, incident_id):
    keep = _run(loop, ann.create(db, incident_id,
                                                section="executive", kind="note",
                                                payload={"note": "keep"},
                                                author="a@x"))
    drop = _run(loop, ann.create(db, incident_id,
                                                section="executive", kind="note",
                                                payload={"note": "drop"},
                                                author="a@x"))
    _run(loop, ann.retire(db, incident_id, drop["id"], author="a@x"))
    active = _run(loop, ann.list_for_incident(db, incident_id))
    active_ids = {d["id"] for d in active}
    assert keep["id"] in active_ids
    assert drop["id"] not in active_ids


def test_group_by_section_shape(loop, db, incident_id):
    _run(loop, ann.create(db, incident_id, section="executive",
                                    kind="note", payload={"n": 1}, author="a@x"))
    _run(loop, ann.create(db, incident_id, section="technical",
                                    kind="override", payload={"k": "v"},
                                    author="a@x"))
    _run(loop, ann.create(db, incident_id, section="recommendations",
                                    kind="custom_reco",
                                    payload={"text": "extra reco"}, author="a@x"))
    grouped = _run(loop, ann.group_by_section(db, incident_id))
    assert len(grouped["executive"])          == 1
    assert len(grouped["technical"])          == 1
    assert len(grouped["recommendations"])    == 1
    assert len(grouped["supporting_evidence"]) == 0


# ── Composer overlay ───────────────────────────────────────────

def test_composer_carries_annotations_alongside_deterministic_output(
        loop, db):
    """The composer must attach analyst_annotations by section WITHOUT
    rewriting the deterministic prose."""
    from detection_content.xdr_pipeline import process_event_through_pipeline
    from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
    inc = (_run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
        .get("closed_loop") or {}).get("incident_id")

    # 1. Compose BEFORE any annotation.
    before = _run(loop, compose(db, inc))
    before_prose = before["executive_summary"]["prose"]
    assert before["analyst_annotations"] == {
        "executive": [], "technical": [], "supporting_evidence": [],
        "recommendations": [],
    }

    # 2. Add an executive finding — must appear in composer output.
    a = _run(loop, ann.create(db, inc, section="executive",
                                            kind="finding",
                                            payload={"text": "beaconing every 60s"},
                                            author="analyst@nivxray"))

    after = _run(loop, compose(db, inc))
    # ─ Deterministic prose must remain byte-identical.
    assert after["executive_summary"]["prose"] == before_prose
    # ─ Annotation must be surfaced in the overlay block.
    exec_anns = after["analyst_annotations"]["executive"]
    assert len(exec_anns) == 1
    assert exec_anns[0]["id"] == a["id"]
    assert exec_anns[0]["origin"] == "ANALYST"
    assert exec_anns[0]["payload"]["text"] == "beaconing every 60s"

    # 3. Retire the annotation → composer no longer surfaces it.
    _run(loop, ann.retire(db, inc, a["id"], author="analyst@nivxray"))
    after_retire = _run(loop, compose(db, inc))
    assert after_retire["analyst_annotations"]["executive"] == []
    # Deterministic prose STILL intact.
    assert after_retire["executive_summary"]["prose"] == before_prose
