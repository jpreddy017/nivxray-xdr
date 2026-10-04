"""P1 · EVIDENCE NAMESPACE BRIDGE — focused proof.

The defect: the canonical evidence identity the ingest pipeline ALREADY
persists on every live observation (`v2_shadow_observations`
`.canonical_event_id` == `xdr_canonical_evidence.event_id`) was dropped when
trajectory frames were built, so a causal anchor (`tf_*` / `evt_*`) could not
deterministically join the incident's own evidence.

These tests drive the REAL routers against the REAL Mongo database and the
REAL incident authority (`routers.incidents.authorized_incident`). Only the
authenticated principal is injected. Nothing is matched on labels, hashes,
timestamps, proximity or array positions anywhere in the bridge.
"""
import os
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from deps import get_current_user, init_database, validate_config
from routers.incident_canonical_evidence import router as canonical_router
from routers.evidence_inspector import router as inspector_router
from services.evidence_bridge import (
    BRIDGED, LEGACY_UNBRIDGED, REFERENCED_RECORD_ABSENT, annotate_frames)
from v2.trajectory.device import build_device_trajectory

validate_config()
init_database()

_W = os.environ.get("PYTEST_XDIST_WORKER", "master")
_P = f"p1bridge-{_W}-"

OWN_T, FOREIGN_T = f"{_P}own", f"{_P}foreign"
INC = f"{_P}inc"
CE_PIPELINE = f"{_P}ce-pipeline"
CE_CAMPAIGN = f"{_P}ce-campaign"
CE_OBS = f"{_P}ce-observation"
CE_FOREIGN = f"{_P}ce-foreign-tenant"
CE_ABSENT = f"{_P}ce-record-not-retained"
CE_FABRICATED = f"{_P}ce-fabricated"

OWN = {"email": f"{_P}own@test", "role": "analyst"}
FOREIGN = {"email": f"{_P}foreign@test", "role": "analyst"}


def _db():
    from pymongo import MongoClient
    return MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]


def _app():
    app = FastAPI()
    app.include_router(canonical_router, prefix="/api")
    app.include_router(inspector_router, prefix="/api")
    return app


def _canonical_row(event_id, tenant, **kw):
    return {"event_id": event_id, "tenant_id": tenant,
            "event_type": "process_create",
            "event_time": "2026-06-01T10:00:00+00:00",
            "ingest_time": "2026-06-01T10:00:05+00:00",
            "source_vendor": "NivXForge", "source_product": "Linux Sensor",
            "raw_ref": {"raw_id": f"raw_{event_id}",
                        "collection": "edr_raw_events"},
            "provenance": {"normalizer_id": "test-normalizer/1.0",
                           "trace_id": f"trace_{event_id}"}, **kw}


def _observation(cid, iid):
    return {"case_id": INC, "tenant_id": OWN_T, "adapter": "test-normalizer",
            "captured_at": "2026-06-01T10:00:00+00:00",
            "kind": "process_create", "origin": "collector-live",
            "ingest_job_id": f"{_P}job",
            "canonical_event_id": cid,
            "event": {"iid": iid, "ts": "2026-06-01T10:00:00+00:00",
                      "kind": "process_create", "adapter": "test-normalizer",
                      "sequence": 0,
                      **({"canonical_event_id": cid} if cid else {})}}


@pytest.fixture
def harness():
    db = _db()
    for coll, q in (("workspace_cases", {"id": {"$regex": f"^{_P}"}}),
                    ("users", {"email": {"$regex": f"^{_P}"}}),
                    ("xdr_canonical_evidence", {"event_id": {"$regex": f"^{_P}"}}),
                    ("v2_shadow_observations", {"case_id": {"$regex": f"^{_P}"}})):
        db[coll].delete_many(q)
    # A fresh Motor client, so this module never talks to a client bound to
    # a previous TestClient portal's (now closed) event loop.
    import deps
    motor = deps.AsyncIOMotorClient(os.environ["MONGO_URL"])
    deps.client._bind(motor)
    deps.db._bind(motor[os.environ["DB_NAME"]])
    now = datetime.now(timezone.utc).isoformat()
    db.workspace_cases.insert_one({
        "id": INC, "doc_type": "xdr_incident", "tenant_id": OWN_T,
        "incident_number": "INC0000971", "title": "p1 bridge fixture",
        "name": "P1-SECRET-INCIDENT", "incident_state": "new",
        "created_at": now, "updated_at": now,
        "xdr_pipeline": {"canonical_event_id": CE_PIPELINE},
        "endpoint_campaign": {"detections": [
            {"canonical_event_id": CE_CAMPAIGN, "rule_id": "RULE-1"}]}})
    for u, t in ((OWN, OWN_T), (FOREIGN, FOREIGN_T)):
        db.users.insert_one({"email": u["email"], "role": "analyst",
                             "tenant_id": t, "created_at": now,
                             "password_hash": "!p1-fixture-no-login"})
    db.xdr_canonical_evidence.insert_many([
        _canonical_row(CE_PIPELINE, OWN_T),
        _canonical_row(CE_CAMPAIGN, OWN_T),
        _canonical_row(CE_OBS, OWN_T),
        # stamped to ANOTHER tenant — must never be disclosed on this incident
        _canonical_row(CE_FOREIGN, FOREIGN_T,
                       source_product="FOREIGN-TENANT-PRODUCT"),
    ])
    db.v2_shadow_observations.insert_many([
        _observation(CE_OBS, f"evt_{_P}1"),
        _observation(CE_ABSENT, f"evt_{_P}2"),      # reference, no record
        _observation(CE_FOREIGN, f"evt_{_P}3"),     # cross-tenant record
        _observation(None, f"evt_{_P}4"),           # legacy, no identifier
    ])
    app = _app()
    with TestClient(app) as client:
        app.state.test_client = client
        yield app, db
    motor.close()
    app.dependency_overrides.clear()
    for coll, q in (("workspace_cases", {"id": {"$regex": f"^{_P}"}}),
                    ("users", {"email": {"$regex": f"^{_P}"}}),
                    ("xdr_canonical_evidence", {"event_id": {"$regex": f"^{_P}"}}),
                    ("v2_shadow_observations", {"case_id": {"$regex": f"^{_P}"}})):
        db[coll].delete_many(q)


def _client(app, user=None):
    """The ONE TestClient of this test — one portal, one event loop, so the
    Motor client bound above stays usable across requests."""
    if user is None:
        app.dependency_overrides.pop(get_current_user, None)
    else:
        app.dependency_overrides[get_current_user] = lambda: user
    return app.state.test_client


ROUTE = f"/api/incidents/{INC}/canonical-evidence"


def _rows(app, user=OWN):
    r = _client(app, user).get(ROUTE)
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    return body, {row["canonical_evidence_id"]: row for row in body["rows"]}


# ── propagation (pure builder · deterministic) ──────────────────────
def test_frame_carries_the_persisted_canonical_identity():
    ev = {"iid": "evt_x", "ts": "2026-06-01T10:00:00+00:00",
          "kind": "process_create", "adapter": "a", "sequence": 0,
          "device_iid": "dev_1", "canonical_event_id": "ce-1"}
    frames = build_device_trajectory([ev], device_iid="dev_1")
    assert len(frames) == 1
    f = frames[0].to_dict()
    assert f["canonical_evidence_id"] == "ce-1"
    # the other identities are NOT collapsed into it
    assert f["frame_iid"].startswith("tf_")
    assert f["evidence_ids"] == ["evt_x"]


def test_propagation_is_deterministic_and_never_invented():
    ev = {"iid": "evt_y", "ts": "2026-06-01T10:00:00+00:00",
          "kind": "file_create", "adapter": "a", "sequence": 3,
          "device_iid": "dev_1", "canonical_event_id": "ce-2"}
    a = build_device_trajectory([ev], device_iid="dev_1")[0].to_dict()
    b = build_device_trajectory([dict(ev)], device_iid="dev_1")[0].to_dict()
    assert a == b
    no_id = dict(ev); no_id.pop("canonical_event_id")
    c = build_device_trajectory([no_id], device_iid="dev_1")[0].to_dict()
    assert c["canonical_evidence_id"] is None


def test_frame_bridge_state_is_stated_not_guessed():
    frames = [{"canonical_evidence_id": "ce-1"},
              {"canonical_evidence_id": "ce-missing"},
              {"canonical_evidence_id": None}]
    annotate_frames(frames, {"ce-1"})
    assert [f["bridge_state"] for f in frames] == [
        BRIDGED, REFERENCED_RECORD_ABSENT, LEGACY_UNBRIDGED]


# ── incident canonical-evidence projection ──────────────────────────
def test_every_authoritative_reference_is_projected(harness):
    app, _ = harness
    body, by_id = _rows(app)
    assert set(by_id) == {CE_PIPELINE, CE_CAMPAIGN, CE_OBS, CE_ABSENT,
                          CE_FOREIGN}
    # multiple canonical ids in ONE incident each resolve on their own
    for cid in (CE_PIPELINE, CE_CAMPAIGN, CE_OBS):
        assert by_id[cid]["bridge_state"] == BRIDGED, cid
        assert by_id[cid]["record"]["source_product"] == "Linux Sensor"
        assert by_id[cid]["record"]["raw_reference"]["kind"] == "POINTER"
    assert body["counts"][BRIDGED] == 3
    # the row identity is the canonical id — no generated row id
    assert all("row_id" not in r for r in body["rows"])


def test_reference_without_a_retained_record_is_truthful(harness):
    app, _ = harness
    _body, by_id = _rows(app)
    row = by_id[CE_ABSENT]
    assert row["bridge_state"] == REFERENCED_RECORD_ABSENT
    assert row["tenant_assertion"] == "NO_RECORD"
    assert row["record"] is None
    assert "not an absence of evidence" in row["reason"]
    # the deterministic reference is still reported, not dropped
    assert row["referenced_by"][0]["source"] == "case_observation"


def test_cross_tenant_record_is_never_disclosed(harness):
    app, _ = harness
    r = _client(app, OWN).get(ROUTE)
    assert "FOREIGN-TENANT-PRODUCT" not in r.text
    by_id = {row["canonical_evidence_id"]: row for row in r.json()["rows"]}
    row = by_id[CE_FOREIGN]
    assert row["bridge_state"] == REFERENCED_RECORD_ABSENT
    assert row["tenant_assertion"] == "CONFLICT"
    assert row["record"] is None


def test_legacy_observation_is_reported_in_its_own_namespace(harness):
    app, _ = harness
    body, by_id = _rows(app)
    legacy = body["legacy_unbridged_observations"]
    assert [o["observation_iid"] for o in legacy] == [f"evt_{_P}4"]
    assert legacy[0]["bridge_state"] == LEGACY_UNBRIDGED
    assert body["counts"][LEGACY_UNBRIDGED] == 1
    # it is NOT attached to any canonical record
    assert all(f"evt_{_P}4" not in (r.get("observation_iids") or [])
               for r in body["rows"])


# ── authorization · the incident is the authority, never an id ──────
def test_anonymous_is_refused_without_disclosure(harness):
    app, _ = harness
    r = _client(app).get(ROUTE)
    assert r.status_code in (401, 403, 404), r.status_code
    assert "P1-SECRET-INCIDENT" not in r.text
    assert CE_PIPELINE not in r.text


def test_cross_tenant_principal_gets_404_without_disclosure(harness):
    app, _ = harness
    r = _client(app, FOREIGN).get(ROUTE)
    assert r.status_code == 404, r.status_code
    assert CE_PIPELINE not in r.text and CE_OBS not in r.text
    assert "P1-SECRET-INCIDENT" not in r.text


def test_unknown_incident_is_404(harness):
    app, _ = harness
    r = _client(app, OWN).get(f"/api/incidents/{_P}nonexistent/canonical-evidence")
    assert r.status_code == 404


# ── inspector · possession of an id is not lookup authority ─────────
def _inspect(app, user, cid, incident=INC):
    return _client(app, user).get(
        f"/api/incidents/{incident}/inspector/event/{cid}")


def test_inspector_resolves_every_canonical_id_of_the_incident(harness):
    app, _ = harness
    for cid in (CE_PIPELINE, CE_CAMPAIGN, CE_OBS):
        r = _inspect(app, OWN, cid)
        assert r.status_code == 200, r.text[:200]
        j = r.json()
        assert j.get("state") != "MISSING", cid
        assert j["identity"]["label"] == cid
        labels = {row["label"] for row in j["context"]["relationships"]}
        assert "RAW SOURCE" in labels          # → original source provenance
        assert "NORMALIZER" in labels


def test_inspector_refuses_a_fabricated_canonical_id(harness):
    app, _ = harness
    r = _inspect(app, OWN, CE_FABRICATED)
    assert r.status_code == 200
    assert r.json()["state"] == "MISSING"


@pytest.mark.parametrize("fake", ["evt_deadbeefdeadbeef", "tf_deadbeefdeadbeef",
                                  "sysmon-1-deadbeef"])
def test_inspector_cannot_be_enumerated_with_engine_ids(harness, fake):
    app, _ = harness
    r = _inspect(app, OWN, fake)
    assert r.json()["state"] == "MISSING", fake


def test_inspector_refuses_a_cross_tenant_canonical_id(harness):
    app, _ = harness
    r = _inspect(app, OWN, CE_FOREIGN)
    assert r.json()["state"] == "MISSING"
    assert "FOREIGN-TENANT-PRODUCT" not in r.text


def test_inspector_refuses_a_cross_tenant_principal(harness):
    app, _ = harness
    r = _inspect(app, FOREIGN, CE_PIPELINE)
    assert r.status_code == 404
    assert "Linux Sensor" not in r.text


def test_inspector_refuses_a_record_that_is_not_retained(harness):
    app, _ = harness
    r = _inspect(app, OWN, CE_ABSENT)
    assert r.json()["state"] == "MISSING"
