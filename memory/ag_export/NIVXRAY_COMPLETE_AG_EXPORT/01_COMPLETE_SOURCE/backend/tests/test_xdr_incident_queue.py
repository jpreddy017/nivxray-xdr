"""test_xdr_incident_queue.py — Phase 2 · Investigation-Aware Queue.

Owner-locked invariants:
  - Queue is a READ MODEL projected from canonical evidence — never
    runs an engine, never fabricates a value.
  - Every filter chip composes with the Phase-1 ``lens``.
  - Deterministic sort (stable id-tiebreaker).
  - Auto-Investigation status reads ``engine_executions`` when present
    and honestly emits ``NOT_RUN`` otherwise.
  - Bulk ops never mutate canonical evidence.
  - Saved views are per-user scoped.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from server import app  # noqa: E402

client = TestClient(app)


def _db():
    from pymongo import MongoClient
    return MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]


def _iso(dt): return dt.isoformat()


@pytest.fixture
def clean():
    db = _db()
    db.workspace_cases.delete_many({"id": {"$regex": "^q2-"}})
    db.xdr_audit_log.delete_many({"incident_id": {"$regex": "^q2-"}})
    db.xdr_saved_views.delete_many({"name": {"$regex": "^q2-"}})
    if "engine_executions" in db.list_collection_names():
        db.engine_executions.delete_many({"incident_id": {"$regex": "^q2-"}})
    yield db
    db.workspace_cases.delete_many({"id": {"$regex": "^q2-"}})
    db.xdr_audit_log.delete_many({"incident_id": {"$regex": "^q2-"}})
    db.xdr_saved_views.delete_many({"name": {"$regex": "^q2-"}})
    if "engine_executions" in db.list_collection_names():
        db.engine_executions.delete_many({"incident_id": {"$regex": "^q2-"}})


def _seed(db, cid, **kw):
    now = _iso(datetime.now(timezone.utc))
    doc = {"id": cid, "name": kw.get("name", "q2-case"),
             "user_email": kw.get("user_email"),
             "tenant_id":  kw.get("tenant", "acme"),
             "created_at": kw.get("created_at", now),
             "updated_at": kw.get("updated_at", now),
             "incident_state":    kw.get("state", "new"),
             "incident_assignee": kw.get("assignee")}
    if "priority"    in kw: doc["incident_priority"] = kw["priority"]
    if "severity"    in kw: doc["incident_severity"] = kw["severity"]
    if "verdict"     in kw or "confidence" in kw or "engine" in kw or "evidence" in kw:
        doc["verdict_stage2"] = {
            "label":             kw.get("verdict"),
            "confidence_bucket": kw.get("confidence"),
            "engine":            kw.get("engine"),
            "evidence":          kw.get("evidence", []),
        }
    if "sla_due_at"  in kw: doc["sla_due_at"] = kw["sla_due_at"]
    if "techniques"  in kw: doc["techniques"] = kw["techniques"]
    db.workspace_cases.insert_one(doc)


# ── Projection shape ─────────────────────────────────────────────
def test_row_projects_all_15_columns(clean):
    db = clean
    _seed(db, "q2-shape-1", priority="P1", severity="critical",
            verdict="malicious", confidence="high",
            engine="cisco-sep",
            evidence=[{"technique_id": "T1059.001"},
                        {"technique_id": "T1204.002"}],
            sla_due_at=_iso(datetime.now(timezone.utc) + timedelta(hours=2)))
    body = client.get("/api/incidents?limit=500").json()
    row = next(r for r in body["incidents"] if r["id"] == "q2-shape-1")
    for c in ("priority", "severity", "verdict", "confidence", "customer",
                "detection_source", "evidence_count", "techniques_top",
                "sla_due_at", "aging_seconds", "assignee", "state",
                "last_activity", "auto_investigation"):
        assert c in row, f"missing column {c}"
    assert row["evidence_count"] == 2
    assert "T1059.001" in row["techniques_top"]
    assert row["detection_source"] == "cisco-sep"
    assert row["verdict"]["stage2_label"] == "malicious"
    assert row["auto_investigation"]["status"] == "NOT_RUN"


def test_invariant_string_in_response():
    body = client.get("/api/incidents?limit=5").json()
    assert "projection" in body["invariant"].lower()
    assert "never runs" in body["invariant"].lower()


# ── Filters compose with lens ────────────────────────────────────
def test_filters_compose_with_lens(clean):
    db = clean
    _seed(db, "q2-flt-1", state="new", priority="P1", verdict="malicious")
    _seed(db, "q2-flt-2", state="new", priority="P1", verdict="suspicious")
    _seed(db, "q2-flt-3", state="new", priority="P2", verdict="malicious")
    body = client.get("/api/incidents?lens=critical&verdict=malicious&limit=500").json()
    ids = {r["id"] for r in body["incidents"]} & {"q2-flt-1", "q2-flt-2", "q2-flt-3"}
    assert ids == {"q2-flt-1"}
    assert body["applied_filters"].get("verdict") == "malicious"


def test_filter_by_technique(clean):
    db = clean
    _seed(db, "q2-tech-1", state="new",
            evidence=[{"technique_id": "T1059.001"}])
    _seed(db, "q2-tech-2", state="new",
            evidence=[{"technique_id": "T1105"}])
    body = client.get("/api/incidents?technique=T1059.001&limit=500").json()
    ids = {r["id"] for r in body["incidents"]} & {"q2-tech-1", "q2-tech-2"}
    assert ids == {"q2-tech-1"}


def test_filter_by_detection_source(clean):
    db = clean
    _seed(db, "q2-ds-1", state="new", engine="cisco-sep")
    _seed(db, "q2-ds-2", state="new", engine="msft-defender")
    body = client.get("/api/incidents?detection_source=cisco-sep&limit=500").json()
    ids = {r["id"] for r in body["incidents"]} & {"q2-ds-1", "q2-ds-2"}
    assert ids == {"q2-ds-1"}


def test_filter_unknown_lens_rejected():
    r = client.get("/api/incidents?lens=nope")
    assert r.status_code == 400


# ── Deterministic sort ────────────────────────────────────────────
def test_sort_by_priority_deterministic(clean):
    db = clean
    for i, p in enumerate(["P3", "P1", "P2", "P1", "P2"]):
        _seed(db, f"q2-sort-{i}", state="new", priority=p)
    a = client.get("/api/incidents?sort=priority&order=asc&limit=500").json()
    b = client.get("/api/incidents?sort=priority&order=asc&limit=500").json()
    a_ids = [r["id"] for r in a["incidents"] if r["id"].startswith("q2-sort-")]
    b_ids = [r["id"] for r in b["incidents"] if r["id"].startswith("q2-sort-")]
    assert a_ids == b_ids


# ── Auto-Investigation status: NOT_RUN honesty ────────────────────
def test_auto_investigation_not_run_when_no_executions(clean):
    db = clean
    _seed(db, "q2-ai-1", state="new")
    if "engine_executions" in db.list_collection_names():
        db.engine_executions.delete_many({"incident_id": "q2-ai-1"})
    body = client.get("/api/incidents?limit=500").json()
    row = next(r for r in body["incidents"] if r["id"] == "q2-ai-1")
    assert row["auto_investigation"]["status"] == "NOT_RUN"
    assert row["auto_investigation"]["engines_total"] == 0


def test_auto_investigation_complete_when_all_ok(clean):
    db = clean
    _seed(db, "q2-ai-c", state="new")
    now = _iso(datetime.now(timezone.utc))
    db.engine_executions.insert_many([
        {"incident_id": "q2-ai-c", "engine": "iue",  "status": "ok",  "at": now},
        {"incident_id": "q2-ai-c", "engine": "uaie", "status": "ok",  "at": now},
        {"incident_id": "q2-ai-c", "engine": "die",  "status": "ok",  "at": now},
    ])
    body = client.get("/api/incidents?limit=500").json()
    row = next(r for r in body["incidents"] if r["id"] == "q2-ai-c")
    assert row["auto_investigation"]["status"] == "COMPLETE"
    assert row["auto_investigation"]["engines_ok"] == 3


def test_auto_investigation_never_fabricated(clean):
    """The queue MUST NEVER emit COMPLETE/RUNNING/FAILED without a
    corresponding row in engine_executions."""
    db = clean
    _seed(db, "q2-ai-f", state="new",
            evidence=[{"technique_id": "T1059.001"}])
    if "engine_executions" in db.list_collection_names():
        db.engine_executions.delete_many({"incident_id": "q2-ai-f"})
    body = client.get("/api/incidents?limit=500").json()
    row = next(r for r in body["incidents"] if r["id"] == "q2-ai-f")
    assert row["auto_investigation"]["status"] == "NOT_RUN"


# ── Bulk operations ──────────────────────────────────────────────
def test_bulk_assign_never_mutates_canonical_evidence(clean):
    db = clean
    _seed(db, "q2-bulk-1", state="new",
            evidence=[{"technique_id": "T1059.001", "rule_id": "R-1"}])
    before = db.workspace_cases.find_one({"id": "q2-bulk-1"},
                                             {"_id": 0, "verdict_stage2": 1})
    r = client.post("/api/xdr/incidents/bulk/assign",
                      json={"incident_ids": ["q2-bulk-1"],
                              "assignee": "alice@ex", "reason": "triage"})
    assert r.status_code == 200
    assert r.json()["updated_count"] == 1
    after = db.workspace_cases.find_one({"id": "q2-bulk-1"},
                                            {"_id": 0, "verdict_stage2": 1})
    assert before == after
    # Audit written.
    a = db.xdr_audit_log.find_one({"incident_id": "q2-bulk-1"})
    assert a and a["action"] == "bulk_assign"
    assert a["canonical_evidence_touched"] is False


def test_bulk_state_records_history_and_audit(clean):
    db = clean
    _seed(db, "q2-bulk-2", state="new")
    r = client.post("/api/xdr/incidents/bulk/state",
                      json={"incident_ids": ["q2-bulk-2"],
                              "target_state": "in_progress",
                              "note": "starting triage"})
    assert r.status_code == 200, r.text
    doc = db.workspace_cases.find_one({"id": "q2-bulk-2"})
    assert doc["incident_state"] == "in_progress"
    assert len(doc["incident_state_history"]) == 1
    assert doc["incident_state_history"][0]["from_state"] == "new"
    assert doc["incident_state_history"][0]["to_state"] == "in_progress"
    audit = db.xdr_audit_log.find_one({"incident_id": "q2-bulk-2"})
    assert audit and audit["action"] == "bulk_state"


def test_bulk_state_rejects_invalid_state():
    r = client.post("/api/xdr/incidents/bulk/state",
                      json={"incident_ids": ["x"], "target_state": "bogus"})
    assert r.status_code == 400


def test_bulk_is_idempotent(clean):
    db = clean
    _seed(db, "q2-idem-1", state="new", assignee="alice@ex")
    r1 = client.post("/api/xdr/incidents/bulk/assign",
                       json={"incident_ids": ["q2-idem-1"],
                               "assignee": "alice@ex"})
    r2 = client.post("/api/xdr/incidents/bulk/assign",
                       json={"incident_ids": ["q2-idem-1"],
                               "assignee": "alice@ex"})
    # First call: no_change (already alice); second: same.
    assert r1.json()["updated_count"] == 0
    assert r2.json()["updated_count"] == 0
    assert r1.json()["skipped"][0]["reason"] == "no_change"


# ── Saved views ──────────────────────────────────────────────────
def test_saved_view_full_crud(clean):
    # Create
    r = client.post("/api/xdr/saved-views",
                      json={"name": "q2-view-A", "filters": {"priority": "P1"},
                              "sort": "sla_due_at", "order": "asc",
                              "lens": "critical",
                              "visible_columns": ["priority", "verdict"]})
    assert r.status_code == 200
    v = r.json()
    assert v["name"] == "q2-view-A"
    vid = v["id"]

    # Read one
    r = client.get(f"/api/xdr/saved-views/{vid}")
    assert r.status_code == 200
    assert r.json()["lens"] == "critical"

    # List
    r = client.get("/api/xdr/saved-views")
    assert r.status_code == 200
    ids = {x["id"] for x in r.json()["views"]}
    assert vid in ids

    # Update
    r = client.put(f"/api/xdr/saved-views/{vid}",
                     json={"name": "q2-view-A2", "filters": {"priority": "P2"},
                             "sort": "updated_at", "order": "desc",
                             "lens": None, "visible_columns": ["priority"]})
    assert r.status_code == 200
    assert r.json()["name"] == "q2-view-A2"

    # Delete
    r = client.delete(f"/api/xdr/saved-views/{vid}")
    assert r.status_code == 200
    r = client.get(f"/api/xdr/saved-views/{vid}")
    assert r.status_code == 404


def test_saved_view_missing_404():
    r = client.get("/api/xdr/saved-views/does-not-exist")
    assert r.status_code == 404


def test_queue_never_writes_to_incidents(clean):
    """Reading the queue must never mutate any incident.  Snapshot →
    hit every filter → verify byte-identical."""
    db = clean
    _seed(db, "q2-ro-1", state="new", priority="P1", verdict="malicious",
            evidence=[{"technique_id": "T1059.001"}])
    before = db.workspace_cases.find_one({"id": "q2-ro-1"}, {"_id": 0})
    for qs in ("?lens=critical", "?priority=P1", "?verdict=malicious",
                 "?technique=T1059.001", "?sort=priority&order=asc"):
        r = client.get(f"/api/incidents{qs}&limit=500")
        assert r.status_code == 200
    after = db.workspace_cases.find_one({"id": "q2-ro-1"}, {"_id": 0})
    assert before == after
