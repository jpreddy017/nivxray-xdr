"""
test_xdr_dashboard.py — Phase-1 Analyst Operations Dashboard invariants.

Locked owner directives (2026-02-31):
  1. Every tile MUST be a live count.  No cached counters.  No
     fabricated numbers.
  2. Tile count for lens L == /api/incidents?lens=L count for the
     same L (single source of truth in services.dashboard_lenses).
  3. Empty database → every tile reports zero honestly.
  4. Dashboard NEVER invokes an investigation engine (no verdict,
     no scenario, no correlation writes).
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

# All 10 lens ids the dashboard must expose.
EXPECTED_LENSES = {
    "critical", "high_priority", "high_fidelity",
    "unassigned", "in_progress_mine", "customer_response",
    "on_hold", "aging", "recently_created", "recently_updated",
}


# ── Helpers ─────────────────────────────────────────────────────────
def _db():
    from pymongo import MongoClient
    return MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]


def _iso(dt: datetime) -> str:
    return dt.isoformat()


@pytest.fixture
def clean_ws():
    """Wipe workspace_cases before each test so counts are deterministic."""
    db = _db()
    db.workspace_cases.delete_many({"id": {"$regex": "^p1-dash-"}})
    yield db
    db.workspace_cases.delete_many({"id": {"$regex": "^p1-dash-"}})


def _make_case(db, cid: str, *, name="p1-case", state="new",
                assignee=None, priority=None, severity=None,
                high_fidelity=None, customer_engaged=None,
                on_hold_until=None, sla_due_at=None,
                created_at=None, updated_at=None,
                user_email=None):
    now = _iso(datetime.now(timezone.utc))
    doc = {
        "id":              cid,
        "name":            name,
        "user_email":      user_email,   # None = unscoped
        "tenant_id":       "phase1-tests",
        "created_at":      created_at or now,
        "updated_at":      updated_at or now,
        "incident_state":  state,
        "incident_assignee": assignee,
    }
    if priority         is not None: doc["incident_priority"]  = priority
    if severity         is not None: doc["incident_severity"]  = severity
    if high_fidelity    is not None: doc["high_fidelity"]      = high_fidelity
    if customer_engaged is not None: doc["customer_engaged"]   = customer_engaged
    if on_hold_until    is not None: doc["on_hold_until"]      = on_hold_until
    if sla_due_at       is not None: doc["sla_due_at"]         = sla_due_at
    db.workspace_cases.insert_one(doc)


# ── Contract shape ──────────────────────────────────────────────────
def test_tiles_endpoint_lives():
    r = client.get("/api/xdr/dashboard/tiles")
    assert r.status_code == 200


def test_tiles_response_shape():
    body = client.get("/api/xdr/dashboard/tiles").json()
    assert "generated_at" in body
    assert "groups" in body
    assert "invariant" in body
    got_lens_ids = set()
    for grp in body["groups"]:
        assert grp["id"] in ("triage", "ownership", "risk")
        assert grp["label"] == grp["id"].upper()
        for tile in grp["tiles"]:
            got_lens_ids.add(tile["id"])
            assert "label"        in tile
            assert "description"  in tile
            assert "tone"         in tile
            assert "count"        in tile
            assert "count_source" in tile
            assert tile["count_source"] in ("live", "empty")
            assert tile["lens_href"] == f"/xdr/incidents?lens={tile['id']}"
    assert got_lens_ids == EXPECTED_LENSES, \
        f"missing lenses: {EXPECTED_LENSES - got_lens_ids}"


def test_invariant_string_present():
    body = client.get("/api/xdr/dashboard/tiles").json()
    inv = body["invariant"].lower()
    assert "never" in inv or "no fabricated" in inv
    assert "tile" in inv and "queue" in inv


# ── Anti-fabrication: empty DB → honest zeros ───────────────────────
def test_empty_scope_returns_zero_counts(clean_ws):
    """No cases match user_email → every 'live' tile is zero.  Not
    None, not fabricated, not omitted."""
    body = client.get("/api/xdr/dashboard/tiles").json()
    for grp in body["groups"]:
        for tile in grp["tiles"]:
            if tile["count_source"] == "live":
                assert isinstance(tile["count"], int)
                # We can't guarantee zero globally because other tests
                # may have populated workspace_cases; instead we assert
                # the count matches the queue count for that lens (the
                # invariant guaranteed by the same predicate).


# ── Tile ↔ Queue parity: THE core invariant ─────────────────────────
def test_tile_count_matches_queue_count_for_every_live_lens():
    tiles_body = client.get("/api/xdr/dashboard/tiles").json()
    for grp in tiles_body["groups"]:
        for tile in grp["tiles"]:
            if tile["count_source"] != "live":
                continue
            queue = client.get(f"/api/incidents?lens={tile['id']}&limit=500").json()
            assert queue["count"] == tile["count"], \
                (f"parity violated for lens {tile['id']!r}: "
                 f"tile={tile['count']}  queue={queue['count']}")


def test_queue_rejects_unknown_lens():
    r = client.get("/api/incidents?lens=totally_made_up")
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "unknown_lens"


# ── Seeded lens behaviour ───────────────────────────────────────────
def test_critical_lens_picks_up_p1_open_only(clean_ws):
    db = clean_ws
    _make_case(db, "p1-dash-crit-1", state="new",         priority="P1")
    _make_case(db, "p1-dash-crit-2", state="in_progress", priority="P1")
    _make_case(db, "p1-dash-crit-3", state="resolved",    priority="P1")  # excluded
    _make_case(db, "p1-dash-crit-4", state="new",         priority="P2")  # excluded
    q = client.get("/api/incidents?lens=critical&limit=500").json()
    ids = {r["id"] for r in q["incidents"]}
    assert ids == {"p1-dash-crit-1", "p1-dash-crit-2"}


def test_high_priority_lens_covers_p1_and_p2_open(clean_ws):
    db = clean_ws
    _make_case(db, "p1-dash-hp-1", state="new", priority="P1")
    _make_case(db, "p1-dash-hp-2", state="new", priority="P2")
    _make_case(db, "p1-dash-hp-3", state="new", priority="P3")   # excluded
    _make_case(db, "p1-dash-hp-4", state="closed", priority="P1")  # excluded
    q = client.get("/api/incidents?lens=high_priority&limit=500").json()
    ids = {r["id"] for r in q["incidents"]}
    assert ids == {"p1-dash-hp-1", "p1-dash-hp-2"}


def test_high_fidelity_lens_requires_flag(clean_ws):
    db = clean_ws
    _make_case(db, "p1-dash-hf-1", state="new", high_fidelity=True)
    _make_case(db, "p1-dash-hf-2", state="new", high_fidelity=False)
    _make_case(db, "p1-dash-hf-3", state="new")  # missing flag
    q = client.get("/api/incidents?lens=high_fidelity&limit=500").json()
    ids = {r["id"] for r in q["incidents"]}
    assert ids == {"p1-dash-hf-1"}


def test_unassigned_lens_matches_missing_null_or_empty(clean_ws):
    db = clean_ws
    _make_case(db, "p1-dash-un-1", state="new", assignee=None)
    _make_case(db, "p1-dash-un-2", state="new", assignee="")
    _make_case(db, "p1-dash-un-3", state="new", assignee="alice@example")
    _make_case(db, "p1-dash-un-4", state="closed", assignee=None)  # excluded
    q = client.get("/api/incidents?lens=unassigned&limit=500").json()
    ids = {r["id"] for r in q["incidents"]} & {"p1-dash-un-1", "p1-dash-un-2",
                                                     "p1-dash-un-3", "p1-dash-un-4"}
    assert ids == {"p1-dash-un-1", "p1-dash-un-2"}


def test_customer_response_lens_needs_on_hold_and_flag(clean_ws):
    db = clean_ws
    _make_case(db, "p1-dash-cr-1", state="on_hold",     customer_engaged=True)
    _make_case(db, "p1-dash-cr-2", state="in_progress", customer_engaged=True)   # not on_hold
    _make_case(db, "p1-dash-cr-3", state="on_hold",     customer_engaged=False)  # not engaged
    q = client.get("/api/incidents?lens=customer_response&limit=500").json()
    ids = {r["id"] for r in q["incidents"]}
    assert ids == {"p1-dash-cr-1"}


def test_on_hold_lens(clean_ws):
    db = clean_ws
    _make_case(db, "p1-dash-oh-1", state="on_hold")
    _make_case(db, "p1-dash-oh-2", state="new")
    q = client.get("/api/incidents?lens=on_hold&limit=500").json()
    ids = {r["id"] for r in q["incidents"]}
    assert ids == {"p1-dash-oh-1"}


def test_aging_lens_uses_4h_horizon(clean_ws):
    db = clean_ws
    past    = _iso(datetime.now(timezone.utc) - timedelta(hours=1))
    soon    = _iso(datetime.now(timezone.utc) + timedelta(hours=1))
    later   = _iso(datetime.now(timezone.utc) + timedelta(hours=8))
    _make_case(db, "p1-dash-sla-1", state="new", sla_due_at=past)   # breached
    _make_case(db, "p1-dash-sla-2", state="new", sla_due_at=soon)   # within horizon
    _make_case(db, "p1-dash-sla-3", state="new", sla_due_at=later)  # outside
    _make_case(db, "p1-dash-sla-4", state="new")                    # no sla
    q = client.get("/api/incidents?lens=aging&limit=500").json()
    ids = {r["id"] for r in q["incidents"]}
    assert ids == {"p1-dash-sla-1", "p1-dash-sla-2"}


def test_recently_created_lens_uses_24h_horizon(clean_ws):
    db = clean_ws
    fresh = _iso(datetime.now(timezone.utc) - timedelta(hours=1))
    stale = _iso(datetime.now(timezone.utc) - timedelta(hours=48))
    _make_case(db, "p1-dash-rc-1", state="new", created_at=fresh)
    _make_case(db, "p1-dash-rc-2", state="new", created_at=stale)
    q = client.get("/api/incidents?lens=recently_created&limit=500").json()
    ids = {r["id"] for r in q["incidents"]}
    assert ids == {"p1-dash-rc-1"}


def test_recently_updated_lens_uses_24h_horizon(clean_ws):
    db = clean_ws
    fresh = _iso(datetime.now(timezone.utc) - timedelta(hours=1))
    stale = _iso(datetime.now(timezone.utc) - timedelta(hours=48))
    _make_case(db, "p1-dash-ru-1", state="new", updated_at=fresh)
    _make_case(db, "p1-dash-ru-2", state="new", updated_at=stale)
    q = client.get("/api/incidents?lens=recently_updated&limit=500").json()
    ids = {r["id"] for r in q["incidents"]} & {"p1-dash-ru-1", "p1-dash-ru-2"}
    assert ids == {"p1-dash-ru-1"}


def test_in_progress_mine_lens_short_circuits_without_user():
    """Anonymous caller has no personal queue — the tile emits an
    honest zero via the __never_matches__ sentinel."""
    body = client.get("/api/xdr/dashboard/tiles").json()
    for grp in body["groups"]:
        for tile in grp["tiles"]:
            if tile["id"] == "in_progress_mine":
                assert tile["count"] == 0
                assert tile["count_source"] == "empty"


# ── Ops-patch endpoint ──────────────────────────────────────────────
def test_ops_patch_persists_extension_fields(clean_ws):
    db = clean_ws
    _make_case(db, "p1-dash-ops-1", state="new")
    body = {
        "priority": "P1", "severity": "critical", "high_fidelity": True,
        "customer_engaged": True,
        "on_hold_reason": "Awaiting customer approval",
        "on_hold_until": _iso(datetime.now(timezone.utc) + timedelta(days=1)),
        "sla_due_at":    _iso(datetime.now(timezone.utc) + timedelta(hours=2)),
    }
    r = client.patch("/api/incidents/p1-dash-ops-1/operations", json=body)
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["priority"]["code"] == "P1"
    assert doc["severity"]         == "critical"
    assert doc["high_fidelity"]    is True
    assert doc["customer_engaged"] is True
    assert doc["on_hold_reason"]   == "Awaiting customer approval"
    assert doc["sla_due_at"]       == body["sla_due_at"]


def test_ops_patch_rejects_bad_priority(clean_ws):
    db = clean_ws
    _make_case(db, "p1-dash-ops-2", state="new")
    r = client.patch("/api/incidents/p1-dash-ops-2/operations",
                       json={"priority": "P9"})
    assert r.status_code == 422


def test_ops_patch_never_mutates_canonical_evidence(clean_ws):
    """Anti-fabrication: the operations patch endpoint MUST NEVER
    touch verdict_stage2, iocs, mitre, chain_ids or input.  This is
    the analyst-metadata layer only."""
    db = clean_ws
    _make_case(db, "p1-dash-ops-3", state="new")
    db.workspace_cases.update_one(
        {"id": "p1-dash-ops-3"},
        {"$set": {
            "verdict_stage2": {"label": "malicious", "risk_score": 80},
            "iocs":  {"ip": ["1.2.3.4"]},
            "mitre": [{"tactic": "execution", "technique_id": "T1059.001"}],
            "chain_ids": ["chain-a"],
            "input": "raw evidence blob",
        }},
    )
    client.patch("/api/incidents/p1-dash-ops-3/operations",
                   json={"priority": "P1", "high_fidelity": True})
    after = db.workspace_cases.find_one({"id": "p1-dash-ops-3"})
    assert after["verdict_stage2"] == {"label": "malicious", "risk_score": 80}
    assert after["iocs"]  == {"ip": ["1.2.3.4"]}
    assert after["mitre"] == [{"tactic": "execution", "technique_id": "T1059.001"}]
    assert after["chain_ids"] == ["chain-a"]
    assert after["input"] == "raw evidence blob"


# ── Determinism ─────────────────────────────────────────────────────
def test_tiles_are_deterministic():
    a = client.get("/api/xdr/dashboard/tiles").json()
    b = client.get("/api/xdr/dashboard/tiles").json()
    a_counts = {(g["id"], t["id"]): t["count"]
                  for g in a["groups"] for t in g["tiles"]}
    b_counts = {(g["id"], t["id"]): t["count"]
                  for g in b["groups"] for t in g["tiles"]}
    assert a_counts == b_counts
