"""
test_xdr_scenarios.py — SOC-100 Scenario Intelligence regression.

Locked invariant (owner directive · 2026-02-30):
  Scenario knowledge  ≠  Incident evidence  ≠  Detection  ≠  Verdict

These tests enforce every architectural guarantee that keeps SOC-100
from becoming a source of fabricated evidence, observations, or
verdicts.  They MUST all remain green.
"""
from __future__ import annotations

import os
import re
import pytest
from fastapi.testclient import TestClient

# Import the app the same way other backend tests do.
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from server import app  # noqa: E402

client = TestClient(app)


# ── Corpus load + schema fidelity ─────────────────────────────────
def test_corpus_loads():
    r = client.get("/api/xdr/scenarios")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1, "corpus must load at least one scenario"
    assert isinstance(body["scenarios"], list)


def test_corpus_ids_are_unique():
    body = client.get("/api/xdr/scenarios").json()
    ids = [s["scenario_id"] for s in body["scenarios"]]
    assert len(ids) == len(set(ids)), "duplicate scenario_ids"


def test_scenario_required_fields():
    body = client.get("/api/xdr/scenarios").json()
    required = {"scenario_id", "scenario_number", "category", "name",
                        "threat", "attack_techniques"}
    for s in body["scenarios"]:
        assert required.issubset(s.keys()), \
            f"scenario {s.get('scenario_id')} missing required fields"


def test_scenario_categories_are_valid():
    body = client.get("/api/xdr/scenarios").json()
    valid = {"phishing", "malware", "credential", "vpn", "dns", "network",
                    "powershell", "ransomware", "cloud", "insider", "web", "other"}
    for s in body["scenarios"]:
        assert s["category"] in valid, \
            f"scenario {s['scenario_id']} has invalid category {s['category']}"


def test_attack_techniques_are_well_formed():
    body = client.get("/api/xdr/scenarios").json()
    tech_re = re.compile(r"^T\d{4}(?:\.\d{3})?$")
    for s in body["scenarios"]:
        for t in s.get("attack_techniques", []) or []:
            assert tech_re.match(t), \
                f"scenario {s['scenario_id']} has malformed technique {t}"


def test_get_single_scenario():
    body = client.get("/api/xdr/scenarios").json()
    sid = body["scenarios"][0]["scenario_id"]
    r = client.get(f"/api/xdr/scenarios/{sid}")
    assert r.status_code == 200
    assert r.json()["scenario_id"] == sid


def test_get_scenario_404():
    r = client.get("/api/xdr/scenarios/S-999999")
    assert r.status_code == 404


# ── Match determinism + anti-fabrication ─────────────────────────
@pytest.fixture
def seeded_incident():
    """Insert a minimal incident with real evidence into Mongo so the
    scenario-match endpoint has something authentic to match against."""
    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    incident_id = "test-scenario-match-fixture"
    doc = {
        "id": incident_id,
        "title": "PowerShell EncodedCommand test",
        "verdict_stage2": {
            "evidence": [
                {"rule_id": "R-PS-ENC-1", "technique_id": "T1059.001",
                    "entity": {"image": "powershell.exe", "pid": 4242}},
            ],
        },
    }
    db.incidents.update_one({"id": incident_id}, {"$set": doc}, upsert=True)
    yield incident_id
    db.incidents.delete_one({"id": incident_id})


def test_scenario_match_deterministic(seeded_incident):
    """Match determinism: same incident → identical response."""
    r1 = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match")
    r2 = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match")
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["matches"] == r2.json()["matches"], \
        "scenario matching is NOT deterministic"


def test_scenario_match_powershell_technique(seeded_incident):
    """The seeded incident has T1059.001 — matches should include
    at least one scenario whose attack_techniques contain T1059.001."""
    body = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
    matched_techs = set()
    for m in body["matches"]:
        matched_techs.update(m["matching_techniques"])
    assert "T1059.001" in matched_techs, \
        "seeded T1059.001 evidence did not match any scenario"


def test_scenario_match_missing_incident():
    r = client.post("/api/xdr/investigation/nonexistent-id/scenario-match")
    assert r.status_code == 404


def test_scenario_match_never_injects_verdict(seeded_incident):
    """Anti-fabrication: the response must NEVER contain a verdict-like
    field or an observation-shaped inference."""
    body = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
    # Recursive scan — no key should look like a verdict.
    forbidden = {"verdict", "confirmed_impact", "observation_id",
                        "confidence", "severity_score"}
    def scan(node):
        if isinstance(node, dict):
            for k, v in node.items():
                assert k.lower() not in forbidden, \
                    f"scenario-match leaked verdict-shaped key: {k}"
                scan(v)
        elif isinstance(node, list):
            for v in node: scan(v)
    scan(body)


def test_invariant_string_in_response(seeded_incident):
    """The response must surface the anti-fabrication invariant so
    downstream consumers cannot forget it."""
    body = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
    assert "guidance" in body["invariant"].lower()
    assert "verdict" in body["invariant"].lower()


def test_matches_ranked_by_score(seeded_incident):
    body = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
    scores = [m["match_score"] for m in body["matches"]]
    assert scores == sorted(scores, reverse=True), \
        "matches must be sorted by match_score DESC"


def test_empty_incident_no_fabrication():
    """An incident with zero evidence must produce zero matches — the
    scenario corpus MUST NOT invent a match to look useful."""
    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    incident_id = "test-empty-fixture"
    db.incidents.update_one({"id": incident_id},
                                             {"$set": {"id": incident_id}}, upsert=True)
    try:
        body = client.post(f"/api/xdr/investigation/{incident_id}/scenario-match").json()
        assert body["matches"] == [], \
            "empty incident produced fabricated scenario matches"
    finally:
        db.incidents.delete_one({"id": incident_id})
