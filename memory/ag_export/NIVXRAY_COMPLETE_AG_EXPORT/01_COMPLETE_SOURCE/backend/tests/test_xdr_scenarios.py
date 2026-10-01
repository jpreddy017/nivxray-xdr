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


def test_corpus_is_exactly_100():
    """Full SOC-100 corpus — no more, no less."""
    body = client.get("/api/xdr/scenarios").json()
    assert body["total"] == 100, f"expected 100 scenarios, got {body['total']}"
    assert body["count"] == 100


def test_corpus_scenario_numbers_are_1_to_100():
    body = client.get("/api/xdr/scenarios").json()
    nums = sorted(s["scenario_number"] for s in body["scenarios"])
    assert nums == list(range(1, 101)), \
        f"scenario_numbers must be 1..100 with no gaps, got {nums}"


def test_corpus_ids_are_unique():
    body = client.get("/api/xdr/scenarios").json()
    ids = [s["scenario_id"] for s in body["scenarios"]]
    assert len(ids) == len(set(ids)), "duplicate scenario_ids"


def test_scenario_required_fields():
    """Every scenario has the required top-level schema fields."""
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


def test_every_scenario_has_at_least_one_attack_technique():
    """Anti-fabrication check: every scenario must map to real MITRE ATT&CK."""
    body = client.get("/api/xdr/scenarios").json()
    empty = [s["scenario_id"] for s in body["scenarios"]
             if not s.get("attack_techniques")]
    assert empty == [], f"scenarios without ATT&CK: {empty}"


def test_get_single_scenario_has_full_playbook_schema():
    """The full-schema endpoint returns the investigation playbook."""
    body = client.get("/api/xdr/scenarios").json()
    sid = body["scenarios"][0]["scenario_id"]
    r = client.get(f"/api/xdr/scenarios/{sid}")
    assert r.status_code == 200
    s = r.json()
    # Extended investigation-playbook schema (owner directive):
    for k in ("investigation_objective", "investigation_steps",
              "decision_evidence", "containment", "escalation",
              "closure", "detection_improvement"):
        assert k in s, f"missing playbook field {k} in {sid}"
    assert isinstance(s["investigation_steps"], list)
    assert len(s["investigation_steps"]) >= 1, \
        f"scenario {sid} has zero investigation steps"


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


@pytest.fixture
def empty_incident():
    """Incident with zero evidence — the anti-fabrication baseline."""
    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    incident_id = "test-empty-honest-fixture"
    db.incidents.update_one({"id": incident_id},
                            {"$set": {"id": incident_id}}, upsert=True)
    yield incident_id
    db.incidents.delete_one({"id": incident_id})


def test_scenario_match_deterministic(seeded_incident):
    """Match determinism: same incident → identical response 3 times."""
    responses = [
        client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
        for _ in range(3)
    ]
    assert responses[0]["matches"] == responses[1]["matches"] == responses[2]["matches"], \
        "scenario matching is NOT deterministic"


def test_scenario_match_score_is_deterministic(seeded_incident):
    """Every match_score value must be identical across repeated calls."""
    a = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
    b = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
    scores_a = [(m["scenario_id"], m["match_score"]) for m in a["matches"]]
    scores_b = [(m["scenario_id"], m["match_score"]) for m in b["matches"]]
    assert scores_a == scores_b, "match_score is NOT deterministic"


def test_scenario_match_ranking_is_deterministic(seeded_incident):
    """Rank order MUST be stable across repeated calls."""
    a = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
    b = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
    order_a = [m["scenario_id"] for m in a["matches"]]
    order_b = [m["scenario_id"] for m in b["matches"]]
    assert order_a == order_b, "ranking is NOT deterministic"


def test_scenario_match_pivots_are_deterministic(seeded_incident):
    """Recommended-pivot output must be stable across repeated calls."""
    a = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
    b = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
    for m1, m2 in zip(a["matches"], b["matches"]):
        assert m1["recommended_pivots"] == m2["recommended_pivots"], \
            f"pivots not deterministic for {m1['scenario_id']}"


def test_scenario_match_powershell_technique(seeded_incident):
    """The seeded incident has T1059.001 — matches must include at least
    one scenario whose attack_techniques contain T1059.001."""
    body = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
    matched_techs = set()
    for m in body["matches"]:
        matched_techs.update(m["matching_techniques"])
    assert "T1059.001" in matched_techs, \
        "seeded T1059.001 evidence did not match any scenario"


def test_scenario_match_missing_incident():
    r = client.post("/api/xdr/investigation/nonexistent-id/scenario-match")
    assert r.status_code == 404


def test_matches_ranked_by_score(seeded_incident):
    body = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
    scores = [m["match_score"] for m in body["matches"]]
    assert scores == sorted(scores, reverse=True), \
        "matches must be sorted by match_score DESC"


# ── Anti-fabrication invariants ──────────────────────────────────
def test_empty_incident_no_fabricated_matches(empty_incident):
    """An incident with zero evidence MUST produce zero matches.  The
    scenario corpus MUST NOT invent a match to look useful."""
    body = client.post(f"/api/xdr/investigation/{empty_incident}/scenario-match").json()
    assert body["matches"] == [], \
        "empty incident produced fabricated scenario matches"


def test_empty_incident_missing_telemetry_honesty(empty_incident):
    """An incident with zero evidence must report empty observed_* arrays
    — the endpoint must not synthesize placeholder telemetry."""
    body = client.post(f"/api/xdr/investigation/{empty_incident}/scenario-match").json()
    assert body["observed_techniques"] == [], \
        "empty incident leaked fabricated observed_techniques"
    assert body["observed_processes"] == [], \
        "empty incident leaked fabricated observed_processes"


def test_scenario_match_never_injects_verdict(seeded_incident):
    """Anti-fabrication: the response must NEVER contain a verdict-shaped
    key or an observation_id-style inference."""
    body = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
    forbidden = {"verdict", "confirmed_impact", "observation_id",
                 "confidence", "severity_score", "verdict_confidence",
                 "risk_score", "is_malicious"}
    def scan(node):
        if isinstance(node, dict):
            for k, v in node.items():
                assert k.lower() not in forbidden, \
                    f"scenario-match leaked verdict-shaped key: {k}"
                scan(v)
        elif isinstance(node, list):
            for v in node:
                scan(v)
    scan(body)


def test_scenario_match_does_not_write_evidence_to_incident(seeded_incident):
    """Scenario knowledge ≠ Incident evidence.  Calling scenario-match
    must NEVER mutate the incident's evidence rows."""
    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]

    before = db.incidents.find_one({"id": seeded_incident})
    before_evidence = ((before or {}).get("verdict_stage2") or {}).get("evidence")
    before_techs = before.get("techniques") or before.get("attack_techniques")

    client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match")

    after = db.incidents.find_one({"id": seeded_incident})
    after_evidence = ((after or {}).get("verdict_stage2") or {}).get("evidence")
    after_techs = after.get("techniques") or after.get("attack_techniques")

    assert before_evidence == after_evidence, \
        "scenario-match wrote fabricated evidence into the incident"
    assert before_techs == after_techs, \
        "scenario-match wrote fabricated ATT&CK observations into the incident"


def test_scenario_match_does_not_generate_observations(seeded_incident):
    """Scenario knowledge must NEVER emit OBSERVATION objects into any
    canonical collection.  Observations are the exclusive output of the
    server-side genealogy / correlation engines."""
    from pymongo import MongoClient
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]

    # A candidate collection for observations exists in Task E — count
    # the docs before/after to prove scenario-match is inert.
    coll_names = ["xdr_observations", "observations", "xdr_scenario_observations"]
    before = {c: db[c].count_documents({}) for c in coll_names
              if c in db.list_collection_names()}

    client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match")

    after = {c: db[c].count_documents({}) for c in coll_names
             if c in db.list_collection_names()}

    for c in before:
        assert before[c] == after.get(c), \
            f"scenario-match wrote {after.get(c) - before[c]} rows into {c}"


def test_scenario_match_never_generates_attack_findings(seeded_incident):
    """Anti-fabrication: matches expose the scenario's ATT&CK expectations
    (attack_techniques field), but they must NEVER label those as
    'observed' or emit them into the incident's ATT&CK arrays."""
    body = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
    observed = set(body["observed_techniques"])
    for m in body["matches"]:
        for t in m["missing_techniques"]:
            assert t not in observed, \
                f"scenario match {m['scenario_id']} labelled missing tech {t} as observed"


def test_invariant_string_in_response(seeded_incident):
    """The response must surface the anti-fabrication invariant so
    downstream consumers cannot forget it."""
    body = client.post(f"/api/xdr/investigation/{seeded_incident}/scenario-match").json()
    inv = body["invariant"].lower()
    assert "guidance" in inv
    assert "verdict" in inv
    assert "never" in inv
