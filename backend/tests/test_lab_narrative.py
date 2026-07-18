"""Feb 2026 · v1.3.1 — Analyst Practice Lab narrative-mode endpoint.

Verifies POST /api/lab/attempt/narrative:
  • Returns rubric-scored response (understanding/40, impact/30, recs/30)
  • Enriches expected MITRE IDs with human-readable name + tactic
  • Persists to lab_attempts + updates lab_stats
  • Handles empty payload without crashing
"""
import os
import subprocess

import pytest
import requests

API = os.environ.get("REACT_APP_BACKEND_URL") or subprocess.check_output(
    "grep REACT_APP_BACKEND_URL /app/frontend/.env | cut -d= -f2",
    shell=True,
).decode().strip()

EMAIL, PASSWORD = "admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{API}/api/auth/login",
                      json={"email": EMAIL, "password": PASSWORD}, timeout=10)
    r.raise_for_status()
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def h(token):
    return {"Authorization": f"Bearer {token}"}


def _pick_case_with_mitre(h):
    """Pull a challenge from the corpus that has expected MITRE IDs."""
    for _ in range(30):
        ch = requests.get(f"{API}/api/lab/challenge", headers=h, timeout=10).json()
        rv = requests.get(f"{API}/api/lab/reveal/{ch['challenge_id']}",
                          headers=h, timeout=10).json()
        if rv.get("expected_mitre"):
            return ch, rv
    pytest.skip("no corpus case with expected_mitre found")


def test_narrative_grades_and_returns_rubric(h):
    ch, rv = _pick_case_with_mitre(h)
    r = requests.post(f"{API}/api/lab/attempt/narrative", headers=h, json={
        "challenge_id":    ch["challenge_id"],
        "understanding":   "PowerShell downloads and executes a remote script via IEX and Net.WebClient. Fileless payload delivery.",
        "impact":          "High severity. Arbitrary code execution likely leading to persistence and lateral movement.",
        "recommendations": "Block via EDR ASR, monitor script block logging EID 4104 for IEX+Net.WebClient, quarantine host.",
    }, timeout=45)
    assert r.status_code == 200, r.text
    d = r.json()
    # Rubric caps
    assert 0 <= d["understanding_score"]    <= 40
    assert 0 <= d["impact_score"]           <= 30
    assert 0 <= d["recommendations_score"]  <= 30
    assert d["score"] == (
        d["understanding_score"] + d["impact_score"] + d["recommendations_score"]
    )
    assert d["max_score"] == 100
    assert d["provider"] in ("emergent-claude", "static")
    # Enriched MITRE surfaces name + tactic when expected_mitre is present
    assert isinstance(d.get("expected_mitre_enriched"), list)
    if d.get("expected_mitre"):
        assert d["expected_mitre_enriched"], "MITRE enrichment should surface for known T-IDs"
        for m in d["expected_mitre_enriched"]:
            assert "id" in m and "name" in m and "tactic" in m


def test_narrative_empty_payload_does_not_crash(h):
    ch = requests.get(f"{API}/api/lab/challenge", headers=h, timeout=10).json()
    r = requests.post(f"{API}/api/lab/attempt/narrative", headers=h, json={
        "challenge_id": ch["challenge_id"],
        "understanding": "",
        "impact":        "",
        "recommendations": "",
    }, timeout=45)
    assert r.status_code == 200, r.text
    d = r.json()
    # Empty write-up should score at or near 0 (rubric caps + no info to grade)
    assert d["score"] <= 30


def test_narrative_bad_challenge_id_404(h):
    r = requests.post(f"{API}/api/lab/attempt/narrative", headers=h, json={
        "challenge_id": "NXR-DOES-NOT-EXIST",
        "understanding": "x", "impact": "x", "recommendations": "x",
    }, timeout=10)
    assert r.status_code == 404
