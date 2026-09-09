"""EDR runtime activation (P0) — iteration_82 backend acceptance.

Covers:
  1. /api/edr/endpoints returns 7 authoritative rows from v2_shadow_observations
  2. /api/edr/device-trajectory resolves by IID and by hostname (case-insensitive)
  3. Honest identity-unresolved state (200, reason='identity_unresolved')
  4. Window semantics — default 24h window is empty but identity is still resolved
  5. Every event carries evidence_ref.type == 'v2_shadow_observation'
  6. Tenant scoping — unauth is rejected (401/403)
  7. Regression: /api/edr/detections and /api/edr/process-tree still respond
"""
from __future__ import annotations

import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL",
    "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

EXPECTED_HOSTS = {"WKS-01", "FILE-SRV-01", "SRV-DC01", "FIN-07",
                  "ENG-42", "HR-11", "WKS-07"}


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=15)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_endpoints_returns_seven_authoritative(auth):
    r = requests.get(f"{BASE_URL}/api/edr/endpoints", headers=auth, timeout=20)
    assert r.status_code == 200, r.text
    data = r.json()
    rows = [d for d in data["endpoints"]
            if d.get("source") == "v2_shadow_observations"]
    # The 7 golden-corpus endpoints must ALL still resolve authoritatively.
    # The total is no longer pinned at 7: since P1.10 activated real
    # telemetry ingestion, live CEF/LEEF sources legitimately register
    # additional endpoints, and asserting an exact total would make a
    # working ingestion path look like a regression.
    corpus = [d for d in rows if d["hostname"] in EXPECTED_HOSTS]
    assert {d["hostname"] for d in corpus} == set(EXPECTED_HOSTS), \
        f"corpus endpoints missing: {set(EXPECTED_HOSTS) - {d['hostname'] for d in corpus}}"
    assert len(rows) >= 7, f"expected at least 7 IRG rows, got {len(rows)}"
    for row in rows:
        assert row["identity_confidence"] == "authoritative"
        assert row["device_iid"] and row["device_iid"].startswith("dev_")
        assert row["observation_count"] > 0
        assert row.get("lane_counts")
    for row in corpus:
        assert row["hostname"] in EXPECTED_HOSTS


def test_device_trajectory_by_iid(auth):
    r = requests.get(f"{BASE_URL}/api/edr/device-trajectory",
                     params={"device": "dev_baaa72285d27", "all_time": "true"},
                     headers=auth, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["reason"] == "ok"
    assert d["identity"]["resolved"] is True
    assert d["identity"]["device_iid"] == "dev_baaa72285d27"
    assert d["identity"]["hostname"] == "FIN-07"
    assert d["identity"]["identity_confidence"] == "authoritative"
    # 45 IRG events for FIN-07
    irg = [e for e in d["events"]
           if e.get("evidence_ref", {}).get("type") == "v2_shadow_observation"]
    assert len(irg) == 45, f"expected 45 IRG events, got {len(irg)}"
    lanes = d["lane_counts"]
    assert lanes.get("process", 0) > 0
    assert lanes.get("file", 0) > 0


@pytest.mark.parametrize("host", ["fin-07", "FIN-07", "Fin-07"])
def test_hostname_case_insensitive(auth, host):
    r = requests.get(f"{BASE_URL}/api/edr/device-trajectory",
                     params={"device": host, "all_time": "true"},
                     headers=auth, timeout=30)
    assert r.status_code == 200
    d = r.json()
    assert d["identity"]["resolved"] is True
    assert d["identity"]["device_iid"] == "dev_baaa72285d27"
    irg = [e for e in d["events"]
           if e.get("evidence_ref", {}).get("type") == "v2_shadow_observation"]
    assert len(irg) == 45


def test_identity_unresolved_honest_state(auth):
    r = requests.get(f"{BASE_URL}/api/edr/device-trajectory",
                     params={"device": "bogus-host-does-not-exist",
                             "all_time": "true"},
                     headers=auth, timeout=15)
    assert r.status_code == 200
    d = r.json()
    assert d["reason"] == "identity_unresolved"
    assert d["identity"]["resolved"] is False
    assert d["events"] == []
    assert all(v == 0 for v in d["lane_counts"].values())


def test_window_semantics_empty_but_identified(auth):
    r = requests.get(f"{BASE_URL}/api/edr/device-trajectory",
                     params={"device": "dev_baaa72285d27", "hours": 24},
                     headers=auth, timeout=15)
    assert r.status_code == 200
    d = r.json()
    # observations dated 2026-02-25 → default 24h window returns empty
    irg = [e for e in d["events"]
           if e.get("evidence_ref", {}).get("type") == "v2_shadow_observation"]
    assert len(irg) == 0
    assert d["identity"]["resolved"] is True
    assert d["identity"]["observation_count"] == 45
    assert d["identity"]["observed_first_seen"]
    assert d["identity"]["observed_last_seen"]


def test_evidence_provenance_on_events(auth):
    r = requests.get(f"{BASE_URL}/api/edr/device-trajectory",
                     params={"device": "dev_baaa72285d27", "all_time": "true"},
                     headers=auth, timeout=30)
    d = r.json()
    irg = [e for e in d["events"]
           if e.get("evidence_ref", {}).get("type") == "v2_shadow_observation"]
    assert irg
    for e in irg:
        ref = e["evidence_ref"]
        assert ref["type"] == "v2_shadow_observation"
        assert "event_iid" in ref
        assert "case_id" in ref
        assert "sequence" in ref
        assert e.get("observation_kind")


def test_unauth_rejected():
    r = requests.get(f"{BASE_URL}/api/edr/endpoints", timeout=10)
    assert r.status_code in (401, 403)
    r = requests.get(f"{BASE_URL}/api/edr/device-trajectory",
                     params={"device": "dev_baaa72285d27"}, timeout=10)
    assert r.status_code in (401, 403)


def test_regression_detections_and_process_tree(auth):
    # find a real workspace case id
    r = requests.get(f"{BASE_URL}/api/incidents?limit=5", headers=auth, timeout=15)
    assert r.status_code == 200
    js = r.json()
    items = js.get("items") or js.get("incidents") or js
    if isinstance(items, dict):
        items = items.get("items", [])
    assert items, "no incidents found for regression"
    incident_id = items[0].get("id") or items[0].get("incident_id")
    assert incident_id

    r = requests.get(f"{BASE_URL}/api/edr/detections",
                     params={"incident_id": incident_id},
                     headers=auth, timeout=15)
    assert r.status_code == 200
    body = r.json()
    assert "detections" in body
    assert isinstance(body["detections"], list)

    r = requests.get(f"{BASE_URL}/api/edr/process-tree",
                     params={"incident_id": incident_id},
                     headers=auth, timeout=15)
    assert r.status_code == 200
    body = r.json()
    assert "nodes" in body and "roots" in body
