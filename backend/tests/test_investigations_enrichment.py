"""Tests for Feb-2026 #5 (Investigation Timeline) + #6 (Threat-Intel Enrichment)."""
from __future__ import annotations
import hashlib
import os

import pytest
import requests


BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or "http://localhost:8001"
if BASE_URL == "http://localhost:8001":
    try:
        with open("/app/frontend/.env") as f:
            for line in f:
                if line.startswith("REACT_APP_BACKEND_URL="):
                    BASE_URL = line.split("=", 1)[1].strip().rstrip("/")
    except Exception:
        pass

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "NivXRay#2026!"


@pytest.fixture(scope="module")
def auth_headers():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                       json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                       timeout=30)
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def iid_for(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


# =====================================================================
# #5 — Investigation Timeline (deterministic ID grouping)
# =====================================================================

class TestInvestigationLookup:
    def test_deterministic_id(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/investigations/lookup",
                           headers=auth_headers,
                           json={"input": "2NEpo7TZRRrLZSi2U"}, timeout=15)
        assert r.status_code == 200
        assert r.json()["investigation_id"] == iid_for("2NEpo7TZRRrLZSi2U")

    def test_decode_emits_timeline_event(self, auth_headers):
        payload = "unique-timeline-test-input-2NEpo7TZRRrLZSi2U"
        # Decode the input — should auto-emit a timeline event
        r = requests.post(f"{BASE_URL}/api/decode/candidates",
                          headers=auth_headers,
                          json={"input": payload}, timeout=30)
        assert r.status_code == 200
        # Look up the timeline for this exact input
        r2 = requests.post(f"{BASE_URL}/api/investigations/lookup",
                           headers=auth_headers,
                           json={"input": payload}, timeout=15)
        assert r2.status_code == 200
        data = r2.json()
        kinds = [e["kind"] for e in data["events"]]
        assert "decode" in kinds


class TestInvestigationNote:
    def test_note_appears_on_timeline(self, auth_headers):
        payload = "note-test-input-abcdefghij"
        iid = iid_for(payload)
        # Post a note
        r = requests.post(f"{BASE_URL}/api/investigations/{iid}/note",
                          headers=auth_headers,
                          json={"note": "Follow up next week"}, timeout=15)
        assert r.status_code == 200
        assert r.json()["ok"] is True
        # Retrieve
        r2 = requests.get(f"{BASE_URL}/api/investigations/{iid}/timeline",
                          headers=auth_headers, timeout=15)
        assert r2.status_code == 200
        titles = [e["title"] for e in r2.json()["events"]]
        assert any("Follow up next week" in t for t in titles)


class TestInvestigationListing:
    def test_list_investigations(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/investigations?limit=10",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        assert "investigations" in r.json()


# =====================================================================
# #6 — Threat-Intel Enrichment
# =====================================================================

class TestEnrichmentClassify:
    @pytest.mark.parametrize("value,expected_kind", [
        ("http://evil.com/x", "url"),
        ("192.0.2.1", "ipv4"),
        ("evil.com", "domain"),
        ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
        ("not-an-ioc", None),
    ])
    def test_classification(self, auth_headers, value, expected_kind):
        r = requests.get(f"{BASE_URL}/api/enrichment/classify",
                         headers=auth_headers,
                         params={"value": value}, timeout=15)
        assert r.status_code == 200
        assert r.json()["kind"] == expected_kind


class TestEnrichmentConfig:
    def test_config_endpoints(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/enrichment/config",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        # Save some keys (with recognizable last-4 chars so we can verify redaction)
        r = requests.post(f"{BASE_URL}/api/enrichment/config",
                          headers=auth_headers,
                          json={"vt_api_key": "sk-test-vt-key-ABCD",
                                 "otx_api_key": "otx-key-EFGH",
                                 "cache_ttl_hours": 12}, timeout=15)
        assert r.status_code == 200
        cfg = r.json()["config"]
        # Redacted display MUST NOT contain the raw key body
        assert "sk-test" not in cfg.get("vt_api_key", "")
        assert cfg["vt_api_key"].endswith("ABCD")


class TestEnrichmentIOC:
    def test_no_key_verdict_returned_cleanly(self, auth_headers):
        # Delete keys to ensure the no-key path
        requests.post(f"{BASE_URL}/api/enrichment/config",
                      headers=auth_headers,
                      json={"vt_api_key": "", "otx_api_key": "",
                             "abuseipdb_api_key": ""}, timeout=15)
        r = requests.post(f"{BASE_URL}/api/enrichment/ioc",
                          headers=auth_headers,
                          json={"value": "http://evil.example.com"}, timeout=30)
        assert r.status_code == 200
        data = r.json()
        assert data["kind"] == "url"
        verdicts = [p["verdict"] for p in data["providers"]]
        assert all(v in {"no-key", "error", "unknown"} for v in verdicts)


class TestEnrichmentBulkEmitsTimelineEvent:
    def test_bulk_enrich_logs_to_timeline(self, auth_headers):
        payload = "bulk-enrich-test-input-xyz"
        iid = iid_for(payload)
        r = requests.post(f"{BASE_URL}/api/enrichment/bulk",
                          headers=auth_headers,
                          json={"iocs": {"urls": ["http://bulk-example.com/x"]},
                                 "input": payload}, timeout=30)
        assert r.status_code == 200
        # Timeline should now have an enrichment event
        r2 = requests.get(f"{BASE_URL}/api/investigations/{iid}/timeline",
                          headers=auth_headers, timeout=15)
        assert r2.status_code == 200
        kinds = [e["kind"] for e in r2.json()["events"]]
        assert "enrichment" in kinds
