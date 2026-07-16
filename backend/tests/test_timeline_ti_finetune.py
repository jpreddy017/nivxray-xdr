"""Tests for Feb-2026 roadmap #5 (Timeline), #6 (Threat Intel), #8 (Fine-tune)."""
from __future__ import annotations
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
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def auth_headers():
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=30,
    )
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# =====================================================================
# #5 Investigation Timeline
# =====================================================================
class TestTimeline:
    def test_create_and_list_event(self, auth_headers):
        r = requests.post(
            f"{BASE_URL}/api/timeline/events",
            headers=auth_headers,
            json={
                "kind": "note",
                "title": "Test event",
                "summary": "unit test",
                "investigation_id": "test-inv-1",
                "severity": "info",
            }, timeout=15,
        )
        assert r.status_code == 200
        assert r.json()["event"]["_id"]

        r2 = requests.get(
            f"{BASE_URL}/api/timeline/events?investigation_id=test-inv-1",
            headers=auth_headers, timeout=15,
        )
        assert r2.status_code == 200
        events = r2.json()["events"]
        assert len(events) >= 1
        assert events[0]["kind"] == "note"
        assert events[0]["title"] == "Test event"

    def test_invalid_kind_normalized(self, auth_headers):
        r = requests.post(
            f"{BASE_URL}/api/timeline/events",
            headers=auth_headers,
            json={
                "kind": "invalid-kind-that-does-not-exist",
                "title": "bad kind",
                "investigation_id": "test-inv-2",
            }, timeout=15,
        )
        assert r.status_code == 200
        # Invalid kind is normalized to "note"
        assert r.json()["event"]["kind"] == "note"

    def test_recent_global_feed(self, auth_headers):
        r = requests.get(
            f"{BASE_URL}/api/timeline/recent?limit=5",
            headers=auth_headers, timeout=15,
        )
        assert r.status_code == 200
        assert isinstance(r.json()["events"], list)

    def test_correction_auto_records_timeline_events(self, auth_headers):
        """A correction with promote_to_corpus should generate correction +
        corpus-promote + benchmark timeline events automatically."""
        # First, count existing events
        r_before = requests.get(
            f"{BASE_URL}/api/timeline/recent?limit=500",
            headers=auth_headers, timeout=15,
        )
        before = len(r_before.json()["events"])

        # Fire a correction with promote_to_corpus
        requests.post(
            f"{BASE_URL}/api/learning/correction",
            headers=auth_headers,
            json={
                "input": "2NEpo7TZRRrLZSi2U",
                "engine_output": "Hello World!",
                "corrected_output": "Hello World!",
                "corrected_chain": [{"op": "base58-decode"}],
                "promote_to_corpus": True,
                "sample_name": "timeline-test-correction",
                "trigger_benchmark": True,
            }, timeout=60,
        )
        r_after = requests.get(
            f"{BASE_URL}/api/timeline/recent?limit=500",
            headers=auth_headers, timeout=15,
        )
        events = r_after.json()["events"]
        # Expect at least 3 new events: correction, corpus-promote, benchmark
        assert len(events) >= before + 3
        kinds = {e["kind"] for e in events[:5]}
        assert {"correction", "corpus-promote", "benchmark"}.issubset(kinds)


# =====================================================================
# #6 Threat Intel Enrichment
# =====================================================================
class TestThreatIntelEnrich:
    def test_kind_detection_ip(self, auth_headers):
        r = requests.post(
            f"{BASE_URL}/api/threat-intel/enrich",
            headers=auth_headers, json={"value": "1.1.1.1"}, timeout=20,
        )
        assert r.status_code == 200
        assert r.json()["kind"] == "ip"

    def test_kind_detection_sha256(self, auth_headers):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        r = requests.post(
            f"{BASE_URL}/api/threat-intel/enrich",
            headers=auth_headers, json={"value": h}, timeout=20,
        )
        assert r.status_code == 200
        assert r.json()["kind"] == "sha256"

    def test_kind_detection_domain(self, auth_headers):
        r = requests.post(
            f"{BASE_URL}/api/threat-intel/enrich",
            headers=auth_headers, json={"value": "evil.example.com"}, timeout=20,
        )
        assert r.status_code == 200
        assert r.json()["kind"] == "domain"

    def test_kind_detection_url(self, auth_headers):
        r = requests.post(
            f"{BASE_URL}/api/threat-intel/enrich",
            headers=auth_headers, json={"value": "http://evil.com/x.ps1"}, timeout=20,
        )
        assert r.status_code == 200
        assert r.json()["kind"] == "url"

    def test_no_key_graceful_fallback(self, auth_headers):
        # Configuration with all keys empty (or the default) → status "no-key"
        # for all providers, no exceptions.
        requests.post(
            f"{BASE_URL}/api/threat-intel/config",
            headers=auth_headers,
            json={
                "virustotal_api_key": "",
                "otx_api_key": "",
                "abuseipdb_api_key": "",
                "enable_virustotal": False,
                "enable_otx": False,
                "enable_abuseipdb": False,
            }, timeout=15,
        )
        r = requests.post(
            f"{BASE_URL}/api/threat-intel/enrich",
            headers=auth_headers, json={"value": "8.8.8.8"}, timeout=20,
        )
        assert r.status_code == 200
        results = r.json()["results"]
        for prov in ("virustotal", "otx", "abuseipdb"):
            assert results[prov]["status"] in ("no-key", "disabled")

    def test_config_key_redaction(self, auth_headers):
        r = requests.post(
            f"{BASE_URL}/api/threat-intel/config",
            headers=auth_headers,
            json={"virustotal_api_key": "vt-super-secret-key-abcdef1234"},
            timeout=15,
        )
        assert r.status_code == 200
        cfg = r.json()["config"]
        # Secret must be redacted (starts with * and ends with last 4)
        vk = cfg.get("virustotal_api_key", "")
        assert "super-secret" not in vk
        assert vk.endswith("1234")


# =====================================================================
# #8 Fine-tuning Dataset Export
# =====================================================================
class TestFinetuneExport:
    def test_summary_shape(self, auth_headers):
        r = requests.get(
            f"{BASE_URL}/api/admin/finetune/dataset/summary",
            headers=auth_headers, timeout=20,
        )
        assert r.status_code == 200
        data = r.json()
        assert set(data["counts"].keys()) >= {
            "regression_corpus", "sample_library", "learning_events",
        }
        assert "preview" in data
        assert "schema" in data

    def test_download_jsonl_shape(self, auth_headers):
        r = requests.get(
            f"{BASE_URL}/api/admin/finetune/dataset.jsonl",
            headers=auth_headers, timeout=60,
        )
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/x-ndjson")
        # Every line must be valid JSON with the required keys
        import json
        rows = [ln for ln in r.text.split("\n") if ln.strip()]
        assert len(rows) >= 1
        for line in rows[:5]:
            obj = json.loads(line)
            for k in ("id", "source", "instruction", "input", "expected_output"):
                assert k in obj

    def test_dedupe_no_duplicate_inputs(self, auth_headers):
        r = requests.get(
            f"{BASE_URL}/api/admin/finetune/dataset.jsonl",
            headers=auth_headers, timeout=60,
        )
        import json
        rows = [json.loads(ln) for ln in r.text.split("\n") if ln.strip()]
        inputs = [row["input"] for row in rows]
        assert len(inputs) == len(set(inputs)), "duplicate inputs found in dataset"
