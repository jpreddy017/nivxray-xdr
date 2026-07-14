"""Tests for new features: async analyze pipeline, SSE stream, LOLBAS catalog."""
import os
import time
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
def auth():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=30)
    assert r.status_code == 200, f"Login failed: {r.text}"
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ---------- Async analysis job pipeline ----------
class TestAnalyzeAsync:
    def test_analyze_async_kicks_off_and_completes(self, auth):
        payload = {
            "input": "powershell.exe -e ZQBjAGgAbwAgAGgAaQA=\n185.220.101.45 http://evil.com/x",
            "output": "",
            "enrich_osint": False,
            "describe": True,
            "use_ai_verdict": True,
        }
        r = requests.post(f"{BASE_URL}/api/analyze/async", headers=auth, json=payload, timeout=15)
        assert r.status_code == 200, r.text
        body = r.json()
        assert "job_id" in body
        assert body["status"] == "running"
        job_id = body["job_id"]

        deadline = time.time() + 120
        last = None
        while time.time() < deadline:
            s = requests.get(f"{BASE_URL}/api/analyze/status/{job_id}", headers=auth, timeout=15)
            assert s.status_code == 200
            last = s.json()
            if last.get("status") == "done":
                break
            if last.get("status") == "error":
                pytest.fail(f"Job errored: {last}")
            time.sleep(2)
        assert last and last.get("status") == "done", f"Job did not complete in time: {last}"
        # required fields present
        for k in ("iocs", "mitre", "yara", "risk"):
            assert k in last, f"missing {k} in done payload"
        # progress terminal
        assert last.get("progress", 0) >= 90

    def test_analyze_status_unknown(self, auth):
        r = requests.get(f"{BASE_URL}/api/analyze/status/does_not_exist_zzz", headers=auth, timeout=10)
        assert r.status_code == 404

    def test_analyze_async_unauth(self):
        r = requests.post(f"{BASE_URL}/api/analyze/async", json={"input": "x", "output": ""}, timeout=10)
        assert r.status_code in (401, 403)


# ---------- SSE stream (fast path) ----------
class TestAnalyzeStream:
    def test_stream_fast_path(self, auth):
        payload = {
            "input": "connect to 8.8.8.8 or http://evil.com/x",
            "output": "",
            "enrich_osint": False,
            "describe": False,
            "use_ai_verdict": False,
        }
        r = requests.post(f"{BASE_URL}/api/analyze/stream", headers=auth, json=payload,
                          stream=True, timeout=30)
        assert r.status_code == 200, r.text
        ct = r.headers.get("Content-Type", "")
        assert "text/event-stream" in ct, f"expected SSE content-type, got: {ct}"
        # collect a couple of events
        collected = []
        start = time.time()
        for raw in r.iter_lines(decode_unicode=True):
            if raw:
                collected.append(raw)
            if time.time() - start > 25:
                break
            if any(l.startswith("event: done") or l.startswith("event: complete") for l in collected):
                break
        r.close()
        assert collected, "no SSE data received"
        joined = "\n".join(collected)
        assert "event:" in joined or "data:" in joined


# ---------- LOLBAS admin ----------
class TestLolbasAdmin:
    def test_lolbas_status(self, auth):
        r = requests.get(f"{BASE_URL}/api/admin/lolbas/status", headers=auth, timeout=30)
        assert r.status_code == 200, r.text
        data = r.json()
        for k in ("active_count", "source_count", "defaults_count", "last_updated", "source_url"):
            assert k in data, f"missing {k}"
        assert data["defaults_count"] >= 30
        # active should be reasonably large (defaults + possibly source)
        assert data["active_count"] >= data["defaults_count"]

    def test_lolbas_status_unauth(self):
        r = requests.get(f"{BASE_URL}/api/admin/lolbas/status", timeout=10)
        assert r.status_code in (401, 403)

    def test_lolbas_sync(self, auth):
        r = requests.post(f"{BASE_URL}/api/admin/lolbas/sync", headers=auth, timeout=60)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get("ok") is True
        assert "count" in data
        assert "source_count" in data
        assert "defaults_count" in data
        # verify /status matches
        s = requests.get(f"{BASE_URL}/api/admin/lolbas/status", headers=auth, timeout=15).json()
        assert s["active_count"] == data["count"]
        # source_count >200 if remote fetch works; tolerate 0 if network blocked
        assert s["source_count"] >= 0

    def test_lolbas_sync_unauth(self):
        r = requests.post(f"{BASE_URL}/api/admin/lolbas/sync", timeout=10)
        assert r.status_code in (401, 403)

    def test_admin_stats_has_lolbas(self, auth):
        r = requests.get(f"{BASE_URL}/api/admin/stats", headers=auth, timeout=15)
        assert r.status_code == 200
        data = r.json()
        assert "lolbas" in data
        for k in ("active_count", "source_count", "defaults_count"):
            assert k in data["lolbas"]


# ---------- Regression: existing endpoints unaffected ----------
class TestRegression:
    def test_analyze_still_works(self, auth):
        r = requests.post(f"{BASE_URL}/api/analyze", headers=auth,
                          json={"input": "10.0.0.1 http://x.com", "output": "", "enrich_osint": False,
                                "describe": False, "use_ai_verdict": False},
                          timeout=60)
        assert r.status_code == 200
        for k in ("iocs", "mitre", "yara", "risk"):
            assert k in r.json()

    def test_operations_count_45(self, auth):
        r = requests.get(f"{BASE_URL}/api/operations", headers=auth, timeout=15)
        assert r.status_code == 200
        assert len(r.json()) == 45
