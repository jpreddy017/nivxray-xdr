"""R1.1 backend endpoint tests: trajectory, mitre coverage, cases list,
observations ingest, and RC5 legacy immutability."""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
CASE_ID = "case_dfir_bumblebee_akira_2026"
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=60)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    tok = r.json().get("access_token") or r.json().get("token")
    assert tok, f"no token in login response: {r.json()}"
    return tok


@pytest.fixture(scope="module")
def headers(token):
    return {"Authorization": f"Bearer {token}"}


# --- Trajectory endpoint ------------------------------------------------

class TestTrajectory:
    def test_requires_auth(self):
        r = requests.get(f"{BASE_URL}/api/v2/cases/{CASE_ID}/trajectory/device", timeout=90)
        assert r.status_code in (401, 403), f"expected 401/403 unauth, got {r.status_code}"

    def test_trajectory_success(self, headers):
        r = requests.get(f"{BASE_URL}/api/v2/cases/{CASE_ID}/trajectory/device", headers=headers, timeout=60)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get("ok") is True
        assert data.get("case_id") == CASE_ID
        lanes = data.get("lanes")
        assert isinstance(lanes, list) and len(lanes) == 5, f"expected 5 lanes, got {lanes}"
        frames = data.get("frames")
        assert isinstance(frames, list) and len(frames) > 0
        assert data.get("count") == len(frames)
        # Field shape
        f0 = frames[0]
        for key in ("frame_iid", "ts", "lane", "action", "mitre"):
            assert key in f0, f"missing {key} in frame: {f0}"
        # at least one entity ref across frames
        entity_keys = {"device", "process", "parent", "file", "network", "registry", "user"}
        assert any(any(k in f for k in entity_keys) for f in frames), "no entity refs in any frame"


# --- MITRE coverage -----------------------------------------------------

class TestMitreCoverage:
    def test_requires_auth(self):
        r = requests.get(f"{BASE_URL}/api/v2/cases/{CASE_ID}/mitre/coverage", timeout=90)
        assert r.status_code in (401, 403)

    def test_coverage_success(self, headers):
        r = requests.get(f"{BASE_URL}/api/v2/cases/{CASE_ID}/mitre/coverage", headers=headers, timeout=90)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get("ok") is True
        assert data.get("case_id") == CASE_ID
        events = data.get("events_with_mitre")
        techniques = data.get("techniques")
        tactics = data.get("tactics")
        assert isinstance(events, int)
        assert events >= 30, f"expected >= 30 events_with_mitre, got {events}"
        assert isinstance(techniques, list) and len(techniques) >= 15, \
            f"expected >= 15 techniques, got {len(techniques)}"
        # at least 5 distinct tactics
        distinct_tactics = {t["id"] for t in tactics if t.get("id") != "unmapped"}
        assert len(distinct_tactics) >= 5, f"expected >= 5 tactics, got {distinct_tactics}"
        # each technique has id + count
        for t in techniques:
            assert "id" in t and "count" in t


# --- Cases list ---------------------------------------------------------

class TestCasesList:
    def test_requires_auth(self):
        r = requests.get(f"{BASE_URL}/api/v2/cases", timeout=90)
        assert r.status_code in (401, 403)

    def test_list_cases(self, headers):
        r = requests.get(f"{BASE_URL}/api/v2/cases", headers=headers, timeout=90)
        assert r.status_code == 200, r.text
        data = r.json()
        assert isinstance(data, list)
        # seeded case should exist
        ids = [c.get("id") or c.get("_id") or c.get("case_id") for c in data]
        assert CASE_ID in ids, f"seeded case {CASE_ID} not present. ids={ids}"


# --- Observations ingest regression ------------------------------------

class TestObservationsIngest:
    def test_ingest_still_works(self, headers):
        payload = {"text": "TEST_regress powershell.exe -enc SGVsbG8gV29ybGQ="}
        r = requests.post(f"{BASE_URL}/api/v2/cases/{CASE_ID}/observations",
                          json=payload, headers=headers, timeout=90)
        # 200/201 accepted; 503 acceptable only if ADAPTERS flag is off (not our case)
        assert r.status_code in (200, 201), f"ingest failed: {r.status_code} {r.text}"
        data = r.json()
        assert data.get("ok") is True
        assert data.get("case_id") == CASE_ID
        assert data.get("event_iid")


# --- Legacy RC5 immutability -------------------------------------------

class TestRC5Legacy:
    def test_rc5_parse_still_works(self, headers):
        r = requests.post(f"{BASE_URL}/api/rc5/parse",
                          json={"input": "powershell.exe -enc SGVsbG8="},
                          headers=headers, timeout=60)
        assert r.status_code == 200, f"rc5 parse broken: {r.status_code} {r.text}"
        data = r.json()
        # verdict should exist somewhere in response
        assert any(k in data for k in ("verdict", "verdict_v2", "result", "analysis")), \
            f"no verdict-like field in rc5 response: {list(data.keys())}"
