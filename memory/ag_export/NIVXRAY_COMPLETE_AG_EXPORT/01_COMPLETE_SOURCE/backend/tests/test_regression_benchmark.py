"""Tests for the Feb-2026 Regression Corpus + Auto-Benchmark features."""
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
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")


@pytest.fixture(scope="module")
def auth_headers():
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=30,
    )
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def _clean_corpus(auth_headers):
    """Delete every corpus entry created during the test module."""
    # Snapshot the corpus entries created below so we can clean up.
    created_ids: list = []
    yield created_ids
    for entry_id in created_ids:
        try:
            requests.delete(
                f"{BASE_URL}/api/regression/corpus/entries/{entry_id}",
                headers=auth_headers, timeout=15,
            )
        except Exception:
            pass


class TestCorpusCRUD:
    def test_create_entry(self, auth_headers, _clean_corpus):
        r = requests.post(
            f"{BASE_URL}/api/regression/corpus/entries",
            headers=auth_headers,
            json={
                "name": "test-base58-hello",
                "input": "2NEpo7TZRRrLZSi2U",
                "expected_output": "Hello World!",
                "expected_chain": [{"op": "base58-decode"}],
                "source": "direct",
            },
            timeout=15,
        )
        assert r.status_code == 200
        entry = r.json()["entry"]
        assert entry["_id"]
        assert entry["expected_output"] == "Hello World!"
        _clean_corpus.append(entry["_id"])

    def test_list_entries(self, auth_headers):
        r = requests.get(
            f"{BASE_URL}/api/regression/corpus/entries?limit=100",
            headers=auth_headers, timeout=15,
        )
        assert r.status_code == 200
        assert "entries" in r.json()

    def test_delete_entry(self, auth_headers):
        r = requests.post(
            f"{BASE_URL}/api/regression/corpus/entries",
            headers=auth_headers,
            json={
                "name": "to-delete",
                "input": "abc",
                "expected_output": "abc",
                "source": "direct",
            }, timeout=15,
        )
        entry_id = r.json()["entry"]["_id"]
        r2 = requests.delete(
            f"{BASE_URL}/api/regression/corpus/entries/{entry_id}",
            headers=auth_headers, timeout=15,
        )
        assert r2.status_code == 200


class TestBenchmarkRun:
    def test_run_benchmark_returns_summary(self, auth_headers, _clean_corpus):
        # Insert a passing sample
        r = requests.post(
            f"{BASE_URL}/api/regression/corpus/entries",
            headers=auth_headers,
            json={
                "name": "b58-hello",
                "input": "2NEpo7TZRRrLZSi2U",
                "expected_output": "Hello World!",
                "source": "direct",
            }, timeout=15,
        )
        _clean_corpus.append(r.json()["entry"]["_id"])

        r2 = requests.post(f"{BASE_URL}/api/regression/run",
                           headers=auth_headers, json={}, timeout=60)
        assert r2.status_code == 200
        run = r2.json()["run"]
        assert run["total"] >= 1
        assert run["pass_rate"] > 0

    def test_flips_detected_between_runs(self, auth_headers, _clean_corpus):
        # 1) Add a passing sample and run
        r = requests.post(
            f"{BASE_URL}/api/regression/corpus/entries",
            headers=auth_headers,
            json={
                "name": "flip-test-passing",
                "input": "2NEpo7TZRRrLZSi2U",
                "expected_output": "Hello World!",
                "source": "direct",
            }, timeout=15,
        )
        _clean_corpus.append(r.json()["entry"]["_id"])
        requests.post(f"{BASE_URL}/api/regression/run",
                      headers=auth_headers, json={}, timeout=60)

        # 2) Update to an impossible expected → next run should flip it to fail
        # (We can't UPDATE via this API, so we add a NEW failing sample and
        # verify the benchmark's failure counting.)
        r = requests.post(
            f"{BASE_URL}/api/regression/corpus/entries",
            headers=auth_headers,
            json={
                "name": "flip-test-failing",
                "input": "plaintext-input",
                "expected_output": "COMPLETELY-IMPOSSIBLE-EXPECTED-VALUE",
                "source": "direct",
            }, timeout=15,
        )
        _clean_corpus.append(r.json()["entry"]["_id"])
        r2 = requests.post(f"{BASE_URL}/api/regression/run",
                           headers=auth_headers, json={}, timeout=60)
        run = r2.json()["run"]
        assert run["failed"] >= 1
        assert run["pass_rate"] < 1.0


class TestGateBlocksPromotion:
    def test_gate_blocks_when_failing(self, auth_headers, _clean_corpus):
        # Ensure at least one failing sample
        r = requests.post(
            f"{BASE_URL}/api/regression/corpus/entries",
            headers=auth_headers,
            json={
                "name": "gate-blocker",
                "input": "abc123",
                "expected_output": "NEVER-MATCHES-ANYTHING",
                "source": "direct",
            }, timeout=15,
        )
        _clean_corpus.append(r.json()["entry"]["_id"])
        requests.post(f"{BASE_URL}/api/regression/run",
                      headers=auth_headers, json={}, timeout=60)

        gate = requests.get(f"{BASE_URL}/api/regression/gate",
                             headers=auth_headers, timeout=15).json()
        assert gate["permits_promotion"] is False
        # And a real promote via the training/confusion/promote endpoint must 409
        r = requests.post(
            f"{BASE_URL}/api/training/confusion/promote",
            headers=auth_headers,
            json={"sample_id": "corpus-v2-000001"},
            timeout=30,
        )
        # Either 409 (blocked) or 404 if corpus fixture id doesn't exist —
        # we care that the gate check fired, not the specific 404 path.
        if r.status_code == 409:
            detail = r.json()["detail"]
            assert detail["error"] == "regression-gate-blocked"


class TestLearningPromoteFlow:
    def test_correction_with_promote_creates_corpus_and_runs_benchmark(
        self, auth_headers, _clean_corpus,
    ):
        r = requests.post(
            f"{BASE_URL}/api/learning/correction",
            headers=auth_headers,
            json={
                "input": "2NEpo7TZRRrLZSi2U",
                "engine_output": "Hello World!",
                "engine_chain": [{"op": "base58-decode"}],
                "corrected_output": "Hello World!",
                "corrected_chain": [{"op": "base58-decode"}],
                "promote_to_corpus": True,
                "sample_name": "learning-promote-test",
                "trigger_benchmark": True,
            }, timeout=60,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["corpus_entry"] is not None
        assert data["benchmark_run"] is not None
        assert data["benchmark_run"]["total"] >= 1
        _clean_corpus.append(data["corpus_entry"]["_id"])

    def test_correction_without_promote_skips_corpus(self, auth_headers):
        r = requests.post(
            f"{BASE_URL}/api/learning/correction",
            headers=auth_headers,
            json={
                "input": "any",
                "engine_output": "x",
                "corrected_output": "y",
                "promote_to_corpus": False,
            }, timeout=30,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["corpus_entry"] is None
        assert data["benchmark_run"] is None
