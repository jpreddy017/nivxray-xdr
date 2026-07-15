"""Confusion Matrix Dashboard tests — /api/training/confusion.

Locks in the v3 endpoint that ranks decoder recall per corpus category so
the analyst sees precisely which archetypes need reinforcement before the
offline LLM fine-tune. All tests target the LIVE preview backend using
`REACT_APP_BACKEND_URL` and admin creds from `test_credentials.md`.
"""
from __future__ import annotations
import os

import pytest
import requests


def _pick_env_backend() -> str:
    for env_path in ("/app/frontend/.env", "/app/backend/.env"):
        try:
            with open(env_path, "r") as f:
                for line in f:
                    if line.startswith("REACT_APP_BACKEND_URL="):
                        return line.split("=", 1)[1].strip()
        except FileNotFoundError:
            continue
    return ""


BASE_URL = os.environ.get("REACT_APP_BACKEND_URL") or _pick_env_backend()
if not BASE_URL:
    pytest.skip("REACT_APP_BACKEND_URL not set", allow_module_level=True)

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "NivXRay#2026!"


@pytest.fixture(scope="module")
def auth():
    r = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email":    ADMIN_EMAIL,
        "password": ADMIN_PASSWORD,
    }, timeout=30)
    r.raise_for_status()
    tok = r.json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}


class TestConfusionMatrix:

    def test_requires_auth(self):
        r = requests.get(f"{BASE_URL}/api/training/confusion", timeout=10)
        assert r.status_code in (401, 403)

    def test_full_matrix_shape(self, auth):
        r = requests.get(f"{BASE_URL}/api/training/confusion", headers=auth, timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        # Envelope
        for k in ("generated_at", "duration_ms", "samples_total", "negatives_total",
                  "overall", "categories", "negatives", "cache"):
            assert k in d, f"missing key: {k}"
        # Corpus has 245 supervised + 10 negatives
        assert d["samples_total"] == 245
        assert d["negatives_total"] == 10
        # 49 categories total
        assert len(d["categories"]) == 49
        # Overall metric bounds
        ov = d["overall"]
        for k in ("precision", "recall", "f1", "accuracy"):
            assert 0.0 <= ov[k] <= 1.0

    def test_high_baseline_metrics(self, auth):
        """Corpus v2 should decode ≥95% of samples with ZERO false positives."""
        r = requests.get(f"{BASE_URL}/api/training/confusion", headers=auth, timeout=60)
        d = r.json()
        assert d["overall"]["recall"] >= 0.95, f"recall regression: {d['overall']}"
        assert d["overall"]["precision"] >= 0.99, f"precision regression: {d['overall']}"
        assert d["negatives"]["fp"] == 0, f"unexpected FPs: {d['negatives']['false_positives']}"

    def test_cache_hit_on_second_call(self, auth):
        # First call — either fresh or already cached from earlier tests
        requests.get(f"{BASE_URL}/api/training/confusion", headers=auth, timeout=60)
        # Second call must be a cache hit
        r = requests.get(f"{BASE_URL}/api/training/confusion", headers=auth, timeout=10)
        d = r.json()
        assert d["cache"]["hit"] is True
        assert d["cache"]["age_s"] >= 0

    def test_refresh_bypasses_cache(self, auth):
        r = requests.get(f"{BASE_URL}/api/training/confusion?refresh=true",
                         headers=auth, timeout=60)
        d = r.json()
        assert d["cache"]["hit"] is False

    def test_category_filter(self, auth):
        r = requests.get(
            f"{BASE_URL}/api/training/confusion?categories=lumma_stealer,clickfix"
            "&include_negatives=false",
            headers=auth, timeout=30)
        d = r.json()
        assert d["samples_total"] == 10  # 2 cats × 5 samples
        assert d["negatives_total"] == 0
        cats = {c["category"] for c in d["categories"]}
        assert cats == {"lumma_stealer", "clickfix"}

    def test_per_category_bounds(self, auth):
        r = requests.get(f"{BASE_URL}/api/training/confusion", headers=auth, timeout=60)
        d = r.json()
        for c in d["categories"]:
            assert c["tp"] + c["fn"] == c["samples"]
            for k in ("precision", "recall", "f1"):
                assert 0.0 <= c[k] <= 1.0


class TestConfusionSummary:

    def test_requires_auth(self):
        r = requests.get(f"{BASE_URL}/api/training/confusion/summary", timeout=10)
        assert r.status_code in (401, 403)

    def test_returns_worst_and_best_5(self, auth):
        r = requests.get(f"{BASE_URL}/api/training/confusion/summary",
                         headers=auth, timeout=60)
        d = r.json()
        for k in ("overall", "worst_5_recall", "best_5_recall",
                  "samples_total", "negatives_total"):
            assert k in d
        assert len(d["worst_5_recall"]) <= 5
        assert len(d["best_5_recall"]) <= 5
