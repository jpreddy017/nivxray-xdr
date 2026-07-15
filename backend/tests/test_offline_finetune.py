"""Tests for Feb-2026 #8 — Offline LLM fine-tuning export + Ollama tiebreaker."""
from __future__ import annotations
import json
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


class TestFinetuneStats:
    def test_stats_endpoint(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/admin/finetune/stats",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        data = r.json()
        assert "regression_corpus" in data
        assert "learning_events_with_correction" in data
        assert "total_available" in data
        assert isinstance(data["corpus_by_source"], list)


class TestFinetuneDataset:
    def test_chatml_format(self, auth_headers):
        r = requests.get(
            f"{BASE_URL}/api/admin/finetune/dataset?fmt=chatml&limit=5",
            headers=auth_headers, timeout=30,
        )
        assert r.status_code == 200
        lines = [line for line in r.text.split("\n") if line.strip()]
        for line in lines:
            doc = json.loads(line)
            assert "messages" in doc
            roles = [m["role"] for m in doc["messages"]]
            assert roles == ["system", "user", "assistant"]
            assistant = doc["messages"][-1]["content"]
            # Must be valid JSON with decoded + chain fields
            parsed = json.loads(assistant)
            assert "decoded" in parsed
            assert "chain" in parsed
            assert isinstance(parsed["chain"], list)
            assert "source" in doc

    def test_alpaca_format(self, auth_headers):
        r = requests.get(
            f"{BASE_URL}/api/admin/finetune/dataset?fmt=alpaca&limit=5",
            headers=auth_headers, timeout=30,
        )
        assert r.status_code == 200
        lines = [line for line in r.text.split("\n") if line.strip()]
        for line in lines:
            doc = json.loads(line)
            assert "instruction" in doc
            assert "input" in doc
            assert "output" in doc

    def test_content_disposition_header(self, auth_headers):
        r = requests.get(
            f"{BASE_URL}/api/admin/finetune/dataset?fmt=chatml&limit=1",
            headers=auth_headers, timeout=30,
        )
        assert r.status_code == 200
        cd = r.headers.get("Content-Disposition", "")
        assert "nivxray-chatml.jsonl" in cd


class TestOfflineLLMEndpoint:
    def test_test_offline_llm_no_config(self, auth_headers):
        """Without OFFLINE_LLM_URL set, endpoint returns clean failure."""
        r = requests.post(
            f"{BASE_URL}/api/admin/finetune/test-offline-llm",
            headers=auth_headers, timeout=15,
        )
        assert r.status_code == 200
        data = r.json()
        # Either ok=true (URL configured + reachable) or ok=false with a reason
        assert "ok" in data
        if not data["ok"]:
            assert "reason" in data or "error" in data


class TestProviderSelection:
    """Unit-test the env-driven provider router."""

    def test_default_provider_is_claude(self, monkeypatch):
        monkeypatch.delenv("LLM_TIEBREAKER_PROVIDER", raising=False)
        from reasoning.llm_tiebreaker import _selected_provider
        assert _selected_provider() == "claude"

    def test_provider_switches_to_ollama(self, monkeypatch):
        monkeypatch.setenv("LLM_TIEBREAKER_PROVIDER", "ollama")
        from reasoning.llm_tiebreaker import _selected_provider
        assert _selected_provider() == "ollama"

    def test_tiebreak_available_ollama_needs_url(self, monkeypatch):
        monkeypatch.setenv("LLM_TIEBREAKER_PROVIDER", "ollama")
        monkeypatch.delenv("OFFLINE_LLM_URL", raising=False)
        from reasoning.llm_tiebreaker import tiebreak_available
        assert tiebreak_available() is False
        monkeypatch.setenv("OFFLINE_LLM_URL", "http://localhost:11434")
        assert tiebreak_available() is True

    def test_ollama_arbitrate_no_url_falls_back(self, monkeypatch):
        monkeypatch.setenv("LLM_TIEBREAKER_PROVIDER", "ollama")
        monkeypatch.delenv("OFFLINE_LLM_URL", raising=False)
        from reasoning.llm_tiebreaker import arbitrate
        cands = [{"op": "rot13", "output": "x", "delta": 0.7,
                  "output_score": 0.8}]
        v = arbitrate("input", cands)
        assert v.winner_op == "rot13"
        assert v.provider == "no-key"
        assert v.used_llm is False
