"""Tests for the Feb-2026 Phase-2 Docs Explain enhancements.

Covers:
- Rich response shape (session_id, suggested_questions)
- Per-page context grounding (workflow vs feature vs unknown page)
- Multi-turn session_id reuse
- Static-registry fallback structure when LLM budget is exhausted
"""
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
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=30)
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


class TestExplainShape:
    def test_shape_has_all_phase2_fields(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/explain",
                          headers=auth_headers,
                          json={"page": "candidate_explorer"}, timeout=45)
        assert r.status_code == 200
        d = r.json()
        # New Phase-2 fields
        assert "session_id" in d and d["session_id"]
        assert "suggested_questions" in d
        assert isinstance(d["suggested_questions"], list)
        assert 1 <= len(d["suggested_questions"]) <= 3
        # Preserved fields
        assert d["provider"] in {"emergent-claude", "static-registry"}
        assert d["explanation"]

    def test_feature_suggestions_reference_feature_title(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/explain",
                          headers=auth_headers,
                          json={"page": "candidate_explorer"}, timeout=45)
        assert r.status_code == 200
        qs = r.json()["suggested_questions"]
        joined = " ".join(qs)
        # Should mention the actual feature title
        assert "Candidate Explorer" in joined

    def test_workflow_suggestions_reference_workflow(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/explain",
                          headers=auth_headers,
                          json={"page": "encoded_powershell"}, timeout=45)
        assert r.status_code == 200
        d = r.json()
        assert d["suggested_questions"]
        # Static summary must include the workflow title AND steps
        assert "Investigate an Encoded PowerShell Command" in d["explanation"] or \
               d["provider"] == "emergent-claude"

    def test_unknown_page_returns_generic_suggestions(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/explain",
                          headers=auth_headers,
                          json={"page": "not-a-real-page-xyz"}, timeout=45)
        assert r.status_code == 200
        d = r.json()
        qs = d["suggested_questions"]
        assert len(qs) == 3
        joined = " ".join(qs).lower()
        assert "nivxray" in joined or "analyst" in joined or "powershell" in joined


class TestExplainSession:
    def test_session_id_returned_on_first_turn(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/explain",
                          headers=auth_headers,
                          json={"page": "base64_decode"}, timeout=45)
        assert r.status_code == 200
        assert r.json()["session_id"]

    def test_session_id_stable_across_turns(self, auth_headers):
        r1 = requests.post(f"{BASE_URL}/api/docs/explain",
                           headers=auth_headers,
                           json={"page": "base64_decode"}, timeout=45)
        sid = r1.json()["session_id"]
        r2 = requests.post(f"{BASE_URL}/api/docs/explain",
                           headers=auth_headers,
                           json={"page": "base64_decode",
                                 "question": "What if the input is URL-safe?",
                                 "session_id": sid}, timeout=45)
        assert r2.status_code == 200
        assert r2.json()["session_id"] == sid
        assert r2.json()["explanation"]

    def test_client_provided_session_id_is_echoed(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/explain",
                          headers=auth_headers,
                          json={"page": "rot13",
                                "session_id": "test-fixed-session-abc"}, timeout=45)
        assert r.status_code == 200
        assert r.json()["session_id"] == "test-fixed-session-abc"


class TestExplainStaticFallbackContent:
    """When LLM is unavailable, static fallback must still return grounded content."""

    def test_feature_static_summary_uses_purpose(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/explain",
                          headers=auth_headers,
                          json={"page": "candidate_explorer"}, timeout=45)
        assert r.status_code == 200
        d = r.json()
        # If LLM is off, must fall back to a grounded summary
        if d["provider"] == "static-registry":
            assert "Candidate Explorer" in d["explanation"]

    def test_workflow_static_summary_lists_steps(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/explain",
                          headers=auth_headers,
                          json={"page": "corpus_promote"}, timeout=45)
        assert r.status_code == 200
        d = r.json()
        if d["provider"] == "static-registry":
            # Numbered step markers
            assert "1." in d["explanation"]
