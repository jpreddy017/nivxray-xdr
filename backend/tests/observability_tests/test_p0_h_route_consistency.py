"""P0-H · Route consistency + OpenAPI acceptance tests.

Sprint 1 · owner-locked closure rule.

Proves that the paths the 360° audit reported as broken/inconsistent
are now reachable at their documented intents.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


BACKEND_ROOT = Path(__file__).resolve().parents[2]


def _live() -> str:
    """Return the ingress-facing backend URL from frontend/.env.

    We test through the LIVE pod (not TestClient) because the
    entire audit finding was 'these paths are unreachable *through
    the ingress*' — not 'these paths exist in code'.  Using
    TestClient here would give a false pass.
    """
    env = (BACKEND_ROOT.parents[0] / "frontend" / ".env").read_text()
    for line in env.splitlines():
        if line.startswith("REACT_APP_BACKEND_URL="):
            return line.split("=", 1)[1].strip()
    raise RuntimeError("REACT_APP_BACKEND_URL missing")


def _curl(path: str, *, token: str | None = None,
           method: str = "GET", data: str | None = None) -> tuple[int, str]:
    url = _live() + path
    cmd = ["curl", "-sS", "-o", "-", "-w", "\n%{http_code}", "-X", method, url]
    if token:
        cmd += ["-H", f"Authorization: Bearer {token}"]
    if data is not None:
        cmd += ["-H", "content-type: application/json", "-d", data]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    body, _, status = r.stdout.rpartition("\n")
    return int(status.strip() or "0"), body


@pytest.fixture(scope="module")
def admin_token() -> str:
    # Prefer the authoritative test_credentials.md value over any env
    # override (conftest.py sets ADMIN_PASSWORD to a stub for other
    # tests — we need the real live-pod password here).
    creds_env: str | None = None
    creds = (BACKEND_ROOT.parents[0] / "memory" / "test_credentials.md").read_text()
    import re as _re
    m = _re.search(r"\*\*Password\*\*:\s*`([^`]+)`", creds)
    if m:
        creds_env = m.group(1)
    if not creds_env:
        creds_env = os.environ.get("ADMIN_PASSWORD")
    assert creds_env, "admin password unavailable"
    import json as _json
    status, body = _curl("/api/auth/login", method="POST",
                          data=_json.dumps({"email": "admin@nivxray.com",
                                              "password": creds_env}))
    assert status == 200, f"login failed {status}: {body}"
    return _json.loads(body)["access_token"]


# ── OpenAPI surface ─────────────────────────────────────────────
def test_openapi_json_reachable_via_ingress():
    status, body = _curl("/api/openapi.json")
    assert status == 200, f"got {status}: {body[:200]}"
    assert '"openapi"' in body
    assert '"paths"' in body


def test_openapi_docs_ui_reachable():
    status, _ = _curl("/api/docs")
    assert status == 200


def test_openapi_redoc_ui_reachable():
    status, _ = _curl("/api/redoc")
    assert status == 200


# ── Response route consistency ──────────────────────────────────
def test_response_actions_alias_reachable(admin_token):
    status, body = _curl("/api/response/actions", token=admin_token)
    assert status == 200, f"got {status}: {body[:200]}"
    import json
    payload = json.loads(body)
    assert "summary" in payload
    assert "actions" in payload
    assert isinstance(payload["actions"], list)
    assert payload["summary"]["total"] >= 1


def test_response_actions_summary_reports_capability_available(admin_token):
    status, body = _curl("/api/response/actions", token=admin_token)
    assert status == 200
    import json
    payload = json.loads(body)
    summary = payload["summary"]
    assert "capability_available" in summary
    # Each action MUST carry an explicit boolean — honest state.
    for a in payload["actions"]:
        assert "capability_available" in a, f"action missing flag: {a.get('action_id')}"
        assert isinstance(a["capability_available"], bool)


def test_response_actions_legacy_path_still_reachable(admin_token):
    """The legacy `/api/admin/content-supply-chain/response/actions`
    remains reachable during the transition — the alias is
    additive, not a replacement."""
    status, _ = _curl(
        "/api/admin/content-supply-chain/response/actions",
        token=admin_token,
    )
    assert status == 200


# ── Metrics + Health remain reachable (regression) ──────────────
def test_metrics_endpoint_reachable_via_ingress():
    status, body = _curl("/api/metrics")
    assert status == 200
    assert body.startswith("# HELP")


def test_health_endpoint_reachable_via_ingress():
    status, body = _curl("/api/health")
    assert status == 200
    assert '"status":"ok"' in body
