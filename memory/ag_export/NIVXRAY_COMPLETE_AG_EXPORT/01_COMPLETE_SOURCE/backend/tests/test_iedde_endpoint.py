"""End-to-end tests for POST /api/iedde/analyze (SSOT endpoint)."""
from __future__ import annotations

import os

import pytest
import requests

BASE_URL = os.environ.get("IEDDE_TEST_BASE_URL") or os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.strip().split("=", 1)[1].rstrip("/")
                break

EMAIL = "admin@nivxray.com"
PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"
TIMEOUT = 60.0


@pytest.fixture(scope="module")
def token() -> str:
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": EMAIL, "password": PASSWORD}, timeout=TIMEOUT)
    r.raise_for_status()
    d = r.json()
    return d.get("token") or d.get("access_token")


def _post(payload: str, token: str, **extra) -> dict:
    body = {"input": payload}
    body.update(extra)
    r = requests.post(f"{BASE_URL}/api/iedde/analyze", json=body,
                      headers={"Authorization": f"Bearer {token}"}, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def test_endpoint_shape_matches_ssot_contract(token: str):
    d = _post("powershell.exe -Command \"Get-Process\"", token)
    for key in (
        "input_len", "canonical_output", "iterations_executed",
        "terminal_state", "stop_reason",
        "initial_interpreter_identification", "initial_technique_inventory",
        "final_interpreter_identification", "final_technique_inventory",
        "stages",
    ):
        assert key in d, f"missing key: {key}"

    ident = d["initial_interpreter_identification"]
    for key in ("primary_interpreter", "confidence", "interpreters", "stability_reason"):
        assert key in ident


def test_endpoint_returns_get_process_lsass(token: str):
    d = _post(
        "powershell.exe -NoProfile -Command \"&(('Get-' + 'Process') 'lsass')\"",
        token,
    )
    assert d["canonical_output"].strip() == "Get-Process lsass"
    assert d["terminal_state"] == "canonical"


def test_endpoint_decision_object_per_stage(token: str):
    d = _post("powershell.exe -Command \"&('whoami')\"", token)
    for s in d["stages"]:
        dec = s["decision"]
        for k in ("selected", "selected_pass", "reason", "confidence",
                  "remaining_candidates", "key_required_deferred"):
            assert k in dec


def test_endpoint_stability_gate_reason_present(token: str):
    """AES-only payload → stability gate with reasoned message."""
    d = _post(
        "$aes = New-Object System.Security.Cryptography.AesManaged; $aes.Mode = 'CBC'",
        token,
    )
    assert d["terminal_state"] == "stability_gate"
    assert "aes" in d["stop_reason"].lower() or "AES" in d["stop_reason"]


def test_endpoint_deterministic_across_repeat_calls(token: str):
    payload = "powershell.exe -Command \"&(('Get-'+'Process') 'lsass')\""
    a = _post(payload, token)
    b = _post(payload, token)
    assert a["canonical_output"] == b["canonical_output"]
    assert a["terminal_state"] == b["terminal_state"]
    assert len(a["stages"]) == len(b["stages"])
    # Every stage's decision.reason should match.
    for sa, sb in zip(a["stages"], b["stages"]):
        assert sa["decision"] == sb["decision"]


def test_endpoint_rejects_empty_input(token: str):
    r = requests.post(f"{BASE_URL}/api/iedde/analyze", json={"input": ""},
                      headers={"Authorization": f"Bearer {token}"}, timeout=TIMEOUT)
    assert r.status_code == 400


def test_endpoint_requires_auth():
    r = requests.post(f"{BASE_URL}/api/iedde/analyze", json={"input": "x"}, timeout=TIMEOUT)
    assert r.status_code in (401, 403)


def test_endpoint_max_iterations_bounded(token: str):
    d = _post("x" * 40, token, max_iterations=3)
    assert d["iterations_executed"] <= 3
