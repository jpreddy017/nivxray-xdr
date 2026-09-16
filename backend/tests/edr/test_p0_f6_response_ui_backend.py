"""P0-F.6 backend read-surface tests for the Response Verification UI.

These validate the two GET endpoints the console consumes:
  - GET /api/edr/response/actions
  - GET /api/edr/response/actions/{command_id}
"""
import os
import pytest
import requests
from pathlib import Path


def _load_backend_url() -> str:
    v = os.environ.get("REACT_APP_BACKEND_URL")
    if v:
        return v.rstrip("/")
    fe = Path("/app/frontend/.env")
    if fe.exists():
        for line in fe.read_text().splitlines():
            if line.startswith("REACT_APP_BACKEND_URL="):
                return line.split("=", 1)[1].strip().rstrip("/")
    raise RuntimeError("REACT_APP_BACKEND_URL not set")


BASE_URL = _load_backend_url()
HEADERS = {"User-Agent": "p0f6-tester/1.0", "Content-Type": "application/json"}
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      headers=HEADERS, timeout=30)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    tok = r.json().get("access_token") or r.json().get("token")
    assert tok, f"no token in login response: {r.json()}"
    return tok


@pytest.fixture(scope="module")
def auth(token):
    return {**HEADERS, "Authorization": f"Bearer {token}"}


def test_list_actions_requires_auth():
    r = requests.get(f"{BASE_URL}/api/edr/response/actions",
                     headers=HEADERS, timeout=30)
    assert r.status_code in (401, 403), f"expected 401/403, got {r.status_code}"


def test_get_action_requires_auth():
    r = requests.get(f"{BASE_URL}/api/edr/response/actions/cmd_xxx",
                     headers=HEADERS, timeout=30)
    assert r.status_code in (401, 403)


def test_list_actions_shape(auth):
    r = requests.get(f"{BASE_URL}/api/edr/response/actions",
                     headers=auth, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    for k in ("commands", "count", "by_state", "verified_count",
              "integrity_alarms", "note"):
        assert k in d, f"missing key {k}"
    assert isinstance(d["commands"], list)
    assert d["count"] == len(d["commands"])
    # every row must carry proof produced by proof_of()
    for r_ in d["commands"]:
        assert "proof" in r_
        p = r_["proof"]
        for k in ("proof", "success_claimed", "integrity_alarm", "meaning"):
            assert k in p
    # Honesty rule: integrity_alarms must be 0
    assert d["integrity_alarms"] == 0, (
        f"integrity_alarms={d['integrity_alarms']} — records claim "
        f"VERIFIED without evidence")
    # Verified count matches rows in state=VERIFIED and success_claimed=True
    verified_rows = [x for x in d["commands"]
                     if x["proof"]["success_claimed"]]
    assert d["verified_count"] == len(verified_rows)
    # HONESTY: EXECUTED must never carry success_claimed=True
    for x in d["commands"]:
        if x["state"] in ("EXECUTED", "DISPATCHED", "REQUESTED", "FAILED",
                          "VERIFICATION_FAILED", "CAPABILITY_UNAVAILABLE",
                          "REFUSED"):
            assert x["proof"]["success_claimed"] is False, (
                f"non-VERIFIED row {x['command_id']} state={x['state']} is "
                f"claimed as success")


def test_get_action_by_id(auth):
    lst = requests.get(f"{BASE_URL}/api/edr/response/actions",
                       headers=auth, timeout=30).json()
    assert lst["count"] >= 1, "no commands on record to inspect"
    cmd = lst["commands"][0]
    cid = cmd["command_id"]
    r = requests.get(f"{BASE_URL}/api/edr/response/actions/{cid}",
                     headers=auth, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["command_id"] == cid
    assert "proof" in d
    assert "history" in d
    assert "state" in d


def test_get_action_unknown_command_id(auth):
    r = requests.get(f"{BASE_URL}/api/edr/response/actions/cmd_does_not_exist",
                     headers=auth, timeout=30)
    assert r.status_code == 404, r.text
    body = r.json()
    detail = body.get("detail") or {}
    assert detail.get("error") == "COMMAND_NOT_FOUND"


def test_list_actions_endpoint_filter_honest_empty(auth):
    r = requests.get(
        f"{BASE_URL}/api/edr/response/actions?endpoint_id=ep_bogus_xxxxx",
        headers=auth, timeout=30)
    assert r.status_code == 200
    d = r.json()
    assert d["count"] == 0
    assert d["commands"] == []


def test_list_actions_endpoint_filter_real(auth):
    ep = "ep_2d57cbe6f80152062109"
    r = requests.get(
        f"{BASE_URL}/api/edr/response/actions?endpoint_id={ep}",
        headers=auth, timeout=30)
    assert r.status_code == 200
    d = r.json()
    assert d["count"] >= 1
    for row in d["commands"]:
        assert row["endpoint_id"] == ep


def test_known_verified_command_carries_proof(auth):
    # Known VERIFIED command mentioned in the review request
    cid = "cmd_62b6dae6d45f4efeb6f9"
    r = requests.get(f"{BASE_URL}/api/edr/response/actions/{cid}",
                     headers=auth, timeout=30)
    if r.status_code == 404:
        pytest.skip("known VERIFIED command not present in this env")
    assert r.status_code == 200
    d = r.json()
    assert d["state"] == "VERIFIED"
    assert d["proof"]["success_claimed"] is True
    assert d["proof"]["proof"] == "VERIFIED_BY_POST_ACTION_EVIDENCE"
    # Must have real verification evidence
    ver = d.get("verification") or {}
    assert ver.get("probe"), "VERIFIED row must carry a probe"
    # Target identity
    t = d.get("target") or {}
    assert t.get("pid") == 6351
    assert t.get("observed_start_ticks") == 1171231
