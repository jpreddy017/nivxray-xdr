"""P0-F.10 · live-API probe of the isolation-policy + authorised-command
routes, using the public preview URL (not localhost).

Every request sends an explicit User-Agent because the edge proxy 403s
default urllib clients.
"""
from __future__ import annotations

import os
import uuid

import pytest
import requests

BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/") \
    if os.environ.get("REACT_APP_BACKEND_URL") else None

if not BASE:
    # fall back to reading frontend/.env
    with open("/app/frontend/.env") as fh:
        for line in fh:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE = line.split("=", 1)[1].strip().rstrip("/")

UA = {"User-Agent": "nivx-test-agent/1.0"}
ADMIN = {"email": "admin@nivxray.com",
         "password": "uulVDp5cCSB3Hva99s7UUAwK"}


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE}/api/auth/login", json=ADMIN, headers=UA,
                      timeout=30)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def h(token):
    return {**UA, "Authorization": f"Bearer {token}"}


# ── auth ───────────────────────────────────────────────────────────────

def test_policy_get_requires_auth():
    r = requests.get(f"{BASE}/api/edr/response/isolation-policy",
                     headers=UA, timeout=30)
    assert r.status_code in (401, 403)


def test_policy_put_requires_auth():
    r = requests.put(f"{BASE}/api/edr/response/isolation-policy",
                     json={"allow_list": []}, headers=UA, timeout=30)
    assert r.status_code in (401, 403)


# ── read ───────────────────────────────────────────────────────────────

def test_policy_read_shape(h):
    r = requests.get(f"{BASE}/api/edr/response/isolation-policy",
                     headers=h, timeout=30)
    assert r.status_code == 200
    p = r.json()
    assert p["control_channel_mode"] == "SENSOR_API_ENDPOINT"
    assert "invariants" in p and isinstance(p["invariants"], list) \
        and len(p["invariants"]) >= 3
    assert p["policy_source"] in ("PLATFORM_DEFAULT_NOT_YET_REVIEWED",
                                  "OPERATOR_CONFIGURED")


# ── write ──────────────────────────────────────────────────────────────

def test_policy_write_bumps_version_and_flips_source(h):
    before = requests.get(f"{BASE}/api/edr/response/isolation-policy",
                          headers=h, timeout=30).json()
    v0 = int(before.get("version") or 0)
    tag = f"10.99.{uuid.uuid4().int % 250}.7"
    payload = {"allow_list": [tag, "patch.internal"],
               "allow_dns": True,
               "verification_target": {"host": "1.1.1.1", "port": 443}}
    r = requests.put(f"{BASE}/api/edr/response/isolation-policy",
                     json=payload, headers=h, timeout=30)
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["version"] == v0 + 1
    assert p["policy_source"] == "OPERATOR_CONFIGURED"
    assert tag in p["allow_list"]

    # partial write preserves allow_list
    r2 = requests.put(f"{BASE}/api/edr/response/isolation-policy",
                      json={"allow_dns": False}, headers=h, timeout=30)
    assert r2.status_code == 200
    p2 = r2.json()
    assert p2["version"] == v0 + 2
    assert p2["allow_dns"] is False
    assert tag in p2["allow_list"]


def test_policy_write_rejects_missing_verification_target(h):
    r = requests.put(f"{BASE}/api/edr/response/isolation-policy",
                     json={"verification_target": {"host": "", "port": 0}},
                     headers=h, timeout=30)
    assert r.status_code == 400
    body = r.json()
    detail = body.get("detail") or {}
    assert detail.get("error") == "INVALID_POLICY"


# ── authorised action + kill regression ────────────────────────────────

def test_isolate_action_carries_authorized_step(h):
    # ensure a real policy exists first
    requests.put(f"{BASE}/api/edr/response/isolation-policy",
                 json={"allow_list": ["10.9.9.9"], "allow_dns": True,
                       "verification_target": {"host": "1.1.1.1",
                                               "port": 443}},
                 headers=h, timeout=30)
    r = requests.post(
        f"{BASE}/api/edr/response/actions",
        json={"endpoint_id": "ep_2d57cbe6f80152062109",
              "action": "ISOLATE_ENDPOINT", "target": {},
              "reason": "iter93-live-probe"},
        headers=h, timeout=30)
    # If endpoint is revoked, the platform must refuse cleanly.
    if r.status_code != 200:
        assert r.status_code in (400, 403, 409), r.text
        return
    cmd = r.json()
    assert cmd["state"] == "AUTHORIZED", cmd
    assert [h_["state"] for h_ in cmd["history"]][:2] == \
        ["REQUESTED", "AUTHORIZED"]
    a = cmd["authorisation"]
    assert a and a["control_channel_protected"] is True
    assert "authorised_by" in a and "policy_version" in a \
        and "policy_source" in a and "basis" in a
    assert "policy" in cmd["target"]


def test_kill_action_still_two_step_no_authorisation(h):
    # This may 400 if there is no observed pid; either way, it MUST NOT
    # return AUTHORIZED for KILL_PROCESS.
    r = requests.post(
        f"{BASE}/api/edr/response/actions",
        json={"endpoint_id": "ep_2d57cbe6f80152062109",
              "action": "KILL_PROCESS", "target": {"pid": 1},
              "reason": "iter93-kill-shape-probe"},
        headers=h, timeout=30)
    if r.status_code == 200:
        cmd = r.json()
        assert cmd["state"] == "REQUESTED"
        assert cmd.get("authorisation") is None
    else:
        # Refusal is fine — the accepted P0-F.5 shape is not asserted
        # here, only that KILL is never silently promoted to AUTHORIZED.
        assert r.status_code in (400, 403, 409), r.text
