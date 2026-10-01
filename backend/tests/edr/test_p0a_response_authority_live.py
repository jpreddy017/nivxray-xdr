"""P0-A · the WIRED authority path, proven end to end on the preview host.

One approval authority, exercised for real:

    admin (holds response.execute)
      → POST /api/xdr/respond/execute            → WAITING_APPROVAL
    approver (holds response.approve, != admin)
      → POST /api/xdr/respond/approve/{id}       → engine approves + dispatches
      → NivXForge EDR validates the approval and records ONE command

and the refusals that matter: a direct unapproved action, a self-approved
action, a replayed approval, a principal without `response.execute`, and a
cross-tenant attempt.

The approver account is a PREVIEW fixture, seeded idempotently here and
recorded in `memory/test_credentials.md`.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
import requests

UA = {"User-Agent": "p0a-authority-tester/1.0"}
ADMIN = {"email": "admin@nivxray.com",
         "password": "uulVDp5cCSB3Hva99s7UUAwK"}
APPROVER = {"email": "p0a-approver@nivxray.com",
            "password": "P0aApprover!2026"}
APPROVER_ROLE = "soc_manager"          # response.approve, NOT response.execute
ANALYST = {"email": "analyst@default.com",
           "password": "DefaultCo!Analyst2026"}


def _backend_env(key: str) -> str:
    """The values the RUNNING backend uses — never the in-process CI DB.

    These live tests drive the real preview API, so every direct read must
    address the same database that API is bound to.
    """
    for line in Path("/app/backend/.env").read_text().splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise RuntimeError(f"{key} not in backend/.env")


def _backend_db():
    from pymongo import MongoClient
    return MongoClient(_backend_env("MONGO_URL"))[_backend_env("DB_NAME")]


def _base() -> str:
    v = os.environ.get("REACT_APP_BACKEND_URL")
    if v:
        return v.rstrip("/")
    for line in Path("/app/frontend/.env").read_text().splitlines():
        if line.startswith("REACT_APP_BACKEND_URL="):
            return line.split("=", 1)[1].strip().rstrip("/")
    raise RuntimeError("REACT_APP_BACKEND_URL not set")


BASE = _base()


def _login(creds: dict) -> str:
    r = requests.post(f"{BASE}/api/auth/login", json=creds, headers=UA,
                      timeout=30)
    assert r.status_code == 200, f"login {creds['email']}: {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="module", autouse=True)
def _seed_approver():
    """A second real operator — separation of duties needs two people."""
    import sys
    sys.path.insert(0, "/app/backend")
    from deps import hash_password
    db = _backend_db()
    db["users"].update_one(
        {"email": APPROVER["email"]},
        {"$set": {"email": APPROVER["email"], "role": APPROVER_ROLE,
                  "name": "P0-A Approval Authority (preview fixture)",
                  "tenant_id": "default", "is_active": True,
                  "password": hash_password(APPROVER["password"])}},
        upsert=True)
    yield


@pytest.fixture(scope="module")
def admin_h():
    return {**UA, "Authorization": f"Bearer {_login(ADMIN)}",
            "X-Tenant-Id": "default"}


@pytest.fixture(scope="module")
def approver_h():
    return {**UA, "Authorization": f"Bearer {_login(APPROVER)}"}


@pytest.fixture(scope="module")
def endpoint_id():
    doc = _backend_db()["edr_endpoints"].find_one(
        {"tenant_id": "default", "enrollment_state": "ENROLLED"},
        {"endpoint_id": 1})
    assert doc, "no enrolled endpoint in tenant default"
    return doc["endpoint_id"]


def _request_isolate(admin_h, endpoint_id) -> dict:
    """Ask the AUTHORITY for an isolation. Returns the execution record."""
    r = requests.post(
        f"{BASE}/api/xdr/respond/execute",
        json={"execution_id": f"p0a-{uuid.uuid4().hex[:12]}",
              "action": {"action_id": "endpoint.isolate",
                         "parameters": {"host_id": endpoint_id}}},
        headers=admin_h, timeout=60)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == "WAITING_APPROVAL", body
    assert body["approval"]["status"] == "pending"
    return body


# ── the refusals ───────────────────────────────────────────────────────

def test_direct_isolate_without_approval_is_refused(admin_h, endpoint_id):
    r = requests.post(f"{BASE}/api/edr/response/actions",
                      json={"endpoint_id": endpoint_id,
                            "action": "ISOLATE_ENDPOINT", "target": {},
                            "reason": "p0a-direct"},
                      headers=admin_h, timeout=30)
    assert r.status_code == 403, r.text
    d = r.json()["detail"]
    assert d["error"] == "APPROVAL_REQUIRED"
    assert d["required_action_id"] == "endpoint.isolate"


def test_principal_without_response_execute_is_refused(endpoint_id):
    h = {**UA, "Authorization": f"Bearer {_login(ANALYST)}",
         "X-Tenant-Id": "default"}
    r = requests.post(f"{BASE}/api/edr/response/actions",
                      json={"endpoint_id": endpoint_id,
                            "action": "RELEASE_ISOLATION", "target": {},
                            "reason": "p0a-no-permission"},
                      headers=h, timeout=30)
    assert r.status_code == 403, r.text
    d = r.json()["detail"]
    assert d["error"] == "RESPONSE_EXECUTE_NOT_AUTHORIZED"
    assert d["required_permission"] == "response.execute"


def test_cross_tenant_response_is_refused(admin_h, endpoint_id):
    r = requests.post(f"{BASE}/api/edr/response/actions",
                      json={"endpoint_id": endpoint_id,
                            "action": "ISOLATE_ENDPOINT", "target": {},
                            "reason": "p0a-cross-tenant"},
                      headers={**admin_h, "X-Tenant-Id": "nivx-live"},
                      timeout=30)
    # The endpoint is not in that tenant, and the approval could never be
    # bound to it: either refusal is authoritative, neither is an accept.
    assert r.status_code in (403, 404), r.text


def test_unauthenticated_response_is_refused(endpoint_id):
    r = requests.post(f"{BASE}/api/edr/response/actions",
                      json={"endpoint_id": endpoint_id,
                            "action": "ISOLATE_ENDPOINT", "target": {},
                            "reason": "p0a-anon"},
                      headers={**UA, "X-Tenant-Id": "default"}, timeout=30)
    assert r.status_code in (401, 403)


def test_self_approved_isolate_is_refused_by_the_endpoint_product(
        admin_h, endpoint_id):
    """The requester approving their own action is refused at the EDR."""
    ex = _request_isolate(admin_h, endpoint_id)
    r = requests.post(
        f"{BASE}/api/xdr/respond/approve/{ex['execution_id']}",
        json={"reason": "p0a-self-approval"}, headers=admin_h, timeout=60)
    assert r.status_code == 200, r.text
    body = r.json()
    # The engine approved (it is the authority) — and NivXForge EDR then
    # refused to act on an approval that satisfies no separation of duties.
    assert body["adapter_ok"] is False, body
    detail = ((body.get("result") or {}).get("edr_detail") or {})
    inner = detail.get("detail") if isinstance(detail, dict) else {}
    assert (inner or detail).get("error") == "SELF_APPROVAL_REFUSED", body


# ── the authorised path, and its replay refusal ────────────────────────

def test_approved_isolate_is_accepted_once_and_cannot_be_replayed(
        admin_h, approver_h, endpoint_id):
    ex = _request_isolate(admin_h, endpoint_id)
    r = requests.post(
        f"{BASE}/api/xdr/respond/approve/{ex['execution_id']}",
        json={"reason": "p0a-second-operator"}, headers=approver_h,
        timeout=60)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["approval"]["approved_by"] == APPROVER["email"]
    assert body["adapter_ok"] is True, body
    result = body["result"]
    command_id = result["edr_command_id"]
    assert command_id, result
    # ACCEPTED is not EXECUTED and not VERIFIED.
    assert result["edr_state"] in ("AUTHORIZED", "REQUESTED"), result

    # The EDR record carries the validated approval and claims nothing.
    got = requests.get(f"{BASE}/api/edr/response/actions/{command_id}",
                       headers=admin_h, timeout=30)
    assert got.status_code == 200, got.text
    cmd = got.json()
    assert cmd["authority"]["approval_ref"] == ex["execution_id"]
    assert cmd["authority"]["approved_by"] == APPROVER["email"]
    assert cmd["authority"]["principal"] == ADMIN["email"]
    assert cmd["proof"]["success_claimed"] is False
    assert cmd["executed_at"] is None and cmd["verified_at"] is None

    # Replay of the SAME approval authorises nothing further.
    again = requests.post(f"{BASE}/api/edr/response/actions",
                          json={"endpoint_id": endpoint_id,
                                "action": "ISOLATE_ENDPOINT", "target": {},
                                "reason": "p0a-replay",
                                "approval_ref": ex["execution_id"]},
                          headers=admin_h, timeout=30)
    assert again.status_code == 409, again.text
    assert again.json()["detail"]["error"] == "APPROVAL_ALREADY_CONSUMED"

    # And the authority itself refuses a second approval decision.
    twice = requests.post(
        f"{BASE}/api/xdr/respond/approve/{ex['execution_id']}",
        json={"reason": "p0a-approve-twice"}, headers=approver_h, timeout=60)
    assert twice.status_code == 409, twice.text


def test_an_approval_cannot_be_moved_to_another_action(admin_h, approver_h,
                                                       endpoint_id):
    ex = _request_isolate(admin_h, endpoint_id)
    ok = requests.post(
        f"{BASE}/api/xdr/respond/approve/{ex['execution_id']}",
        json={"reason": "p0a-bound"}, headers=approver_h, timeout=60)
    assert ok.status_code == 200, ok.text
    r = requests.post(f"{BASE}/api/edr/response/actions",
                      json={"endpoint_id": endpoint_id,
                            "action": "KILL_PROCESS", "target": {"pid": 1},
                            "reason": "p0a-action-swap",
                            "approval_ref": ex["execution_id"]},
                      headers=admin_h, timeout=30)
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"] == "APPROVAL_ACTION_MISMATCH"


def test_isolation_policy_write_requires_response_execute():
    h = {**UA, "Authorization": f"Bearer {_login(ANALYST)}",
         "X-Tenant-Id": "default"}
    r = requests.put(f"{BASE}/api/edr/response/isolation-policy",
                     json={"allow_dns": True}, headers=h, timeout=30)
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"] == "RESPONSE_EXECUTE_NOT_AUTHORIZED"
