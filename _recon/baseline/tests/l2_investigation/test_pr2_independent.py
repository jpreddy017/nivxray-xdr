"""Independent PR-2 L1 Investigation API validation.

Written from scratch (does NOT depend on main agent's test_api_pr2.py).
Runs against the external preview URL so we test the same surface a
frontend/analyst would.

Coverage (per ARB review request):
  1. Auth gate — every /api/investigation/* endpoint rejects anonymous.
  2. Case creation (happy path, invalid mode, duplicate 409, auto-uuid).
  3. List cases (owner-scoped).
  4. Owner scoping — second user cannot access admin's case.
  5. Single-call hydration — all 7 L2 services present.
  6. Determinism — repeated GETs identical + identical fingerprints.
  7. Workspace State GET/PUT idempotency + invalid mode/lens.
  8. State machine happy path + illegal + invalid + reopen loop + audit.
  9. Delete → 204 → 404.
 10. Not-found → 404.
"""
from __future__ import annotations

import os
import sys
import uuid
from typing import Any

import pytest
import requests

# Load backend/.env so JWT_SECRET matches the running server.
from pathlib import Path

_BACKEND_DIR = Path("/app/backend")
sys.path.insert(0, str(_BACKEND_DIR))

# Load .env manually to avoid requiring python-dotenv side-effects.
# NOTE: /app/backend/conftest.py sets ADMIN_PASSWORD to a CI stub via
# ``setdefault`` before this file loads; we must FORCE-OVERRIDE with the
# real preview password from backend/.env so the login endpoint (which
# runs against the real Mongo via supervisor) accepts our credentials.
_ENV_OVERRIDES = {"ADMIN_EMAIL", "ADMIN_PASSWORD", "JWT_SECRET", "MONGO_URL", "DB_NAME"}
for line in (_BACKEND_DIR / ".env").read_text().splitlines():
    if "=" in line and not line.startswith("#"):
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k in _ENV_OVERRIDES:
            os.environ[k] = v
        else:
            os.environ.setdefault(k, v)

# Also inject the fixtures dir on the path.
sys.path.insert(0, str(_BACKEND_DIR / "tests" / "l2_investigation"))
from _fixtures import synthetic_bundle  # noqa: E402

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    # Fall back to reading frontend/.env
    for line in Path("/app/frontend/.env").read_text().splitlines():
        if line.startswith("REACT_APP_BACKEND_URL"):
            BASE_URL = line.split("=", 1)[1].strip().rstrip("/")
            break

API = f"{BASE_URL}/api"

ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _login(email: str, password: str) -> str:
    r = requests.post(f"{API}/auth/login", json={"email": email, "password": password}, timeout=30)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def admin_token() -> str:
    return _login(ADMIN_EMAIL, ADMIN_PASSWORD)


@pytest.fixture(scope="module")
def admin_headers(admin_token) -> dict:
    return {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}


@pytest.fixture(scope="module", autouse=True)
def _cleanup():
    """Purge any prior IND_* cases before + after run."""
    from deps import sync_collection
    col = sync_collection("investigation_cases")
    col.delete_many({"case_id": {"$regex": "^ind-"}})
    yield
    col.delete_many({"case_id": {"$regex": "^ind-"}})


def _new_case_id(tag: str) -> str:
    return f"ind-{tag}-{uuid.uuid4().hex[:8]}"


def _bundle(case_id: str) -> dict:
    return synthetic_bundle(case_id).to_dict()


def _create(admin_headers, case_id: str, mode: str = "investigation") -> dict:
    r = requests.post(
        f"{API}/investigation",
        headers=admin_headers,
        json={"bundle": _bundle(case_id), "mode": mode},
        timeout=30,
    )
    assert r.status_code == 201, r.text
    return r.json()


# ---------------------------------------------------------------------------
# 1. Auth gate
# ---------------------------------------------------------------------------


AUTH_PROTECTED = [
    ("GET", "/investigation"),
    ("POST", "/investigation"),
    ("GET", "/investigation/xyz"),
    ("DELETE", "/investigation/xyz"),
    ("GET", "/investigation/xyz/workspace"),
    ("PUT", "/investigation/xyz/workspace"),
    ("POST", "/investigation/xyz/state/transition"),
    ("GET", "/investigation/xyz/state"),
    ("GET", "/investigation/xyz/summary"),
    ("GET", "/investigation/xyz/story"),
    ("GET", "/investigation/xyz/iocs"),
    ("GET", "/investigation/xyz/capabilities"),
    ("GET", "/investigation/xyz/threat"),
    ("GET", "/investigation/xyz/detections"),
    ("GET", "/investigation/xyz/hunting"),
]


@pytest.mark.parametrize("method,path", AUTH_PROTECTED)
def test_auth_gate_rejects_unauthenticated(method, path):
    r = requests.request(method, f"{API}{path}", json={}, timeout=30)
    assert r.status_code in (401, 403), f"{method} {path} returned {r.status_code}"


def test_auth_gate_rejects_invalid_bearer():
    r = requests.get(
        f"{API}/investigation",
        headers={"Authorization": "Bearer not-a-real-jwt"},
        timeout=30,
    )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# 2. Case creation
# ---------------------------------------------------------------------------


def test_create_case_returns_default_workspace(admin_headers):
    cid = _new_case_id("create")
    j = _create(admin_headers, cid)
    assert j["case_id"] == cid
    assert j["state"] == "new"
    assert j["workspace"]["mode"] == "investigation"
    assert j["workspace"]["active_lens"] == "summary"


def test_create_case_invalid_mode_returns_400(admin_headers):
    cid = _new_case_id("bad-mode")
    r = requests.post(
        f"{API}/investigation",
        headers=admin_headers,
        json={"bundle": _bundle(cid), "mode": "bogus_mode"},
        timeout=30,
    )
    assert r.status_code == 400


def test_create_case_duplicate_returns_409(admin_headers):
    cid = _new_case_id("dup")
    _create(admin_headers, cid)
    r = requests.post(
        f"{API}/investigation",
        headers=admin_headers,
        json={"bundle": _bundle(cid)},
        timeout=30,
    )
    assert r.status_code == 409


def test_create_case_auto_generates_case_id_when_missing(admin_headers):
    b = _bundle("placeholder")
    b["case_id"] = None
    r = requests.post(
        f"{API}/investigation",
        headers=admin_headers,
        json={"bundle": b},
        timeout=30,
    )
    assert r.status_code == 201
    assert r.json()["case_id"].startswith("case-")


# ---------------------------------------------------------------------------
# 3. List cases (owner-scoped)
# ---------------------------------------------------------------------------


def test_list_cases_only_shows_owner(admin_headers):
    cid = _new_case_id("list")
    _create(admin_headers, cid)
    r = requests.get(f"{API}/investigation", headers=admin_headers, timeout=30)
    assert r.status_code == 200
    ids = {c["case_id"] for c in r.json()["cases"]}
    assert cid in ids


# ---------------------------------------------------------------------------
# 4. Owner scoping (second user via direct DB insert + minted JWT)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def other_user_token():
    """Create a second user directly in the DB and mint a JWT.

    Owner-scoping (SEC-003) can't otherwise be exercised because there's
    no public register endpoint.
    """
    from deps import create_token, sync_collection
    email = f"ind-other-{uuid.uuid4().hex[:6]}@nivxray.test"
    users = sync_collection("users")
    users.delete_many({"email": {"$regex": "^ind-other-"}})
    users.insert_one({
        "email": email,
        "password": "x",  # unused; we mint a JWT directly
        "role": "analyst",
        "must_change_password": False,
    })
    token = create_token(email)
    yield token
    users.delete_many({"email": email})


def test_owner_scoping_other_user_gets_403(admin_headers, other_user_token):
    cid = _new_case_id("owner")
    _create(admin_headers, cid)
    other_hdrs = {"Authorization": f"Bearer {other_user_token}"}

    # GET workspace bundle
    r = requests.get(f"{API}/investigation/{cid}", headers=other_hdrs, timeout=30)
    assert r.status_code == 403, r.text

    # PUT workspace state
    r = requests.put(
        f"{API}/investigation/{cid}/workspace",
        headers={**other_hdrs, "Content-Type": "application/json"},
        json={"active_lens": "story"},
        timeout=30,
    )
    assert r.status_code == 403

    # DELETE
    r = requests.delete(f"{API}/investigation/{cid}", headers=other_hdrs, timeout=30)
    assert r.status_code == 403


def test_owner_scoping_list_isolated(admin_headers, other_user_token):
    cid = _new_case_id("owner-list")
    _create(admin_headers, cid)
    other_hdrs = {"Authorization": f"Bearer {other_user_token}"}
    r = requests.get(f"{API}/investigation", headers=other_hdrs, timeout=30)
    assert r.status_code == 200
    ids = {c["case_id"] for c in r.json()["cases"]}
    assert cid not in ids


# ---------------------------------------------------------------------------
# 5. Single-call hydration
# ---------------------------------------------------------------------------


def test_workspace_bundle_hydrates_all_seven_services(admin_headers):
    cid = _new_case_id("hydrate")
    _create(admin_headers, cid)
    r = requests.get(f"{API}/investigation/{cid}", headers=admin_headers, timeout=30)
    assert r.status_code == 200
    services = set(r.json()["output"]["body"]["services"].keys())
    assert services == {
        "attack_story",
        "capability_explorer",
        "detection_rules",
        "executive_summary",
        "hunting_queries",
        "ioc_intelligence",
        "threat_assessment",
    }


# ---------------------------------------------------------------------------
# 6. Determinism
# ---------------------------------------------------------------------------


def test_bundle_deterministic_byte_identical(admin_headers):
    cid = _new_case_id("det-bundle")
    _create(admin_headers, cid)
    r1 = requests.get(f"{API}/investigation/{cid}", headers=admin_headers, timeout=30)
    r2 = requests.get(f"{API}/investigation/{cid}", headers=admin_headers, timeout=30)
    assert r1.status_code == 200 and r2.status_code == 200
    # Byte-identical body
    assert r1.content == r2.content, "workspace_bundle body differs across calls"
    assert r1.json()["fingerprint"] == r2.json()["fingerprint"]


SERVICE_PATHS = ["summary", "story", "iocs", "capabilities", "threat", "detections", "hunting"]


@pytest.mark.parametrize("svc", SERVICE_PATHS)
def test_per_service_deterministic(admin_headers, svc):
    cid = _new_case_id(f"det-{svc}")
    _create(admin_headers, cid)
    a = requests.get(f"{API}/investigation/{cid}/{svc}", headers=admin_headers, timeout=30)
    b = requests.get(f"{API}/investigation/{cid}/{svc}", headers=admin_headers, timeout=30)
    assert a.status_code == 200 and b.status_code == 200
    assert a.json()["fingerprint"] == b.json()["fingerprint"]
    assert a.content == b.content


# ---------------------------------------------------------------------------
# 7. Workspace state GET/PUT
# ---------------------------------------------------------------------------


def test_workspace_state_put_idempotent(admin_headers):
    cid = _new_case_id("ws-idem")
    _create(admin_headers, cid)
    body = {
        "mode": "deep_analysis",
        "active_lens": "evidence",
        "scroll_positions": {"evidence": 100},
        "filters": {"only_high": True},
        "timeline_position": 5,
        "selected_evidence_id": "ioc-001",
    }
    a = requests.put(f"{API}/investigation/{cid}/workspace", headers=admin_headers, json=body, timeout=30)
    b = requests.put(f"{API}/investigation/{cid}/workspace", headers=admin_headers, json=body, timeout=30)
    assert a.status_code == 200 and b.status_code == 200
    assert a.json()["fingerprint"] == b.json()["fingerprint"]

    g = requests.get(f"{API}/investigation/{cid}/workspace", headers=admin_headers, timeout=30)
    assert g.status_code == 200
    gj = g.json()
    assert gj["mode"] == "deep_analysis"
    assert gj["active_lens"] == "evidence"
    assert gj["timeline_position"] == 5


def test_workspace_state_put_invalid_lens_400(admin_headers):
    cid = _new_case_id("ws-badlens")
    _create(admin_headers, cid)
    r = requests.put(
        f"{API}/investigation/{cid}/workspace",
        headers=admin_headers,
        json={"active_lens": "chaos"},
        timeout=30,
    )
    assert r.status_code == 400


def test_workspace_state_put_invalid_mode_400(admin_headers):
    cid = _new_case_id("ws-badmode")
    _create(admin_headers, cid)
    r = requests.put(
        f"{API}/investigation/{cid}/workspace",
        headers=admin_headers,
        json={"mode": "chaos_mode"},
        timeout=30,
    )
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# 8. State machine
# ---------------------------------------------------------------------------


HAPPY_PATH = ["collecting", "correlating", "reviewing", "completed", "reported"]


def test_state_machine_happy_path(admin_headers):
    cid = _new_case_id("sm-happy")
    _create(admin_headers, cid)
    for target in HAPPY_PATH:
        r = requests.post(
            f"{API}/investigation/{cid}/state/transition",
            headers=admin_headers,
            json={"target": target, "reason": f"advance to {target}"},
            timeout=30,
        )
        assert r.status_code == 200, f"{target}: {r.text}"
        assert r.json()["current_state"] == target


def test_state_machine_illegal_transition_409(admin_headers):
    cid = _new_case_id("sm-illegal")
    _create(admin_headers, cid)
    r = requests.post(
        f"{API}/investigation/{cid}/state/transition",
        headers=admin_headers,
        json={"target": "reported"},
        timeout=30,
    )
    assert r.status_code == 409


def test_state_machine_invalid_target_400(admin_headers):
    cid = _new_case_id("sm-badtarget")
    _create(admin_headers, cid)
    r = requests.post(
        f"{API}/investigation/{cid}/state/transition",
        headers=admin_headers,
        json={"target": "flying"},
        timeout=30,
    )
    assert r.status_code == 400


def test_state_machine_reopen_loop(admin_headers):
    cid = _new_case_id("sm-reopen")
    _create(admin_headers, cid)
    for t in HAPPY_PATH + ["reopened", "correlating"]:
        r = requests.post(
            f"{API}/investigation/{cid}/state/transition",
            headers=admin_headers,
            json={"target": t},
            timeout=30,
        )
        assert r.status_code == 200, f"{t}: {r.text}"


def test_state_machine_audit_log_records_actor_and_reason(admin_headers):
    cid = _new_case_id("sm-audit")
    _create(admin_headers, cid)
    r = requests.post(
        f"{API}/investigation/{cid}/state/transition",
        headers=admin_headers,
        json={"target": "collecting", "reason": "kickoff"},
        timeout=30,
    )
    assert r.status_code == 200
    entry = r.json()["transition"]
    assert entry["actor"] == ADMIN_EMAIL
    assert entry["reason"] == "kickoff"
    assert entry["from_state"] == "new"
    assert entry["to_state"] == "collecting"


# ---------------------------------------------------------------------------
# 9. Delete
# ---------------------------------------------------------------------------


def test_delete_case_204_then_404(admin_headers):
    cid = _new_case_id("del")
    _create(admin_headers, cid)
    r = requests.delete(f"{API}/investigation/{cid}", headers=admin_headers, timeout=30)
    assert r.status_code == 204
    r2 = requests.get(f"{API}/investigation/{cid}", headers=admin_headers, timeout=30)
    assert r2.status_code == 404


# ---------------------------------------------------------------------------
# 10. Not-found
# ---------------------------------------------------------------------------


def test_get_nonexistent_case_404(admin_headers):
    r = requests.get(f"{API}/investigation/does-not-exist-xyz", headers=admin_headers, timeout=30)
    assert r.status_code == 404
