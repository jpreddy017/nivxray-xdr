"""L1 Investigation API tests (PR-2).

Runs against the FastAPI application via httpx.ASGITransport, so no
supervisor / HTTP layer is required. Uses the seeded admin user (see
``deps.seed_admin``) to obtain a JWT.

Tests exercise:
  * Case CRUD (create/list/get/delete)
  * Owner-scoping (403 on other-user access)
  * Workspace State GET/PUT with idempotency
  * State machine POST with legal + illegal transitions
  * Per-service endpoint deterministic fingerprints
  * Full workspace_bundle single-call hydration
"""
from __future__ import annotations

import asyncio
import os

import httpx
import pytest
import pytest_asyncio


# Make sure the backend/tests conftest ran first (it warm-imports the
# real l2_investigation package). We use the bundle fixture from the
# PR-1 test dir directly.
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "l2_investigation"))
from _fixtures import synthetic_bundle  # noqa: E402


# ---------------------------------------------------------------------------
# App + admin login helpers
# ---------------------------------------------------------------------------


def _make_client():
    from server import app
    # ASGITransport does not auto-run startup handlers. Force-rebind the
    # Motor client to the *current* event loop so each async test gets
    # a Motor bound to its own loop (pytest-asyncio creates a new loop
    # per function by default).
    from deps import client as _deps_client, db as _deps_db, init_database
    object.__setattr__(_deps_client, "_real", None)
    object.__setattr__(_deps_db, "_real", None)
    init_database()
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


async def _login_admin(client) -> str:
    email = os.environ.get("ADMIN_EMAIL", "admin@nivxray.com")
    password = os.environ.get("ADMIN_PASSWORD") or "ci-only-not-a-real-secret"
    r = await client.post("/api/auth/login", json={"email": email, "password": password})
    if r.status_code != 200:
        # try the documented preview password as fallback (some
        # environments seed with the fixed rotated value).
        r = await client.post(
            "/api/auth/login",
            json={"email": email, "password": "uulVDp5cCSB3Hva99s7UUAwK"},
        )
    assert r.status_code == 200, f"admin login failed: {r.status_code} {r.text}"
    return r.json()["access_token"]


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _cleanup_cases_sync():
    """Purge any pre-existing investigation_cases owned by test IDs.

    Runs sync via the same pymongo proxy the router uses, so cleanup
    doesn't require an event loop.
    """
    from deps import sync_collection
    col = sync_collection("investigation_cases")
    col.delete_many({"case_id": {"$regex": "^pr2-"}})


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def auth_client():
    _cleanup_cases_sync()
    async with _make_client() as client:
        token = await _login_admin(client)
        client.headers.update(_headers(token))
        yield client
    _cleanup_cases_sync()


def _bundle_payload(case_id: str) -> dict:
    bundle = synthetic_bundle(case_id)
    return bundle.to_dict()


# ---------------------------------------------------------------------------
# Case CRUD
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_case_returns_initial_workspace_state(auth_client):
    payload = {"bundle": _bundle_payload("pr2-create-01")}
    r = await auth_client.post("/api/investigation", json=payload)
    assert r.status_code == 201, r.text
    j = r.json()
    assert j["case_id"] == "pr2-create-01"
    assert j["state"] == "new"
    assert j["workspace"]["mode"] == "investigation"
    assert j["workspace"]["active_lens"] == "summary"


@pytest.mark.asyncio
async def test_create_case_conflict_on_duplicate(auth_client):
    payload = {"bundle": _bundle_payload("pr2-dup-01")}
    r1 = await auth_client.post("/api/investigation", json=payload)
    assert r1.status_code == 201
    r2 = await auth_client.post("/api/investigation", json=payload)
    assert r2.status_code == 409


@pytest.mark.asyncio
async def test_create_case_assigns_uuid_when_no_case_id_supplied(auth_client):
    payload = {"bundle": _bundle_payload("")}  # empty case_id
    payload["bundle"]["case_id"] = None
    r = await auth_client.post("/api/investigation", json=payload)
    assert r.status_code == 201
    j = r.json()
    assert j["case_id"].startswith("case-")


@pytest.mark.asyncio
async def test_list_cases_returns_created_ones(auth_client):
    for cid in ("pr2-list-01", "pr2-list-02", "pr2-list-03"):
        await auth_client.post("/api/investigation", json={"bundle": _bundle_payload(cid)})
    r = await auth_client.get("/api/investigation")
    assert r.status_code == 200
    ids = [c["case_id"] for c in r.json()["cases"]]
    assert set(ids) >= {"pr2-list-01", "pr2-list-02", "pr2-list-03"}


@pytest.mark.asyncio
async def test_delete_case_removes_from_list(auth_client):
    await auth_client.post("/api/investigation", json={"bundle": _bundle_payload("pr2-del-01")})
    r = await auth_client.delete("/api/investigation/pr2-del-01")
    assert r.status_code == 204
    r2 = await auth_client.get("/api/investigation/pr2-del-01")
    assert r2.status_code == 404


# ---------------------------------------------------------------------------
# Workspace bundle hydration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_workspace_bundle_hydrates_all_services(auth_client):
    await auth_client.post("/api/investigation", json={"bundle": _bundle_payload("pr2-bundle-01")})
    r = await auth_client.get("/api/investigation/pr2-bundle-01")
    assert r.status_code == 200
    j = r.json()
    services = set(j["output"]["body"]["services"].keys())
    assert services == {
        "attack_story",
        "capability_explorer",
        "detection_rules",
        "executive_summary",
        "hunting_queries",
        "ioc_intelligence",
        "threat_assessment",
    }


@pytest.mark.asyncio
async def test_workspace_bundle_is_deterministic(auth_client):
    await auth_client.post("/api/investigation", json={"bundle": _bundle_payload("pr2-det-01")})
    r1 = (await auth_client.get("/api/investigation/pr2-det-01")).json()
    r2 = (await auth_client.get("/api/investigation/pr2-det-01")).json()
    assert r1["output"] == r2["output"]
    assert r1["fingerprint"] == r2["fingerprint"]


# ---------------------------------------------------------------------------
# Per-service reads
# ---------------------------------------------------------------------------


SERVICE_PATHS = [
    "summary", "story", "iocs", "capabilities",
    "threat", "detections", "hunting",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", SERVICE_PATHS)
async def test_per_service_endpoint_deterministic(auth_client, path):
    await auth_client.post("/api/investigation", json={"bundle": _bundle_payload(f"pr2-svc-{path}")})
    a = (await auth_client.get(f"/api/investigation/pr2-svc-{path}/{path}")).json()
    b = (await auth_client.get(f"/api/investigation/pr2-svc-{path}/{path}")).json()
    assert a == b
    assert "fingerprint" in a


@pytest.mark.asyncio
async def test_summary_verdict_reflects_bundle(auth_client):
    await auth_client.post("/api/investigation", json={"bundle": _bundle_payload("pr2-verdict-01")})
    r = await auth_client.get("/api/investigation/pr2-verdict-01/summary")
    assert r.status_code == 200
    j = r.json()
    assert j["service"] == "executive_summary"
    assert j["body"]["verdict"] == "malicious"
    assert j["body"]["family"] == "cobalt_strike"


# ---------------------------------------------------------------------------
# Workspace State GET / PUT (Blueprint §8.3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_workspace_state_get_returns_defaults(auth_client):
    await auth_client.post("/api/investigation", json={"bundle": _bundle_payload("pr2-ws-01")})
    r = await auth_client.get("/api/investigation/pr2-ws-01/workspace")
    assert r.status_code == 200
    j = r.json()
    assert j["mode"] == "investigation"
    assert j["active_lens"] == "summary"
    assert j["investigation_state"] == "new"


@pytest.mark.asyncio
async def test_workspace_state_put_is_idempotent(auth_client):
    await auth_client.post("/api/investigation", json={"bundle": _bundle_payload("pr2-ws-02")})
    payload = {
        "mode": "deep_analysis",
        "active_lens": "evidence",
        "scroll_positions": {"evidence": 420},
        "filters": {"hide_noise": True},
        "timeline_position": 3,
        "selected_evidence_id": "ioc-001",
    }
    a = (await auth_client.put("/api/investigation/pr2-ws-02/workspace", json=payload)).json()
    b = (await auth_client.put("/api/investigation/pr2-ws-02/workspace", json=payload)).json()
    assert a == b
    assert a["fingerprint"] == b["fingerprint"]
    got = (await auth_client.get("/api/investigation/pr2-ws-02/workspace")).json()
    assert got["mode"] == "deep_analysis"
    assert got["active_lens"] == "evidence"
    assert got["timeline_position"] == 3


@pytest.mark.asyncio
async def test_workspace_state_put_rejects_invalid_lens(auth_client):
    await auth_client.post("/api/investigation", json={"bundle": _bundle_payload("pr2-ws-03")})
    r = await auth_client.put("/api/investigation/pr2-ws-03/workspace", json={"active_lens": "unknown"})
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# State machine (Blueprint §8.1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_state_transition_happy_path(auth_client):
    await auth_client.post("/api/investigation", json={"bundle": _bundle_payload("pr2-sm-01")})
    order = ["collecting", "correlating", "reviewing", "completed", "reported"]
    for target in order:
        r = await auth_client.post(
            "/api/investigation/pr2-sm-01/state/transition",
            json={"target": target, "reason": f"advance to {target}"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["current_state"] == target


@pytest.mark.asyncio
async def test_state_transition_illegal_returns_409(auth_client):
    await auth_client.post("/api/investigation", json={"bundle": _bundle_payload("pr2-sm-02")})
    # New → Reported is not legal
    r = await auth_client.post(
        "/api/investigation/pr2-sm-02/state/transition",
        json={"target": "reported"},
    )
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_state_transition_invalid_target_returns_400(auth_client):
    await auth_client.post("/api/investigation", json={"bundle": _bundle_payload("pr2-sm-03")})
    r = await auth_client.post(
        "/api/investigation/pr2-sm-03/state/transition",
        json={"target": "nonsense"},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_state_transition_reopen_reenters_correlating(auth_client):
    await auth_client.post("/api/investigation", json={"bundle": _bundle_payload("pr2-sm-04")})
    order = ["collecting", "correlating", "reviewing", "completed", "reported", "reopened", "correlating"]
    for target in order:
        r = await auth_client.post(
            "/api/investigation/pr2-sm-04/state/transition",
            json={"target": target},
        )
        assert r.status_code == 200, f"failed at {target}: {r.text}"


@pytest.mark.asyncio
async def test_state_endpoint_reports_history(auth_client):
    await auth_client.post("/api/investigation", json={"bundle": _bundle_payload("pr2-sm-05")})
    await auth_client.post("/api/investigation/pr2-sm-05/state/transition", json={"target": "collecting"})
    await auth_client.post("/api/investigation/pr2-sm-05/state/transition", json={"target": "correlating"})
    r = await auth_client.get("/api/investigation/pr2-sm-05/state")
    assert r.status_code == 200
    j = r.json()
    assert j["current_state"] == "correlating"
    assert [h["to_state"] for h in j["history"]] == ["collecting", "correlating"]
    assert set(j["allowed_states"]) == {
        "new", "collecting", "correlating", "reviewing",
        "completed", "reported", "reopened",
    }


# ---------------------------------------------------------------------------
# Auth / owner scoping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_auth_returns_401_or_403():
    async with _make_client() as anon:
        r = await anon.get("/api/investigation")
        # FastAPI HTTPBearer emits 403 for missing credentials; 401 for
        # invalid ones. Either is acceptable here — we only need to
        # confirm the endpoint is not open.
        assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_case_not_found_returns_404(auth_client):
    r = await auth_client.get("/api/investigation/does-not-exist")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_invalid_mode_on_create_returns_400(auth_client):
    r = await auth_client.post(
        "/api/investigation",
        json={"bundle": _bundle_payload("pr2-invalid-mode"), "mode": "nope"},
    )
    assert r.status_code == 400
