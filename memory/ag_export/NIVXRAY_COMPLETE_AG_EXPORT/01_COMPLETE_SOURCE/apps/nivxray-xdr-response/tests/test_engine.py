"""Response Engine · pytest suite (state machine + approval workflow)."""
import os
import tempfile

import httpx
import pytest
from contextlib import asynccontextmanager


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch, tmp_path):
    """Every test gets its own SQLite DB — no leakage between cases.

    We DO NOT reload framework modules; reloading breaks exception-class
    identity (`except ExecutorError` in the route becomes a different
    class than the one the executor raises).  A fresh tmp_path gives us
    a fresh SQLite file on the next app lifespan; that's enough."""
    monkeypatch.setenv("XDR_RESPOND_STATE_DIR", str(tmp_path))
    yield


def _make_app():
    from main import app
    return app


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                base_url="http://t")

@asynccontextmanager
async def _lc():
    app = _make_app()
    async with app.router.lifespan_context(app):
        async with _client(app) as c:
            yield c


BASE_REQ = {
    "execution_id": "exec-001",
    "tenant_id":    "acme",
    "invoker":      {"kind": "analyst", "id": "user:alice@acme.com",
                     "context": {"incident_id": "INC-1"}},
    "action":       {"action_id": "endpoint.collect_forensics",
                     "parameters": {"host_id": "THEBORG-PHX"}},
    "authorization": {"scopes": ["analyst:endpoint:collect"]},
}


# ── Basic sanity ────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_health():
    async with _lc() as c: r = await c.get("/health")
    j = r.json()
    assert j["service"] == "nivxray-xdr-response"
    assert j["actions"] > 0
    assert isinstance(j["executions"], dict)


# ── Straight-through succeeded execution ────────────────────────────
@pytest.mark.asyncio
async def test_execute_succeeds_and_produces_all_three_refs():
    async with _lc() as c: r = await c.post("/api/respond/execute", json=BASE_REQ)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["state"] == "SUCCEEDED"
    assert j["status"] == "succeeded"
    assert j["evidence_ref"] and j["audit_ref"] and j["timeline_ref"]
    assert j["forwarding_state"] == "not_wired"    # NIVX_RESPONSE_EVIDENCE_URL unset


# ── Idempotent replay returns identical response ────────────────────
@pytest.mark.asyncio
async def test_idempotent_replay_returns_prior_result():
    async with _lc() as c:
        r1 = await c.post("/api/respond/execute", json={**BASE_REQ, "execution_id": "exec-idem"})
        r2 = await c.post("/api/respond/execute", json={**BASE_REQ, "execution_id": "exec-idem"})
    j1, j2 = r1.json(), r2.json()
    assert j1["evidence_ref"] == j2["evidence_ref"]
    assert j2.get("idempotent_replay") is True


# ── Authorization / scope failures ──────────────────────────────────
@pytest.mark.asyncio
async def test_missing_scope_returns_403():
    body = {**BASE_REQ, "execution_id": "exec-403",
              "authorization": {"scopes": []}}
    async with _lc() as c: r = await c.post("/api/respond/execute", json=body)
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "authorization_failed"


# ── Approval workflow · new async lifecycle ─────────────────────────
@pytest.mark.asyncio
async def test_approval_required_action_parks_in_waiting_approval():
    body = {**BASE_REQ, "execution_id": "exec-approv-wait",
              "action": {"action_id": "endpoint.isolate",
                          "parameters": {"host_id": "H1"}},
              "authorization": {"scopes": ["responder:endpoint:isolate"]}}   # no approval_ref
    async with _lc() as c:
        r = await c.post("/api/respond/execute", json=body)
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["state"] == "WAITING_APPROVAL"
        assert j["status"] == "waiting_approval"
        assert j["approval"]["required"] is True
        assert j["approval"]["status"] == "pending"


@pytest.mark.asyncio
async def test_approval_resumes_same_execution():
    body = {**BASE_REQ, "execution_id": "exec-approv-resume",
              "action": {"action_id": "endpoint.isolate",
                          "parameters": {"host_id": "H1"}},
              "authorization": {"scopes": ["responder:endpoint:isolate"]}}
    async with _lc() as c:
        r1 = await c.post("/api/respond/execute", json=body)
        assert r1.json()["state"] == "WAITING_APPROVAL"

        r2 = await c.post("/api/respond/approve/exec-approv-resume",
                              json={"approved_by": "user:lead@acme.com",
                                      "reason": "IR playbook step 3"})
        assert r2.status_code == 200, r2.text
        j = r2.json()
        assert j["state"] == "SUCCEEDED"
        assert j["approval"]["approved_by"] == "user:lead@acme.com"
        assert j["evidence_ref"]


@pytest.mark.asyncio
async def test_rejection_terminates_same_execution():
    body = {**BASE_REQ, "execution_id": "exec-approv-rej",
              "action": {"action_id": "endpoint.isolate",
                          "parameters": {"host_id": "H1"}},
              "authorization": {"scopes": ["responder:endpoint:isolate"]}}
    async with _lc() as c:
        await c.post("/api/respond/execute", json=body)
        r = await c.post("/api/respond/reject/exec-approv-rej",
                             json={"rejected_by": "user:lead@acme.com",
                                     "reason": "not authorised on this host"})
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["state"] == "FAILED_APPROVAL"
        assert j["approval"]["rejected_by"] == "user:lead@acme.com"
        # Second approve MUST fail immutably.
        r2 = await c.post("/api/respond/approve/exec-approv-rej",
                               json={"approved_by": "user:lead@acme.com"})
        assert r2.status_code == 409


@pytest.mark.asyncio
async def test_approve_unknown_execution_returns_404():
    async with _lc() as c:
        r = await c.post("/api/respond/approve/does-not-exist",
                             json={"approved_by": "user:lead@acme.com"})
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_double_approval_rejected():
    body = {**BASE_REQ, "execution_id": "exec-double-approve",
              "action": {"action_id": "endpoint.isolate",
                          "parameters": {"host_id": "H1"}},
              "authorization": {"scopes": ["responder:endpoint:isolate"]}}
    async with _lc() as c:
        await c.post("/api/respond/execute", json=body)
        r1 = await c.post("/api/respond/approve/exec-double-approve",
                               json={"approved_by": "user:lead@acme.com"})
        assert r1.status_code == 200
        r2 = await c.post("/api/respond/approve/exec-double-approve",
                               json={"approved_by": "user:other@acme.com"})
        assert r2.status_code == 409


# ── Pre-approved (legacy synchronous flow) still works ──────────────
@pytest.mark.asyncio
async def test_preapproved_execution_runs_straight_through():
    body = {**BASE_REQ, "execution_id": "exec-approv-preok",
              "action": {"action_id": "endpoint.isolate",
                          "parameters": {"host_id": "H1"}},
              "authorization": {"scopes": ["responder:endpoint:isolate"],
                                  "approval_ref": "approval-1",
                                  "approved_by":  "user:lead@acme.com",
                                  "reason":       "IR playbook step 3"}}
    async with _lc() as c: r = await c.post("/api/respond/execute", json=body)
    assert r.status_code == 200
    j = r.json()
    assert j["state"] == "SUCCEEDED"
    assert j["approval"]["approved_by"] == "user:lead@acme.com"


# ── Target / parameter / action validation ──────────────────────────
@pytest.mark.asyncio
async def test_unresolved_target_rejects_with_422():
    body = {**BASE_REQ, "execution_id": "exec-target-bad",
              "action": {"action_id": "network.block_ip",
                          "parameters": {"ip": "not-an-ip"}},
              "authorization": {"scopes": ["responder:network:block"],
                                  "approval_ref": "a", "approved_by": "u"}}
    async with _lc() as c: r = await c.post("/api/respond/execute", json=body)
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "unresolved_target"


@pytest.mark.asyncio
async def test_unknown_action_returns_422():
    body = {**BASE_REQ, "execution_id": "exec-unknown",
              "action": {"action_id": "not.a.real.action", "parameters": {}}}
    async with _lc() as c: r = await c.post("/api/respond/execute", json=body)
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "unknown_action"


@pytest.mark.asyncio
async def test_missing_parameter_returns_422():
    body = {**BASE_REQ, "execution_id": "exec-missing-param",
              "action": {"action_id": "endpoint.kill_process",
                          "parameters": {"host_id": "h1"}},         # no pid
              "authorization": {"scopes": ["responder:endpoint:kill"],
                                  "approval_ref": "a", "approved_by": "u"}}
    async with _lc() as c: r = await c.post("/api/respond/execute", json=body)
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "missing_parameter"


# ── Dry-run ─────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_dry_run_never_calls_real_adapter():
    body = {**BASE_REQ, "execution_id": "exec-dry",
              "action": {"action_id": "endpoint.isolate",
                          "parameters": {"host_id": "H1"}},
              "authorization": {"scopes": ["responder:endpoint:isolate"],
                                  "approval_ref": "a", "approved_by": "u"},
              "constraints": {"dry_run": True}}
    async with _lc() as c: r = await c.post("/api/respond/execute", json=body)
    j = r.json()
    assert j["state"] == "SUCCEEDED"
    assert j["result"]["dry_run"] is True


# ── Read + tenant isolation ─────────────────────────────────────────
@pytest.mark.asyncio
async def test_get_execution_returns_prior_result():
    async with _lc() as c:
        await c.post("/api/respond/execute", json={**BASE_REQ, "execution_id": "exec-fetch"})
        r = await c.get("/api/respond/executions/exec-fetch",
                             params={"tenant_id": "acme",
                                       "invoker_kind": "analyst",
                                       "invoker_id":   "user:alice@acme.com"})
    assert r.status_code == 200
    assert r.json()["execution_id"] == "exec-fetch"


@pytest.mark.asyncio
async def test_tenant_isolation_on_pending_approvals():
    """Executions under tenant A must never appear when B queries."""
    async with _lc() as c:
        for tid in ("acme", "globex"):
            body = {**BASE_REQ,
                      "execution_id": f"exec-iso-{tid}",
                      "tenant_id":    tid,
                      "action": {"action_id": "endpoint.isolate",
                                    "parameters": {"host_id": "H1"}},
                      "authorization": {"scopes": ["responder:endpoint:isolate"]}}
            await c.post("/api/respond/execute", json=body)
        acme = await c.get("/api/respond/pending-approvals", params={"tenant_id": "acme"})
        globex = await c.get("/api/respond/pending-approvals", params={"tenant_id": "globex"})
    assert acme.json()["count"]   == 1
    assert globex.json()["count"] == 1
    assert acme.json()["rows"][0]["execution_id"]   == "exec-iso-acme"
    assert globex.json()["rows"][0]["execution_id"] == "exec-iso-globex"


# ── Playbook simulator ──────────────────────────────────────────────
@pytest.mark.asyncio
async def test_simulate_playbook_walks_the_graph():
    body = {
        "playbook_id": "pb-1",
        "entry": "n1",
        "event": {"verdict": "malicious"},
        "nodes": [
            {"id": "n1", "kind": "start", "next": "n2"},
            {"id": "n2", "kind": "condition",
                "config": {"field": "verdict", "op": "eq", "value": "malicious"},
                "yes_next": "n3", "no_next": "n5"},
            {"id": "n3", "kind": "action",
                "action_id": "endpoint.isolate",
                "config": {"parameters": {"host_id": "H1"}},
                "next": "n4"},
            {"id": "n4", "kind": "end"},
            {"id": "n5", "kind": "end"},
        ],
    }
    async with _lc() as c: r = await c.post("/api/respond/simulate-playbook", json=body)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["mode"] == "simulation"
    kinds = [t["kind"] for t in j["trace"]]
    assert kinds == ["start", "condition", "action", "end"]
    assert j["trace"][1]["branch"] == "yes"
    assert j["trace"][2]["status"] == "succeeded"


# ── Action registry catalogue ───────────────────────────────────────
@pytest.mark.asyncio
async def test_list_actions_returns_registry():
    async with _lc() as c: r = await c.get("/api/respond/actions")
    j = r.json()
    ids = {a["action_id"] for a in j["actions"]}
    assert "endpoint.isolate" in ids and "network.block_ip" in ids
    assert j["count"] >= 18
    assert all("adapter_status" in a for a in j["actions"])
