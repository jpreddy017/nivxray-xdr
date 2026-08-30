"""Response Engine · pytest suite."""
import httpx
import pytest
from contextlib import asynccontextmanager
from main import app


def _client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                base_url="http://t")

@asynccontextmanager
async def _lc():
    async with app.router.lifespan_context(app):
        async with _client() as c:
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


@pytest.mark.asyncio
async def test_health():
    async with _lc() as c: r = await c.get("/health")
    j = r.json(); assert j["phase"] == "1" and j["actions"] > 0


@pytest.mark.asyncio
async def test_execute_succeeds_and_produces_all_three_refs():
    async with _lc() as c: r = await c.post("/api/respond/execute", json=BASE_REQ)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["status"] == "succeeded"
    assert j["evidence_ref"] and j["audit_ref"] and j["timeline_ref"]
    assert j["forwarding_state"] == "not_wired"    # NIVX_RESPONSE_EVIDENCE_URL unset in tests


@pytest.mark.asyncio
async def test_idempotent_replay_returns_prior_result():
    async with _lc() as c:
        r1 = await c.post("/api/respond/execute", json={**BASE_REQ, "execution_id": "exec-idem"})
        r2 = await c.post("/api/respond/execute", json={**BASE_REQ, "execution_id": "exec-idem"})
    j1, j2 = r1.json(), r2.json()
    assert j1["evidence_ref"] == j2["evidence_ref"]
    assert j2.get("idempotent_replay") is True


@pytest.mark.asyncio
async def test_missing_scope_returns_403():
    body = {**BASE_REQ, "execution_id": "exec-403",
              "authorization": {"scopes": []}}
    async with _lc() as c: r = await c.post("/api/respond/execute", json=body)
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "authorization_failed"


@pytest.mark.asyncio
async def test_approval_required_action_rejects_without_approval():
    body = {**BASE_REQ, "execution_id": "exec-approv",
              "action": {"action_id": "endpoint.isolate",
                          "parameters": {"host_id": "H1"}},
              "authorization": {"scopes": ["responder:endpoint:isolate"]}}   # no approval_ref
    async with _lc() as c: r = await c.post("/api/respond/execute", json=body)
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "approval_required"


@pytest.mark.asyncio
async def test_approval_required_action_succeeds_with_approval():
    body = {**BASE_REQ, "execution_id": "exec-approv-ok",
              "action": {"action_id": "endpoint.isolate",
                          "parameters": {"host_id": "H1"}},
              "authorization": {"scopes": ["responder:endpoint:isolate"],
                                  "approval_ref": "approval-1",
                                  "approved_by":  "user:lead@acme.com",
                                  "reason":       "IR playbook step 3"}}
    async with _lc() as c: r = await c.post("/api/respond/execute", json=body)
    assert r.status_code == 200
    j = r.json()
    assert j["status"] == "succeeded"
    assert j["reversal"]["reversible"] is True
    assert j["reversal"]["reversal_id"]


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
    assert j["status"] == "succeeded"
    assert j["result"]["dry_run"] is True


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
    # start → condition(yes) → isolate → end
    kinds = [t["kind"] for t in j["trace"]]
    assert kinds == ["start", "condition", "action", "end"]
    assert j["trace"][1]["branch"] == "yes"
    assert j["trace"][2]["status"] == "succeeded"


@pytest.mark.asyncio
async def test_list_actions_returns_registry():
    async with _lc() as c: r = await c.get("/api/respond/actions")
    j = r.json()
    ids = {a["action_id"] for a in j["actions"]}
    assert "endpoint.isolate" in ids and "network.block_ip" in ids
    assert j["count"] >= 18
