"""P0-F.10 · isolation must be POLICY-controlled and DOUBLY proven.

These tests pin the rules that make containment trustworthy rather than a
button:

  * the allow-list is policy, not code, and is versioned;
  * a containment command carries an explicit AUTHORIZED step;
  * VERIFIED requires kernel policy state AND independent connectivity
    behaviour — either one alone is a VERIFICATION_FAILED, and losing the
    control channel is a failure too;
  * the endpoint's isolation state changes only on verified evidence;
  * there is no automatic release; a configured timeout raises a NEW
    authorised release command instead.
"""
from __future__ import annotations

import importlib.util
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from motor.motor_asyncio import AsyncIOMotorClient

from edr_plane import isolation_policy as pol
from edr_plane import response as resp

SENSOR_PATH = "/app/agents/nivxforge-linux/nivxforge_sensor.py"


def _sensor():
    spec = importlib.util.spec_from_file_location("nivx_sensor", SENSOR_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Scope:
    def __init__(self):
        self.tenant = f"t_{uuid.uuid4().hex[:12]}"
        self.endpoint = f"ep_{uuid.uuid4().hex[:16]}"

    async def __aenter__(self):
        self.client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        self.db = self.client[os.environ["DB_NAME"]]
        await self.db["edr_endpoints"].insert_one(
            {"tenant_id": self.tenant, "endpoint_id": self.endpoint,
             "hostname": "iso-test-host", "enrollment_state": "ENROLLED"})
        return self

    async def __aexit__(self, *_):
        for c in ("edr_endpoints", "edr_response_commands",
                  pol.COLLECTION):
            await self.db[c].delete_many({"tenant_id": self.tenant})
        self.client.close()

    async def isolate(self):
        return await resp.request_action(
            self.db, tenant_id=self.tenant, endpoint_id=self.endpoint,
            action="ISOLATE_ENDPOINT", target={},
            requested_by="analyst", reason="test")

    async def to_executed(self, command_id):
        await resp.claim_pending(self.db, tenant_id=self.tenant,
                                 endpoint_id=self.endpoint)
        await resp.record_result(self.db, tenant_id=self.tenant,
                                 endpoint_id=self.endpoint,
                                 command_id=command_id, outcome="EXECUTED",
                                 detail="applied")

    async def verify(self, command_id, probe):
        return await resp.verify(self.db, tenant_id=self.tenant,
                                 endpoint_id=self.endpoint,
                                 command_id=command_id, probe=probe)

    async def isolation_state(self):
        ep = await self.db["edr_endpoints"].find_one(
            {"endpoint_id": self.endpoint})
        return (ep.get("isolation") or {}).get("state")


def _probe(*, installed=True, blocked=True, control=True):
    return {"method": "post_action_dual_proof",
            "control_plane": {"rules_installed": installed,
                              "rules_absent": not installed,
                              "backend": "nft",
                              "deny_chains": ["nivx_out", "nivx_in"],
                              "allowed_missing_in_kernel": []},
            "behavioural": {"external_blocked": blocked,
                            "external_target": "1.1.1.1:443",
                            "control_channel": "platform:443",
                            "control_channel_reachable": control}}


# ─── policy ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_default_policy_is_labelled_as_unreviewed_and_release_is_manual():
    async with _Scope() as s:
        p = await pol.get_policy(s.db, tenant_id=s.tenant)
        assert p["policy_source"] == "PLATFORM_DEFAULT_NOT_YET_REVIEWED"
        assert p["auto_release_seconds"] is None
        assert p["control_channel_mode"] == "SENSOR_API_ENDPOINT"
        assert p["allow_list"] == []


@pytest.mark.asyncio
async def test_policy_is_versioned_and_requires_a_verification_target():
    async with _Scope() as s:
        p1 = await pol.put_policy(
            s.db, tenant_id=s.tenant, updated_by="admin",
            allow_list=["10.1.2.3", "patch.internal"], allow_dns=True)
        assert p1["version"] == 1 and p1["policy_source"] == \
            "OPERATOR_CONFIGURED"
        assert p1["allow_list"] == ["10.1.2.3", "patch.internal"]
        p2 = await pol.put_policy(s.db, tenant_id=s.tenant,
                                  updated_by="admin", allow_dns=False)
        assert p2["version"] == 2 and p2["allow_list"] == p1["allow_list"]
        with pytest.raises(ValueError):
            await pol.put_policy(s.db, tenant_id=s.tenant, updated_by="a",
                                 verification_target={"host": "", "port": 0})


# ─── authorisation ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_containment_has_an_explicit_authorized_step_with_policy():
    async with _Scope() as s:
        await pol.put_policy(s.db, tenant_id=s.tenant, updated_by="admin",
                             allow_list=["10.9.9.9"])
        cmd = await s.isolate()
        assert cmd["state"] == "AUTHORIZED"
        assert [h["state"] for h in cmd["history"]] == ["REQUESTED",
                                                        "AUTHORIZED"]
        assert cmd["authorisation"]["control_channel_protected"] is True
        assert cmd["target"]["policy"]["allow_list"] == ["10.9.9.9"]
        assert cmd["target"]["policy"]["policy_version"] == 1
        assert cmd["proof"] if "proof" in cmd else True
        # AUTHORIZED still proves nothing happened.
        assert resp.proof_of({"state": "AUTHORIZED"})["success_claimed"] \
            is False


@pytest.mark.asyncio
async def test_a_kill_keeps_its_proven_two_step_start():
    """The isolation AUTHORIZED step must not silently change the kill
    lifecycle that was already accepted."""
    async with _Scope() as s:
        await s.db["edr_raw_events"].insert_one(
            {"raw_id": "raw_x", "tenant_id": s.tenant,
             "endpoint_ref": s.endpoint,
             "payload": '{"activity":"PROCESS","pid":7777,'
                        '"start_ticks":42,"image_path":"/bin/x"}'})
        cmd = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="KILL_PROCESS", target={"pid": 7777},
            requested_by="analyst", reason="t")
        assert cmd["state"] == "REQUESTED"
        assert cmd["authorisation"] is None
        await s.db["edr_raw_events"].delete_many({"tenant_id": s.tenant})


# ─── the dual proof ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_isolation_verified_only_when_both_proofs_hold():
    async with _Scope() as s:
        cmd = await s.isolate()
        await s.to_executed(cmd["command_id"])
        out = await s.verify(cmd["command_id"], _probe())
        assert out["state"] == "VERIFIED"
        assert "AND" in out["finding"]
        assert await s.isolation_state() == "ISOLATED"


@pytest.mark.asyncio
async def test_a_rule_alone_is_not_containment():
    async with _Scope() as s:
        cmd = await s.isolate()
        await s.to_executed(cmd["command_id"])
        out = await s.verify(cmd["command_id"], _probe(blocked=False))
        assert out["state"] == "VERIFICATION_FAILED"
        assert "RULES_INSTALLED_BUT_NOT_EFFECTIVE" in out["finding"]
        assert await s.isolation_state() == "ISOLATION_UNPROVEN"


@pytest.mark.asyncio
async def test_losing_the_control_channel_is_a_failure_not_a_success():
    async with _Scope() as s:
        cmd = await s.isolate()
        await s.to_executed(cmd["command_id"])
        out = await s.verify(cmd["command_id"], _probe(control=False))
        assert out["state"] == "VERIFICATION_FAILED"
        assert "CONTROL_CHANNEL_LOST" in out["finding"]


@pytest.mark.asyncio
async def test_a_single_sided_probe_cannot_verify_containment():
    async with _Scope() as s:
        for probe in ({"method": "m", "control_plane":
                       {"rules_installed": True}},
                      {"method": "m", "behavioural":
                       {"external_blocked": True,
                        "control_channel_reachable": True}},
                      {"method": "m", "effect_confirmed": True}):
            cmd = await s.isolate()
            await s.to_executed(cmd["command_id"])
            out = await s.verify(cmd["command_id"], probe)
            assert out["state"] == "VERIFICATION_FAILED", probe
            assert "VERIFICATION_INCOMPLETE" in out["finding"]


@pytest.mark.asyncio
async def test_release_requires_rules_gone_and_traffic_restored():
    async with _Scope() as s:
        cmd = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="RELEASE_ISOLATION", target={}, requested_by="analyst",
            reason="t")
        await s.to_executed(cmd["command_id"])
        stuck = {"method": "m",
                 "control_plane": {"rules_absent": False},
                 "behavioural": {"external_restored": False,
                                 "control_channel_reachable": True}}
        out = await s.verify(cmd["command_id"], stuck)
        assert out["state"] == "VERIFICATION_FAILED"
        assert "CONTAINMENT_POLICY_STILL_PRESENT" in out["finding"]

        cmd2 = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="RELEASE_ISOLATION", target={}, requested_by="analyst",
            reason="t")
        await s.to_executed(cmd2["command_id"])
        half = {"method": "m", "control_plane": {"rules_absent": True},
                "behavioural": {"external_restored": False,
                                "control_channel_reachable": True}}
        out2 = await s.verify(cmd2["command_id"], half)
        assert out2["state"] == "VERIFICATION_FAILED"
        assert "RULES_REMOVED_BUT_TRAFFIC_STILL_BLOCKED" in out2["finding"]

        cmd3 = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="RELEASE_ISOLATION", target={}, requested_by="analyst",
            reason="t")
        await s.to_executed(cmd3["command_id"])
        good = {"method": "m", "control_plane": {"rules_absent": True},
                "behavioural": {"external_restored": True,
                                "external_target": "1.1.1.1:443",
                                "control_channel_reachable": True}}
        out3 = await s.verify(cmd3["command_id"], good)
        assert out3["state"] == "VERIFIED"
        assert await s.isolation_state() == "RELEASED"


# ─── auto-release ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_auto_release_by_default_and_a_timeout_raises_a_command():
    async with _Scope() as s:
        cmd = await s.isolate()
        await s.to_executed(cmd["command_id"])
        await s.verify(cmd["command_id"], _probe())
        # default: nothing is raised, and the endpoint stays isolated
        assert await resp.expire_isolations(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint) == 0
        assert await s.isolation_state() == "ISOLATED"

        await pol.put_policy(s.db, tenant_id=s.tenant, updated_by="admin",
                             auto_release_seconds=60)
        await s.db[resp.COLLECTION].update_one(
            {"command_id": cmd["command_id"]},
            {"$set": {"verified_at": (datetime.now(timezone.utc)
                                      - timedelta(minutes=5)).isoformat()}})
        raised = await resp.expire_isolations(s.db, tenant_id=s.tenant,
                                              endpoint_id=s.endpoint)
        assert raised == 1
        # It is a REQUEST, verified like anything else — the endpoint is
        # still recorded as ISOLATED until a release is proven.
        assert await s.isolation_state() == "ISOLATED"
        rows = await resp.list_commands(s.db, tenant_id=s.tenant,
                                        endpoint_id=s.endpoint)
        rel = [r for r in rows["commands"]
               if r["action"] == "RELEASE_ISOLATION"]
        assert len(rel) == 1
        assert rel[0]["state"] == "AUTHORIZED"
        assert rel[0]["requested_by"] == "policy:auto_release"
        # and it is not raised twice
        assert await resp.expire_isolations(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint) == 0


# ─── sensor side ─────────────────────────────────────────────────────────

def test_sensor_names_the_exact_missing_privilege():
    mod = _sensor()
    cap = mod._isolation_capability()
    assert set(cap["missing"]) <= {"CAP_NET_ADMIN", "nft or iptables"}
    assert cap["available"] is (cap["cap_net_admin"] and bool(cap["backend"]))
    if not cap["available"]:
        outcome, detail, ev = mod._execute_command(
            {"action": "ISOLATE_ENDPOINT", "target": {"policy": {}}},
            "https://example.invalid")
        assert outcome == "CAPABILITY_UNAVAILABLE"
        assert "MISSING_PRIVILEGE" in detail
        assert cap["missing"][0] in detail


def test_sensor_refuses_to_isolate_if_it_cannot_resolve_its_control_channel(
        monkeypatch):
    """A contained host we cannot reach is not contained, it is lost."""
    mod = _sensor()
    monkeypatch.setattr(mod, "_isolation_capability",
                        lambda: {"available": True, "backend": "nft",
                                 "cap_net_admin": True, "missing": [],
                                 "detail": "test"})
    applied = []
    monkeypatch.setattr(mod, "_apply_isolation",
                        lambda *a, **k: (applied.append(a) or (True, "")))
    outcome, detail, _ = mod._execute_command(
        {"action": "ISOLATE_ENDPOINT", "target": {"policy": {}}},
        "https://this-host-does-not-resolve.invalid")
    assert outcome == "FAILED"
    assert "CONTROL_CHANNEL_UNRESOLVED" in detail
    assert applied == [], "nothing may be applied when self-lockout is possible"


def test_the_control_channel_is_always_in_the_applied_allow_list(monkeypatch):
    mod = _sensor()
    monkeypatch.setattr(mod, "_isolation_capability",
                        lambda: {"available": True, "backend": "nft",
                                 "cap_net_admin": True, "missing": [],
                                 "detail": "test"})
    monkeypatch.setattr(mod, "_resolve_allow",
                        lambda entries: ((["203.0.113.10"], [])
                                         if entries == ["localhost"]
                                         else (["198.51.100.7"], [])))
    seen = {}
    monkeypatch.setattr(mod, "_apply_isolation",
                        lambda backend, allowed, dns: (seen.update(
                            allowed=allowed, dns=dns) or (True, "")))
    monkeypatch.setattr(mod, "_nameservers", lambda: ["10.0.0.53"])
    outcome, detail, ev = mod._execute_command(
        {"action": "ISOLATE_ENDPOINT",
         "target": {"policy": {"allow_dns": True, "allow_list": ["x"]}}},
        "http://localhost:8001")
    assert outcome == "EXECUTED", detail
    assert "203.0.113.10" in seen["allowed"], seen
    assert seen["dns"] == ["10.0.0.53"]
    assert ev["control_channel"] == "localhost:8001"


def test_nft_ruleset_is_default_deny_on_all_three_hooks():
    mod = _sensor()
    text = mod._nft_ruleset(["10.0.0.1"], ["10.0.0.53"])
    assert text.count("policy drop") == 3
    assert "10.0.0.1" in text
    assert "udp dport 53" in text and "10.0.0.53" in text
    for hook in ("output", "input", "forward"):
        assert f"hook {hook}" in text
