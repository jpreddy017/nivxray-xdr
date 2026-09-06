"""P0-F.5 · a response action must name ONE exact process.

The weakness these tests exist to close: a bare pid is not a process.
Linux reuses pids, so between observation and execution the pid can hold
a completely different process. A response plane that falls back to
pid-only targeting will eventually kill the wrong thing, and it will
report success while doing it.

Enforced in two independent places, because either alone leaks:
  * the PLATFORM refuses to issue a kill it cannot bind to an observed
    process start identity (`TARGET_IDENTITY_UNVERIFIED`);
  * the SENSOR re-reads /proc and refuses when the start identity at that
    pid does not match (`TARGET_IDENTITY_MISMATCH_PID_REUSE`).
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest
from motor.motor_asyncio import AsyncIOMotorClient

from edr_plane import response as resp

SENSOR_PATH = "/app/agents/nivxforge-linux/nivxforge_sensor.py"


def _sensor():
    spec = importlib.util.spec_from_file_location("nivx_sensor", SENSOR_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Scope:
    """Real Mongo, isolated tenant, always cleaned up."""

    def __init__(self):
        self.tenant = f"t_{uuid.uuid4().hex[:12]}"
        self.endpoint = f"ep_{uuid.uuid4().hex[:16]}"

    async def __aenter__(self):
        self.client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        self.db = self.client[os.environ["DB_NAME"]]
        await self.db["edr_endpoints"].insert_one(
            {"tenant_id": self.tenant, "endpoint_id": self.endpoint,
             "hostname": "identity-test-host", "enrollment_state": "ENROLLED"})
        return self

    async def __aexit__(self, *_):
        for c in ("edr_endpoints", "edr_raw_events", "edr_response_commands"):
            await self.db[c].delete_many({"tenant_id": self.tenant})
        self.client.close()

    async def observe(self, *, pid: int, start_ticks: int | None) -> str:
        """Append REAL-shaped sensor process evidence for this endpoint."""
        ev = {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
              "observed_at": "2026-06-01T00:00:00+00:00",
              "start_time": "2026-06-01T00:00:00+00:00",
              "pid": pid, "ppid": 1, "image": "sleep",
              "image_path": "/usr/bin/sleep",
              "command_line": "/bin/sleep 600", "user": "root"}
        if start_ticks is not None:
            ev["start_ticks"] = start_ticks
        raw_id = f"raw_{uuid.uuid4().hex[:24]}"
        await self.db["edr_raw_events"].insert_one(
            {"raw_id": raw_id, "tenant_id": self.tenant,
             "endpoint_ref": self.endpoint, "payload": json.dumps(ev),
             "derivations": [{"event_id": f"cev_{raw_id[4:]}_0"}]})
        return raw_id


@pytest.mark.asyncio
async def test_kill_binds_to_observed_start_identity():
    async with _Scope() as s:
        await s.observe(pid=4242, start_ticks=987654)
        cmd = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="KILL_PROCESS", target={"pid": 4242},
            requested_by="analyst", reason="test")
        assert cmd["state"] == "REQUESTED"
        assert cmd["target"]["observed_start_ticks"] == 987654
        assert cmd["target"]["identity_basis"] == \
            "endpoint_id + pid + start_ticks"
        assert cmd["target"]["evidence_raw_id"].startswith("raw_")


@pytest.mark.asyncio
async def test_kill_refused_when_start_identity_was_never_captured():
    """The regression that P0-F.5 was NOT accepted without."""
    async with _Scope() as s:
        await s.observe(pid=4243, start_ticks=None)
        with pytest.raises(resp.ResponseError) as e:
            await resp.request_action(
                s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
                action="KILL_PROCESS", target={"pid": 4243},
                requested_by="analyst", reason="test")
        assert e.value.code == "TARGET_IDENTITY_UNVERIFIED"
        assert "pid alone" in e.value.reason
        # And nothing was recorded: a refused request is not a command.
        assert await s.db[resp.COLLECTION].count_documents(
            {"tenant_id": s.tenant}) == 0


@pytest.mark.asyncio
async def test_kill_refused_for_a_pid_never_observed():
    async with _Scope() as s:
        with pytest.raises(resp.ResponseError) as e:
            await resp.request_action(
                s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
                action="KILL_PROCESS", target={"pid": 999999},
                requested_by="analyst", reason="test")
        assert e.value.code == "TARGET_NOT_OBSERVED"


@pytest.mark.asyncio
async def test_verification_without_start_identity_cannot_reach_verified():
    """"The pid is free" is not evidence about the target process."""
    async with _Scope() as s:
        await s.observe(pid=4244, start_ticks=111)
        cmd = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="KILL_PROCESS", target={"pid": 4244},
            requested_by="analyst", reason="test")
        cid = cmd["command_id"]
        await resp.claim_pending(s.db, tenant_id=s.tenant,
                                 endpoint_id=s.endpoint)
        await resp.record_result(s.db, tenant_id=s.tenant,
                                 endpoint_id=s.endpoint, command_id=cid,
                                 outcome="EXECUTED", detail="killed")
        out = await resp.verify(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint, command_id=cid,
            probe={"method": "post_action_proc_read",
                   "process_present": False})
        assert out["state"] == "VERIFICATION_FAILED"
        assert "IDENTITY_UNPROVEN" in out["finding"]


@pytest.mark.asyncio
async def test_verification_with_mismatched_identity_is_rejected():
    async with _Scope() as s:
        await s.observe(pid=4245, start_ticks=222)
        cmd = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="KILL_PROCESS", target={"pid": 4245},
            requested_by="analyst", reason="test")
        cid = cmd["command_id"]
        await resp.claim_pending(s.db, tenant_id=s.tenant,
                                 endpoint_id=s.endpoint)
        await resp.record_result(s.db, tenant_id=s.tenant,
                                 endpoint_id=s.endpoint, command_id=cid,
                                 outcome="EXECUTED", detail="killed")
        out = await resp.verify(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint, command_id=cid,
            probe={"method": "post_action_proc_read", "process_present": False,
                   "identity_basis": "start_ticks",
                   "observed_start_ticks": 999})
        assert out["state"] == "VERIFICATION_FAILED"


@pytest.mark.asyncio
async def test_verified_requires_the_bound_identity_and_absence():
    async with _Scope() as s:
        await s.observe(pid=4246, start_ticks=333)
        cmd = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="KILL_PROCESS", target={"pid": 4246},
            requested_by="analyst", reason="test")
        cid = cmd["command_id"]
        await resp.claim_pending(s.db, tenant_id=s.tenant,
                                 endpoint_id=s.endpoint)
        await resp.record_result(s.db, tenant_id=s.tenant,
                                 endpoint_id=s.endpoint, command_id=cid,
                                 outcome="EXECUTED", detail="killed")
        out = await resp.verify(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint, command_id=cid,
            probe={"method": "post_action_proc_read", "process_present": False,
                   "identity_basis": "start_ticks",
                   "observed_start_ticks": 333, "pid_reoccupied": False})
        assert out["state"] == "VERIFIED"


# ─── sensor side · real /proc, real processes ────────────────────────────

def test_sensor_refuses_a_kill_with_no_start_identity():
    mod = _sensor()
    victim = subprocess.Popen(["/bin/sleep", "30"])
    try:
        outcome, detail, ev = mod._execute_command(
            {"action": "KILL_PROCESS", "target": {"pid": victim.pid}})
        assert outcome == "FAILED"
        assert "TARGET_IDENTITY_UNVERIFIED" in detail
        assert ev["pre_state"] == "IDENTITY_ABSENT"
        assert victim.poll() is None, "the process must NOT have been killed"
    finally:
        victim.kill()
        victim.wait(timeout=5)


def test_sensor_refuses_a_kill_when_the_start_identity_does_not_match():
    """PID reuse: the pid is occupied, but by a DIFFERENT process."""
    mod = _sensor()
    victim = subprocess.Popen(["/bin/sleep", "30"])
    time.sleep(0.3)
    try:
        real = mod._proc_identity(victim.pid)["start_ticks"]
        outcome, detail, ev = mod._execute_command(
            {"action": "KILL_PROCESS",
             "target": {"pid": victim.pid,
                        "observed_start_ticks": real + 4242}})
        assert outcome == "FAILED"
        assert "TARGET_IDENTITY_MISMATCH_PID_REUSE" in detail
        assert ev["current_start_ticks"] == real
        assert victim.poll() is None, "the wrong process must NOT be killed"
        assert Path(f"/proc/{victim.pid}").exists()
    finally:
        victim.kill()
        victim.wait(timeout=5)


def test_sensor_kills_and_probes_when_the_identity_matches():
    mod = _sensor()
    victim = subprocess.Popen(["/bin/sleep", "30"])
    time.sleep(0.3)
    real = mod._proc_identity(victim.pid)["start_ticks"]
    target = {"pid": victim.pid, "observed_start_ticks": real}
    outcome, detail, ev = mod._execute_command(
        {"action": "KILL_PROCESS", "target": target})
    assert outcome == "EXECUTED", detail
    assert ev["signal"] == "SIGKILL"
    probe = mod._verify_command({"action": "KILL_PROCESS", "target": target},
                                (outcome, detail, ev))
    assert probe["identity_basis"] == "start_ticks"
    assert probe["observed_start_ticks"] == real
    assert probe["process_present"] is False
    # A zombie is already dead; the OS must confirm signal 9.
    assert probe["proc_state"] in (None, "Z")
    assert victim.wait(timeout=5) == -9


def test_proc_identity_treats_a_zombie_as_terminated():
    mod = _sensor()
    victim = subprocess.Popen(["/bin/sleep", "30"])
    time.sleep(0.3)
    victim.kill()
    time.sleep(0.3)
    ident = mod._proc_identity(victim.pid)
    assert ident["present"] is False
    assert ident["state"] == "Z"
    assert ident["reason"] == "ZOMBIE_ALREADY_TERMINATED"
    assert victim.wait(timeout=5) == -9
    assert mod._proc_identity(victim.pid)["reason"] == "NO_PROC_ENTRY"
