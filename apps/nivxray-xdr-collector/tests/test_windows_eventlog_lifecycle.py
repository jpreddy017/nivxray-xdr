"""G1 · the Windows Event Log connector's PRODUCTION acquisition lifecycle.

Owner standard: bounded scope, complete fix. These tests hold the whole
lifecycle the collector service actually performs, not just the constructor:

    configuration validation
      → service startup → construction → rehydration → auto-start
      → running (Read → Make Durable → Advance Acquisition)
      → controlled stop
      → service restart → rehydration → resume

and the permanent identity contract:

    authoritative configuration source · validation · stability across
    process restart · bookmark namespace stability · duplicate / cross-tenant
    identity rejection · missing identity fails closed · no random fallback

What these tests do NOT prove: that a real Windows host reads real records.
That is the endpoint proof, and it cannot be substituted from Linux.
"""
from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

from framework import collector_identity
from framework.base import Health
from framework.runtime import CollectorRuntime
from framework.windows_eventlog import WindowsEventLogConnector
from tests.test_windows_eventlog_acquisition import (
    SYSMON, FakeReader, sysmon_xml,
)

PS = "Microsoft-Windows-PowerShell/Operational"
TENANT = "ten_g1_lifecycle"
OTHER_TENANT = "ten_g1_other"
REC_ID = "windows-eventlog::lifecycle"


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("XDR_DISABLE_DELIVERY_WORKER", "1")
    monkeypatch.delenv("NIVX_COLLECTOR_ID", raising=False)
    for cid in list(collector_identity.bindings()):
        collector_identity.release(cid)
    yield
    for cid in list(collector_identity.bindings()):
        collector_identity.release(cid)


class _StubScheduler:
    """Captures what the runtime asked the scheduler to run."""

    def __init__(self):
        self.started = {}
        self.stopped = []

    async def start(self, conn, on_envelopes, *, on_error=None,
                    always_callback=False):
        self.started[conn.identity] = {
            "conn": conn, "on_envelopes": on_envelopes,
            "on_error": on_error, "always_callback": always_callback}

    async def stop(self, identity):
        self.stopped.append(identity)
        self.started.pop(identity, None)

    def running(self):
        return list(self.started)


def _connector(collector="col_g1life", channels=(SYSMON,), reader=None,
               tenant=TENANT):
    return WindowsEventLogConnector(
        tenant_id=tenant,
        config={"channels": list(channels), "collector_id": collector,
                "interval_seconds": 5},
        identity=REC_ID, reader=reader or FakeReader([]))


def _runtime():
    rt = CollectorRuntime()
    rt.scheduler = _StubScheduler()
    return rt


# ── start / stop lifecycle ──────────────────────────────────────────
@pytest.mark.asyncio
async def test_runtime_starts_the_windows_connector():
    """Before this fix the runtime had NO branch for this connector and
    answered `unsupported_connector_kind`, so it was never scheduled."""
    rt, conn = _runtime(), _connector()
    result = await rt.start(conn)
    assert result["ok"] is True, result
    assert result["mode"] == "eventlog-subscription"
    assert result["collector_id"] == "col_g1life"
    assert result["durable_acquisition_state"] is True
    assert conn.health == Health.CONNECTED
    assert rt.scheduler.running() == [REC_ID]
    # the acquisition loop must be driven even when a read returns nothing
    assert rt.scheduler.started[REC_ID]["always_callback"] is True


@pytest.mark.asyncio
async def test_controlled_stop_reports_disconnected_and_pending_positions():
    rt, conn = _runtime(), _connector()
    await rt.start(conn)
    stopped = await rt.stop(conn)
    assert stopped["ok"] is True
    assert conn.health == Health.DISCONNECTED
    assert rt.scheduler.running() == []
    assert stopped["pending_bookmarks"] == []


@pytest.mark.asyncio
async def test_profile_with_no_collectible_channel_fails_closed():
    rt = _runtime()
    conn = _connector(channels=["ForwardedEvents", "Definitely/NotAChannel"])
    result = await rt.start(conn)
    assert result["ok"] is False
    assert result["reason"] == "no_collectible_channel"
    assert conn.health == Health.ERROR
    assert rt.scheduler.running() == []          # nothing was scheduled
    assert result["problems"]


@pytest.mark.asyncio
async def test_a_partly_invalid_profile_starts_and_states_the_problem():
    rt = _runtime()
    conn = _connector(channels=[SYSMON, "ForwardedEvents"])
    result = await rt.start(conn)
    assert result["ok"] is True
    assert [p["channel"] for p in result["channel_problems"]] \
        == ["ForwardedEvents"]


# ── running · Read → Make Durable → Advance ─────────────────────────
@pytest.mark.asyncio
async def test_position_advances_only_after_the_outbox_holds_the_records():
    rt = _runtime()
    reader = FakeReader([(SYSMON, {"records": [sysmon_xml(11)],
                                   "bookmark_xml": "<BM>11</BM>",
                                   "state": "READ_OK"})])
    conn = _connector(reader=reader)
    await rt.start(conn)
    envs = await conn.collect()
    assert len(envs) == 1
    assert conn._pending.get(SYSMON) == "<BM>11</BM>"   # read, not advanced

    await rt.scheduler.started[REC_ID]["on_envelopes"](conn, envs)

    assert conn._pending == {}                          # advanced
    resume = conn.bookmarks.resume_for(TENANT, conn.collector_id, SYSMON)
    assert resume.get("bookmark_xml") == "<BM>11</BM>"
    assert conn.metrics.events_accepted == 1


@pytest.mark.asyncio
async def test_position_does_not_advance_when_durability_fails(monkeypatch):
    rt = _runtime()
    reader = FakeReader([(SYSMON, {"records": [sysmon_xml(12)],
                                   "bookmark_xml": "<BM>12</BM>",
                                   "state": "READ_OK"})])
    conn = _connector(reader=reader)
    await rt.start(conn)
    envs = await conn.collect()
    monkeypatch.setattr(rt.outbox, "record", lambda e: ("", "failed"))

    await rt.scheduler.started[REC_ID]["on_envelopes"](conn, envs)

    assert conn._pending.get(SYSMON) == "<BM>12</BM>"   # stays put
    resume = conn.bookmarks.resume_for(TENANT, conn.collector_id, SYSMON)
    assert resume.get("bookmark_xml") != "<BM>12</BM>"
    assert conn.metrics.events_accepted == 0


@pytest.mark.asyncio
async def test_channel_that_read_nothing_may_advance():
    rt = _runtime()
    reader = FakeReader([(SYSMON, {"records": [], "bookmark_xml": "<BM>e</BM>",
                                   "state": "READ_OK"})])
    conn = _connector(reader=reader)
    await rt.start(conn)
    envs = await conn.collect()
    assert envs == []
    await rt.scheduler.started[REC_ID]["on_envelopes"](conn, envs)
    assert conn.channel_reports[SYSMON]["events_read"] == 0
    assert conn._pending == {}


@pytest.mark.asyncio
async def test_channel_that_failed_to_read_never_advances():
    rt = _runtime()
    reader = FakeReader([(SYSMON, {"records": [], "bookmark_xml": None,
                                   "state": "READ_FAILED",
                                   "reason": "access denied"})])
    conn = _connector(reader=reader)
    await rt.start(conn)
    envs = await conn.collect()
    await rt.scheduler.started[REC_ID]["on_envelopes"](conn, envs)
    report = conn.channel_reports[SYSMON]
    assert report["state"] == "READ_FAILED"
    assert report["reason"] == "access denied"
    resume = conn.bookmarks.resume_for(TENANT, conn.collector_id, SYSMON)
    assert resume.get("bookmark_xml") is None


@pytest.mark.asyncio
async def test_a_collect_failure_is_observable_not_silent():
    rt, conn = _runtime(), _connector()
    await rt.start(conn)
    on_error = rt.scheduler.started[REC_ID]["on_error"]
    assert on_error is not None
    on_error(conn, RuntimeError("EvtSubscribe failed"))
    assert conn.health == Health.ERROR
    assert "EvtSubscribe failed" in conn.metrics.last_error


# ── permanent identity contract ─────────────────────────────────────
def test_cross_tenant_identity_reuse_is_refused():
    _connector(collector="col_shared", tenant=TENANT)
    with pytest.raises(collector_identity.CollectorIdentityConflict):
        _connector(collector="col_shared", tenant=OTHER_TENANT)
    assert collector_identity.tenant_of("col_shared") == TENANT


def test_same_tenant_may_rebind_its_own_identity_across_restart():
    a = _connector(collector="col_same", tenant=TENANT)
    b = _connector(collector="col_same", tenant=TENANT)
    assert a.collector_id == b.collector_id == "col_same"


def test_identity_with_whitespace_is_refused():
    with pytest.raises(ValueError):
        _connector(collector="col bad")


# ── service startup · rehydration is OBSERVABLE ─────────────────────
def _seed_connectors(state_dir, records):
    with open(os.path.join(state_dir, "connectors.json"), "w",
              encoding="utf-8") as f:
        json.dump({"connectors": records}, f)


def test_rehydration_failure_is_reported_not_swallowed(tmp_path):
    """A bad record must not come up silently: boot survives, the failure is
    named on /health, and the healthy connector still starts."""
    good = {"id": "windows-eventlog::good", "tenant_id": TENANT,
            "source_type": "windows-eventlog", "label": "good",
            "config": {"channels": [SYSMON], "collector_id": "col_good",
                       "interval_seconds": 3600},
            "created_at": "", "updated_at": "", "enabled": True}
    # no collector_id anywhere → must fail closed, observably
    bad = {"id": "windows-eventlog::bad", "tenant_id": TENANT,
           "source_type": "windows-eventlog", "label": "bad",
           "config": {"channels": [SYSMON], "interval_seconds": 3600},
           "created_at": "", "updated_at": "", "enabled": True}
    _seed_connectors(str(tmp_path), [good, bad])

    import main
    with TestClient(main.app) as client:
        body = client.get("/health").json()
    reh = body["rehydration"]
    assert reh["records"] == 2
    assert reh["constructed"] == 1
    assert reh["started"] == 1
    assert [f["connector_id"] for f in reh["failures"]] \
        == ["windows-eventlog::bad"]
    failure = reh["failures"][0]
    assert failure["stage"] == "construct"
    assert "collector_id" in failure["error"]


def test_rehydration_resumes_the_same_bookmark_scope(tmp_path):
    """Service restart → rehydrate → resume: the identity that anchors the
    bookmark scope is the configured one, so the position is found again."""
    rec = {"id": "windows-eventlog::resume", "tenant_id": TENANT,
           "source_type": "windows-eventlog", "label": "resume",
           "config": {"channels": [SYSMON], "collector_id": "col_resume",
                      "interval_seconds": 3600},
           "created_at": "", "updated_at": "", "enabled": True}
    _seed_connectors(str(tmp_path), [rec])

    import main
    with TestClient(main.app) as client:
        assert client.get("/health").json()["rehydration"]["started"] == 1
        inst = main.app.state.instances["windows-eventlog::resume"]
        assert inst.collector_id == "col_resume"
        inst.bookmarks.record_read(
            tenant_id=TENANT, collector_id="col_resume", channel=SYSMON,
            bookmark_xml="<BM>restart</BM>", record_ids=[42],
            profile_id=inst.profile.profile_id,
            profile_version=inst.profile.version, error=None)
        inst.bookmarks.commit_delivered(
            tenant_id=TENANT, collector_id="col_resume", channel=SYSMON,
            bookmark_xml="<BM>restart</BM>")

    for cid in list(collector_identity.bindings()):
        collector_identity.release(cid)

    with TestClient(main.app) as client:
        assert client.get("/health").json()["rehydration"]["started"] == 1
        inst2 = main.app.state.instances["windows-eventlog::resume"]
        assert inst2.collector_id == "col_resume"
        resume = inst2.bookmarks.resume_for(TENANT, "col_resume", SYSMON)
        assert resume.get("bookmark_xml") == "<BM>restart</BM>"
