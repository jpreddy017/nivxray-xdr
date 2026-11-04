"""G1/S3+S4 · the Windows runtime contract: fail closed, persist where told.

Two defects are pinned here.

S3 — a Windows host without `pywin32` used to produce a CONNECTED connector
that acquired zero events forever: the missing native binding surfaced only
as a per-read `READER_UNAVAILABLE`, and nothing refused to start. Capability
is now decided at start-up and the runtime fails closed on it.

S4 — `WindowsBookmarkStore` hard-coded `/var/lib/nivxray`, which on Windows
resolves to `C:\\var\\lib\\nivxray` on whatever drive happens to be current:
writable, and nowhere an operator backs up or ACLs. The default is now
platform-resolved, and `XDR_STATE_DIR` still wins.

TEST/SYNTHETIC — these run on Linux. They prove the CONTRACT (probe →
refuse, path resolution); they do not prove a real Windows host reads real
records. That is the endpoint proof and cannot be substituted from here.
"""
from __future__ import annotations

import os

import pytest

from framework import collector_identity, state_paths
from framework.base import Health
from framework.runtime import CollectorRuntime
from framework.windows_bookmarks import WindowsBookmarkStore
from framework.windows_eventlog import (BINDING_NOT_PROBED,
                                        NATIVE_BINDING_BOUND,
                                        NATIVE_BINDING_UNAVAILABLE,
                                        PLATFORM_NOT_WINDOWS,
                                        NativeEvtReader,
                                        UnsupportedPlatformReader,
                                        WindowsEventLogConnector)
from tests.test_windows_eventlog_acquisition import SYSMON, FakeReader

TENANT = "ten_g1_runtime"
REC_ID = "windows-eventlog::runtime-contract"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("XDR_DISABLE_DELIVERY_WORKER", "1")
    monkeypatch.delenv("NIVX_COLLECTOR_ID", raising=False)
    for cid in list(collector_identity.bindings()):
        collector_identity.release(cid)
    yield
    for cid in list(collector_identity.bindings()):
        collector_identity.release(cid)


class _StubScheduler:
    def __init__(self):
        self.started = {}

    async def start(self, conn, on_envelopes, *, on_error=None,
                    always_callback=False):
        self.started[conn.identity] = True

    def running(self):
        return list(self.started)


def _connector(reader, collector="col_g1runtime"):
    return WindowsEventLogConnector(
        TENANT, {"channels": [SYSMON], "collector_id": collector},
        identity=REC_ID, reader=reader)


# ── S3 · capability is a first-class answer ──────────────────────────
def test_unsupported_platform_reader_reports_platform_not_windows():
    cap = _connector(UnsupportedPlatformReader()).acquisition_capability()
    assert cap["bound"] is False
    assert cap["code"] == PLATFORM_NOT_WINDOWS
    assert cap["reader"] == "UnsupportedPlatformReader"


def test_native_reader_reports_the_missing_dependency_by_name():
    """On this Linux host `win32evtlog` is genuinely absent, so the probe
    returns the same answer a Windows host without pywin32 would give — and
    it names the requirement instead of saying 'unavailable'."""
    cap = _connector(NativeEvtReader()).acquisition_capability()
    assert cap["bound"] is False
    assert cap["code"] == NATIVE_BINDING_UNAVAILABLE
    assert "pywin32" in cap["reason"]
    assert cap["requirement"] == "requirements-windows.txt · pywin32==312"


def test_injected_reader_is_taken_at_its_word_not_probed():
    cap = _connector(FakeReader([])).acquisition_capability()
    assert cap["bound"] is True
    assert cap["code"] == BINDING_NOT_PROBED


@pytest.mark.asyncio
async def test_windows_host_without_native_bindings_refuses_to_start(
        monkeypatch):
    """THE S3 gate: on Windows, no binding means no subscription — not a
    CONNECTED connector that acquires nothing."""
    monkeypatch.setattr("framework.runtime.platform.system",
                        lambda: "Windows")
    conn = _connector(NativeEvtReader())
    rt = CollectorRuntime()
    rt.scheduler = _StubScheduler()
    result = await rt.start(conn)
    assert result["ok"] is False
    assert result["reason"] == "native_binding_unavailable"
    assert result["acquisition_capability"]["code"] == \
        NATIVE_BINDING_UNAVAILABLE
    assert conn.health == Health.ERROR
    assert "pywin32" in conn.metrics.last_error
    # and nothing was scheduled: a refused start does not poll
    assert rt.scheduler.running() == []


@pytest.mark.asyncio
async def test_a_bound_connector_starts_and_reports_its_capability():
    conn = _connector(FakeReader([]))
    rt = CollectorRuntime()
    rt.scheduler = _StubScheduler()
    result = await rt.start(conn)
    assert result["ok"] is True
    assert result["acquisition_capability"]["bound"] is True
    assert conn.health == Health.CONNECTED


@pytest.mark.asyncio
async def test_non_windows_host_still_starts_and_never_fabricates_events():
    """Off Windows the platform is the reason, not a missing package, so the
    connector runs and every channel reports UNSUPPORTED_PLATFORM."""
    conn = _connector(UnsupportedPlatformReader())
    rt = CollectorRuntime()
    rt.scheduler = _StubScheduler()
    result = await rt.start(conn)
    assert result["ok"] is True
    assert result["acquisition_capability"]["code"] == PLATFORM_NOT_WINDOWS
    envs = await conn.collect()
    assert envs == []
    assert conn.channel_reports[SYSMON]["state"] == "UNSUPPORTED_PLATFORM"


def test_binding_codes_are_distinct_facts():
    assert len({NATIVE_BINDING_BOUND, NATIVE_BINDING_UNAVAILABLE,
                PLATFORM_NOT_WINDOWS, BINDING_NOT_PROBED}) == 4


# ── S4 · persistent state lands where the operator declared ──────────
def test_windows_default_state_root_is_programdata_not_var_lib():
    assert state_paths.default_state_dir("Windows") == \
        r"C:\ProgramData\NivXForge\state"
    assert state_paths.default_state_dir("Linux") == "/var/lib/nivxray"
    assert "/var/lib/nivxray" not in state_paths.default_state_dir("Windows")


def test_declared_state_dir_always_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("XDR_STATE_DIR", str(tmp_path / "declared"))
    assert state_paths.state_dir() == str(tmp_path / "declared")


def test_unset_state_dir_falls_back_to_the_platform_default(monkeypatch):
    monkeypatch.delenv("XDR_STATE_DIR", raising=False)
    assert state_paths.state_dir() == state_paths.default_state_dir()


def test_bookmarks_live_in_the_declared_state_dir_beside_the_outbox(
        tmp_path, monkeypatch):
    """One fsync domain: the bookmark and the delivery record that justifies
    advancing it share `outbox.db`."""
    monkeypatch.setenv("XDR_STATE_DIR", str(tmp_path / "state"))
    store = WindowsBookmarkStore()
    store.record_read(tenant_id=TENANT, collector_id="col_g1runtime",
                      channel=SYSMON, bookmark_xml="<BM>1</BM>",
                      record_ids=[1])
    db = tmp_path / "state" / "outbox.db"
    assert db.is_file()
    assert store.state_for(TENANT, "col_g1runtime", SYSMON)[
        "bookmark_xml"] == "<BM>1</BM>"


def test_state_survives_a_new_store_instance(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_STATE_DIR", str(tmp_path / "state"))
    WindowsBookmarkStore().record_read(
        tenant_id=TENANT, collector_id="col_g1runtime", channel=SYSMON,
        bookmark_xml="<BM>7</BM>", record_ids=[7])
    resumed = WindowsBookmarkStore().resume_for(TENANT, "col_g1runtime",
                                                SYSMON)
    assert resumed["classification"] == "RESUME_FROM_BOOKMARK"
    assert resumed["bookmark_xml"] == "<BM>7</BM>"


def test_unwritable_state_dir_fails_loudly(tmp_path, monkeypatch):
    """A state root that cannot be created is a deployment fault, and it is
    raised — never downgraded to in-memory acquisition state."""
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    monkeypatch.setenv("XDR_STATE_DIR", str(blocker / "state"))
    with pytest.raises(OSError):
        WindowsBookmarkStore()
    assert not os.path.isdir(str(blocker / "state"))
