"""B5-GAP-1 · C. DURABILITY, D. DELIVERY, F. DISK PRESSURE, G. IDENTITY,
H. EID5 REGRESSION, plus legacy-state migration.

The invariant under test throughout:

    THE SOURCE CURSOR MUST NEVER ADVANCE BEYOND THE LAST SOURCE RECORD
    DURABLY OWNED BY NIVXFORGE.

EVIDENCE LABELLING — TEST/SYNTHETIC. No live telemetry, no production
query, no endpoint contact.
"""
from __future__ import annotations

import json
import sqlite3

import pytest
from edr_plane import windows_eventlog as w
from tests.edr import fixtures_b5_gap1_source as fx

SYSMON = fx.SYSMON_CHANNEL
SECURITY = fx.SECURITY_CHANNEL
SYSTEM = fx.SYSTEM_CHANNEL
PROCESS_GUID = "{9949e5f2-d54c-6abb-0000-000000002100}"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NIVXFORGE_SENSOR_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("NIVX_SENSOR_ACQUIRE_PAGE_SIZE", "100")
    monkeypatch.delenv("NIVX_SENSOR_FILE_HASHING", raising=False)
    module = fx.load_sensor(tmp_path / "state")
    source = fx.FakeSource(fx.FakeChannel(SYSMON), fx.FakeChannel(SECURITY),
                           fx.FakeChannel(SYSTEM))
    calls = fx.wire(module, source, monkeypatch=monkeypatch)
    fx.write_identity(module)
    journal = module.nvx_journal.open_journal(module.STATE_DIR)
    yield module, source, journal, calls
    journal.close()


def _acquire(module, journal, budget=30.0):
    excl = module.nvx_excl.Journal(module.EXCLUSION_JOURNAL)
    return module.acquire(journal, {"exclusions": []}, excl, budget,
                          fx.IDENTITY)


def _page(channel, count, start):
    return [fx.sensor_event(channel, r) for r in range(start, start + count)]


# ═══════════════════════ C · DURABILITY ═══════════════════════════
def test_successful_commit_moves_evidence_and_cursor_together(env):
    module, _source, journal, _calls = env
    result = journal.commit_page(SYSMON, _page(SYSMON, 5, 1), 5, [])
    assert result["journaled"] == 5
    assert journal.cursor(SYSMON) == 5

    journal.close()
    reopened = module.nvx_journal.open_journal(module.STATE_DIR)
    try:
        assert reopened.cursor(SYSMON) == 5
        assert reopened.depth() == 5, (
            "evidence and cursor are one transaction, so a crash can never "
            "leave a cursor ahead of the evidence")
    finally:
        reopened.close()


def test_journal_write_failure_must_not_advance_the_cursor(env):
    """CASE B. The single most important negative test in this suite.

    A genuine write failure, not a mocked one: the connection is made
    read-only, exactly as an I/O error or a read-only volume would present.
    """
    module, _source, journal, _calls = env
    journal.commit_page(SYSMON, _page(SYSMON, 2, 1), 2, [])
    assert journal.cursor(SYSMON) == 2

    journal._db.execute("PRAGMA query_only=ON")
    with pytest.raises(sqlite3.OperationalError):
        journal.commit_page(SYSMON, _page(SYSMON, 100, 3), 102, [])
    journal._db.execute("PRAGMA query_only=OFF")

    assert journal.cursor(SYSMON) == 2, (
        "a failed durable write must leave the cursor exactly where it was, "
        "so the next cycle re-reads the same source range")
    assert journal.depth() == 2
    del module


def test_acquisition_cursor_holds_when_the_journal_cannot_accept(env):
    """The same invariant seen from the acquisition loop rather than from
    the journal API: a page that cannot be committed leaves the source
    position untouched, so nothing is silently skipped."""
    module, source, journal, _calls = env
    source.channel(SYSMON).produce(50, start=1)
    journal._db.execute("PRAGMA query_only=ON")
    with pytest.raises(sqlite3.OperationalError):
        _acquire(module, journal)
    journal._db.execute("PRAGMA query_only=OFF")
    assert journal.cursor(SYSMON) == 0
    assert journal.depth() == 0

    result = _acquire(module, journal)
    assert result["records_journaled"] == 50, (
        "the same source range is re-read and fully acquired on recovery")
    assert journal.gap_count() == 0


def test_partial_transaction_rolls_back_entirely(env):
    """CASE D. A half-written transaction is not durable ownership."""
    module, _source, journal, _calls = env
    journal.commit_page(SYSMON, _page(SYSMON, 1, 1), 1, [])
    with pytest.raises(KeyError):
        journal.commit_page(SYSMON, _page(SYSMON, 3, 2), 4,
                            [{"channel": SYSMON}])   # malformed gap
    assert journal.cursor(SYSMON) == 1
    assert journal.depth() == 1, "no row of a rolled-back page may survive"
    assert journal.gap_count() == 0
    del module


def test_crash_before_commit_loses_nothing_because_source_is_rescanned(env):
    """CASE A. The source range is simply re-read, and the unique index
    makes that re-read idempotent instead of duplicative."""
    module, source, journal, _calls = env
    source.channel(SYSMON).produce(150, start=1)
    _acquire(module, journal)
    assert journal.cursor(SYSMON) == 150

    replay = journal.commit_page(SYSMON, _page(SYSMON, 150, 1), 150, [])
    assert replay["journaled"] == 0
    assert replay["duplicates_ignored"] == 150
    assert journal.depth() == 150, "a replay must not duplicate evidence"


def test_journal_survives_restart_with_backend_unavailable(env):
    """CASE C."""
    module, source, journal, _calls = env
    source.channel(SYSMON).produce(40, start=1)
    _acquire(module, journal)
    journal.close()

    reopened = module.nvx_journal.open_journal(module.STATE_DIR)
    try:
        assert reopened.depth() == 40
        assert reopened.counts_by_state()["ACQUIRED"] == 40
        source.channel(SYSMON).produce(10, start=41)
        _acquire(module, reopened)
        assert reopened.depth() == 50, "acquisition resumes after a restart"
    finally:
        reopened.close()


def test_accept_then_crash_redelivers_byte_identical_payload(env):
    """CASE E. Retry safety is the BACKEND's identity authority, so the
    sensor's duty is to resend the same bytes, never to mint a new id."""
    module, source, journal, calls = env
    source.channel(SYSMON).produce(1, start=7)
    _acquire(module, journal)
    row = journal.next_undelivered()[0]
    first = row["payload"]

    module._drain_journal("http://api", fx.IDENTITY, {"token": "t"}, journal,
                          30, 5.0)
    # The accept landed but the local acknowledgement was 'lost': replay it.
    journal._db.execute("UPDATE evidence SET state='ACQUIRED'")
    second = journal.next_undelivered()[0]["payload"]
    assert second == first, "a retry must carry the identical evidence bytes"
    assert len(calls["posted"]) >= 1
    del module


def test_record_without_a_record_id_is_still_owned(env):
    module, _source, journal, _calls = env
    orphan = fx.sensor_event(SYSMON, 1)
    orphan["winlog"]["record_id"] = None
    result = journal.commit_page(SYSMON, [orphan, orphan], 0, [])
    assert result["journaled"] == 2, (
        "SQLite treats NULLs as distinct, so a record the source did not "
        "number is never deduplicated away")
    del module


def test_corrupt_journal_is_visible_and_preserved(env):
    module, _source, journal, _calls = env
    journal.commit_page(SYSMON, _page(SYSMON, 1, 1), 1, [])
    journal.close()
    module.JOURNAL_FILE.write_bytes(b"this is not a database" * 100)

    with pytest.raises(module.nvx_journal.JournalUnavailable):
        module.nvx_journal.open_journal(module.STATE_DIR)

    fault = json.loads(
        (module.STATE_DIR / module.nvx_journal.FAULT_FILENAME).read_text())
    assert fault["state"] == "JOURNAL_CORRUPT"
    preserved = list(module.STATE_DIR.glob("evidence_journal.corrupt-*"))
    assert preserved, "corrupt bytes must be preserved, never deleted"


# ═══════════════════════ D · DELIVERY ═════════════════════════════
def test_normal_backend_accepts_then_reclaims(env):
    module, source, journal, calls = env
    source.channel(SYSMON).produce(25, start=1)
    _acquire(module, journal)

    out = module._drain_journal("http://api", fx.IDENTITY, {"token": "t"},
                               journal, 30, 30.0)
    assert out["sent"] == 25
    assert out["backend_unreachable"] is False
    assert journal.depth() == 0
    assert journal.counts_by_state()["BACKEND_ACCEPTED"] == 25
    assert journal.reclaim()["reclaimed"] == 25
    assert journal.counts_by_state() == {}
    assert len(calls["posted"]) == 25


def test_unavailable_backend_retains_evidence_and_says_so(env, monkeypatch):
    module, source, journal, _calls = env
    source.channel(SYSMON).produce(10, start=1)
    _acquire(module, journal)

    def _down(api, path, body, bearer=None):
        raise RuntimeError("503 backend unavailable")

    monkeypatch.setattr(module, "_post", _down)
    out = module._drain_journal("http://api", fx.IDENTITY, {"token": "t"},
                               journal, 30, 5.0)
    assert out["backend_unreachable"] is True
    assert out["sent"] == 0
    assert journal.depth() == 10, "a failed send is not an acceptance"
    assert journal.counts_by_state().get("BACKEND_ACCEPTED") is None
    health = journal.health(backend_unreachable=True)
    assert "BACKEND_UNREACHABLE" in health["states"]
    assert "DELIVERY_BACKLOG" in health["states"]


def test_slow_backend_produces_a_backlog_never_acquisition_loss(env,
                                                                monkeypatch):
    """THE B5-GAP-1 FAILURE MODE, inverted. Delivery is slower than the
    source, and acquisition must keep going anyway."""
    module, source, journal, _calls = env
    import time as _time

    def _slow(api, path, body, bearer=None):
        if path == "/api/edr/agent/telemetry":
            _time.sleep(0.01)
        return {"accepted": True}

    monkeypatch.setattr(module, "_post", _slow)
    source.channel(SYSMON).produce(400, start=1)
    _acquire(module, journal)
    assert journal.depth() == 400

    out = module._drain_journal("http://api", fx.IDENTITY, {"token": "t"},
                               journal, 30, 0.25)
    assert out["sent"] < 400, "the delivery budget must bound the drain"
    assert out["budget_exhausted"] is True

    # The source keeps producing; acquisition must NOT have been starved.
    source.channel(SYSMON).produce(400, start=401)
    again = _acquire(module, journal)
    assert again["records_journaled"] == 400
    assert journal.cursor(SYSMON) == 800
    assert journal.gap_count() == 0, (
        "a delivery backlog must never become a source discontinuity")


def test_recovery_delivers_everything_exactly_once(env, monkeypatch):
    module, source, journal, _calls = env
    state = {"down": True}
    seen: list[str] = []

    def _flaky(api, path, body, bearer=None):
        if path != "/api/edr/agent/telemetry":
            return {}
        if state["down"]:
            raise RuntimeError("503 backend unavailable")
        seen.append(body["payload"])
        return {"accepted": True}

    monkeypatch.setattr(module, "_post", _flaky)
    source.channel(SYSMON).produce(60, start=1)
    _acquire(module, journal)
    module._drain_journal("http://api", fx.IDENTITY, {"token": "t"}, journal,
                          30, 2.0)
    assert journal.depth() == 60

    state["down"] = False
    module._drain_journal("http://api", fx.IDENTITY, {"token": "t"}, journal,
                          30, 30.0)
    assert journal.depth() == 0
    assert len(seen) == 60
    assert len(set(seen)) == 60, "no duplicates across a recovery"


def test_delivery_follows_journal_order(env):
    module, source, journal, calls = env
    source.channel(SYSMON).produce(30, start=1)
    _acquire(module, journal)
    module._drain_journal("http://api", fx.IDENTITY, {"token": "t"}, journal,
                          30, 30.0)
    ids = [json.loads(b["payload"])["winlog"]["record_id"]
           for _p, b in calls["posted"]]
    assert ids == sorted(ids) == list(range(1, 31))
    del module


# ═══════════════════════ F · DISK PRESSURE ════════════════════════
def test_warning_threshold_is_reported(env, monkeypatch):
    module, source, journal, _calls = env
    source.channel(SYSMON).produce(200, start=1)
    _acquire(module, journal)
    live = journal.pressure()["journal_live_bytes"]
    monkeypatch.setenv("NIVX_SENSOR_JOURNAL_MAX_BYTES", str(int(live / 0.75)))
    state = journal.pressure()
    assert state["warning"] is True and state["critical"] is False
    assert "JOURNAL_PRESSURE" in journal.health()["states"]
    del module


def test_capacity_is_judged_on_live_evidence_not_the_file_high_water_mark(
        env, monkeypatch):
    """A sensor that once held a big backlog and has since delivered it all
    must NOT be permanently halted by the file it left behind."""
    module, source, journal, _calls = env
    source.channel(SYSMON).produce(2000, start=1)
    _acquire(module, journal)
    peak_file_bytes = journal.bytes_used()
    monkeypatch.setenv("NIVX_SENSOR_JOURNAL_MAX_BYTES",
                       str(journal.live_bytes()))
    assert journal.pressure()["critical"] is True
    assert peak_file_bytes > 0

    module._drain_journal("http://api", fx.IDENTITY, {"token": "t"}, journal,
                          30, 60.0)
    while journal.reclaim()["reclaimed"]:
        pass
    state = journal.pressure()
    assert state["journal_live_bytes"] == 0
    assert state["critical"] is False, (
        "an empty journal is not a full journal, whatever the file size is")
    admitted, reason = journal.admits_acquisition()
    assert admitted is True and reason is None


def test_exhausted_capacity_halts_acquisition_and_keeps_evidence(env,
                                                                 monkeypatch):
    module, source, journal, _calls = env
    source.channel(SYSMON).produce(100, start=1)
    _acquire(module, journal)
    held = journal.depth()
    assert held == 100
    monkeypatch.setenv("NIVX_SENSOR_JOURNAL_MAX_BYTES", "1")

    source.channel(SYSMON).produce(100, start=101)
    result = _acquire(module, journal)
    assert result["acquisition_halted"], (
        "a full journal must stop acquisition, not read records it cannot own")
    assert result["records_journaled"] == 0
    assert journal.depth() == held, (
        "unacknowledged evidence is never overwritten or dropped, at any "
        "pressure")
    assert journal.cursor(SYSMON) == 100
    states = journal.health()["states"]
    assert "ACQUISITION_HALTED_JOURNAL_FULL" in states
    assert "HEALTHY" not in states


def test_low_free_disk_is_treated_as_pressure(env, monkeypatch):
    module, _source, journal, _calls = env
    monkeypatch.setenv("NIVX_SENSOR_JOURNAL_MIN_FREE_BYTES",
                       str(1 << 62))
    state = journal.pressure()
    assert state["low_disk"] is True and state["critical"] is True
    del module


def test_reclaim_only_removes_what_the_platform_accepted(env):
    module, source, journal, _calls = env
    source.channel(SYSMON).produce(20, start=1)
    _acquire(module, journal)
    journal.mark_accepted([1, 2, 3])
    assert journal.reclaim()["reclaimed"] == 3
    assert journal.depth() == 17
    assert journal.reclaim()["reclaimed"] == 0, (
        "nothing unacknowledged may ever be considered reclaimable")
    del module


# ═══════════════════════ G · IDENTITY ═════════════════════════════
def test_journaling_does_not_change_canonicalization(env):
    module, source, journal, _calls = env
    original = fx.sensor_event(SYSMON, 8470141, event_id=5,
                               data={"ProcessGuid": PROCESS_GUID,
                                     "UtcTime": "2026-09-29 14:45:09.305"})
    source.channel(SYSMON).add(original)
    _acquire(module, journal)

    journaled = json.loads(journal.next_undelivered()[0]["payload"])
    assert w.is_windows_envelope(journaled)
    assert w.to_canonical(journaled) == w.to_canonical(original), (
        "passing through the durable journal must not alter one canonical "
        "field, or every identifier downstream shifts")


def test_tenant_and_endpoint_binding_is_carried(env):
    module, source, journal, _calls = env
    source.channel(SYSMON).produce(1, start=1)
    _acquire(module, journal)
    row = journal._db.execute(
        "SELECT tenant_id, endpoint_id FROM evidence").fetchone()
    assert row["tenant_id"] == fx.IDENTITY["tenant_id"]
    assert row["endpoint_id"] == fx.IDENTITY["endpoint_id"]
    del module


def test_identical_content_observations_stay_separately_addressable(env):
    module, _source, journal, _calls = env
    first = fx.sensor_event(SYSMON, 10)
    second = json.loads(json.dumps(first))
    second["winlog"]["record_id"] = 11
    second["winlog"]["xml"] = first["winlog"]["xml"]
    journal.commit_page(SYSMON, [first, second], 11, [])
    rows = list(journal._db.execute(
        "SELECT journal_sequence, content_digest FROM evidence"
        " ORDER BY journal_sequence"))
    assert len(rows) == 2
    assert rows[0]["journal_sequence"] != rows[1]["journal_sequence"], (
        "observation identity is journal_sequence; content identity is the "
        "digest, and the two must not be conflated")
    del module


def test_journal_never_stores_the_agent_credential(env):
    module, source, journal, _calls = env
    source.channel(SYSMON).produce(5, start=1)
    _acquire(module, journal)
    module._drain_journal("http://api", fx.IDENTITY, {"token": "t"}, journal,
                          30, 5.0)
    blob = module.JOURNAL_FILE.read_bytes()
    assert fx.IDENTITY["agent_credential"].encode() not in blob
    assert b"Bearer" not in blob
    snapshot = (module.STATE_DIR
                / module.nvx_journal.INTEGRITY_FILENAME)
    journal.write_integrity_snapshot(journal.health())
    assert fx.IDENTITY["agent_credential"] not in snapshot.read_text()


# ═══════════════ H · B5 / EID5 REGRESSION ═════════════════════════
def test_eid1_and_eid5_survive_the_journal_with_processguid_intact(env):
    module, source, journal, _calls = env
    source.channel(SYSMON).add(fx.sensor_event(
        SYSMON, 8470140, event_id=1,
        data={"ProcessGuid": PROCESS_GUID, "ProcessId": "8448",
              "Image": r"C:\Windows\System32\notepad.exe",
              "UtcTime": "2026-09-29 14:45:08.100"}))
    source.channel(SYSMON).add(fx.sensor_event(
        SYSMON, 8470141, event_id=5,
        data={"ProcessGuid": PROCESS_GUID, "ProcessId": "8448",
              "Image": r"C:\Windows\System32\notepad.exe",
              "UtcTime": "2026-09-29 14:45:09.305"}))
    _acquire(module, journal)

    payloads = [r["payload"] for r in journal.next_undelivered()]
    assert len(payloads) == 2

    canonical = [w.to_canonical(json.loads(p)) for p in payloads]
    activities = [c["activity"] for c in canonical]
    assert w.ACTIVITY_PROCESS in activities
    assert w.ACTIVITY_PROCESS_TERMINATION in activities, (
        "B5 must remain CLOSED/PASS: ProcessTerminate still maps to a "
        "termination through the new durable path")
    for entry in canonical:
        assert entry["process"].get("process_guid") == PROCESS_GUID

    terminations = [p for p in payloads if w.is_sysmon_event(p, 5)]
    assert len(terminations) == 1, (
        "provider-qualified EID5 counting must still hold on the journaled "
        "payload")


def test_non_sysmon_event_id_5_is_still_not_a_termination(env):
    module, source, journal, _calls = env
    source.channel(SYSTEM).add(fx.sensor_event(
        SYSTEM, 9001, event_id=5,
        provider="Microsoft-Windows-IsolatedUserMode"))
    _acquire(module, journal)
    payload = journal.next_undelivered()[0]["payload"]
    assert w.is_sysmon_event(payload, 5) is False
    del module


# ═══════════════════════ MIGRATION ════════════════════════════════
def test_migration_adopts_legacy_cursors_without_replaying_history(env):
    module, _source, journal, _calls = env
    journal.close()
    module.BOOKMARK_FILE.parent.mkdir(parents=True, exist_ok=True)
    module.BOOKMARK_FILE.write_text(json.dumps({
        "Security": 284760, "System": 22702, SYSMON: 8969348}))
    module.QUEUE_FILE.write_text(
        json.dumps(fx.sensor_event(SYSMON, 999)) + "\n")

    migrated = module.nvx_journal.open_journal(module.STATE_DIR,
                                               module.BOOKMARK_FILE)
    try:
        assert migrated.cursor(SYSMON) == 8969348, (
            "the production cursor must be adopted, not reset: a reset would "
            "replay the entire Windows Event Log")
        assert migrated.cursor("Security") == 284760
        assert migrated.continuity_established(SYSMON) is True
        assert migrated.depth() == 0, "migration must not import history"
        assert module.QUEUE_FILE.exists(), (
            "the legacy outbox must stay deliverable, never be deleted")
        assert module._legacy_remaining() == 1
    finally:
        migrated.close()


def test_migration_is_idempotent_and_never_regresses_a_cursor(env):
    module, _source, journal, _calls = env
    journal.commit_page(SYSMON, _page(SYSMON, 1, 9000000), 9000000, [])
    journal.close()
    module.BOOKMARK_FILE.write_text(json.dumps({SYSMON: 1}))

    for _ in range(3):
        again = module.nvx_journal.open_journal(module.STATE_DIR,
                                                module.BOOKMARK_FILE)
        try:
            assert again.cursor(SYSMON) == 9000000, (
                "a stale legacy bookmark must never drag the cursor back")
        finally:
            again.close()


def test_bookmark_file_becomes_a_mirror_of_the_journal(env):
    module, source, journal, _calls = env
    source.channel(SYSMON).produce(7, start=1)
    _acquire(module, journal)
    module._mirror_bookmarks(journal)
    assert json.loads(module.BOOKMARK_FILE.read_text())[SYSMON] == 7
