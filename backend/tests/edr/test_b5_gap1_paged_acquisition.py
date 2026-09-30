"""B5-GAP-1 · A. PAGED ACQUISITION, B. GAP AUTHORITY, E. FAIRNESS.

The defect these tests pin: the Windows sensor read at most 100 records per
channel per cycle with NO pagination, so a channel producing more than one
batch between scheduling opportunities was abandoned — and because the
circular EVTX kept rotating, the abandoned records were permanently lost
with the sensor still reporting `collected: 100`.

EVIDENCE LABELLING — TEST/SYNTHETIC. No live telemetry, no production
query, no endpoint contact.
"""
from __future__ import annotations

import pytest
from tests.edr import fixtures_b5_gap1_source as fx

SYSMON = fx.SYSMON_CHANNEL
SECURITY = fx.SECURITY_CHANNEL
SYSTEM = fx.SYSTEM_CHANNEL


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NIVXFORGE_SENSOR_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("NIVX_SENSOR_ACQUIRE_PAGE_SIZE", "100")
    monkeypatch.delenv("NIVX_SENSOR_FILE_HASHING", raising=False)
    module = fx.load_sensor(tmp_path / "state")
    source = fx.FakeSource(fx.FakeChannel(SYSMON), fx.FakeChannel(SECURITY),
                           fx.FakeChannel(SYSTEM))
    fx.wire(module, source, monkeypatch=monkeypatch)
    journal = module.nvx_journal.open_journal(module.STATE_DIR)
    yield module, source, journal
    journal.close()


def _acquire(module, journal, budget=30.0):
    excl = module.nvx_excl.Journal(module.EXCLUSION_JOURNAL)
    return module.acquire(journal, {"exclusions": []}, excl, budget,
                          fx.IDENTITY)


def _journaled_ids(journal, channel):
    return [int(r["source_record_id"]) for r in journal._db.execute(
        "SELECT source_record_id FROM evidence WHERE channel=?"
        " ORDER BY journal_sequence", (channel,))]


# ═══════════════════════ A · PAGING ═══════════════════════════════
@pytest.mark.parametrize("count", [0, 1, 99, 100, 101, 200, 201, 1000, 10000])
def test_paging_acquires_every_record_with_no_loss(env, count):
    """The matrix that would have caught B5-GAP-1 before production."""
    module, source, journal = env
    expected = source.channel(SYSMON).produce(count, start=1)
    result = _acquire(module, journal)

    ids = _journaled_ids(journal, SYSMON)
    assert ids == expected, "every source record must be durably journaled"
    assert result["records_journaled"] == count
    assert result["duplicates_ignored"] == 0
    assert len(ids) == len(set(ids)), "no page-boundary duplication"
    assert ids == sorted(ids), "journal order must follow source order"
    assert journal.cursor(SYSMON) == (count if count else 0)
    assert journal.gap_count() == 0, "contiguous source is not a gap"
    assert result["caught_up"][SYSMON] is True


def test_more_than_one_page_takes_more_than_one_query(env):
    """The regression proof: 100 records used to END acquisition."""
    module, source, journal = env
    source.channel(SYSMON).produce(250, start=1)
    _acquire(module, journal)

    sysmon_calls = [c for c in source.calls if c[0] == SYSMON]
    assert len(sysmon_calls) >= 3, (
        "a 250-record backlog needs 3 pages at page_size=100; the pre-fix "
        "sensor issued exactly one query per cycle")
    assert [c[1] for c in sysmon_calls[:3]] == [0, 100, 200], \
        "each page must resume strictly after the committed cursor"
    assert journal.cursor(SYSMON) == 250


def test_page_size_is_configurable_and_reaches_wevtutil(env, monkeypatch):
    module, _source, _journal = env
    monkeypatch.setenv("NIVX_SENSOR_ACQUIRE_PAGE_SIZE", "750")
    argv = module._wevtutil_argv(SYSMON, 8470185, module.page_size())
    assert "/c:750" in argv
    assert "/rd:false" in argv, (
        "oldest-first is load-bearing: /rd:true would read the newest N and "
        "walk the cursor to the channel tail")
    assert "/q:*[System[EventRecordID>8470185]]" in argv


def test_per_channel_ceiling_bounds_one_cycle_but_keeps_the_cursor(env,
                                                                  monkeypatch):
    """A permanently hot channel must be bounded, and the bound must be a
    PAUSE, not a skip: the cursor stays exactly where the evidence ends."""
    module, source, journal = env
    monkeypatch.setenv("NIVX_SENSOR_ACQUIRE_MAX_PER_CHANNEL", "300")
    source.channel(SYSMON).produce(1000, start=1)

    first = _acquire(module, journal)
    assert first["records_journaled"] == 300
    assert journal.cursor(SYSMON) == 300
    assert first["caught_up"][SYSMON] is False

    second = _acquire(module, journal)
    assert _journaled_ids(journal, SYSMON) == list(range(1, 601))
    assert second["records_journaled"] == 300
    assert journal.gap_count() == 0, "a bounded cycle must not create a gap"


def test_budget_exhaustion_pauses_without_gap(env):
    module, source, journal = env
    source.channel(SYSMON).produce(5000, start=1)
    result = _acquire(module, journal, budget=0.0)
    assert result["records_read"] == 0
    assert journal.cursor(SYSMON) == 0
    assert journal.gap_count() == 0


# ═══════════════════════ B · GAP DETECTION ════════════════════════
def test_adjacent_record_is_not_a_gap(env):
    module, source, journal = env
    source.channel(SYSMON).produce(1, start=100)
    _acquire(module, journal)
    source.channel(SYSMON).produce(1, start=101)
    _acquire(module, journal)
    assert journal.gap_count() == 0
    assert _journaled_ids(journal, SYSMON) == [100, 101]


def test_cursor_100_next_105_reports_exactly_four_missing(env):
    module, source, journal = env
    source.channel(SYSMON).produce(1, start=100)
    _acquire(module, journal)
    assert journal.cursor(SYSMON) == 100

    source.channel(SYSMON).produce(1, start=105)
    _acquire(module, journal)

    gaps = journal.unreported_gaps()
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap["expected_next_record_id"] == 101
    assert gap["first_observed_record_id"] == 105
    assert gap["missing_start_record_id"] == 101
    assert gap["missing_end_record_id"] == 104
    assert gap["missing_record_id_count"] == 4
    assert gap["cause"] == "NOT_PROVEN"
    assert gap["classification"] == "SOURCE_RECORD_DISCONTINUITY"


def test_production_b5_gap_1_discontinuity_is_reported_exactly(env):
    """The real production numbers: 8470185 -> 8496595 is 26409 RecordIDs."""
    module, source, journal = env
    source.channel(SYSMON).produce(100, start=8470086)
    _acquire(module, journal)
    assert journal.cursor(SYSMON) == 8470185

    # The circular 64 MiB EVTX rotated while delivery held the only thread.
    source.channel(SYSMON).roll_to(8496595)
    source.channel(SYSMON).produce(100, start=8496595)
    _acquire(module, journal)

    gap = journal.last_gap()
    assert gap["expected_next_record_id"] == 8470186
    assert gap["first_observed_record_id"] == 8496595
    assert gap["missing_end_record_id"] == 8496594
    assert gap["missing_record_id_count"] == 26409
    assert gap["cause"] == "NOT_PROVEN", (
        "rollover is plausible but was NOT proven from the endpoint; the "
        "sensor must not label a cause it cannot establish")


def test_gap_fabricates_nothing(env):
    module, source, journal = env
    source.channel(SYSMON).produce(1, start=100)
    _acquire(module, journal)
    source.channel(SYSMON).produce(2, start=200)
    _acquire(module, journal)
    assert _journaled_ids(journal, SYSMON) == [100, 200, 201], (
        "a declared gap must never materialise as invented evidence")
    assert journal.counts_by_state()["ACQUIRED"] == 3


def test_interior_discontinuity_inside_a_page_is_reported(env):
    module, source, journal = env
    channel = source.channel(SYSMON)
    channel.produce(2, start=1)
    channel.produce(2, start=50)
    _acquire(module, journal)
    gap = journal.last_gap()
    assert gap["position"] == "INTERIOR"
    assert (gap["missing_start_record_id"],
            gap["missing_end_record_id"]) == (3, 49)


def test_first_ever_acquisition_declares_no_gap(env):
    """Without a cursor this sensor itself committed, the pre-install
    history is not a gap. Reporting it would be a fabricated finding."""
    module, source, journal = env
    source.channel(SYSMON).produce(10, start=8_000_000)
    result = _acquire(module, journal)
    assert journal.gap_count() == 0
    assert result["records_journaled"] == 10
    assert journal.continuity_established(SYSMON) is True


def test_gap_is_neither_benign_nor_malicious(env):
    module, source, journal = env
    source.channel(SYSMON).produce(1, start=10)
    _acquire(module, journal)
    source.channel(SYSMON).produce(1, start=20)
    _acquire(module, journal)
    health = journal.health()
    assert "ACQUISITION_GAP" in health["states"]
    assert "HEALTHY" not in health["states"]
    text = str(health).upper()
    for forbidden in ("BENIGN", "MALICIOUS", "COMPROMISE", "ATTACK"):
        assert forbidden not in text


# ═══════════════════════ E · FAIRNESS ═════════════════════════════
def test_hot_sysmon_does_not_starve_security_or_system(env):
    module, source, journal = env
    source.channel(SYSMON).produce(20000, start=1)
    source.channel(SECURITY).produce(3, start=500)
    source.channel(SYSTEM).produce(2, start=700)

    result = _acquire(module, journal)
    assert result["caught_up"][SECURITY] is True
    assert result["caught_up"][SYSTEM] is True
    assert _journaled_ids(journal, SECURITY) == [500, 501, 502]
    assert _journaled_ids(journal, SYSTEM) == [700, 701]
    assert result["per_channel_read"][SYSMON] > 0


def test_one_channel_failure_does_not_stop_the_others(env):
    module, source, journal = env
    source.channel(SECURITY).failure = "TimeoutExpired: wevtutil timed out"
    source.channel(SYSMON).produce(5, start=1)
    source.channel(SYSTEM).produce(5, start=1)

    result = _acquire(module, journal)
    assert SECURITY in result["channels_unavailable"]
    assert journal.cursor(SECURITY) == 0, (
        "an unreadable channel must NOT advance its cursor")
    assert len(_journaled_ids(journal, SYSMON)) == 5
    assert len(_journaled_ids(journal, SYSTEM)) == 5
    assert journal.gap_count() == 0


def test_unreadable_channel_is_not_reported_as_silence(env):
    module, source, journal = env
    source.channel(SYSMON).failure = "channel unreadable"
    _acquire(module, journal)
    health = journal.health(
        channels_unavailable={SYSMON: "channel unreadable"})
    assert "CHANNEL_UNAVAILABLE" in health["states"]
    assert "HEALTHY" not in health["states"]


def test_malformed_source_record_is_journaled_not_dropped(env):
    """A record the parser cannot fully understand is still EVIDENCE. It
    must be owned, not quietly discarded on the way to the journal."""
    module, source, journal = env
    broken = fx.sensor_event(SYSMON, 4)
    broken["winlog"]["event_id"] = None
    broken["winlog"]["xml"] = "<Event><System><EventRecordID>4"
    source.channel(SYSMON).add(broken)
    source.channel(SYSMON).produce(2, start=5)

    result = _acquire(module, journal)
    assert result["records_journaled"] == 3
    assert _journaled_ids(journal, SYSMON) == [4, 5, 6]
    assert journal.cursor(SYSMON) == 6
