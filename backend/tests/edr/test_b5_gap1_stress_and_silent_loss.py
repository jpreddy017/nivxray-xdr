"""B5-GAP-1 · §23 STRESS (>=10,000 events) and §24 FAILURE INJECTION.

§24 reproduces the EXACT class of failure that caused B5-GAP-1: the source
keeps producing faster than delivery, the backlog grows, and more than one
page of source records accumulates between scheduling opportunities. Before
the fix that combination silently destroyed evidence. These tests assert it
now produces a DELIVERY BACKLOG and nothing else.

A counterfactual test is included that re-creates the PRE-FIX acquisition
shape (one bounded page per cycle, no pagination) against the same rotating
channel, so the suite demonstrates the defect as well as the repair.

Measured throughput here is SYNTHETIC. It is not a claim about production
throughput: there is no real `wevtutil`, no real HTTP and no real endpoint
in this harness.

EVIDENCE LABELLING — TEST/SYNTHETIC. No live telemetry, no production
query, no endpoint contact.
"""
from __future__ import annotations

import json
import time

import pytest
from tests.edr import fixtures_b5_gap1_source as fx

SYSMON = fx.SYSMON_CHANNEL
SECURITY = fx.SECURITY_CHANNEL
SYSTEM = fx.SYSTEM_CHANNEL
MEASUREMENTS: dict = {}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NIVXFORGE_SENSOR_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("NIVX_SENSOR_ACQUIRE_PAGE_SIZE", "500")
    monkeypatch.setenv("NIVX_SENSOR_SOURCE_TAIL_PROBE", "1")
    monkeypatch.delenv("NIVX_SENSOR_FILE_HASHING", raising=False)
    module = fx.load_sensor(tmp_path / "state")
    source = fx.FakeSource(fx.FakeChannel(SYSMON), fx.FakeChannel(SECURITY),
                           fx.FakeChannel(SYSTEM))
    calls = fx.wire(module, source, monkeypatch=monkeypatch)
    fx.write_identity(module)
    journal = module.nvx_journal.open_journal(module.STATE_DIR)
    yield module, source, journal, calls
    journal.close()


def _all_journaled_ids(journal, channel):
    return [int(r["source_record_id"]) for r in journal._db.execute(
        "SELECT source_record_id FROM evidence WHERE channel=?"
        " ORDER BY source_record_id", (channel,))]


# ═══════════════════ §23 · STRESS, 10,000 EVENTS ══════════════════
def test_stress_10000_events_with_delivery_slower_than_acquisition(
        env, monkeypatch):
    module, source, journal, calls = env
    total = 10000
    expected = source.channel(SYSMON).produce(total, start=8470086)
    accepted: list[str] = []

    def _slow_post(api, path, body, bearer=None):
        if path == "/api/edr/agent/telemetry":
            # Deliberately slower than acquisition, which is the whole
            # premise of B5-GAP-1.
            time.sleep(0.0004)
            accepted.append(body["payload"])
            return {"accepted": True}
        return {}

    monkeypatch.setattr(module, "_post", _slow_post)

    # ── phase 1 · the DURABILITY BOUNDARY ──────────────────────────
    started = time.monotonic()
    acquired = 0
    for _ in range(40):
        excl = module.nvx_excl.Journal(module.EXCLUSION_JOURNAL)
        result = module.acquire(journal, {"exclusions": []}, excl, 10.0,
                                fx.IDENTITY)
        acquired += result["records_read"]
        if result["caught_up"][SYSMON]:
            break
    acquire_seconds = time.monotonic() - started
    journaled = _all_journaled_ids(journal, SYSMON)

    assert acquired == total, "every produced record must be acquired"
    assert journaled == expected, (
        "fixture == acquired == journaled at the durability boundary")
    assert len(journaled) == len(set(journaled)), "zero duplicates"
    assert journal.gap_count() == 0, "zero unexplained gaps"
    assert journal.cursor(SYSMON) == expected[-1]
    max_depth = journal.depth()
    assert max_depth == total

    # ── phase 2 · eventual drain ───────────────────────────────────
    delivery_started = time.monotonic()
    for _ in range(200):
        out = module._drain_journal("http://api", fx.IDENTITY,
                                    {"token": "t"}, journal, 30, 1.0)
        if journal.depth() == 0:
            break
        assert out["backend_unreachable"] is False
    delivery_seconds = time.monotonic() - delivery_started

    assert journal.depth() == 0
    assert len(accepted) == total, "journaled == accepted"
    assert len(set(accepted)) == total, "zero duplicate deliveries"
    assert journal.counts_by_state()["BACKEND_ACCEPTED"] == total

    bytes_before = journal.bytes_used()
    while journal.reclaim()["reclaimed"]:
        pass
    assert journal.counts_by_state() == {}

    MEASUREMENTS["stress_10000"] = {
        "source_events": total,
        "events_acquired": acquired,
        "events_journaled": len(journaled),
        "events_backend_accepted": len(accepted),
        "unexplained_gaps": journal.gap_count(),
        "duplicates": total - len(set(journaled)),
        "acquisition_seconds": round(acquire_seconds, 3),
        "acquisition_events_per_sec": round(total / acquire_seconds, 1),
        "delivery_seconds": round(delivery_seconds, 3),
        "delivery_events_per_sec": round(total / delivery_seconds, 1),
        "max_journal_depth": max_depth,
        "ending_journal_depth": journal.depth(),
        "journal_bytes_peak": bytes_before,
        "journal_bytes_after_reclaim": journal.bytes_used(),
        "note": "SYNTHETIC harness. Not a production throughput claim.",
    }
    print("\nB5-GAP-1 STRESS MEASUREMENTS "
          + json.dumps(MEASUREMENTS["stress_10000"], indent=2))
    del calls


# ═══════════════════ §24 · FAILURE INJECTION ══════════════════════
def test_b5_gap_1_failure_class_now_yields_backlog_not_loss(env, monkeypatch):
    """Source outruns delivery across many cycles; nothing may be lost.

    Each cycle produces 1,500 records — three pages at page_size 500, i.e.
    far more than the single bounded batch the pre-fix sensor could take —
    while delivery accepts only a trickle.
    """
    module, source, journal, _calls = env
    produced: list[int] = []
    next_record = 8470086
    delivered: list[str] = []

    def _trickle(api, path, body, bearer=None):
        if path == "/api/edr/agent/telemetry":
            time.sleep(0.002)
            delivered.append(body["payload"])
            return {"accepted": True}
        return {}

    monkeypatch.setattr(module, "_post", _trickle)
    monkeypatch.setenv("NIVX_SENSOR_ACQUIRE_BUDGET_SECONDS", "5")
    monkeypatch.setenv("NIVX_SENSOR_DELIVER_BUDGET_SECONDS", "0.1")
    monkeypatch.setenv("NIVX_SENSOR_LEGACY_DRAIN_BUDGET_SECONDS", "0.1")

    depths = []
    for _ in range(8):
        produced += source.channel(SYSMON).produce(1500, start=next_record)
        next_record += 1500
        report = module._cycle("http://api", fx.IDENTITY, {"token": "t"},
                               journal, 30)
        depths.append(report["queue_depth"])
        assert report["records_journaled"] == 1500, (
            "acquisition must follow a channel producing several pages "
            "between scheduling opportunities")
        assert report["acquisition_halted"] is None
        assert report["acquisition_gaps"] == []

    journaled = _all_journaled_ids(journal, SYSMON)
    # Accepted rows are reclaimed each cycle, so ownership is proven by the
    # UNION of what was delivered and what is still held — never by the
    # journal alone.
    owned = sorted(set(journaled) | {
        json.loads(p)["winlog"]["record_id"] for p in delivered})
    assert owned == produced, "no record produced may go unowned"
    assert journal.gap_count() == 0, (
        "a growing delivery backlog must never present as a source "
        "discontinuity")
    assert depths[-1] > depths[0], "the backlog is expected to GROW"
    assert "DELIVERY_BACKLOG" in journal.health()["states"]
    assert journal.cursor(SYSMON) == produced[-1]
    MEASUREMENTS["failure_injection"] = {
        "cycles": 8, "produced_per_cycle": 1500,
        "produced_total": len(produced), "owned_total": len(owned),
        "delivered_total": len(delivered),
        "final_backlog": depths[-1], "gaps": journal.gap_count()}


def test_rotation_while_paging_is_declared_not_hidden(env):
    """If the source DOES rotate past us, the loss must be declared with a
    cause of NOT_PROVEN — never inferred, never hidden, never backfilled."""
    module, source, journal, _calls = env
    channel = source.channel(SYSMON)
    channel.produce(500, start=8470086)
    excl = module.nvx_excl.Journal(module.EXCLUSION_JOURNAL)
    module.acquire(journal, {"exclusions": []}, excl, 5.0, fx.IDENTITY)
    assert journal.cursor(SYSMON) == 8470585

    channel.roll_to(8496595)
    channel.produce(100, start=8496595)
    module.acquire(journal, {"exclusions": []}, excl, 5.0, fx.IDENTITY)

    gap = journal.last_gap()
    assert gap["missing_start_record_id"] == 8470586
    assert gap["missing_end_record_id"] == 8496594
    assert gap["cause"] == "NOT_PROVEN"
    health = journal.health(source_tails=source.tails())
    assert "ACQUISITION_GAP" in health["states"]
    assert health["acquisition_lag_records"][SYSMON] == 0
    assert len(_all_journaled_ids(journal, SYSMON)) == 600, (
        "the declared gap must not be filled with invented records")


def test_source_rollover_risk_is_measured_not_deduced(env):
    """SOURCE_ROLLOVER_RISK appears only when the oldest record the source
    still holds is newer than our cursor. A backlog alone must never
    produce it."""
    module, source, journal, _calls = env
    source.channel(SYSMON).produce(10, start=100)
    excl = module.nvx_excl.Journal(module.EXCLUSION_JOURNAL)
    module.acquire(journal, {"exclusions": []}, excl, 5.0, fx.IDENTITY)

    backlog_only = journal.health(source_tails=source.tails())
    assert "SOURCE_ROLLOVER_RISK" not in backlog_only["states"], (
        "a delivery backlog is not evidence of rollover")

    source.channel(SYSMON).roll_to(5000)
    source.channel(SYSMON).produce(5, start=5000)
    risky = journal.health(source_tails=source.tails())
    assert "SOURCE_ROLLOVER_RISK" in risky["states"]
    assert risky["source_rollover_risk"][SYSMON] == {
        "committed_record_id": 109, "source_oldest_record_id": 5000}
    assert risky["acquisition_lag_records"][SYSMON] == 5004 - 109


# ═════════════ PRE-FIX COUNTERFACTUAL · the defect itself ═════════
def test_prefix_single_bounded_page_loses_records_silently(env):
    """The regression witness.

    Re-creates the pre-fix acquisition shape — ONE bounded page per cycle,
    no pagination, cursor advanced to the last record read — against a
    channel that rotates between cycles because delivery held the thread.
    It reproduces the production signature exactly: 100 records, a large
    RecordID jump, 100 records. Then it proves the FIXED path keeps the
    same source fully.
    """
    module, source, journal, _calls = env
    channel = source.channel(SYSMON)
    channel.produce(100, start=8470086)

    # --- pre-fix behaviour, spelled out rather than imported -------
    legacy_cursor = 8470085
    collected: list[int] = []
    page, _reason, _ms = source.query(SYSMON, legacy_cursor, 100)
    ids = [e["winlog"]["record_id"] for e in page]
    collected += ids
    legacy_cursor = max(ids)
    assert len(ids) == 100 and legacy_cursor == 8470185

    # delivery occupied the only thread for ~22 minutes; the circular
    # 64 MiB EVTX rotated in the meantime.
    channel.roll_to(8496595)
    channel.produce(100, start=8496595)

    page, _reason, _ms = source.query(SYSMON, legacy_cursor, 100)
    ids = [e["winlog"]["record_id"] for e in page]
    collected += ids
    assert ids[0] == 8496595, (
        "the pre-fix sensor resumes at the oldest SURVIVING record, which "
        "is the observed production signature")
    assert ids[0] - legacy_cursor - 1 == 26409
    assert len(collected) == 200
    assert max(collected) - min(collected) + 1 == 26609, (
        "200 records collected across a 26,609-RecordID span: the loss the "
        "pre-fix sensor never reported")

    # --- the fixed path, same source, nothing rotated -------------
    fresh = fx.FakeSource(fx.FakeChannel(SYSMON))
    fresh.channel(SYSMON).produce(26609, start=8470086)
    from unittest import mock
    with mock.patch.object(module, "_query_channel", fresh.query), \
            mock.patch.object(module, "CHANNELS", (SYSMON,)):
        excl = module.nvx_excl.Journal(module.EXCLUSION_JOURNAL)
        for _ in range(5):
            # The per-channel ceiling is a PAUSE between scheduling
            # opportunities, not a skip: successive cycles resume exactly
            # where the evidence ended.
            result = module.acquire(journal, {"exclusions": []}, excl, 30.0,
                                    fx.IDENTITY)
            if result["caught_up"][SYSMON]:
                break
    assert len(_all_journaled_ids(journal, SYSMON)) == 26609
    assert journal.gap_count() == 0
