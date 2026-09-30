"""B5-GAP-1 · DISPOSABLE-CANARY HARNESS CONTRACT.

The canary has not run and must not run until the owner authorises it.
These tests prove the HARNESS is trustworthy before it is ever pointed at
an endpoint:

  * it measures every stage of the evidence chain and writes a stable
    machine-readable schema;
  * it is READ-ONLY with respect to the sensor's journal — including while
    a writer holds the database open;
  * its acceptance invariants actually FAIL on loss, duplicates, cursor
    regression, unacknowledged deletion, an absorbed discontinuity and an
    undrained backlog;
  * it reports NOT_PROVABLE instead of inventing a number it cannot read.

EVIDENCE LABELLING — TEST/SYNTHETIC. No endpoint contact, no production
query, `DESKTOP-A9HGFJJ` untouched.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from tests.edr import fixtures_b5_gap1_source as fx

REPO = fx.AGENT_DIR.parents[1]
CANARY_DIR = REPO / "scripts/canary"
PLAN = REPO / "docs/B5_GAP_1_CANARY_PLAN.md"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
CHANNELS = ("Security", SYSMON)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def collector_module():
    return _load("b5gap1_canary_collector",
                 CANARY_DIR / "b5gap1_canary_collector.py")


@pytest.fixture()
def journal_module():
    sys.path.insert(0, str(fx.AGENT_DIR))
    return _load("nivxforge_journal", fx.AGENT_DIR / "nivxforge_journal.py")


def _event(channel: str, record_id: int) -> dict:
    return {"observed_at": "2026-06-01T00:00:00+00:00",
            "kind": "WINDOWS_EVENT_LOG",
            "winlog": {"channel": channel, "record_id": record_id,
                       "event_id": "1", "provider": "canary",
                       "time_created": "2026-06-01T00:00:00Z",
                       "xml": f"<Event>{record_id}</Event>"}}


def _seed_journal(journal_module, state_dir: Path, *, per_channel=5,
                  accept=0, gap=False):
    journal = journal_module.open_journal(str(state_dir))
    for channel in CHANNELS:
        events = [_event(channel, i) for i in range(1, per_channel + 1)]
        gaps = []
        if gap and channel == SYSMON:
            gaps = [journal_module.build_gap(channel, 100, 140, "INTERIOR")]
        journal.commit_page(channel, events, per_channel, gaps)
        journal.bump("records_read", per_channel)
        journal.bump("records_journaled", per_channel)
        journal.set_gauge(f"last_record_id_journaled:{channel}", per_channel)
    if accept:
        sequences = [row["journal_sequence"]
                     for row in journal.next_undelivered(limit=accept)]
        journal.mark_accepted(sequences)
        journal.bump("backend_accepted", len(sequences))
    journal.write_integrity_snapshot(journal.health())
    journal.close()


class FakeBackend:
    def __init__(self, **counters):
        self.counters = {"received": 0, "parsed": 0, "accepted": 0,
                         "canonicalized": 0, "deduplicated": 0,
                         "refused": 0, **counters}
        self.gap_rows: list[dict] = []
        self.tenants = ["ten_canary"]

    def read(self) -> dict:
        return {"http_status": 200, "rtt_ms": 12.0,
                "integrity_http_status": 200, **self.counters,
                "gap_count": len(self.gap_rows), "gap_rows": self.gap_rows,
                "channel_rows": [], "tenants_observed": list(self.tenants)}


def _collector(collector_module, state_dir, tmp_path, scenario="NORMAL",
               backend=None, tails=None):
    def source(channel):
        return (tails or {}).get(
            channel, {"oldest": None, "newest": None,
                      "unknown_reason": "SOURCE_TAIL_UNAVAILABLE_OFF_WINDOWS"})

    return collector_module.CanaryCollector(
        state_dir=state_dir, scenario=scenario,
        out_dir=tmp_path / "out", channels=CHANNELS,
        backend_reader=backend, source_reader=source,
        tenant="ten_canary", endpoint="ep_canary",
        artifact_sha256="deadbeef")


# ═══════════ SCHEMA + STAGE COVERAGE ═════════════════════════════
def test_sample_covers_every_pipeline_stage(collector_module, journal_module,
                                            tmp_path):
    state = tmp_path / "state"
    _seed_journal(journal_module, state, per_channel=5, accept=3)
    collector = _collector(collector_module, state, tmp_path,
                           backend=FakeBackend(accepted=3, canonicalized=3))
    rows = collector.sample()
    assert len(rows) == len(CHANNELS)
    for row in rows:
        assert set(row) == set(collector_module.COLUMNS)
    row = next(r for r in rows if r["channel"] == SYSMON)
    assert row["cursor_committed"] == 5              # ACQUISITION
    assert row["journal_rows"] == 5                  # JOURNAL
    assert sum(r["journal_rows_backend_accepted"] for r in rows) == 3
    assert row["backend_canonicalized"] == 3         # CANONICAL EVIDENCE
    assert row["delivery_backlog"] == row["journal_depth"]
    assert row["health_states"]


def test_csv_and_verdict_are_machine_readable(collector_module,
                                              journal_module, tmp_path):
    state = tmp_path / "state"
    _seed_journal(journal_module, state, accept=10)
    collector = _collector(collector_module, state, tmp_path,
                           backend=FakeBackend(accepted=10))
    collector.sample()
    collector.sample()
    csv_path = collector.write_csv()
    header = csv_path.read_text().splitlines()[0].split(",")
    assert header == collector_module.COLUMNS
    assert len(csv_path.read_text().strip().splitlines()) == 1 + 4

    verdict_path = collector.write_verdict()
    verdict = json.loads(verdict_path.read_text())
    assert verdict["contract"] == "nivxforge.b5gap1.canary_measurement"
    assert verdict["verdict"] in ("PASS", "FAIL", "NOT_PROVABLE")
    assert verdict["boundary"]["DESKTOP_A9HGFJJ_TOUCHED"] == "NO"
    assert verdict["boundary"][
        "PRODUCT_CODE_MODIFIED_FOR_MEASUREMENT"] == "NO"
    assert "delivery_headroom" in verdict["throughput"]
    assert "owner decision" in verdict["throughput"]["note"]


def test_collector_never_writes_to_the_journal(collector_module,
                                               journal_module, tmp_path):
    state = tmp_path / "state"
    _seed_journal(journal_module, state, accept=2)
    path = state / journal_module.JOURNAL_FILENAME

    # a live writer holds the WAL open, exactly as the service would. The
    # baseline is taken AFTER it attaches, so the only thing the comparison
    # can attribute a change to is the collector.
    live = journal_module.open_journal(str(state))
    try:
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        collector = _collector(collector_module, state, tmp_path,
                               backend=FakeBackend())
        rows = collector.sample()
        assert rows[0]["journal_read_mode"] in (
            "LIVE_READONLY", "SNAPSHOT_COPY_READONLY")
        after = hashlib.sha256(path.read_bytes()).hexdigest()
    finally:
        live.close()
    assert before == after, "the journal bytes must be untouched"


# ═══════════ INVARIANTS MUST ACTUALLY FAIL ═══════════════════════
def _rows(collector, **overrides):
    """Two hand-built samples so an invariant can be driven directly."""
    template = {name: None for name in
                sys.modules["b5gap1_canary_collector"].COLUMNS}
    first = {**template, "channel": SYSMON, "scenario": collector.scenario,
             "elapsed_seconds": 0, "cursor_committed": 10,
             "last_record_id_journaled": 10, "journal_rows": 10,
             "journal_rows_deliverable": 0, "journal_rows_backend_accepted":
             10, "delivery_backlog": 0, "acquisition_gap_count": 0,
             "backend_deduplicated": 0, "backend_tenants_observed":
             "ten_canary", "journaled_records_per_sec": 1.0}
    second = {**first, "elapsed_seconds": 30}
    second.update(overrides)
    return [first, second]


def test_cursor_regression_fails(collector_module, journal_module, tmp_path):
    collector = _collector(collector_module, tmp_path / "state", tmp_path)
    collector.rows = _rows(collector, cursor_committed=4)
    verdict = collector.verdict()
    assert verdict["invariants"]["CURSOR_MONOTONIC"]["result"] == "FAIL"
    assert verdict["verdict"] == "FAIL"


def test_cursor_beyond_durable_ownership_fails(collector_module, tmp_path):
    collector = _collector(collector_module, tmp_path / "state", tmp_path)
    collector.rows = _rows(collector, cursor_committed=99,
                           last_record_id_journaled=10)
    verdict = collector.verdict()
    assert verdict["invariants"][
        "SOURCE_CURSOR_LE_DURABLY_OWNED"]["result"] == "FAIL"


def test_unacknowledged_deletion_fails(collector_module, tmp_path):
    collector = _collector(collector_module, tmp_path / "state", tmp_path)
    rows = _rows(collector)
    rows[0].update({"journal_rows": 10, "journal_rows_deliverable": 10,
                    "journal_rows_backend_accepted": 0})
    rows[1].update({"journal_rows": 10, "journal_rows_deliverable": 4,
                    "journal_rows_backend_accepted": 0})
    collector.rows = rows
    verdict = collector.verdict()
    assert verdict["invariants"][
        "UNACKNOWLEDGED_DELETION"]["result"] == "FAIL"


def test_duplicates_fail_in_normal_but_are_allowed_after_an_outage(
        collector_module, tmp_path):
    normal = _collector(collector_module, tmp_path / "s", tmp_path,
                        scenario="NORMAL")
    normal.rows = _rows(normal, backend_deduplicated=7)
    assert normal.verdict()["invariants"]["DUPLICATES"]["result"] == "FAIL"

    recovery = _collector(collector_module, tmp_path / "s", tmp_path,
                          scenario="RECOVERY")
    rows = _rows(recovery, backend_deduplicated=7, delivery_backlog=0)
    rows[0]["delivery_backlog"] = 500
    recovery.rows = rows
    invariants = recovery.verdict()["invariants"]
    assert invariants["DUPLICATES"]["result"] == "PASS"
    assert invariants["BACKLOG_DRAINED_TO_ZERO"]["result"] == "PASS"


def test_recovery_fails_if_the_backlog_never_drains(collector_module,
                                                    tmp_path):
    collector = _collector(collector_module, tmp_path / "s", tmp_path,
                           scenario="RECOVERY")
    rows = _rows(collector, delivery_backlog=1200)
    rows[0]["delivery_backlog"] = 900
    collector.rows = rows
    assert collector.verdict()["invariants"][
        "BACKLOG_DRAINED_TO_ZERO"]["result"] == "FAIL"


def test_absorbed_source_discontinuity_fails(collector_module, tmp_path):
    collector = _collector(collector_module, tmp_path / "s", tmp_path,
                           scenario="SOURCE_DISCONTINUITY")
    collector.rows = _rows(collector, acquisition_gap_count=0)
    assert collector.verdict()["invariants"][
        "DECLARED_GAP_FOR_INJECTED_DISCONTINUITY"]["result"] == "FAIL"

    collector.rows = _rows(collector, acquisition_gap_count=1)
    assert collector.verdict()["invariants"][
        "DECLARED_GAP_FOR_INJECTED_DISCONTINUITY"]["result"] == "PASS"


def test_unexplained_gap_in_normal_operation_fails(collector_module,
                                                   tmp_path):
    collector = _collector(collector_module, tmp_path / "s", tmp_path)
    collector.rows = _rows(collector, acquisition_gap_count=1)
    assert collector.verdict()["invariants"][
        "UNEXPLAINED_ACQUISITION_GAPS"]["result"] == "FAIL"


def test_foreign_tenant_evidence_fails(collector_module, tmp_path):
    collector = _collector(collector_module, tmp_path / "s", tmp_path)
    collector.rows = _rows(collector,
                           backend_tenants_observed="ten_canary,ten_other")
    assert collector.verdict()["invariants"][
        "WRONG_TENANT_EVIDENCE"]["result"] == "FAIL"


def test_stalled_acquisition_during_impairment_fails(collector_module,
                                                     tmp_path):
    collector = _collector(collector_module, tmp_path / "s", tmp_path,
                           scenario="BACKEND_DOWN")
    rows = _rows(collector, journaled_records_per_sec=0.0,
                 delivery_backlog=500)
    rows[0]["journaled_records_per_sec"] = 0.0
    rows[0]["delivery_backlog"] = 100
    collector.rows = rows
    assert collector.verdict()["invariants"][
        "ACQUISITION_CONTINUES_WHILE_DELIVERY_IMPAIRED"]["result"] == "FAIL"


# ═══════════ HONESTY ABOUT WHAT IT CANNOT PROVE ══════════════════
def test_silent_loss_is_not_provable_without_the_source_tail(
        collector_module, journal_module, tmp_path):
    state = tmp_path / "state"
    _seed_journal(journal_module, state, accept=10)
    collector = _collector(collector_module, state, tmp_path,
                           backend=FakeBackend(accepted=10))
    collector.sample()
    collector.sample()
    verdict = collector.verdict()
    assert verdict["invariants"]["SILENT_LOSS"]["result"] == "NOT_PROVABLE"
    assert verdict["verdict"] == "NOT_PROVABLE", (
        "an unprovable invariant must never be reported as a pass")
    assert any("source channel tail" in note
               for note in verdict["limitations"])


def test_silent_loss_reconciles_when_the_source_tail_is_known(
        collector_module, journal_module, tmp_path):
    state = tmp_path / "state"
    _seed_journal(journal_module, state, per_channel=5, accept=10)
    tails = {channel: {"oldest": 1, "newest": 5, "unknown_reason": None}
             for channel in CHANNELS}
    collector = _collector(collector_module, state, tmp_path,
                           backend=FakeBackend(accepted=10), tails=tails)
    collector.sample()
    collector.sample()
    verdict = collector.verdict()
    loss = verdict["invariants"]["SILENT_LOSS"]
    assert loss["result"] == "PASS", loss
    assert verdict["verdict"] == "PASS", verdict["invariants"]


def test_journal_corruption_is_a_failure(collector_module, journal_module,
                                         tmp_path):
    state = tmp_path / "state"
    _seed_journal(journal_module, state, accept=2)
    (state / journal_module.FAULT_FILENAME).write_text(
        json.dumps({"state": "JOURNAL_CORRUPT"}))
    collector = _collector(collector_module, state, tmp_path,
                           backend=FakeBackend())
    collector.sample()
    collector.sample()
    assert collector.verdict()["invariants"][
        "JOURNAL_NOT_CORRUPT"]["result"] == "FAIL"


# ═══════════ PACKAGE COMPLETENESS + SAFETY ═══════════════════════
def test_all_ten_scenarios_are_defined_and_documented(collector_module):
    expected = {"NORMAL", "BURST", "BACKEND_SLOW", "BACKEND_DOWN",
                "RECOVERY", "SENSOR_RESTART", "NETWORK_INTERRUPTION",
                "MULTI_CHANNEL", "JOURNAL_PRESSURE",
                "SOURCE_DISCONTINUITY"}
    assert set(collector_module.SCENARIOS) == expected
    plan = PLAN.read_text()
    for scenario in expected:
        assert scenario in plan, f"{scenario} absent from the canary plan"
    assert "CANARY_STARTED = NO" in plan or "NOT RUN" in plan


def test_load_generator_refuses_the_production_validation_host():
    script = (CANARY_DIR / "b5gap1_canary_load.ps1").read_text()
    assert "DESKTOP-A9HGFJJ" in script
    assert "REFUSED" in script
    assert "NVX-CANARY" in script
    # the guard must not be bypassable with a switch
    assert "[switch]$Confirm" not in script
    assert "CANARY_DESIGNATION.json" in script, (
        "an owner-written designation file must be required")
    assert "$authorized = @('KUSHU')" in script, (
        "authorised hosts must be named explicitly, never waved through")


def test_impairment_relay_keeps_tls_end_to_end_and_holds_no_credential():
    script = (CANARY_DIR / "b5gap1_canary_impair.py").read_text()
    assert "TLS stays end-to-end" in script
    assert "cannot read or alter any payload" in script
    assert "credential" in script
    for mode in ("slow", "down", "cut", "normal"):
        assert f'"{mode}"' in script


def test_backend_profiling_is_reused_not_reinvented():
    plan = PLAN.read_text()
    assert "scripts/b5gap1_ingest_cost_profile.py" in plan
    assert "middleware" in plan.lower(), (
        "the plan must state that no ingest middleware is added")
    assert (REPO / "scripts/b5gap1_ingest_cost_profile.py").exists()


def test_read_token_is_never_written_to_evidence(collector_module):
    source = (CANARY_DIR / "b5gap1_canary_collector.py").read_text()
    assert "NIVX_CANARY_READ_TOKEN" in source
    assert "token" not in collector_module.COLUMNS
    assert "never printed" in source


# ═══════════ AUTHORITATIVE CANARY SYSMON CONFIGURATION ═══════════
SYSMON_CFG = REPO / "agents/nivxforge-windows/sysmon/nivx-b5gap1-canary-sysmon.xml"
SYSMON_CFG_SHA256_LF = (
    "60F585860CFBEA3D62888B6CCB90C15F28A49D91832D4FC4526EBEEAA316C67C")
SYSMON_CFG_SHA256_CRLF = (
    "452E331298DF9A3DF3314E2CF707F153891DCE0BCE625B4EE99548D8D5E479AB")


def test_canary_sysmon_config_is_pinned_and_unchanged():
    """The canary must be provably loaded with THIS configuration. A drift
    here would silently change what the canary proves."""
    raw = SYSMON_CFG.read_bytes()
    assert b"\r\n" not in raw, "the repository form is LF"
    assert hashlib.sha256(raw).hexdigest().upper() == SYSMON_CFG_SHA256_LF
    assert hashlib.sha256(raw.replace(b"\n", b"\r\n")).hexdigest().upper() \
        == SYSMON_CFG_SHA256_CRLF, "the Windows-written form must be pinned"
    plan = PLAN.read_text()
    assert SYSMON_CFG_SHA256_CRLF in plan
    assert SYSMON_CFG_SHA256_LF in plan


def test_canary_sysmon_config_enables_eid1_and_eid5_only_as_validated():
    import xml.etree.ElementTree as ET                    # noqa: PLC0415

    root = ET.fromstring(SYSMON_CFG.read_text())
    assert root.get("schemaversion") == "4.90"
    rules = {node.tag: node.get("onmatch")
             for node in root.find("EventFiltering")}
    # exclude with no children == log everything for that event id
    assert rules["ProcessCreate"] == "exclude", "EID 1 must be ON"
    assert rules["ProcessTerminate"] == "exclude", (
        "EID 5 must be ON — the B5-validated change")
    for supported in ("NetworkConnect", "FileCreate", "RegistryEvent",
                      "DnsQuery"):
        assert rules[supported] == "exclude", supported
    # every event id the DSM does not accept stays OFF
    for unsupported in ("DriverLoad", "ImageLoad", "CreateRemoteThread",
                        "RawAccessRead", "ProcessAccess", "FileCreateTime",
                        "FileCreateStreamHash", "PipeEvent", "WmiEvent",
                        "FileDelete", "ClipboardChange", "ProcessTampering",
                        "FileDeleteDetected"):
        assert rules[unsupported] == "include", unsupported
    assert all(len(list(node)) == 0
               for node in root.find("EventFiltering")), (
        "no rule may carry children: that would filter evidence")


def test_canary_config_differs_from_w1_baseline_by_exactly_one_token():
    w1 = (REPO / "memory/W1_PHASE1_WINDOWS_LAPTOP_PREP.md").read_text()
    assert '<ProcessTerminate onmatch="include"/>' in w1, (
        "the W1 baseline is the source this config derives from")
    text = SYSMON_CFG.read_text()
    assert '<ProcessTerminate onmatch="exclude"/>' in text
    assert '<ProcessTerminate onmatch="include"/>' not in text
    # the stale 'LOG NOTHING' comment is preserved deliberately: the B5
    # change swapped only the onmatch token, and rule equivalence with
    # production matters more than tidying a comment
    assert "LOG NOTHING for every unsupported event id" in text
