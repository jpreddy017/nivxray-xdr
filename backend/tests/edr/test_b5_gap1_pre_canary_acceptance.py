"""B5-GAP-1 GATE D · PRE-CANARY ACCEPTANCE HARNESS.

Runs the whole sensor cycle — acquisition, journal, batch delivery,
acknowledgement, reclamation, integrity reporting — against a fake backend
that implements the real batch and integrity contracts, under the nine
conditions the owner named. It runs BEFORE any endpoint is touched.

Acceptance invariants, asserted in every scenario that can express them:

    UNEXPLAINED_LOSS = 0
    DUPLICATES       = 0
    SOURCE_CURSOR   <= LAST_DURABLY_OWNED_SOURCE_RECORD
    SLOW_BACKEND    != STOP_ACQUISITION
    DELIVERY_BACKLOG != SOURCE_LOSS
    SENT            != ACCEPTED

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


class FakeBackend:
    """Implements the real contracts: per-event batch acceptance, event
    idempotency, and the acquisition-integrity route."""

    def __init__(self) -> None:
        self.accepted: dict[str, int] = {}          # payload -> times seen
        self.integrity: list[dict] = []
        self.down = False
        self.per_event_delay = 0.0
        self.batch_supported = True
        self.max_batch_bytes = 4 * 1024 * 1024
        self.refuse_payloads: set[str] = set()
        self.batch_calls = 0
        self.single_calls = 0

    def post(self, api, path, body, bearer=None):
        if self.down and path.startswith("/api/edr/agent/"):
            raise RuntimeError("503 backend unavailable")
        if path == "/api/edr/agent/telemetry/batch":
            if not self.batch_supported:
                raise RuntimeError("404 Not Found")
            self.batch_calls += 1
            events = body["events"]
            total = sum(len(e["payload"].encode()) for e in events)
            if total > self.max_batch_bytes:
                raise RuntimeError("413 BATCH_TOO_LARGE")
            results = []
            for index, event in enumerate(events):
                time.sleep(self.per_event_delay)
                if event["payload"] in self.refuse_payloads:
                    results.append({"index": index, "accepted": False,
                                    "error": "RuntimeError",
                                    "detail": "refused by test"})
                    continue
                self.accepted[event["payload"]] = self.accepted.get(
                    event["payload"], 0) + 1
                results.append({"index": index, "accepted": True,
                                "stored": self.accepted[
                                    event["payload"]] == 1,
                                "duplicate": self.accepted[
                                    event["payload"]] > 1})
            return {"batch_id": body.get("batch_id"), "count": len(events),
                    "accepted": sum(1 for r in results if r["accepted"]),
                    "results": results}
        if path == "/api/edr/agent/telemetry":
            self.single_calls += 1
            time.sleep(self.per_event_delay)
            if body["payload"] in self.refuse_payloads:
                raise RuntimeError("500 refused by test")
            self.accepted[body["payload"]] = self.accepted.get(
                body["payload"], 0) + 1
            return {"stored": self.accepted[body["payload"]] == 1}
        if path == "/api/edr/agent/acquisition-integrity":
            self.integrity.append(body)
            return {"gaps_newly_recorded": len(
                body.get("acquisition_gaps") or [])}
        return {}

    def record_ids(self, channel: str | None = None) -> list[int]:
        out = []
        for raw in self.accepted:
            winlog = json.loads(raw)["winlog"]
            if channel is None or winlog["channel"] == channel:
                out.append(winlog["record_id"])
        return sorted(out)

    def duplicates(self) -> int:
        return sum(v - 1 for v in self.accepted.values())


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NIVXFORGE_SENSOR_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("NIVX_SENSOR_ACQUIRE_PAGE_SIZE", "500")
    monkeypatch.setenv("NIVX_SENSOR_ACQUIRE_BUDGET_SECONDS", "10")
    monkeypatch.setenv("NIVX_SENSOR_DELIVER_BUDGET_SECONDS", "10")
    monkeypatch.delenv("NIVX_SENSOR_FILE_HASHING", raising=False)
    module = fx.load_sensor(tmp_path / "state")
    source = fx.FakeSource(fx.FakeChannel(SYSMON), fx.FakeChannel(SECURITY),
                           fx.FakeChannel(SYSTEM))
    backend = FakeBackend()
    monkeypatch.setattr(module, "_query_channel", source.query)
    monkeypatch.setattr(module, "_post", backend.post)
    monkeypatch.setattr(module, "_get", lambda *a, **k: {})
    monkeypatch.setattr(module, "_open_session", lambda api, i: "tok")
    monkeypatch.setattr(module, "_sync_policy",
                        lambda api, i, s: {"exclusions": [], "stale": False})
    monkeypatch.setattr(module, "_report_enforcement",
                        lambda *a, **k: "NOTHING_TO_REPORT")
    monkeypatch.setattr(module, "_probe_source_tail",
                        lambda channel: source.tails().get(channel, {}))
    monkeypatch.setattr(module, "CHANNELS", tuple(source.channels))
    module.BATCH_SUPPORT.update(available=True, reason=None)
    fx.write_identity(module)
    journal = module.nvx_journal.open_journal(module.STATE_DIR)
    yield module, source, backend, journal
    journal.close()


def _cycle(module, journal):
    return module._cycle("http://api", fx.IDENTITY, {"token": "t"},
                         journal, 30)


def _owned(journal, backend, channel):
    """Everything NivXForge owns: still journaled plus already accepted.
    Accepted rows are reclaimed, so neither store alone is the answer."""
    held = {int(r["source_record_id"]) for r in journal._db.execute(
        "SELECT source_record_id FROM evidence WHERE channel=?", (channel,))}
    return sorted(held | set(backend.record_ids(channel)))


def _assert_core_invariants(journal, backend, produced, channel=SYSMON):
    assert _owned(journal, backend, channel) == produced, \
        "UNEXPLAINED_LOSS must be 0"
    assert backend.duplicates() == 0, "DUPLICATES must be 0"
    owned_max = max(_owned(journal, backend, channel) or [0])
    assert journal.cursor(channel) <= owned_max, \
        "SOURCE_CURSOR must never exceed the last durably owned record"


# ═══════════════════════ NORMAL ═══════════════════════════════════
def test_pre_canary_normal(env):
    module, source, backend, journal = env
    produced = source.channel(SYSMON).produce(400, start=8470086)
    report = _cycle(module, journal)

    assert report["records_journaled"] == 400
    assert report["sent"] == 400
    assert report["queue_depth"] == 0
    assert backend.batch_calls > 0 and backend.single_calls == 0, \
        "delivery must use the batch contract by default"
    assert report["delivery_batch_size"] == 50
    assert report["integrity_report"].startswith("SENT")
    _assert_core_invariants(journal, backend, produced)


# ═══════════════════════ BURST ════════════════════════════════════
def test_pre_canary_burst(env):
    """>100 events between acquisition opportunities — the exact condition
    the pre-fix sensor abandoned."""
    module, source, backend, journal = env
    produced = source.channel(SYSMON).produce(3000, start=8470086)
    report = _cycle(module, journal)
    assert report["records_journaled"] == 3000
    assert report["pages"] >= 7, "a burst must be PAGED, not truncated"
    assert report["acquisition_gaps"] == []
    _assert_core_invariants(journal, backend, produced)


# ═══════════════════════ BACKEND SLOW ════════════════════════════
def test_pre_canary_backend_slow(env, monkeypatch):
    module, source, backend, journal = env
    backend.per_event_delay = 0.004
    monkeypatch.setenv("NIVX_SENSOR_DELIVER_BUDGET_SECONDS", "0.4")
    produced = source.channel(SYSMON).produce(1000, start=8470086)

    first = _cycle(module, journal)
    assert first["records_journaled"] == 1000
    assert first["queue_depth"] > 0, "a slow backend must produce a BACKLOG"
    assert "DELIVERY_BACKLOG" in first["health"]

    produced += source.channel(SYSMON).produce(1000, start=8471086)
    second = _cycle(module, journal)
    assert second["records_journaled"] == 1000, \
        "SLOW_BACKEND != STOP_ACQUISITION"
    assert journal.gap_count() == 0, "DELIVERY_BACKLOG != SOURCE_LOSS"
    _assert_core_invariants(journal, backend, produced)


# ═══════════════════════ BACKEND DOWN ════════════════════════════
def test_pre_canary_backend_down(env):
    module, source, backend, journal = env
    backend.down = True
    produced = source.channel(SYSMON).produce(500, start=8470086)

    first = _cycle(module, journal)
    assert first["records_journaled"] == 500
    assert first["sent"] == 0
    assert "BACKEND_UNREACHABLE" in first["health"]
    assert journal.depth() == 500, "SENT != ACCEPTED — nothing was released"

    produced += source.channel(SYSMON).produce(500, start=8470586)
    second = _cycle(module, journal)
    assert second["records_journaled"] == 500, \
        "acquisition continues while the backend is down"
    assert journal.depth() == 1000
    assert journal.gap_count() == 0
    assert backend.accepted == {}
    _assert_core_invariants(journal, backend, produced)


# ═══════════════════════ RECOVERY ════════════════════════════════
def test_pre_canary_recovery(env):
    module, source, backend, journal = env
    backend.down = True
    produced = source.channel(SYSMON).produce(600, start=8470086)
    _cycle(module, journal)
    assert journal.depth() == 600

    backend.down = False
    for _ in range(10):
        _cycle(module, journal)
        if journal.depth() == 0:
            break
    assert journal.depth() == 0, "the journal must drain on recovery"
    assert len(backend.accepted) == 600
    _assert_core_invariants(journal, backend, produced)


def test_pre_canary_partial_refusal_keeps_only_the_refused_event(env):
    """Per-event acceptance, proven through the whole cycle."""
    module, source, backend, journal = env
    source.channel(SYSMON).produce(60, start=1)
    excl = module.nvx_excl.Journal(module.EXCLUSION_JOURNAL)
    module.acquire(journal, {"exclusions": []}, excl, 10.0, fx.IDENTITY)
    stubborn = journal.next_undelivered(limit=60)[7]["payload"]
    backend.refuse_payloads.add(stubborn)

    for _ in range(4):
        module._drain_journal("http://api", fx.IDENTITY, {"token": "t"},
                              journal, 30, 5.0)
    assert len(backend.accepted) == 59
    assert journal.depth() == 1, (
        "exactly the refused event stays owned by the endpoint")
    assert journal.next_undelivered()[0]["payload"] == stubborn
    assert backend.duplicates() == 0


# ═══════════════════════ RESTART ═════════════════════════════════
def test_pre_canary_restart(env):
    module, source, backend, journal = env
    backend.down = True
    produced = source.channel(SYSMON).produce(300, start=8470086)
    _cycle(module, journal)
    cursor = journal.cursor(SYSMON)
    journal.close()

    reopened = module.nvx_journal.open_journal(module.STATE_DIR,
                                               module.BOOKMARK_FILE)
    try:
        assert reopened.cursor(SYSMON) == cursor, "cursors survive a restart"
        assert reopened.depth() == 300, "evidence survives a restart"
        backend.down = False
        for _ in range(8):
            _cycle(module, reopened)
            if reopened.depth() == 0:
                break
        assert reopened.depth() == 0
        _assert_core_invariants(reopened, backend, produced)
    finally:
        reopened.close()


# ═══════════════════════ GAP ═════════════════════════════════════
def test_pre_canary_gap(env):
    module, source, backend, journal = env
    source.channel(SYSMON).produce(100, start=8470086)
    _cycle(module, journal)

    source.channel(SYSMON).roll_to(8496595)
    source.channel(SYSMON).produce(100, start=8496595)
    report = _cycle(module, journal)

    assert len(report["acquisition_gaps"]) == 1
    gap = report["acquisition_gaps"][0]
    assert gap["missing_record_id_count"] == 26409
    assert gap["cause"] == "NOT_PROVEN"
    assert "ACQUISITION_GAP" in report["health"]
    assert report["integrity_report"] == "SENT:1", (
        "the declaration must reach the platform, not stay on the host")
    delivered = backend.integrity[-1]["acquisition_gaps"]
    assert delivered[0]["expected_next_record_id"] == 8470186
    assert journal.unreported_gaps() == [], "reported once, not forever"
    # nothing invented to fill the hole
    assert len(backend.accepted) == 200


def test_pre_canary_gap_declaration_survives_a_failed_report(env):
    module, source, backend, journal = env
    source.channel(SYSMON).produce(10, start=100)
    _cycle(module, journal)
    source.channel(SYSMON).produce(10, start=200)
    backend.down = True
    report = _cycle(module, journal)
    assert journal.gap_count() == 1
    assert report["integrity_report"].startswith("FAILED")
    assert len(journal.unreported_gaps()) == 1, (
        "a gap is only marked reported once the platform has it")


# ═══════════════════════ MULTI-CHANNEL ═══════════════════════════
def test_pre_canary_multi_channel(env):
    module, source, backend, journal = env
    sysmon = source.channel(SYSMON).produce(5000, start=1)
    security = source.channel(SECURITY).produce(40, start=284760)
    system = source.channel(SYSTEM).produce(25, start=22702)

    report = _cycle(module, journal)
    assert report["caught_up"][SECURITY] is True
    assert report["caught_up"][SYSTEM] is True
    assert report["per_channel_read"][SYSMON] == len(sysmon)
    _assert_core_invariants(journal, backend, security, SECURITY)
    _assert_core_invariants(journal, backend, system, SYSTEM)
    for channel in (SYSMON, SECURITY, SYSTEM):
        assert journal.cursor(channel) > 0
    assert journal.gap_count() == 0


# ═══════════════════════ PRESSURE ════════════════════════════════
def test_pre_canary_pressure(env, monkeypatch):
    module, source, backend, journal = env
    backend.down = True
    source.channel(SYSMON).produce(500, start=1)
    _cycle(module, journal)
    held = journal.depth()
    monkeypatch.setenv("NIVX_SENSOR_JOURNAL_MAX_BYTES",
                       str(journal.live_bytes()))

    source.channel(SYSMON).produce(500, start=501)
    report = _cycle(module, journal)
    assert report["acquisition_halted"], "capacity must halt, not overwrite"
    assert "ACQUISITION_HALTED_JOURNAL_FULL" in report["health"]
    assert "HEALTHY" not in report["health"]
    assert journal.depth() == held, "no unacknowledged evidence was dropped"

    # And it must RECOVER once the backend drains it.
    monkeypatch.delenv("NIVX_SENSOR_JOURNAL_MAX_BYTES")
    backend.down = False
    for _ in range(8):
        recovered = _cycle(module, journal)
        if journal.depth() == 0:
            break
    assert journal.depth() == 0
    assert recovered["acquisition_halted"] is None
    assert backend.duplicates() == 0


# ═══════════════════ TRANSPORT / COMPATIBILITY ═══════════════════
def test_batch_route_absent_falls_back_to_single_event_delivery(env):
    module, source, backend, journal = env
    backend.batch_supported = False
    produced = source.channel(SYSMON).produce(120, start=1)
    for _ in range(4):
        _cycle(module, journal)
        if journal.depth() == 0:
            break
    assert module.BATCH_SUPPORT["available"] is False
    assert backend.single_calls == 120
    assert journal.depth() == 0
    _assert_core_invariants(journal, backend, produced)


def test_oversized_batch_is_halved_until_it_fits(env):
    module, source, backend, journal = env
    backend.max_batch_bytes = 6000        # forces several reductions
    produced = source.channel(SYSMON).produce(60, start=1)
    for _ in range(6):
        _cycle(module, journal)
        if journal.depth() == 0:
            break
    assert journal.depth() == 0
    _assert_core_invariants(journal, backend, produced)


def test_transport_reuses_one_connection_and_reconnects_once(monkeypatch):
    """The pre-fix sensor paid DNS+TCP+TLS per event — measured at 44% of
    every request. Proven here without a network."""
    import importlib.util
    import sys
    sys.path.insert(0, str(fx.AGENT_DIR))
    spec = importlib.util.spec_from_file_location("nvx_tx_probe", fx.SENSOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    made = {"connections": 0, "requests": 0}

    class _Resp:
        status = 200

        def read(self):
            return b"{}"

    class _Conn:
        def __init__(self, netloc, timeout=None):
            made["connections"] += 1
            self.fail_next = False

        def request(self, *a, **k):
            made["requests"] += 1
            if self.fail_next:
                raise OSError("peer closed the reused connection")

        def getresponse(self):
            return _Resp()

        def close(self):
            pass

    monkeypatch.setattr(module.http.client, "HTTPSConnection", _Conn)
    transport = module._Transport()
    for _ in range(5):
        transport.request("https://api.example", "/x", "POST", b"{}", {})
    assert made["connections"] == 1, "one connection for five requests"

    transport._conn.fail_next = True
    transport.request("https://api.example", "/x", "POST", b"{}", {})
    assert made["connections"] == 2, (
        "a stale reused connection must reconnect once, not look like an "
        "outage")
    transport.close()


# ═══════════ GATE A · FROZEN-ARTIFACT SELFTEST WIRING ════════════
def test_setup_exposes_the_journal_selftest(tmp_path, monkeypatch):
    """The frozen artifact must be able to prove the journal about ITSELF.

    A Linux unit test cannot know whether PyInstaller packed `sqlite3` and
    its native extension, so the binary answers that question and the
    Windows build gates on the answer.
    """
    import importlib.util
    import sys
    monkeypatch.setenv("NIVXFORGE_SENSOR_STATE", str(tmp_path / "state"))
    sys.path.insert(0, str(fx.AGENT_DIR))
    for name in ("nivxforge_setup", "nivxforge_sensor", "nivxforge_journal"):
        sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(
        "nivxforge_setup", fx.AGENT_DIR / "nivxforge_setup.py")
    setup = importlib.util.module_from_spec(spec)
    sys.modules["nivxforge_setup"] = setup
    spec.loader.exec_module(setup)

    assert "journal-selftest" in setup.build_parser().format_help()
    out = setup.journal_selftest(str(tmp_path / "scratch"))
    assert out["result"] == "PASS", out["failed"]
    for check in ("sqlite3_importable", "wal_mode", "synchronous_full",
                  "auto_vacuum_incremental", "schema_initialized",
                  "durable_commit", "cursor_committed",
                  "replay_is_idempotent", "gap_contract"):
        assert out["checks"][check] is True, check


def test_windows_build_gates_on_the_frozen_journal_selftest():
    workflow = (fx.AGENT_DIR.parents[1]
                / ".github/workflows/windows-sensor-installer.yml").read_text()
    assert "journal-selftest" in workflow
    assert '"frozen": true' in workflow, (
        "the gate must require the FROZEN binary, not a system Python")
    assert '"wal_mode": true' in workflow
    assert '"synchronous_full": true' in workflow
    build = (fx.AGENT_DIR / "build/build_windows_installer.ps1").read_text()
    assert "'nivxforge_journal'" in build
    assert "'sqlite3'" in build
