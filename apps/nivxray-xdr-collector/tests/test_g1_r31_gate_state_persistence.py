"""G1-R3.1 · Durable delivery health gate.

R3 stops a dead destination from consuming every event's retry budget — for
as long as the process lives. A collector service restarts, and a crash-loop
restarts it repeatedly; an in-memory gate then rediscovers the same dead
destination from CLOSED every time and spends another full threshold of REAL
event attempts proving what it already knew. That is the exact retry-budget
burn R3 exists to prevent, re-entering through the process lifecycle.

These tests prove the gate remembers, that remembering is bounded, and that
an unreadable memory fails safe rather than silently turning into traffic:

  * OPEN survives restart, with its REMAINING cooldown, and generates no
    delivery traffic;
  * the consecutive-failure run survives, so a crash-loop cannot reset it;
  * a restart while HALF_OPEN permits exactly ONE bounded probe, not a burst;
  * after cooldown a restored gate probes once, and a successful probe closes;
  * a failed probe re-opens with a longer, bounded cooldown that also persists;
  * corrupt / unreadable / future-version state pauses delivery VISIBLY;
  * a restart consumes no row retry budget and strands no DELIVERING row;
  * nothing secret is written to the persisted row.
"""
from __future__ import annotations

import sqlite3

import httpx
import pytest

from framework.base            import Envelope
from framework.delivery        import APP_ATTRIBUTION_HEADER, IngestClient
from framework.delivery_worker import DeliveryWorker
from framework.health_gate     import (DEFAULT_DESTINATION_KEY,
                                       GATE_STATE_VERSION,
                                       DeliveryHealthGate, GateState,
                                       GateStateUnreadable, scrub_reason,
                                       validate_snapshot)
from framework.outbox          import Outbox, OutboxStatus

URL = "https://ingest.example/api/xdr/ingest/telemetry"
RID = {APP_ATTRIBUTION_HEADER: "nvx-r31-test"}
TEN = "ten_f1a5479243e901cf159e230fa0"


class FakeClock:
    """Deterministic monotonic clock."""

    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class FakeWall:
    """Deterministic wall clock — the ONLY clock that can cross a restart."""

    def __init__(self, t: float = 1_800_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture()
def store(tmp_path):
    ob = Outbox(path=str(tmp_path))
    yield ob
    ob.close()


def _gate(store, clock, wall, **kw):
    return DeliveryHealthGate(failure_threshold=kw.pop("threshold", 3),
                              cooldown_seconds=kw.pop("cooldown", 30.0),
                              max_cooldown_seconds=kw.pop("max_cooldown",
                                                          120.0),
                              clock=clock, wall_clock=wall, store=store, **kw)


def _open_the_gate(gate, threshold=3):
    for _ in range(threshold):
        gate.record_destination_failure("HTTP 404 from the edge, unattributed")
    assert gate.state == GateState.OPEN


def _env(eid):
    return Envelope(
        tenant_id=TEN,
        source="windows_sysmon",
        source_event_id=str(eid),
        connector_id="windows-eventlog-g1proof01",
        collector_id="col_d6b0b9e8172246f29be9",
        collection_method="windows-eventlog",
        parser_version="sysmon-1",
        source_timestamp="2026-09-22T17:50:00+00:00",
        collection_timestamp="2026-09-22T17:50:01+00:00",
        event_type="registry_event",
        raw={"xml": "<Event/>"},
        canonical={},
        declared_source="microsoft-sysmon",
    )


class Destination:
    def __init__(self, status=404, headers=None):
        self.status = status
        self.headers = headers or {}
        self.attempts = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.attempts += 1
        if self.status == 200:
            return httpx.Response(200, json={"accepted": 1},
                                  headers=self.headers)
        return httpx.Response(self.status, text="not found",
                              headers=self.headers)


def _ingest(monkeypatch, handler):
    monkeypatch.setenv("NIVX_INGEST_URL", URL)
    monkeypatch.setenv("NIVX_INGEST_TOKEN", "test-token")
    transport = httpx.MockTransport(handler)
    orig = httpx.AsyncClient

    def _c(*a, **kw):
        kw["transport"] = transport
        return orig(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", _c)
    return IngestClient()


# ── the row itself ───────────────────────────────────────────────────
def test_first_boot_persists_nothing_and_starts_closed(store):
    gate = _gate(store, FakeClock(), FakeWall())
    assert gate.state == GateState.CLOSED
    assert gate.restored_from is None
    assert gate.state_load_error is None
    # Nothing is known about the destination yet, so nothing is claimed.
    assert store.load_health_gate(DEFAULT_DESTINATION_KEY) is None


def test_open_is_written_to_the_outbox_store(store):
    gate = _gate(store, FakeClock(), FakeWall())
    _open_the_gate(gate)
    row = store.load_health_gate(DEFAULT_DESTINATION_KEY)
    assert row["state"] == GateState.OPEN
    assert row["state_version"] == GATE_STATE_VERSION
    assert row["consecutive_failures"] == 3
    assert row["cooldown_until_epoch"] == pytest.approx(
        1_800_000_000.0 + 30.0)
    assert row["updated_at"]


def test_persisted_row_is_in_the_same_store_as_the_envelopes(store, tmp_path):
    gate = _gate(store, FakeClock(), FakeWall())
    _open_the_gate(gate)
    con = sqlite3.connect(str(tmp_path / "outbox.db"))
    try:
        names = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"envelopes", "delivery_health_gate"} <= names
    finally:
        con.close()


def test_no_secret_reaches_the_persisted_row(store):
    gate = _gate(store, FakeClock(), FakeWall())
    for _ in range(3):
        gate.record_destination_failure(
            "refused: Authorization: Bearer sk-live-abc123 token=hunter2")
    row = store.load_health_gate(DEFAULT_DESTINATION_KEY)
    assert "sk-live-abc123" not in (row["last_reason"] or "")
    assert "hunter2" not in (row["last_reason"] or "")
    assert "[REDACTED]" in row["last_reason"]


def test_reason_is_bounded(store):
    gate = _gate(store, FakeClock(), FakeWall())
    for _ in range(3):
        gate.record_destination_failure("x" * 5000)
    row = store.load_health_gate(DEFAULT_DESTINATION_KEY)
    assert len(row["last_reason"]) <= 300


def test_scrub_reason_leaves_ordinary_text_alone():
    assert scrub_reason("HTTP 404 at the edge") == "HTTP 404 at the edge"
    assert scrub_reason(None) is None


# ── restart semantics ────────────────────────────────────────────────
def test_open_survives_restart_with_remaining_cooldown(store):
    wall = FakeWall()
    gate = _gate(store, FakeClock(), wall)
    _open_the_gate(gate)

    wall.advance(10.0)                      # 20s of the 30s pause remain
    revived = _gate(store, FakeClock(5_000.0), wall)

    assert revived.state == GateState.OPEN
    assert revived.restored_from == GateState.OPEN
    assert revived.consecutive_failures == 3
    assert revived.seconds_until_probe() == pytest.approx(20.0, abs=0.01)
    # A restart during OPEN generates NO delivery traffic.
    assert revived.allow_delivery() is False


def test_restart_during_open_does_not_probe_until_cooldown_elapses(store):
    wall = FakeWall()
    clock = FakeClock()
    gate = _gate(store, clock, wall)
    _open_the_gate(gate)

    wall.advance(10.0)
    clock2 = FakeClock(9_000.0)
    revived = _gate(store, clock2, wall)
    assert revived.allow_delivery() is False
    clock2.advance(19.9)
    assert revived.allow_delivery() is False
    clock2.advance(0.2)
    assert revived.allow_delivery() is True
    assert revived.state == GateState.HALF_OPEN
    assert revived.probe_limit() == 1


def test_cooldown_already_elapsed_while_down_probes_once_immediately(store):
    wall = FakeWall()
    gate = _gate(store, FakeClock(), wall)
    _open_the_gate(gate)

    wall.advance(600.0)                     # the service was down for 10 min
    revived = _gate(store, FakeClock(), wall)
    assert revived.state == GateState.OPEN
    assert revived.seconds_until_probe() == pytest.approx(0.0, abs=0.01)
    assert revived.allow_delivery() is True
    assert revived.state == GateState.HALF_OPEN
    assert revived.probe_limit() == 1       # ONE probe, never a burst


def test_restart_while_half_open_resumes_as_one_bounded_probe(store):
    wall = FakeWall()
    clock = FakeClock()
    gate = _gate(store, clock, wall)
    _open_the_gate(gate)
    clock.advance(31.0)
    assert gate.allow_delivery() is True
    assert gate.state == GateState.HALF_OPEN

    revived = _gate(store, FakeClock(), wall)
    assert revived.restored_from == GateState.HALF_OPEN
    assert revived.state == GateState.OPEN          # never restored mid-probe
    assert revived.allow_delivery() is True         # probe-eligible now
    assert revived.state == GateState.HALF_OPEN
    assert revived.probe_limit() == 1


def test_suspect_failure_run_survives_a_crash_loop(store):
    """The core R3.1 property: restarting must not reset a building outage."""
    wall = FakeWall()
    gate = _gate(store, FakeClock(), wall, threshold=5)
    for _ in range(4):
        gate.record_destination_failure("connection refused")
    assert gate.state == GateState.SUSPECT

    for _ in range(3):                      # crash-loop: three restarts
        gate = _gate(store, FakeClock(), wall, threshold=5)
        assert gate.state == GateState.SUSPECT
        assert gate.consecutive_failures == 4

    gate.record_destination_failure("connection refused")
    assert gate.state == GateState.OPEN
    # Five real destination failures opened it — not 5 per restart.
    assert gate.opened_count == 1


def test_closed_gate_restores_closed(store):
    wall = FakeWall()
    gate = _gate(store, FakeClock(), wall)
    gate.record_success()
    revived = _gate(store, FakeClock(), wall)
    assert revived.state == GateState.CLOSED
    assert revived.consecutive_failures == 0
    assert revived.allow_delivery() is True


def test_escalated_cooldown_survives_restart_and_stays_bounded(store):
    wall = FakeWall()
    clock = FakeClock()
    gate = _gate(store, clock, wall, cooldown=30.0, max_cooldown=120.0)
    _open_the_gate(gate)
    for expected in (60.0, 120.0, 120.0):
        clock.advance(gate.current_cooldown + 1.0)
        assert gate.allow_delivery() is True            # HALF_OPEN
        gate.record_destination_failure("probe failed")  # re-open, doubled
        assert gate.current_cooldown == pytest.approx(expected)

    revived = _gate(store, FakeClock(), wall, cooldown=30.0,
                    max_cooldown=120.0)
    assert revived.current_cooldown == pytest.approx(120.0)
    assert revived.seconds_until_probe() == pytest.approx(120.0, abs=0.01)
    assert revived.state == GateState.OPEN


def test_probe_success_after_restart_closes_and_persists_closed(store):
    wall = FakeWall()
    gate = _gate(store, FakeClock(), wall)
    _open_the_gate(gate)
    wall.advance(31.0)

    revived = _gate(store, FakeClock(), wall)
    assert revived.allow_delivery() is True
    revived.note_probe()
    revived.record_success()
    assert revived.state == GateState.CLOSED

    row = store.load_health_gate(DEFAULT_DESTINATION_KEY)
    assert row["state"] == GateState.CLOSED
    assert row["cooldown_until_epoch"] is None
    assert _gate(store, FakeClock(), wall).allow_delivery() is True


def test_clock_moved_backwards_cannot_extend_the_pause(store):
    wall = FakeWall()
    gate = _gate(store, FakeClock(), wall, cooldown=30.0)
    _open_the_gate(gate)
    wall.t -= 10_000.0                      # the host clock jumped backwards
    revived = _gate(store, FakeClock(), wall, cooldown=30.0)
    assert revived.seconds_until_probe() <= 30.0


# ── corruption / unreadable state ────────────────────────────────────
@pytest.mark.parametrize("mutation", [
    "UPDATE delivery_health_gate SET state='NOT_A_STATE'",
    "UPDATE delivery_health_gate SET state_version=999",
    "UPDATE delivery_health_gate SET cooldown_seconds=-1",
    "UPDATE delivery_health_gate SET consecutive_failures=-4",
    "UPDATE delivery_health_gate SET cooldown_until_epoch=NULL",
    "UPDATE delivery_health_gate SET opened_count='banana'",
])
def test_corrupt_state_fails_safe_and_visibly(store, mutation):
    wall = FakeWall()
    gate = _gate(store, FakeClock(), wall)
    _open_the_gate(gate)
    store._conn.execute(mutation)                       # noqa: SLF001

    revived = _gate(store, FakeClock(), wall)
    assert revived.state == GateState.OPEN              # fails SAFE
    assert revived.state_load_error                      # and VISIBLY
    assert "unreadable" in (revived.last_reason or "")
    assert revived.allow_delivery() is False
    assert revived.status()["state_load_error"]
    # Bounded: the fail-safe pause is the base cooldown, not forever.
    assert revived.seconds_until_probe() == pytest.approx(30.0, abs=0.01)


def test_unreadable_store_fails_safe(store):
    class Broken:
        def load_health_gate(self, key):
            raise sqlite3.DatabaseError("database disk image is malformed")

        def save_health_gate(self, key, snapshot):
            pass

    gate = DeliveryHealthGate(store=Broken(), clock=FakeClock(),
                              wall_clock=FakeWall())
    assert gate.state == GateState.OPEN
    assert "DatabaseError" in gate.state_load_error
    assert gate.allow_delivery() is False


def test_unwritable_store_is_reported_but_does_not_stall_delivery(store):
    class WriteOnlyFails:
        def load_health_gate(self, key):
            return None

        def save_health_gate(self, key, snapshot):
            raise sqlite3.OperationalError("attempt to write a readonly "
                                           "database")

    gate = DeliveryHealthGate(store=WriteOnlyFails(), clock=FakeClock(),
                              wall_clock=FakeWall(), failure_threshold=3)
    assert gate.state == GateState.CLOSED
    assert gate.allow_delivery() is True
    gate.record_destination_failure("connection refused")
    assert gate.state_load_error and "persisted" in gate.state_load_error
    assert gate.state == GateState.SUSPECT               # in-memory truth holds


def test_validate_snapshot_rejects_non_records():
    for bad in (None, "OPEN", 7, []):
        with pytest.raises(GateStateUnreadable):
            validate_snapshot(bad)


# ── end to end · restart costs no row anything ───────────────────────
@pytest.mark.asyncio
async def test_restart_during_outage_consumes_no_retry_budget(
        monkeypatch, tmp_path):
    """A restart must not cost a row an attempt, and must not resume traffic."""
    dest = Destination(404, RID)
    ingest = _ingest(monkeypatch, dest)
    wall = FakeWall()
    clock = FakeClock()

    outbox = Outbox(path=str(tmp_path))
    for i in range(20):
        outbox.record(_env(4000 + i))
    gate = _gate(outbox, clock, wall)
    worker = DeliveryWorker(outbox, ingest, batch_size=20,
                            health_gate=gate)
    await worker.tick_once()
    assert gate.state == GateState.OPEN
    attempts_before = dest.attempts
    counts_before = outbox.counts()
    assert counts_before[OutboxStatus.DELIVERING] == 0   # nothing stranded
    outbox.close()

    # ---- restart: brand-new Outbox and worker over the SAME file ----
    for _ in range(3):
        revived_outbox = Outbox(path=str(tmp_path))
        revived_gate = _gate(revived_outbox, FakeClock(), wall)
        revived_worker = DeliveryWorker(revived_outbox, ingest,
                                        batch_size=20,
                                        health_gate=revived_gate)
        assert revived_gate.state == GateState.OPEN
        assert revived_gate.restored_from == GateState.OPEN
        result = await revived_worker.tick_once()
        assert result["gate_skipped"] is True
        assert result["drained"] == 0
        # No HTTP attempt, no row change, nothing stranded.
        assert dest.attempts == attempts_before
        assert revived_outbox.counts() == counts_before
        revived_outbox.close()

    # ---- destination restored: one probe closes the gate, delivery resumes --
    dest.status = 200
    wall.advance(31.0)
    final_outbox = Outbox(path=str(tmp_path))
    final_gate = _gate(final_outbox, FakeClock(), wall)
    final_worker = DeliveryWorker(final_outbox, ingest, batch_size=20,
                                  health_gate=final_gate)
    probe = await final_worker.tick_once()
    assert probe["drained"] == 1 and probe["delivered"] == 1
    assert final_gate.state == GateState.CLOSED

    drained = 0
    for _ in range(5):
        drained += (await final_worker.tick_once()).get("delivered", 0)
    counts = final_outbox.counts()
    assert counts[OutboxStatus.DEAD_LETTER] == 0         # no loss
    assert counts[OutboxStatus.DELIVERING] == 0          # nothing stranded
    assert counts[OutboxStatus.DELIVERED] >= 1 + drained
    final_outbox.close()


@pytest.mark.asyncio
async def test_worker_gate_is_durable_by_default(monkeypatch, tmp_path):
    ingest = _ingest(monkeypatch, Destination(404, RID))
    outbox = Outbox(path=str(tmp_path))
    worker = DeliveryWorker(outbox, ingest)
    assert worker.gate.status()["durable"] is True
    assert worker.gate.status()["destination_key"] == DEFAULT_DESTINATION_KEY
    outbox.close()
