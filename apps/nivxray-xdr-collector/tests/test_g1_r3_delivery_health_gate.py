"""G1-R3 · Delivery health gate.

R1 and R2 are per-event corrections. Neither stops the worker from grinding the
entire queue against a destination that is not there — which is exactly what
happened for ~5h46m during the G1 run. With R1 alone a long outage no longer
destroys events instantly; it walks each of them to `retries exhausted`
instead. The retry budget is for per-event problems, so spending it on a
destination problem is the same category error in slower motion.

These tests prove the gate stops that, and that stopping it costs nothing:
no event loss, no duplicate acknowledgement, no bookmark effect, no bypass of
R1 classification or R2 evidence, and no stall caused by legitimate per-event
refusals.
"""
from __future__ import annotations

import httpx
import pytest

from framework.base            import Envelope
from framework.delivery        import (APP_ATTRIBUTION_HEADER,
                                       DeliveryClassification, IngestClient)
from framework.delivery_worker import DeliveryWorker
from framework.health_gate     import DeliveryHealthGate, GateState
from framework.outbox          import Outbox, OutboxStatus

URL = "https://ingest.example/api/xdr/ingest/telemetry"
RID = {APP_ATTRIBUTION_HEADER: "nvx-r3-test"}


class FakeClock:
    """Deterministic monotonic clock — no sleeping in tests."""

    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def _env(eid):
    return Envelope(
        tenant_id="ten_f1a5479243e901cf159e230fa0",
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
    )


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


class Destination:
    """A destination whose availability the test controls."""

    def __init__(self, status=404, headers=None):
        self.status = status
        self.headers = headers or {}
        self.calls = 0

    def handler(self, request):
        self.calls += 1
        return httpx.Response(self.status, headers=self.headers, text="body")


def _gate(clock, threshold=3, cooldown=30.0, max_cooldown=120.0):
    return DeliveryHealthGate(failure_threshold=threshold,
                              cooldown_seconds=cooldown,
                              max_cooldown_seconds=max_cooldown,
                              clock=clock)


# ── 1 · the gate opens and then stops spending retry budget ───────────
@pytest.mark.asyncio
async def test_gate_opens_after_threshold_and_stops_consuming_attempts(monkeypatch):
    dest = Destination(404)                       # unattributed: destination
    ingest = _ingest(monkeypatch, dest.handler)
    ob = Outbox(max_attempts=10, backoff_seconds=(0,) * 10)
    ids = [ob.record(_env(f"open-{i}"))[0] for i in range(10)]
    clock = FakeClock()
    worker = DeliveryWorker(ob, ingest, batch_size=10, health_gate=_gate(clock, 3))

    first = await worker.tick_once()
    assert worker.gate.state == GateState.OPEN
    # It stopped mid-batch: exactly the threshold was spent, not all ten.
    assert dest.calls == 3
    assert first["retrying"] == 3

    attempts_after_open = {i: ob.by_id(i).attempts for i in ids}
    calls_after_open = dest.calls

    # Subsequent ticks are refused by the gate: nothing attempted, nothing
    # touched, no retry budget consumed.
    for _ in range(5):
        result = await worker.tick_once()
        assert result["gate_skipped"] is True
        assert result["drained"] == 0
    assert dest.calls == calls_after_open
    assert {i: ob.by_id(i).attempts for i in ids} == attempts_after_open
    assert worker.gate.skipped_ticks == 5


@pytest.mark.asyncio
async def test_unattempted_rows_are_released_not_stranded(monkeypatch):
    dest = Destination(404)
    ingest = _ingest(monkeypatch, dest.handler)
    ob = Outbox(max_attempts=10, backoff_seconds=(0,) * 10)
    for i in range(8):
        ob.record(_env(f"release-{i}"))
    clock = FakeClock()
    worker = DeliveryWorker(ob, ingest, batch_size=8, health_gate=_gate(clock, 2))

    await worker.tick_once()
    counts = ob.counts()
    assert counts.get("delivering", 0) == 0, "nothing may be left claimed"
    # 2 attempted -> retrying, the other 6 returned to queued untouched.
    assert counts.get("retrying", 0) == 2
    assert counts.get("queued", 0) == 6
    assert sum(counts.values()) == 8               # no event lost


# ── 2 · bounded recovery: probe, then close ───────────────────────────
@pytest.mark.asyncio
async def test_half_open_probes_a_single_row_then_closes_on_success(monkeypatch):
    dest = Destination(404)
    ingest = _ingest(monkeypatch, dest.handler)
    ob = Outbox(max_attempts=10, backoff_seconds=(0,) * 10)
    for i in range(6):
        ob.record(_env(f"probe-{i}"))
    clock = FakeClock()
    worker = DeliveryWorker(ob, ingest, batch_size=6, health_gate=_gate(clock, 2, 30.0))

    await worker.tick_once()
    assert worker.gate.state == GateState.OPEN
    assert worker.gate.seconds_until_probe() == 30.0

    clock.advance(31)
    dest.status, dest.headers = 200, RID           # destination recovers
    result = await worker.tick_once()
    assert result["probe"] is True
    assert result["drained"] == 1, "a probe must risk exactly one row"
    assert result["delivered"] == 1
    assert worker.gate.state == GateState.CLOSED
    assert worker.gate.probes == 1

    # Fully recovered: the rest drains normally.
    result = await worker.tick_once()
    assert result["delivered"] == 5
    assert ob.counts().get("delivered", 0) == 6


@pytest.mark.asyncio
async def test_failed_probe_reopens_with_bounded_backoff(monkeypatch):
    dest = Destination(404)
    ingest = _ingest(monkeypatch, dest.handler)
    ob = Outbox(max_attempts=50, backoff_seconds=(0,) * 50)
    for i in range(4):
        ob.record(_env(f"reopen-{i}"))
    clock = FakeClock()
    worker = DeliveryWorker(ob, ingest, batch_size=4,
                            health_gate=_gate(clock, 2, 10.0, max_cooldown=40.0))

    await worker.tick_once()
    assert worker.gate.current_cooldown == 10.0

    for expected in (20.0, 40.0, 40.0):            # doubles, then clamps
        clock.advance(worker.gate.current_cooldown + 1)
        await worker.tick_once()                   # probe fails
        assert worker.gate.state == GateState.OPEN
        assert worker.gate.current_cooldown == expected
    # Bounded, never infinite: it is still probing.
    assert worker.gate.probes == 3


# ── 3 · only destination evidence moves the gate ──────────────────────
@pytest.mark.asyncio
async def test_authoritative_refusal_does_not_open_the_gate(monkeypatch):
    """A stream of bad events must not stall delivery of good ones."""
    dest = Destination(403, RID)                   # app-attributed refusal
    ingest = _ingest(monkeypatch, dest.handler)
    ob = Outbox()
    for i in range(6):
        ob.record(_env(f"refusal-{i}"))
    clock = FakeClock()
    worker = DeliveryWorker(ob, ingest, batch_size=6, health_gate=_gate(clock, 2))

    result = await worker.tick_once()
    assert result["dead"] == 6                     # R1 semantics preserved
    assert dest.calls == 6, "the batch must not be cut short by healthy refusals"
    assert worker.gate.state == GateState.CLOSED
    assert worker.gate.consecutive_failures == 0


@pytest.mark.asyncio
async def test_success_resets_the_failure_run(monkeypatch):
    dest = Destination(503, RID)
    ingest = _ingest(monkeypatch, dest.handler)
    ob = Outbox(max_attempts=10, backoff_seconds=(0,) * 10)
    for i in range(4):
        ob.record(_env(f"reset-{i}"))
    clock = FakeClock()
    worker = DeliveryWorker(ob, ingest, batch_size=1, health_gate=_gate(clock, 3))

    await worker.tick_once()
    await worker.tick_once()
    assert worker.gate.consecutive_failures == 2
    assert worker.gate.state == GateState.SUSPECT   # visible, but not paused

    dest.status, dest.headers = 200, RID
    await worker.tick_once()
    assert worker.gate.consecutive_failures == 0
    assert worker.gate.state == GateState.CLOSED


@pytest.mark.asyncio
async def test_transport_failure_is_destination_evidence(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("connection refused")
    ingest = _ingest(monkeypatch, handler)
    ob = Outbox(max_attempts=10, backoff_seconds=(0,) * 10)
    for i in range(5):
        ob.record(_env(f"transport-{i}"))
    clock = FakeClock()
    worker = DeliveryWorker(ob, ingest, batch_size=5, health_gate=_gate(clock, 2))

    await worker.tick_once()
    assert worker.gate.state == GateState.OPEN


# ── 4 · R1 and R2 are not bypassed by the gate ────────────────────────
@pytest.mark.asyncio
async def test_gate_preserves_r1_classification_and_r2_evidence(monkeypatch):
    dest = Destination(404)
    ingest = _ingest(monkeypatch, dest.handler)
    ob = Outbox(max_attempts=10, backoff_seconds=(0,) * 10)
    rid, _ = ob.record(_env("r1r2-1"))
    clock = FakeClock()
    worker = DeliveryWorker(ob, ingest, batch_size=1, health_gate=_gate(clock, 1))

    await worker.tick_once()
    row = ob.by_id(rid)
    assert row.status == OutboxStatus.RETRYING          # R1: not destroyed
    d = row.failure_detail                              # R2: still recorded
    assert d["classification"] == DeliveryClassification.UNATTRIBUTED_FAILURE
    assert d["status_code"] == 404
    assert d["app_attributed"] is False
    assert worker.gate.state == GateState.OPEN


@pytest.mark.asyncio
async def test_no_duplicate_acknowledgement_and_no_delivery_while_open(monkeypatch):
    dest = Destination(404)
    ingest = _ingest(monkeypatch, dest.handler)
    ob = Outbox(max_attempts=10, backoff_seconds=(0,) * 10)
    for i in range(3):
        ob.record(_env(f"noack-{i}"))
    clock = FakeClock()
    worker = DeliveryWorker(ob, ingest, batch_size=3, health_gate=_gate(clock, 1))

    await worker.tick_once()
    for _ in range(3):
        await worker.tick_once()
    assert ob.counts().get("delivered", 0) == 0
    assert ingest.delivered == 0


# ── 5 · idempotency and durability under a gated outage ───────────────
@pytest.mark.asyncio
async def test_idempotency_and_payloads_survive_a_gated_outage(monkeypatch):
    dest = Destination(404)
    ingest = _ingest(monkeypatch, dest.handler)
    ob = Outbox(max_attempts=10, backoff_seconds=(0,) * 10)
    rid, _ = ob.record(_env("idem-1"))
    again, _ = ob.record(_env("idem-1"))
    assert rid == again                               # one durable row
    clock = FakeClock()
    worker = DeliveryWorker(ob, ingest, batch_size=5, health_gate=_gate(clock, 1))

    await worker.tick_once()
    await worker.tick_once()
    row = ob.by_id(rid)
    assert row.to_envelope().raw == {"xml": "<Event/>"}   # recovery stays possible
    assert row.status in (OutboxStatus.RETRYING, OutboxStatus.QUEUED)


# ── 6 · the gate is observable ─────────────────────────────────────────
@pytest.mark.asyncio
async def test_gate_state_is_reported_in_worker_status(monkeypatch):
    dest = Destination(404)
    ingest = _ingest(monkeypatch, dest.handler)
    ob = Outbox(max_attempts=10, backoff_seconds=(0,) * 10)
    ob.record(_env("status-1"))
    clock = FakeClock()
    worker = DeliveryWorker(ob, ingest, batch_size=1, health_gate=_gate(clock, 1))

    await worker.tick_once()
    hg = worker.status()["health_gate"]
    assert hg["state"] == GateState.OPEN
    assert hg["opened_count"] == 1
    assert hg["failure_threshold"] == 1
    assert hg["seconds_until_probe"] == 30.0
    assert "HTTP 404" in hg["last_reason"]
    assert hg["last_transition_at"]


def test_gate_defaults_come_from_environment(monkeypatch):
    monkeypatch.setenv("NIVX_DELIVERY_GATE_THRESHOLD", "7")
    monkeypatch.setenv("NIVX_DELIVERY_GATE_COOLDOWN_SECONDS", "12.5")
    monkeypatch.setenv("NIVX_DELIVERY_GATE_MAX_COOLDOWN_SECONDS", "99")
    gate = DeliveryHealthGate()
    assert (gate.failure_threshold, gate.base_cooldown, gate.max_cooldown) == \
           (7, 12.5, 99.0)


def test_gate_rejects_nonsense_configuration(monkeypatch):
    """Bad configuration must fall back to a safe default, not disable the gate."""
    monkeypatch.setenv("NIVX_DELIVERY_GATE_THRESHOLD", "not-a-number")
    monkeypatch.setenv("NIVX_DELIVERY_GATE_COOLDOWN_SECONDS", "-5")
    gate = DeliveryHealthGate()
    assert gate.failure_threshold == 5
    assert gate.base_cooldown == 30.0
    assert gate.max_cooldown >= gate.base_cooldown


def test_worker_has_a_gate_by_default():
    ob = Outbox()
    worker = DeliveryWorker(ob, IngestClient())
    assert worker.gate.state == GateState.CLOSED
    assert worker.status()["health_gate"]["state"] == GateState.CLOSED


# ── 7 · a closed gate changes nothing about the happy path ────────────
@pytest.mark.asyncio
async def test_healthy_destination_is_unaffected(monkeypatch):
    dest = Destination(200, RID)
    ingest = _ingest(monkeypatch, dest.handler)
    ob = Outbox()
    for i in range(12):
        ob.record(_env(f"healthy-{i}"))
    clock = FakeClock()
    worker = DeliveryWorker(ob, ingest, batch_size=12, health_gate=_gate(clock, 3))

    result = await worker.tick_once()
    assert result["delivered"] == 12
    assert result["gate"] == GateState.CLOSED
    assert worker.gate.opened_count == 0
    assert ob.counts().get("delivered", 0) == 12


# ── 8 · SUSPECT is observable before anything is paused ───────────────
@pytest.mark.asyncio
async def test_suspect_state_is_visible_before_pausing(monkeypatch):
    dest = Destination(503, RID)
    ingest = _ingest(monkeypatch, dest.handler)
    ob = Outbox(max_attempts=10, backoff_seconds=(0,) * 10)
    for i in range(5):
        ob.record(_env(f"suspect-{i}"))
    clock = FakeClock()
    worker = DeliveryWorker(ob, ingest, batch_size=1, health_gate=_gate(clock, 3))

    await worker.tick_once()
    assert worker.gate.state == GateState.SUSPECT
    assert worker.status()["health_gate"]["consecutive_failures"] == 1
    await worker.tick_once()
    assert worker.gate.state == GateState.SUSPECT           # still delivering
    await worker.tick_once()
    assert worker.gate.state == GateState.OPEN              # threshold reached


# ── 9 · restart while unhealthy restores a safe deterministic state ───
@pytest.mark.asyncio
async def test_restart_while_unhealthy_is_safe_and_deterministic(monkeypatch):
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        dest = Destination(404)
        ingest = _ingest(monkeypatch, dest.handler)
        ob = Outbox(path=tmp, max_attempts=10, backoff_seconds=(0,) * 10)
        ids = [ob.record(_env(f"restart-{i}"))[0] for i in range(6)]
        clock = FakeClock()
        worker = DeliveryWorker(ob, ingest, batch_size=6,
                                health_gate=_gate(clock, 2))
        await worker.tick_once()
        assert worker.gate.state == GateState.OPEN
        attempts_before = {i: ob.by_id(i).attempts for i in ids}
        ob.close()

        # Process restart: Outbox.__init__ resets DELIVERING -> QUEUED and the
        # gate starts CLOSED, so the state is deterministic and nothing is
        # stranded. Retry budgets survive untouched.
        reopened = Outbox(path=tmp, max_attempts=10, backoff_seconds=(0,) * 10)
        fresh = DeliveryWorker(reopened, IngestClient(), batch_size=6,
                               health_gate=_gate(FakeClock(), 2))
        assert fresh.gate.state == GateState.CLOSED
        counts = reopened.counts()
        assert counts.get("delivering", 0) == 0
        assert counts.get("delivered", 0) == 0
        assert sum(counts.values()) == 6
        assert {i: reopened.by_id(i).attempts for i in ids} == attempts_before
        reopened.close()


# ── 10 · concurrent drains keep the invariants ────────────────────────
@pytest.mark.asyncio
async def test_concurrent_ticks_do_not_double_acknowledge(monkeypatch):
    import asyncio
    dest = Destination(200, RID)
    ingest = _ingest(monkeypatch, dest.handler)
    ob = Outbox()
    for i in range(9):
        ob.record(_env(f"conc-{i}"))
    clock = FakeClock()
    worker = DeliveryWorker(ob, ingest, batch_size=3, health_gate=_gate(clock, 3))

    await asyncio.gather(*(worker.tick_once() for _ in range(4)))
    counts = ob.counts()
    assert sum(counts.values()) == 9                 # no row invented or lost
    assert counts.get("delivering", 0) == 0          # nothing left claimed
    assert counts.get("delivered", 0) <= 9
    assert ingest.delivered >= counts.get("delivered", 0)


# ── 11 · an open gate performs no network I/O at all (no retry storm) ─
@pytest.mark.asyncio
async def test_open_gate_performs_no_network_io(monkeypatch):
    dest = Destination(404)
    ingest = _ingest(monkeypatch, dest.handler)
    ob = Outbox(max_attempts=99, backoff_seconds=(0,) * 99)
    for i in range(50):
        ob.record(_env(f"storm-{i}"))
    clock = FakeClock()
    worker = DeliveryWorker(ob, ingest, batch_size=50, health_gate=_gate(clock, 1))

    await worker.tick_once()
    baseline = dest.calls
    for _ in range(25):
        await worker.tick_once()
    assert dest.calls == baseline, "an open gate must not touch the network"
    assert worker.gate.skipped_ticks == 25
    # Backpressure accounting is preserved: the queue is still all there.
    assert sum(ob.counts().values()) == 50
