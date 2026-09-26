#!/usr/bin/env python3
"""G1-R3.1 · Automated delivery-health acceptance harness.

Runs the full destination-outage lifecycle against a CONTROLLABLE FAKE
destination, using DISPOSABLE proof events in a throwaway outbox:

    HEALTHY -> destination unavailable -> SUSPECT -> OPEN
            -> RESTART while OPEN (new Outbox + new gate, same file)
            -> remains safely paused -> cooldown -> HALF_OPEN
            -> ONE bounded probe -> destination restored -> CLOSED
            -> normal delivery resumes

and asserts, at every step:

  * retry-budget preservation — no row loses an attempt while OPEN, and a
    restart costs a row nothing;
  * durability — the outage is remembered across process boundaries;
  * no stranded DELIVERING rows;
  * no event loss and no duplicate acknowledgement;
  * truthful health telemetry (the reported state matches the persisted row).

THIS IS NOT A LIVE PRODUCTION-DESTINATION PROOF. The destination is a local
in-process fake. It touches no real endpoint, no real collector service, and
none of the preserved G1 evidence. The scratch-collector runbook
(`/app/memory/G1_R31_SCRATCH_ACCEPTANCE_RUNBOOK.md`) is the next level of
acceptance.

Usage:  python scripts/g1_r31_delivery_health_acceptance.py
Exit 0 = ACCEPTED, exit 1 = REFUSED (with the failing assertion named).
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx                                              # noqa: E402

from framework.base            import Envelope            # noqa: E402
from framework.delivery        import (APP_ATTRIBUTION_HEADER,  # noqa: E402
                                       IngestClient)
from framework.delivery_worker import DeliveryWorker       # noqa: E402
from framework.health_gate     import (DEFAULT_DESTINATION_KEY,  # noqa: E402
                                       DeliveryHealthGate, GateState)
from framework.outbox          import Outbox, OutboxStatus  # noqa: E402

URL = "https://acceptance.invalid/api/xdr/ingest/telemetry"
TENANT = "ten_r31_acceptance_disposable"
CONNECTOR = "r31-acceptance-disposable"
THRESHOLD = 3
COOLDOWN = 30.0
EVENTS = 12

_STEPS: list[dict] = []
_FAILED: list[str] = []


def _check(name: str, condition: bool, detail: str = "") -> None:
    _STEPS.append({"check": name, "result": "PASS" if condition else "FAIL",
                   "detail": detail})
    if not condition:
        _FAILED.append(f"{name} :: {detail}")


class Wall:
    """Controllable wall clock — the only clock that crosses a restart."""

    def __init__(self) -> None:
        self.t = 1_800_000_000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class Mono:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class Destination:
    """A destination whose availability this harness controls."""

    def __init__(self) -> None:
        self.status = 200
        self.attempts = 0
        self.accepted_ids: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.attempts += 1
        headers = {APP_ATTRIBUTION_HEADER: "r31-acceptance"}
        if self.status == 200:
            body = json.loads(request.content.decode() or "{}")
            envs = body.get("envelopes") or []
            for e in envs:
                self.accepted_ids.append(e.get("source_event_id"))
            return httpx.Response(200, json={"accepted": len(envs)},
                                  headers=headers)
        return httpx.Response(self.status, text="destination unavailable",
                              headers=headers)


def _ingest(dest: Destination) -> IngestClient:
    os.environ["NIVX_INGEST_URL"] = URL
    os.environ["NIVX_INGEST_TOKEN"] = "acceptance-disposable-token"
    transport = httpx.MockTransport(dest.handler)
    orig = httpx.AsyncClient

    class _Client(orig):                                    # type: ignore
        def __init__(self, *a, **kw):
            kw["transport"] = transport
            super().__init__(*a, **kw)

    httpx.AsyncClient = _Client                             # type: ignore
    return IngestClient()


def _event(n: int) -> Envelope:
    return Envelope(
        tenant_id=TENANT,
        source="r31_acceptance",
        source_event_id=f"r31-disposable-{n}",
        connector_id=CONNECTOR,
        collector_id="col_r31_acceptance",
        collection_method="acceptance-harness",
        parser_version="r31-acceptance/1",
        source_timestamp="2026-06-01T00:00:00+00:00",
        collection_timestamp="2026-06-01T00:00:01+00:00",
        event_type="acceptance_event",
        raw={"disposable": True, "n": n},
        canonical={},
        declared_source="microsoft-sysmon",
    )


def _open_outbox(path: str) -> Outbox:
    return Outbox(path=path)


def _gate(store: Outbox, mono: Mono, wall: Wall) -> DeliveryHealthGate:
    return DeliveryHealthGate(failure_threshold=THRESHOLD,
                              cooldown_seconds=COOLDOWN,
                              max_cooldown_seconds=120.0,
                              clock=mono, wall_clock=wall, store=store)


def _attempt_totals(store: Outbox) -> dict:
    rows = store.list(limit=1000)
    return {r.source_event_id: r.attempts for r in rows}


async def run(state_dir: str) -> None:
    dest = Destination()
    ingest = _ingest(dest)
    wall = Wall()

    # ── 1 · HEALTHY ──────────────────────────────────────────────
    outbox = _open_outbox(state_dir)
    for n in range(EVENTS):
        outbox.record(_event(n))
    gate = _gate(outbox, Mono(), wall)
    worker = DeliveryWorker(outbox, ingest, batch_size=2, health_gate=gate)

    first = await worker.tick_once()
    _check("healthy_delivery", first.get("delivered") == 2, json.dumps(first))
    _check("healthy_gate_closed", gate.state == GateState.CLOSED, gate.state)

    # ── 2 · destination unavailable -> SUSPECT -> OPEN ───────────
    dest.status = 503
    await worker.tick_once()
    _check("suspect_before_threshold", gate.state == GateState.SUSPECT,
           f"{gate.state} failures={gate.consecutive_failures}")
    await worker.tick_once()
    _check("open_after_threshold", gate.state == GateState.OPEN,
           f"{gate.state} failures={gate.consecutive_failures}")

    counts_open = outbox.counts()
    attempts_open = _attempt_totals(outbox)
    _check("nothing_stranded_delivering",
           counts_open[OutboxStatus.DELIVERING] == 0, json.dumps(counts_open))
    _check("no_dead_letter_from_outage",
           counts_open[OutboxStatus.DEAD_LETTER] == 0, json.dumps(counts_open))

    persisted = outbox.load_health_gate(DEFAULT_DESTINATION_KEY)
    _check("health_state_persisted", persisted is not None
           and persisted["state"] == GateState.OPEN, json.dumps(persisted))
    _check("telemetry_matches_persisted_row",
           gate.status()["state"] == (persisted or {}).get("state"),
           f'{gate.status()["state"]} vs {(persisted or {}).get("state")}')

    attempts_at_open = dest.attempts
    outbox.close()

    # ── 3 · RESTART while OPEN, three times (crash-loop) ─────────
    for i in range(3):
        rb = _open_outbox(state_dir)
        rg = _gate(rb, Mono(50_000.0 + i), wall)
        rw = DeliveryWorker(rb, ingest, batch_size=2, health_gate=rg)
        _check(f"restart_{i}_restored_open", rg.state == GateState.OPEN,
               f"{rg.state} restored_from={rg.restored_from}")
        _check(f"restart_{i}_no_load_error", rg.state_load_error is None,
               str(rg.state_load_error))
        tick = await rw.tick_once()
        _check(f"restart_{i}_paused", tick.get("gate_skipped") is True
               and tick.get("drained") == 0, json.dumps(tick))
        _check(f"restart_{i}_no_traffic", dest.attempts == attempts_at_open,
               f"{dest.attempts} vs {attempts_at_open}")
        _check(f"restart_{i}_retry_budget_preserved",
               _attempt_totals(rb) == attempts_open, "attempt counts changed")
        _check(f"restart_{i}_counts_unchanged", rb.counts() == counts_open,
               json.dumps(rb.counts()))
        rb.close()

    # ── 4 · cooldown elapses -> ONE bounded probe, still failing ─
    wall.advance(COOLDOWN + 1.0)
    pb = _open_outbox(state_dir)
    pg = _gate(pb, Mono(60_000.0), wall)
    pw = DeliveryWorker(pb, ingest, batch_size=2, health_gate=pg)
    _check("probe_eligible_after_cooldown", pg.allow_delivery() is True
           and pg.state == GateState.HALF_OPEN, pg.state)
    _check("probe_limit_is_one", pg.probe_limit() == 1, str(pg.probe_limit()))
    before_probe = dest.attempts
    probe = await pw.tick_once()
    _check("failed_probe_sent_exactly_one_request",
           dest.attempts == before_probe + 1,
           f"{dest.attempts - before_probe} requests")
    _check("failed_probe_reopens", pg.state == GateState.OPEN, pg.state)
    _check("failed_probe_escalates_cooldown",
           pg.current_cooldown == COOLDOWN * 2, str(pg.current_cooldown))
    _check("failed_probe_bounded", pg.current_cooldown <= 120.0,
           str(pg.current_cooldown))
    pb.close()

    # ── 5 · destination restored -> probe closes -> drain ────────
    dest.status = 200
    wall.advance(COOLDOWN * 2 + 1.0)
    fb = _open_outbox(state_dir)
    fg = _gate(fb, Mono(70_000.0), wall)
    fw = DeliveryWorker(fb, ingest, batch_size=4, health_gate=fg)
    _check("escalated_cooldown_survived_restart",
           fg.current_cooldown == COOLDOWN * 2, str(fg.current_cooldown))
    ok_probe = await fw.tick_once()
    _check("successful_probe_delivers_one", ok_probe.get("delivered") == 1,
           json.dumps(ok_probe))
    _check("successful_probe_closes_gate", fg.state == GateState.CLOSED,
           fg.state)
    _check("closed_state_persisted",
           (fb.load_health_gate(DEFAULT_DESTINATION_KEY) or {}).get("state")
           == GateState.CLOSED,
           str((fb.load_health_gate(DEFAULT_DESTINATION_KEY) or {}).get(
               "state")))

    for _ in range(40):
        tick = await fw.tick_once()
        if tick.get("drained", 0) == 0:
            break

    counts_final = fb.counts()
    delivered_ids = [r.source_event_id
                     for r in fb.list(status=OutboxStatus.DELIVERED,
                                      limit=1000)]
    _check("no_event_loss",
           counts_final[OutboxStatus.DEAD_LETTER] == 0, json.dumps(counts_final))
    _check("no_stranded_delivering_at_end",
           counts_final[OutboxStatus.DELIVERING] == 0,
           json.dumps(counts_final))
    _check("no_duplicate_acknowledgement",
           len(dest.accepted_ids) == len(set(dest.accepted_ids)),
           f"{len(dest.accepted_ids)} acks, "
           f"{len(set(dest.accepted_ids))} unique")
    _check("delivered_rows_are_unique",
           len(delivered_ids) == len(set(delivered_ids)),
           f"{len(delivered_ids)} delivered rows")
    fb.close()

    # Rows still under backoff are queued/retrying, never lost.
    _check("every_event_accounted_for",
           sum(counts_final[s] for s in OutboxStatus.ALL) == EVENTS,
           json.dumps(counts_final))

    print(json.dumps({
        "harness": "g1-r3.1-delivery-health-acceptance",
        "destination": "IN-PROCESS FAKE (httpx.MockTransport) — NOT a live "
                       "production destination",
        "events": EVENTS,
        "threshold": THRESHOLD,
        "base_cooldown_seconds": COOLDOWN,
        "http_attempts_total": dest.attempts,
        "final_counts": counts_final,
        "steps": _STEPS,
        "result": "REFUSED" if _FAILED else "ACCEPTED",
        "failures": _FAILED,
    }, indent=2))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="r31-acceptance-") as tmp:
        asyncio.run(run(tmp))
    if _FAILED:
        print(f"\nG1_R31_LIVE_ACCEPTANCE = REFUSED ({len(_FAILED)} failing)")
        return 1
    print(f"\nG1_R31_LIVE_ACCEPTANCE = ACCEPTED ({len(_STEPS)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
