#!/usr/bin/env python3
"""G1-R3.1 · Scratch acceptance driver — a real collector process.

The in-repo harness (`g1_r31_delivery_health_acceptance.py`) proves the
contract deterministically against an in-process fake. This driver is the
NEXT level: a real OS process, a real socket, the real wall clock and a real
on-disk outbox, so `Ctrl-C` is an actual restart rather than a simulated one.

It refuses to run against production state:
  * `XDR_STATE_DIR` must be set and must NOT be the NivXForge state directory;
  * the ingest URL must be a loopback address;
  * every event it seeds is disposable and tenant-scoped to a scratch tenant.

Commands:
    seed   --count N      record N disposable envelopes into the scratch outbox
    run    [--seconds S]  drain with the durable health gate (Ctrl-C to
                          simulate a service restart)
    status                print the persisted gate row + outbox counts
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.base            import Envelope            # noqa: E402
from framework.delivery        import IngestClient         # noqa: E402
from framework.delivery_worker import DeliveryWorker       # noqa: E402
from framework.health_gate     import (DEFAULT_DESTINATION_KEY,  # noqa: E402
                                       DeliveryHealthGate)
from framework.outbox          import Outbox, OutboxStatus  # noqa: E402

TENANT = "ten_r31_scratch_disposable"
CONNECTOR = "r31-scratch-disposable"
FORBIDDEN = ("nivxforge", "programdata")


def _guard() -> str:
    state = os.environ.get("XDR_STATE_DIR")
    if not state:
        raise SystemExit("XDR_STATE_DIR must be set to a SCRATCH directory")
    low = state.replace("\\", "/").lower()
    if any(token in low for token in FORBIDDEN):
        raise SystemExit(f"refusing to touch production collector state: "
                         f"{state}")
    url = os.environ.get("NIVX_INGEST_URL") or ""
    if not any(h in url for h in ("127.0.0.1", "localhost", "[::1]")):
        raise SystemExit("NIVX_INGEST_URL must point at a loopback scratch "
                         f"destination, got: {url!r}")
    os.makedirs(state, exist_ok=True)
    return state


def _event(n: int) -> Envelope:
    return Envelope(
        tenant_id=TENANT,
        source="r31_scratch",
        source_event_id=f"r31-scratch-{n}",
        connector_id=CONNECTOR,
        collector_id="col_r31_scratch",
        collection_method="scratch-driver",
        parser_version="r31-scratch/1",
        source_timestamp="2026-06-01T00:00:00+00:00",
        collection_timestamp="2026-06-01T00:00:01+00:00",
        event_type="scratch_event",
        raw={"disposable": True, "n": n},
        canonical={},
        declared_source="microsoft-sysmon",
    )


def _report(outbox: Outbox) -> dict:
    return {
        "counts": outbox.counts(),
        "attempts": {r.source_event_id: r.attempts
                     for r in outbox.list(limit=1000)},
        "persisted_health_gate": outbox.load_health_gate(
            DEFAULT_DESTINATION_KEY),
    }


async def _run(outbox: Outbox, seconds: float | None) -> None:
    ingest = IngestClient()
    gate = DeliveryHealthGate(store=outbox)
    worker = DeliveryWorker(outbox, ingest, batch_size=2,
                            poll_interval_seconds=2.0, health_gate=gate)
    print(json.dumps({"boot_gate": gate.status()}, indent=2), flush=True)
    elapsed = 0.0
    try:
        while seconds is None or elapsed < seconds:
            tick = await worker.tick_once()
            print(json.dumps({"tick": tick,
                              "gate": gate.status()["state"],
                              "seconds_until_probe":
                                  gate.status()["seconds_until_probe"],
                              "counts": outbox.counts()}), flush=True)
            await asyncio.sleep(worker.interval)
            elapsed += worker.interval
    except KeyboardInterrupt:
        print("\n[driver] interrupted — this is the restart boundary",
              flush=True)
    print(json.dumps(_report(outbox), indent=2), flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=("seed", "run", "status"))
    ap.add_argument("--count", type=int, default=12)
    ap.add_argument("--seconds", type=float, default=None)
    args = ap.parse_args()

    state = _guard()
    outbox = Outbox(path=state)
    try:
        if args.command == "seed":
            for n in range(args.count):
                outbox.record(_event(n))
            print(json.dumps({"seeded": args.count,
                              "counts": outbox.counts()}, indent=2))
        elif args.command == "status":
            print(json.dumps(_report(outbox), indent=2))
        else:
            asyncio.run(_run(outbox, args.seconds))
    finally:
        outbox.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
