"""
Telemetry health projection · Phase B.5.

Provides per-transport health, ingest health, and outbox health in
a single canonical response the Admin UI can render without cross-
endpoint composition.
"""
from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter(tags=["telemetry-health"])


KNOWN_SOURCE_TYPES = ["rest", "webhook", "syslog"]


def _transport_health(instances):
    by_type: dict[str, list[dict]] = {}
    for inst in instances.values():
        by_type.setdefault(inst.source_type, []).append(inst.describe())
    rows = []
    for st in KNOWN_SOURCE_TYPES:
        insts = by_type.get(st, [])
        if not insts:
            rows.append({"source_type": st,
                          "health":      "never_connected",
                          "instances":   0,
                          "note":        "no connector instance configured"})
        else:
            for inst in insts:
                rows.append({"source_type": st,
                              "identity":    inst["identity"],
                              "health":      inst["health"],
                              "metrics":     inst["metrics"]})
    return rows


@router.get("/telemetry-health")
def telemetry_health(request: Request):
    runtime   = getattr(request.app.state, "runtime", None)
    instances = getattr(request.app.state, "instances", {})
    transports = _transport_health(instances)
    ingest = runtime.ingest.status() if runtime else {"state": "not_ready"}
    outbox = runtime.outbox.metrics() if runtime else {}
    worker = runtime.worker.status() if runtime else {"running": False}
    return {
        "transports": transports,
        "ingest":     ingest,
        "outbox":     outbox,
        "worker":     worker,
        "phase":      "B.5",
    }
