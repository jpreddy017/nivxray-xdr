"""
Telemetry health projection · Phase B.

Emits per-configured-source health rows.  When no instances exist for
a source-type the row is honestly `NEVER CONNECTED`.  With instances,
the row reflects the running connector's health + metrics.
"""
from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter(tags=["telemetry-health"])


KNOWN_SOURCE_TYPES = ["rest", "webhook", "syslog"]


@router.get("/telemetry-health")
def telemetry_health(request: Request):
    instances = getattr(request.app.state, "instances", {})
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
    return {"rows": rows, "phase": "B",
              "ingest": request.app.state.runtime.ingest.status()
                          if hasattr(request.app.state, "runtime") else None}
