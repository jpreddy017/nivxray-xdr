"""
Telemetry health projection · Phase B.5.

Provides per-transport health, ingest health, and outbox health in
a single canonical response the Admin UI can render without cross-
endpoint composition.
"""
from __future__ import annotations

from fastapi import APIRouter, Request

from framework.tenant_scope import tenant_scope

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
    tenant = tenant_scope(request)
    owned = {r.id for r in request.app.state.store.list(tenant_id=tenant)}
    transports = _transport_health({k: v for k, v in instances.items() if k in owned})
    ingest = {"state": "not_available"}
    outbox = runtime.outbox.metrics(tenant_id=tenant) if runtime else {}
    worker = {"state": "not_available"}
    report = getattr(request.app.state, 'rehydration', None)
    rehydration = {'state': 'not_available'}
    if report is not None:
        rehydration = {**report.get('tenants', {}).get(tenant,
                          {'records': 0, 'constructed': 0, 'started': 0}),
                       'auto_start': report['auto_start'],
                       'failures': [r for r in report['failures'] if r['connector_id'] in owned],
                       'not_started': [r for r in report['not_started'] if r['connector_id'] in owned]}
    return {
        "transports": transports,
        "ingest":     ingest,
        "outbox":     outbox,
        "worker":     worker,
        "rehydration": rehydration,
        "phase":      "B.5",
    }
