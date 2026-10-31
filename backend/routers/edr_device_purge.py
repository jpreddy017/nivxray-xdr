"""Device-scoped evidence purge — one named endpoint, optionally one date window.

Separate from `edr_maintenance.dev_reset`, which wipes a WHOLE TENANT and is
deliberately not mounted. This route can only ever touch the evidence of the
single endpoint it resolves, so a mistyped tenant cannot cascade.

Safety model (same vocabulary as the dev-reset port, intentionally):
  * 404s unless EDR_MAINTENANCE_TOKEN is set in the environment
  * every call must present that token in X-Maintenance-Token
  * mode="dry" is the DEFAULT and writes nothing — it reports what would go
  * mode="execute" additionally requires confirm="DELETE-DEVICE-EVIDENCE" and a
    non-empty backup reference, echoed back so the decision is auditable
  * the endpoint record itself is NEVER deleted: the device stays in Computers
    with its enrolment history, only its ingested evidence is removed
  * a hostname that resolves to more than one endpoint is refused, not guessed
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from deps import db as _db

router = APIRouter(prefix="/edr/maintenance", tags=["edr-maintenance"])

# collection -> (device field, time field). The time field is only consulted
# when the caller supplies a window; an unwindowed purge ignores it entirely.
EVIDENCE = {
    "v2_shadow_observations": ("event.raw.computer", "captured_at"),
    "xdr_canonical_evidence": ("host.hostname", "event_time"),
}

CONFIRM = "DELETE-DEVICE-EVIDENCE"


class PurgeRequest(BaseModel):
    endpoint_id: str = ""
    hostname: str = ""
    time_start: str = ""
    time_end: str = ""
    mode: str = Field("dry", pattern="^(dry|execute)$")
    confirm: str = ""
    backup: str = ""


def _guard(token: str | None) -> None:
    expected = os.environ.get("EDR_MAINTENANCE_TOKEN")
    if not expected:
        raise HTTPException(status_code=404, detail="Not Found")
    if not token or token != expected:
        raise HTTPException(status_code=403, detail="maintenance token required")


async def _resolve(body: PurgeRequest) -> dict[str, Any]:
    """Name the device from the registry. Identity is never inferred."""
    if body.endpoint_id:
        flt: dict[str, Any] = {"endpoint_id": body.endpoint_id}
    elif body.hostname:
        flt = {"hostname": body.hostname}
    else:
        raise HTTPException(status_code=400, detail="endpoint_id or hostname is required")
    rows = await _db["edr_endpoints"].find(flt).to_list(length=10)
    if not rows:
        raise HTTPException(status_code=404, detail={"code": "ENDPOINT_NOT_FOUND", "filter": flt})
    if len(rows) > 1:
        raise HTTPException(status_code=409, detail={
            "code": "ENDPOINT_AMBIGUOUS",
            "reason": "more than one endpoint carries this hostname; purge by endpoint_id",
            "endpoint_ids": [r.get("endpoint_id") for r in rows]})
    r = rows[0]
    if not r.get("hostname"):
        raise HTTPException(status_code=409, detail={
            "code": "ENDPOINT_HAS_NO_HOSTNAME",
            "reason": "evidence is keyed by hostname; this endpoint carries none"})
    return r


def _window(body: PurgeRequest, field: str) -> dict[str, Any]:
    if not body.time_start and not body.time_end:
        return {}
    bounds: dict[str, Any] = {}
    if body.time_start:
        bounds["$gte"] = body.time_start
    if body.time_end:
        bounds["$lt"] = body.time_end
    return {field: bounds}


@router.post("/purge-device-evidence")
async def purge_device_evidence(body: PurgeRequest,
                                x_maintenance_token: str | None = Header(default=None)):
    _guard(x_maintenance_token)
    executing = body.mode == "execute"
    if executing:
        if body.confirm != CONFIRM:
            raise HTTPException(status_code=400, detail=f"confirm must equal {CONFIRM!r}")
        if not body.backup.strip():
            raise HTTPException(status_code=400, detail="a backup reference is required to execute")

    ep = await _resolve(body)
    hostname = ep["hostname"]

    report: dict[str, Any] = {}
    for coll, (device_field, time_field) in EVIDENCE.items():
        flt = {device_field: hostname, **_window(body, time_field)}
        matched = await _db[coll].count_documents(flt)
        tenants = await _db[coll].distinct("tenant_id", flt)
        entry = {"filter": flt, "matched": matched, "tenants": sorted(t for t in tenants if t)}
        if executing and matched:
            entry["deleted"] = (await _db[coll].delete_many(flt)).deleted_count
            entry["remaining"] = await _db[coll].count_documents(flt)
        report[coll] = entry

    return {
        "mode": body.mode,
        "executed": executing,
        "device": {"endpoint_id": ep.get("endpoint_id"), "hostname": hostname,
                   "tenant_id": ep.get("tenant_id"),
                   "enrollment_state": ep.get("enrollment_state"),
                   "device_iid": ep.get("device_iid")},
        "window": {"time_start": body.time_start or None, "time_end": body.time_end or None},
        "collections": report,
        "endpoint_record": "preserved — this route never deletes the device itself",
        "backup": body.backup or None,
        "at": datetime.now(timezone.utc).isoformat(),
    }
