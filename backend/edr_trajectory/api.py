"""Read-only E3 Device Trajectory API (namespaced /e3/trajectory). Serves SYNTHETIC / SHAPE-FAITHFUL
fixtures through the EvidenceProvider. Not mounted by E1's server; the preview mounts it behind a flag."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, Body, HTTPException, Query

from . import CONTRACT_VERSION
from .actions import APPROVAL_ACTIONS, PIVOTS, RESPONSE_STATES, pivot
from .contracts import TenantRequired, parse_instant
from .fixtures import BUILDERS
from .lineage import isolate, lanes
from .paging import PAGE_DEFAULT, BadCursor, page_newest_first
from .service import APPROVALS, SEED_CANONICAL, SEED_SHADOW, load, scenario, scenario_meta, status_log_for, window
from .ti import file_status
from .timeline import coverage, density, viewport

CONTRACTS = {"event": "e3.dt.event.v1", "paging": "e3.dt.paging.newest_first.v1", "identity": "e3.dt.process_key.v1",
             "lineage": "e3.dt.lineage.v1", "lanes": "e3.dt.lanes.v1", "viewport": "e3.dt.viewport.v1",
             "density": "e3.dt.density.v1", "coverage": "e3.dt.coverage.v1", "file_status": "e3.dt.file_status.v1",
             "status_events": "e3.dt.status_log.append_only.v1", "approvals": "e3.dt.approval_only.v1"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def build_router(get_db: Callable[[], Any] = lambda: None) -> APIRouter:
    r = APIRouter(prefix="/e3/trajectory", tags=["e3-trajectory (read-only, SYNTHETIC preview)"])

    def _sid(s: str) -> str:
        if s not in BUILDERS:
            raise HTTPException(404, f"unknown scenario {s!r}")
        return s

    async def _load(sid, tenant, device, source, t0=None, t1=None):
        try:
            return await load(_sid(sid), tenant, device, source=source, db=get_db(), t0=t0, t1=t1)
        except TenantRequired as ex:
            raise HTTPException(400, str(ex)) from ex
        except ValueError as ex:
            raise HTTPException(400, str(ex)) from ex

    def _win(sid, t0, t1):
        return window(sid, parse_instant(t0), parse_instant(t1))

    @r.get("/contracts")
    async def contracts() -> Dict[str, Any]:
        return {"version": CONTRACT_VERSION, "contracts": CONTRACTS, "approval_actions": APPROVAL_ACTIONS,
                "pivots": PIVOTS, "response_states": RESPONSE_STATES, "e3_can_set": ["APPROVAL_REQUESTED"]}

    @r.get("/scenarios")
    async def scenarios() -> Dict[str, Any]:
        return {"scenarios": [scenario_meta(s) for s in BUILDERS]}

    @r.get("/devices/{device_id}/events")
    async def events(device_id: str, scenario_id: str = Query(..., alias="scenario"), tenant: str = "",
                     source: str = "merged", page_size: int = PAGE_DEFAULT, cursor: Optional[str] = None):
        d = await _load(scenario_id, tenant, device_id, source)
        try:
            pg = page_newest_first(d["events"], page_size, cursor, as_of_ms=scenario(scenario_id)["reference_ms"])
        except BadCursor as ex:
            raise HTTPException(400, str(ex)) from ex
        return {**pg, "suppressed_duplicates": d["suppressed_duplicates"], "provenance": d["provenance"]}

    @r.get("/devices/{device_id}/lanes")
    async def lanes_ep(device_id: str, scenario_id: str = Query(..., alias="scenario"), tenant: str = "",
                       source: str = "merged", t0: Optional[str] = None, t1: Optional[str] = None):
        a, b = _win(scenario_id, t0, t1)
        d = await _load(scenario_id, tenant, device_id, source)
        ln = lanes(d["events"], a, b)
        return {"window": {"from_ms": a, "to_ms": b}, "lanes": ln["lanes"], "provenance": d["provenance"]}

    @r.get("/devices/{device_id}/viewport")
    async def viewport_ep(device_id: str, scenario_id: str = Query(..., alias="scenario"), tenant: str = "",
                          source: str = "merged", t0: Optional[str] = None, t1: Optional[str] = None,
                          width: int = 1200, rows: int = 50, offset: int = 0, bucket_px: int = 8):
        a, b = _win(scenario_id, t0, t1)
        d = await _load(scenario_id, tenant, device_id, source)
        ids = [x["lane_id"] for x in lanes(d["events"], a, b)["lanes"]]
        return {**viewport(d["events"], ids, a, b, width, bucket_px, rows, offset), "provenance": d["provenance"]}

    @r.get("/devices/{device_id}/density")
    async def density_ep(device_id: str, scenario_id: str = Query(..., alias="scenario"), tenant: str = "",
                         source: str = "merged", days: int = 30):
        d = await _load(scenario_id, tenant, device_id, source)
        return {**density(d["events"], scenario(scenario_id)["reference_ms"], days), "provenance": d["provenance"]}

    @r.get("/devices/{device_id}/coverage")
    async def coverage_ep(device_id: str, scenario_id: str = Query(..., alias="scenario"), tenant: str = "",
                          source: str = "merged", t0: Optional[str] = None, t1: Optional[str] = None):
        a, b = _win(scenario_id, t0, t1)
        d = await _load(scenario_id, tenant, device_id, source)
        s = scenario(scenario_id)
        own = s["tenant_id"] == tenant
        return {**coverage(d["events"], a, b, heartbeats_ms=s["heartbeats_ms"] if own else [],
                           declared_gaps=s["declared_gaps"] if own else []), "provenance": d["provenance"]}

    @r.get("/devices/{device_id}/lineage")
    async def lineage_ep(device_id: str, scenario_id: str = Query(..., alias="scenario"), tenant: str = "",
                         source: str = "merged", sha256: Optional[str] = None, filename: Optional[str] = None,
                         process_key: Optional[str] = None):
        if not (sha256 or filename or process_key):
            raise HTTPException(400, "one of sha256, filename, process_key is required")
        d = await _load(scenario_id, tenant, device_id, source)
        return {**isolate(d["events"], sha256=sha256, filename=filename, process_key=process_key),
                "provenance": d["provenance"]}

    @r.get("/files/{sha256}/status")
    async def file_status_ep(sha256: str, scenario_id: str = Query(..., alias="scenario"), tenant: str = ""):
        s = scenario(_sid(scenario_id))
        if not tenant:
            raise HTTPException(400, "tenant_id is required for every evidence read")
        dets = s["detections"].get(sha256.lower(), []) if s["tenant_id"] == tenant else []
        out = file_status(sha256.lower(), detections=dets, providers={}, now_iso=_now())
        log = status_log_for(scenario_id)
        out["status_events"] = log.history(tenant, sha256.lower())
        return {**out, "provenance": {"scenario_id": scenario_id, "label": s["label"]}}

    @r.get("/status-events")
    async def status_events(scenario_id: str = Query(..., alias="scenario"), tenant: str = "",
                            subject: Optional[str] = None):
        try:
            return {"append_only": True, "events": status_log_for(_sid(scenario_id)).history(tenant, subject)}
        except TenantRequired as ex:
            raise HTTPException(400, str(ex)) from ex

    @r.post("/approvals", status_code=201)
    async def approvals_create(body: Dict[str, Any] = Body(...)):
        try:
            row, created = APPROVALS.request(tenant_id=body.get("tenant_id", ""), action=body.get("action", ""),
                                             target=body.get("target") or {}, requested_by=body.get("requested_by", ""),
                                             idempotency_key=body.get("idempotency_key", ""),
                                             reason=body.get("reason", ""), at=_now())
        except (TenantRequired, ValueError) as ex:
            raise HTTPException(400, str(ex)) from ex
        return {"created": created, "request": row}

    @r.get("/approvals")
    async def approvals_list(tenant: str = ""):
        try:
            return {"requests": APPROVALS.list(tenant)}
        except TenantRequired as ex:
            raise HTTPException(400, str(ex)) from ex

    @r.get("/pivots")
    async def pivots(kind: str, value: str):
        try:
            return pivot(kind, value)
        except ValueError as ex:
            raise HTTPException(400, str(ex)) from ex

    @r.post("/seed")
    async def seed(scenario_id: str = Query(..., alias="scenario")):
        """Writes ONLY to the E3-namespaced SYNTHETIC seed collections (never to source stores)."""
        db = get_db()
        if db is None:
            raise HTTPException(503, "no database configured for the preview")
        s = scenario(_sid(scenario_id))
        for coll, docs in ((SEED_SHADOW, s["shadow"]), (SEED_CANONICAL, s["canonical"])):
            await db[coll].delete_many({"provenance_seed": scenario_id})
            if docs:
                await db[coll].insert_many([{**d, "provenance_seed": scenario_id} for d in docs])
        return {"seeded": scenario_id, "collections": [SEED_SHADOW, SEED_CANONICAL], "label": s["label"]}

    return r
