"""Lane G · `Data Sources → Windows` — the read-only admin truth surface.

Read-only by construction. Every value is measured server-side by
`services.windows_channel_truth`, which publishes five INDEPENDENT
dimensions and deliberately publishes no composite HEALTHY verdict.

Benchmark note (owner standing rule): the state vocabulary here follows the
established XDR/EDR pattern of separating *connector/ingestion* health from
*content coverage* — as Defender XDR does for data connectors and Cortex
XDR does for data sources — and then keeps NivXRay's own stricter
invariant: INSTALLED ≠ ENROLLED ≠ CONNECTED ≠ RECEIVING ≠ HEALTHY, and no
stage may be inferred from a neighbouring one.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from routers.xdr_rbac import require_permission
from services import windows_channel_truth as truth

router = APIRouter(prefix="/api/xdr/windows", tags=["xdr-windows"])

READ = Depends(require_permission("data_sources.read"))


def _tenant(req: Request) -> str:
    from routers.xdr_rbac import resolve_principal
    tenant, _, _ = resolve_principal(req)
    return tenant


def _adb():
    from deps import db
    return db


@router.get("/overview", dependencies=[READ])
async def windows_overview(request: Request):
    data = await truth.overview(_adb(), _tenant(request))
    return {"ok": True, "data": data}


@router.get("/channels", dependencies=[READ])
async def windows_channels(request: Request):
    rows = await truth.channel_truth(_adb(), _tenant(request))
    return {"ok": True, "data": {
        "channels": rows,
        "count": len(rows),
        "vocabularies": {
            "collection": list(truth.COLLECTION_STATES),
            "parsing": list(truth.SUPPORT_STATES),
            "normalization": list(truth.SUPPORT_STATES),
            "detection_capability": list(truth.CAPABILITY_STATES),
        },
        "independence_note": (
            "collection, parsing, normalization, detection capability and "
            "detection activity are five separate facts. None is derived "
            "from another and there is no composite health state"),
    }}


@router.get("/channels/{channel:path}", dependencies=[READ])
async def windows_channel(channel: str, request: Request):
    rows = await truth.channel_truth(_adb(), _tenant(request),
                                     channels=[channel])
    if not rows:
        raise HTTPException(404, detail={"code": "UNKNOWN_CHANNEL",
                                         "channel": channel})
    return {"ok": True, "data": rows[0]}


@router.get("/devices", dependencies=[READ])
async def windows_devices(request: Request,
                          limit: int = Query(200, ge=1, le=1000)):
    rows = await truth.device_truth(_adb(), _tenant(request))
    return {"ok": True, "data": {
        "devices": rows[:limit],
        "count": len(rows),
        "identity_contract": {
            "evidence_origin": ("the machine identity the delivered record "
                                "asserted (`origin_computer`)"),
            "collector_host": ("the machine/process that collected and "
                               "shipped the record — a different fact"),
            "canonical_device_id": ("a permanent NivX asset identity with "
                                    "evidence-backed aliases. NOT yet "
                                    "established: a hostname is reused, "
                                    "renamed and reimaged, so it must not "
                                    "become the permanent asset id"),
            "edr_association": ("NOT ESTABLISHED when no EDR endpoint "
                                "record has been correlated. This is never "
                                "reported as UNENROLLED — enrolment status "
                                "is independently unknown"),
        },
    }}


@router.get("/devices/{origin}", dependencies=[READ])
async def windows_device(origin: str, request: Request):
    tenant = _tenant(request)
    devices = await truth.device_truth(_adb(), tenant)
    match = next((d for d in devices if d["evidence_origin"] == origin), None)
    if not match:
        raise HTTPException(404, detail={"code": "UNKNOWN_DEVICE_ORIGIN",
                                         "origin": origin})
    channels = await truth.channel_truth(
        _adb(), tenant, channels=list(match["channels_observed"]) or None)
    return {"ok": True, "data": {"device": match,
                                 "channel_matrix": channels}}


@router.get("/collectors", dependencies=[READ])
async def windows_collectors(request: Request):
    tenant = _tenant(request)
    authorized, collectors = await truth._authorized_channels(_adb(), tenant)
    windows_sources = {str(d.get("declared_source") or "").lower()
                       for d in truth.CHANNEL_DECLARATIONS.values()}
    rows: list[dict[str, Any]] = []
    for c in collectors:
        srcs = {s.strip().lower() for s in c["authorized_sources"]}
        windows_authorized = sorted(srcs & windows_sources)
        rows.append({**c, "windows_authorized_sources": windows_authorized,
                     "is_windows_collector": bool(windows_authorized)})
    return {"ok": True, "data": {
        "collectors": rows,
        "windows_collectors": sum(1 for r in rows if r["is_windows_collector"]),
        "authorization_note": (
            "authorization is the SERVER's record of what a collector may "
            "send. A collector with an empty allowlist is authorized for "
            "nothing — an empty allowlist never means 'any source'"),
        "sources_index": authorized,
    }}


@router.get("/configuration", dependencies=[READ])
async def windows_configuration(request: Request):
    """The declarative contract: channels, declared sources, DSMs, roadmap."""
    _ = _tenant(request)
    return {"ok": True, "data": {
        "channels": [
            {"channel": ch, **{k: v for k, v in decl.items()
                               if k != "provides"},
             "provides": sorted(decl.get("provides") or ())}
            for ch, decl in truth.CHANNEL_DECLARATIONS.items()],
        "unsupported": [{"channel": ch, "reason": why}
                        for ch, why in truth.UNSUPPORTED_CHANNELS.items()],
        "freshness_minutes": truth.FRESH_MINUTES,
        "window_hours": truth.WINDOW_HOURS,
    }}
