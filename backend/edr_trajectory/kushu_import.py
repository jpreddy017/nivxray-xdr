"""E3 PREVIEW-ONLY (E1: STRIP). Ingest an owner-run, read-only browser export of the production
/api/edr/endpoints/{id}/trajectory projection into E3_PREVIEW_DB and serve it back in the same shape.
The export is E1's projected rows (not raw v2_shadow_observations); nothing here contacts production."""
from __future__ import annotations

import base64
import json
import os
import re
import time
from collections import Counter
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pymongo import ReplaceOne

FORMAT = "NVX_DT_EXPORT_V1"
LABEL = "KUSHU PRODUCTION EXPORT · read-only browser export by owner · stored in e3_dt_preview"
EV, META = "e3_kushu_events", "e3_kushu_meta"
DEVICE_RE = re.compile(r"^[A-Za-z0-9_.:\-]{3,128}$")
M, D = 60_000, 86_400_000


def _iso(ms: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ms / 1000)) + f".{ms % 1000:03d}Z"


def _enc(ms: int, iid: str) -> str:
    return base64.urlsafe_b64encode(json.dumps({"ms": ms, "iid": iid}).encode()).decode()


def _dec(c: str) -> tuple[int, str]:
    d = json.loads(base64.urlsafe_b64decode(c.encode()))
    return int(d["ms"]), str(d["iid"])


async def devices(db) -> list[dict[str, Any]]:
    return [m async for m in db[META].find({}, {"_id": 0})]


async def meta_for(db, ref: str) -> dict[str, Any] | None:
    return await db[META].find_one({"$or": [{"device": ref}, {"identity.endpoint_id": ref}, {"computer.hostname": ref}]},
                                   {"_id": 0})


def _detection(e: dict[str, Any]) -> dict[str, Any] | None:
    d = e.get("detection")
    if not (e.get("is_detection") or d):
        return None
    d = d if isinstance(d, dict) else {"name": d}
    return {"observation_id": e.get("observation_id"), "kind": d.get("kind") or "E1_DETECTION",
            "name": d.get("name") or d.get("rule_name") or e.get("rule_id") or "detection",
            "severity": (d.get("severity") or "UNKNOWN").upper(), "engine": d.get("engine") or "E1 (exported)",
            "at": e.get("timestamp"), "is_verdict": False, "response": d.get("response"),
            "basis": "E1_EXPORTED_DETECTION_FIELD"}


async def ingest(db, body: dict[str, Any], *, label: str = LABEL, source: str = "KUSHU_BROWSER_EXPORT") -> dict[str, Any]:
    if body.get("format") != FORMAT:
        raise HTTPException(422, f"format must be {FORMAT}")
    dev = str(body.get("device") or "")
    if not DEVICE_RE.match(dev):
        raise HTTPException(422, "device is required")
    evs = body.get("events")
    if not isinstance(evs, list):
        raise HTTPException(422, "events must be a list")
    ops, bad = [], 0
    for e in evs:
        iid, ms = (e or {}).get("event_iid"), (e or {}).get("timestamp_instant_ms")
        if not isinstance(iid, str) or not isinstance(ms, (int, float)):
            bad += 1
            continue
        ops.append(ReplaceOne({"device": dev, "event_iid": iid}, {"device": dev, "event_iid": iid, "ms": int(ms),
                                                                    "observation_id": e.get("observation_id"), "event": e},
                              upsert=True))
    if ops:
        await db[EV].bulk_write(ops, ordered=False)
        await db[EV].create_index([("device", 1), ("ms", 1), ("event_iid", 1)])
    count = await db[EV].count_documents({"device": dev})
    prev = await db[META].find_one({"device": dev}) or {}
    meta = {"device": dev, "label": label, "source": source,
            "source_origin": body.get("source_origin") or prev.get("source_origin"),
            "exported_at": body.get("exported_at") or prev.get("exported_at"),
            "export_window": body.get("window") or prev.get("export_window"),
            "identity": body.get("identity") or prev.get("identity") or {"device_iid": dev},
            "computer": body.get("computer") or prev.get("computer"), "probes": body.get("probes") or prev.get("probes"),
            "imported_at": _iso(int(time.time() * 1000)), "count": count,
            "chunks": sorted({*prev.get("chunks", []), (body.get("chunk") or {}).get("index", 0)})}
    await db[META].replace_one({"device": dev}, meta, upsert=True)
    return {"device": dev, "accepted": len(ops), "rejected": bad, "stored_total": count, "label": label}


async def _rows(db, dev: str, t0: int | None, t1: int | None) -> list[dict[str, Any]]:
    q: dict[str, Any] = {"device": dev}
    if t0 is not None or t1 is not None:
        q["ms"] = {k: v for k, v in (("$gte", t0), ("$lte", t1)) if v is not None}
    return [d async for d in db[EV].find(q, {"_id": 0}).sort([("ms", 1), ("event_iid", 1)])]


async def trajectory(db, meta: dict[str, Any], *, time_start=None, time_end=None, before=None, limit=500,
                     q=None, **_) -> dict[str, Any]:
    from edr_plane.instant import instant_ms
    dev = meta["device"]
    t0, t1 = (instant_ms(time_start) if time_start else None), (instant_ms(time_end) if time_end else None)
    rows = await _rows(db, dev, t0, t1)
    if q and q.strip():
        n = q.strip().lower()
        rows = [r for r in rows if n in json.dumps(r["event"]).lower()]
    end = len(rows)
    if before:
        bm, bi = _dec(before)
        end = sum(1 for r in rows if (r["ms"], r["event_iid"]) < (bm, bi))
    start = max(0, end - max(1, min(int(limit), 4000)))
    page = [dict(r["event"]) for r in rows[start:end]]
    lanes: dict[str, dict[str, Any]] = {}
    for e in page:
        lid = e.get("lane_id") or f"lane::{e.get('lane_label') or e.get('entity')}"
        ln = lanes.setdefault(lid, {"lane_index": len(lanes), "lane_id": lid, "label": e.get("lane_label") or e.get("entity"),
                                    "group": e.get("lane_group")})
        e["lane_index"] = ln["lane_index"]
        det = _detection(e)
        if det:
            e["e3_detection"] = det
    allr = await _rows(db, dev, None, None)
    days = Counter(_iso(r["ms"])[:10] for r in allr)
    dets = [{"observation_id": r.get("observation_id"), "event_iid": r["event_iid"], "at": _iso(r["ms"]), "ms": r["ms"],
             "name": d["name"], "severity": d["severity"]} for r in allr if (d := _detection(r["event"]))]
    ident = {"device_iid": dev, "addressed_by": [dev], **(meta.get("identity") or {})}
    return {"engine_id": "E3_KUSHU_EXPORT_REPLAY", "events": page, "returned": len(page),
            "matched_in_window": len(rows), "observations_all_time": len(allr),
            "lane_axis": {"total_lanes": len(lanes), "lanes": list(lanes.values())},
            "activity": {"days": [{"day": k, "total": v} for k, v in sorted(days.items())]},
            "time_range": {"observed_start": allr and _iso(allr[0]["ms"]), "observed_end": allr and _iso(allr[-1]["ms"])},
            "identity": ident, "computer": meta.get("computer") or {"hostname": dev, "device_iid": dev},
            "has_more": end < len(rows), "next_cursor": None,
            "e3_preview": {"engine": "E3_NEWEST_FIRST_OVER_KUSHU_EXPORT", "order": "NEWEST_FIRST", "window_rows": len(rows),
                           "remaining_older": start, "remaining_newer": len(rows) - end,
                           "older_cursor": _enc(rows[start]["ms"], rows[start]["event_iid"]) if start > 0 else None,
                           "data_label": meta.get("label") or LABEL, "source": meta.get("source"), "preview_only": True,
                           "source_origin": meta.get("source_origin"), "detections_all": dets,
                           "exported_at": meta.get("exported_at"), "status_events": [],
                           "detections_basis": "E1 detection fields as exported (not re-derived)"}}


async def focus(db, meta: dict[str, Any], *, event_iid=None, observation_id=None, raw_event_id=None, **_) -> dict[str, Any]:
    dev = meta["device"]
    q = ({"event_iid": event_iid} if event_iid else {"observation_id": observation_id} if observation_id
         else {"event.provenance.raw_event_id": raw_event_id} if raw_event_id else None)
    hit = q and await db[EV].find_one({"device": dev, **q}, {"_id": 0})
    if not hit:
        return {"state": "OBSERVATION_NOT_RESOLVED", "focus": None}
    e, ms = hit["event"], hit["ms"]
    return {"state": "FOCUS_RESOLVED", "focus": {"event_iid": hit["event_iid"], "timestamp": e.get("timestamp"),
                                                 "event_type": e.get("event_type"), "observation_id": hit.get("observation_id"),
                                                 "window": {"time_start": _iso(ms - 30 * M), "time_end": _iso(ms + 30 * M)}}}


async def trace(db, meta: dict[str, Any], *, event_iid: str | None, now_ms: int, limit: int = 500) -> dict[str, Any]:
    """Stale trace over the exported projection. Raw-store stages (2a/2b) are not observable from a browser export."""
    dev = meta["device"]
    allr = await _rows(db, dev, None, None)
    if not allr:
        return {"state": "NO_EXPORT"}
    tgt = next((r for r in allr if r["event_iid"] == event_iid or r.get("observation_id") == event_iid), None) if event_iid else allr[-1]
    t1 = now_ms if now_ms - allr[-1]["ms"] < D else allr[-1]["ms"]
    t0 = t1 - D
    win = [r for r in allr if t0 <= r["ms"] <= t1]
    key = tgt and tgt["event_iid"]
    idx_all = next((i for i, r in enumerate(allr) if r["event_iid"] == key), None)
    idx_win = next((i for i, r in enumerate(win) if r["event_iid"] == key), None)
    stages = [{"stage": "1_present_in_prod_projection_export", "present": tgt is not None, "detail": tgt and tgt["event"].get("timestamp")},
              {"stage": "2_raw_store_and_normalization", "present": None, "detail": "NOT OBSERVABLE from a browser export"},
              {"stage": "3_window_filter_24h", "present": idx_win is not None, "detail": f"{len(win)} rows in [{_iso(t0)}, {_iso(t1)}]"}]
    e1 = idx_win is not None and idx_win < limit
    e3 = idx_win is not None and idx_win >= len(win) - limit
    return {"event_iid": key, "window": [_iso(t0), _iso(t1)], "limit": limit, "stages": stages, "basis": "KUSHU_BROWSER_EXPORT",
            "e1": {"page_selection": {"present": e1, "matched_in_window": len(win), "rule": "oldest-first first page"}},
            "e3": {"page_selection": {"present": e3, "remaining_older": max(0, len(win) - limit), "rule": "newest-first first page"}},
            "e1_deep_link_locate": {"present": idx_all is not None and idx_all < 15000, "observations_examined": min(len(allr), 15000),
                                    "all_time": len(allr), "rule": "6 x 2500 forward from oldest"},
            "e1_disappears_at": None if e1 else ("3_window_filter_24h" if idx_win is None else "4_page_selection_oldest_first"),
            "e3_disappears_at": None if e3 else ("3_window_filter_24h" if idx_win is None else "4_page_selection")}


def add_routes(r: APIRouter, get_db) -> None:
    @r.post("/e3/trajectory/import")
    async def import_export(body: dict[str, Any], x_e3_import_token: str | None = Header(default=None)):
        tok = os.environ.get("E3_IMPORT_TOKEN")
        if not tok:
            raise HTTPException(503, "import disabled: E3_IMPORT_TOKEN not configured")
        if x_e3_import_token != tok:
            raise HTTPException(401, "bad import token")
        return await ingest(get_db(), body)

    @r.get("/e3/trajectory/imports")
    async def imports():
        return {"imports": await devices(get_db())}

    @r.get("/e3/trajectory/imports/{device}/stale-trace")
    async def imported_trace(device: str, event: str | None = None, limit: int = 500):
        m = await meta_for(get_db(), device)
        if not m:
            raise HTTPException(404, "no export imported for this device")
        return await trace(get_db(), m, event_iid=event, now_ms=int(time.time() * 1000), limit=limit)
