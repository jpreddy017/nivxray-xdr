"""E3 PREVIEW-ONLY (E1: STRIP). Serves the REAL Device Trajectory page's own API shape
(/api/edr/endpoints/{id}/trajectory, /trajectory/focus, the shell's session reads) over the
SYNTHETIC / SHAPE-FAITHFUL dataset in prodshape.py. The projection is E1's own
`trajectory_window.query_window`; the E3 adapter only chooses WHICH page of the window is returned
(newest-first, Phase 1 paging) by positioning E1's own cursor. engine=e1 serves E1 unchanged.
Mounted only when E3_PREVIEW_E1_SHAPE=1; reads/writes only the E3_PREVIEW_DB database."""
from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from fastapi import APIRouter, HTTPException

from . import kushu_import as kx
from . import prodshape as ps

FLAG = "E3_PREVIEW_E1_SHAPE"
STALE_AFTER_MS = 6 * ps.H
_state: dict[str, Any] = {"ident": None, "lock": None}


def _db():
    from motor.motor_asyncio import AsyncIOMotorClient
    if "client" not in _state:
        _state["client"] = AsyncIOMotorClient(os.environ["MONGO_URL"])
    return _state["client"][os.environ["E3_PREVIEW_DB"]]


async def ensure_seeded(force: bool = False) -> dict[str, Any]:
    _state["lock"] = _state["lock"] or asyncio.Lock()
    async with _state["lock"]:
        db = _db()
        meta = await db["e3_preview_meta"].find_one({"_id": "dataset"})
        now = int(time.time() * 1000)
        if meta and not force and now - meta["ref_ms"] < STALE_AFTER_MS:
            _state["ident"] = meta["identity"]
            return meta
        ref = now // 60_000 * 60_000
        export = os.environ.get("E3_PREVIEW_EXPORT")
        docs = ps.load_export(export) if export else await asyncio.to_thread(lambda: ps.to_docs(ps.generate(ref)[0]))
        await db["v2_shadow_observations"].delete_many({})
        await db["v2_shadow_observations"].insert_many([dict(d) for d in docs])
        await db["v2_shadow_observations"].create_index([("collector_id", 1), ("event.ts", -1)])
        dev = next((d["event"].get("device_iid") for d in docs if d.get("event", {}).get("device_iid")), None)
        ident = {"device_iid": dev, "hostname": ps.HOST, "tenant_id": ps.TENANT, "endpoint_id": ps.ENDPOINT,
                 "identity_confidence": "SYNTHETIC_PREVIEW"}
        await db["edr_endpoints"].replace_one({"endpoint_id": ps.ENDPOINT}, {
            "endpoint_id": ps.ENDPOINT, "hostname": ps.HOST, "device_iid": dev, "tenant_id": ps.TENANT,
            "platform": "Windows 11 Pro 23H2 (synthetic)", "sensor_version": "nivxforge-windows-sensor 1.0.0 (synthetic)",
            "enrollment_state": "ENROLLED", "sensor_state": "DELIVERING", "data_label": ps.LABEL}, upsert=True)
        meta = {"_id": "dataset", "ref_ms": ref, "identity": ident, "count": len(docs), "label": ps.LABEL,
                "source": "EXPORT" if export else "GENERATED"}
        await db["e3_preview_meta"].replace_one({"_id": "dataset"}, meta, upsert=True)
        await _seed_detections(db, docs, ref)
        from edr_plane import trajectory_window as tw
        tw._proj_cache.clear()
        _state["ident"] = ident
        return meta


def _refs(ident):
    return [ps.ENDPOINT, ident["hostname"], ident["device_iid"]]


async def _seed_detections(db, docs, ref):
    """E3 overlay collection in e3_dt_preview only. E1's own attribution path (edr_raw_events joins) is not modelled."""
    def find(pred):
        return next((d["observation_id"] for d in docs if pred(d["event"])), None)
    raw = lambda e: e.get("raw") or {}
    eicar = find(lambda e: e["kind"] == "file_create" and raw(e).get("target", "").endswith("eicar_test_file.com"))
    psh = find(lambda e: e["kind"] == "process_create" and "-enc" in (raw(e).get("command_line") or ""))
    upd = find(lambda e: e["kind"] == "process_create" and (raw(e).get("image_path") or "").endswith("upd.exe"))
    dets = [d for d in [
        eicar and {"observation_id": eicar, "kind": "SIGNATURE", "name": "EICAR-Test-Signature", "severity": "MEDIUM",
                   "engine": "nivxforge-av (synthetic)", "at": ps._iso(ref - 3 * ps.H + 4000), "is_verdict": False,
                   "response": None},
        psh and {"observation_id": psh, "kind": "BEHAVIORAL_MATCH", "name": "E3-SEQ-OFFICE-SCRIPT-PS", "severity": "HIGH",
                 "engine": "nivxforge-behavior", "at": ps._iso(ref - 46 * ps.M), "is_verdict": False, "mitre": ["T1059.001"],
                 "response": None},
    ] if d]
    status = [{"observation_id": upd, "subject_path": "C:\\Users\\priya\\AppData\\Local\\Temp\\upd.exe",
               "kind": "RETRO_DISPOSITION_CHANGE", "from": "UNKNOWN", "to": "DETECTED", "recorded_at": ps._iso(ref - 5 * ps.M),
               "provenance": {"source": "nivxforge-own:retro-rescan", "rule": "E3-RETRO-DROPPED-PE"},
               "note": "appended; the original observation is unchanged"}] if upd else []
    await db["e3_dt_detections"].delete_many({})
    await db["e3_dt_status_events"].delete_many({})
    if dets:
        await db["e3_dt_detections"].insert_many([dict(d) for d in dets])
    if status:
        await db["e3_dt_status_events"].insert_many([dict(s) for s in status])


async def window_rows(db, ident, *, time_start, time_end, lane_start, lane_end, kinds, q, dispositions):
    """The rows E1's query_window considers for this request, in E1's own chrono order."""
    from edr_plane import trajectory_window as tw
    proj = await tw._projected(db, ident=ident, refs=_refs(ident), docs_limit=None)
    rows, cat = proj["rows"], proj["cat"]
    ks = {k.strip().lower() for k in kinds.split(",") if k.strip()} if kinds else None
    ds = {d.strip().upper() for d in dispositions.split(",") if d.strip()} if dispositions else None
    nd = q.strip().lower() if q and q.strip() else None
    if ks or ds or nd:
        rows = [r for r in rows if tw._matches(r, ks, nd, ds)]
        keep = {r["lane_id"] for r in rows}
        remap = {ln["lane_id"]: i for i, ln in enumerate(ln for ln in cat["lanes"] if ln["lane_id"] in keep)}
        lane_of = lambda r: remap[r["lane_id"]]
    else:
        lane_of = lambda r: r["lane_index"]
    t0 = tw.instant_ms(time_start) if time_start else None
    t1 = tw.instant_ms(time_end) if time_end else None

    def inside(r):
        i = tw._row_ms(r)
        return i is not None and (t0 is None or i >= t0) and (t1 is None or i <= t1)
    out = [r for r in rows if inside(r) and lane_start <= lane_of(r) < lane_end]
    out.sort(key=tw._row_chrono)
    return out


async def trajectory(engine: str = "e3", **p) -> dict[str, Any]:
    from edr_plane import trajectory as dt2
    from edr_plane import trajectory_window as tw
    from edr_plane.trajectory import projection as dt2_projection
    await ensure_seeded()
    db, ident = _db(), _state["ident"]
    limit = max(1, min(int(p.get("limit") or 500), tw.MAX_LIMIT))
    cursor, before = p.get("cursor"), p.pop("before", None)
    e3 = {"engine": "E1_LEGACY_OLDEST_FIRST" if engine == "e1" else "E3_NEWEST_FIRST_ADAPTER_OVER_E1_PROJECTION"}
    if engine != "e1" and not cursor:
        rows = await window_rows(db, ident, time_start=p.get("time_start"), time_end=p.get("time_end"),
                                 lane_start=p["lane_start"], lane_end=p["lane_end"], kinds=p.get("kinds"),
                                 q=p.get("q"), dispositions=p.get("dispositions"))
        end = len(rows)
        if before:
            at = tw._cursor_decode(before)
            end = sum(1 for r in rows if tw._row_chrono(r) < tw._chrono(at.get("ms"), at["iid"]))
        start = max(0, end - limit)
        if start > 0:
            prev = rows[start - 1]
            cursor = tw._cursor_encode(prev["timestamp"] or "", prev["event_iid"], tw._row_ms(prev))
        e3.update({"order": "NEWEST_FIRST", "window_rows": len(rows), "remaining_older": start,
                   "remaining_newer": len(rows) - end,
                   "older_cursor": (tw._cursor_encode(rows[start]["timestamp"] or "", rows[start]["event_iid"],
                                                      tw._row_ms(rows[start])) if start > 0 else None)})
        p["limit"] = end - start if before else limit
    out = await tw.query_window(db, identity=ident, refs=_refs(ident), cursor=cursor,
                                **{k: v for k, v in p.items() if k != "cursor"})
    if engine != "e1" and before:
        out["has_more"], out["next_cursor"] = e3["remaining_newer"] > 0, None
    elif engine != "e1" and not p.get("cursor"):
        out["has_more"], out["next_cursor"] = False, None
    ep = await db["edr_endpoints"].find_one({"endpoint_id": ps.ENDPOINT}, {"_id": 0}) or {}
    out["identity"] = {"endpoint_id": ps.ENDPOINT, "hostname": ident["hostname"], "device_iid": ident["device_iid"],
                       "tenant_id": ps.TENANT, "addressed_by": _refs(ident)}
    out["epistemic_state"] = tw.empty_state(identity=ident, enrolled=True, observations_all_time=out["observations_all_time"],
                                            observations_in_window=out["matched_in_window"])
    nc = {"state": "NOT_COLLECTED", "reason": "not reported by the sensor"}
    out["computer"] = {"hostname": ident["hostname"], "device_iid": ident["device_iid"], "identity_confidence": "SYNTHETIC_PREVIEW",
                       "operating_system": ep.get("platform") or nc, "connector_version": ep.get("sensor_version") or nc,
                       "enrollment_state": "ENROLLED", "sensor_state": ep.get("sensor_state") or nc,
                       "last_telemetry_at": out["time_range"].get("observed_end"), "endpoint_id": ps.ENDPOINT,
                       "tenant": ps.TENANT, "group": nc, "policy": nc}
    try:
        dt2.augment(out, endpoint_id=ps.ENDPOINT, requested_start=p.get("time_start"), requested_end=p.get("time_end"), focus=None)
        out["dt2"]["graph"] = dt2_projection.build_graph(out, endpoint_id=ps.ENDPOINT, requested_start=p.get("time_start"),
                                                         requested_end=p.get("time_end"), focus=None).to_dict()
    except Exception as ex:  # noqa: BLE001
        out["dt2"] = {"state": "DT2_CONTRACT_UNAVAILABLE", "reason": type(ex).__name__}
    dets = {d["observation_id"]: d async for d in db["e3_dt_detections"].find({}, {"_id": 0})}
    stat = [s async for s in db["e3_dt_status_events"].find({}, {"_id": 0})]
    obs_ids = [e.get("observation_id") for e in out.get("events") or []]
    ing = {d["observation_id"]: d.get("ingest_time") async for d in db["v2_shadow_observations"].find(
        {"observation_id": {"$in": obs_ids + list(dets)}}, {"_id": 0, "observation_id": 1, "ingest_time": 1, "event.ts": 1})}
    for e in out.get("events") or []:
        e["e3_ingested_at"] = ing.get(e.get("observation_id"))
    for e in out.get("events") or []:
        if e.get("observation_id") in dets:
            e["e3_detection"] = dets[e["observation_id"]]
        hits = [s for s in stat if s["observation_id"] == e.get("observation_id")]
        if hits:
            e["e3_status_history"] = hits
    out["e3_preview"] = {**e3, "data_label": ps.LABEL, "preview_only": True, "status_events": stat,
                         "detections_all": [{"observation_id": k, "at": d["at"], "name": d["name"], "severity": d["severity"]}
                                            for k, d in dets.items()],
                         "detections_basis": "E3 overlay collection e3_dt_detections (synthetic); not E1 attribution"}
    return out


def build_router() -> APIRouter:
    r = APIRouter(prefix="/api")
    tenant = {"customer": ps.TENANT, "display_name": "Synthetic Preview Customer", "name": "Synthetic Preview Customer"}

    kx.add_routes(r, _db)

    @r.get("/edr/endpoints")
    async def endpoints():
        await ensure_seeded()
        i = _state["ident"]
        imported = [{"endpoint_id": m["device"], "hostname": (m.get("computer") or {}).get("hostname") or m["device"],
                     "device_iid": m["device"], "data_label": m["label"]} for m in await kx.devices(_db())]
        return {"endpoints": imported + [{"endpoint_id": ps.ENDPOINT, "hostname": i["hostname"], "device_iid": i["device_iid"],
                                          "tenant_id": ps.TENANT, "data_label": ps.LABEL}]}

    @r.get("/edr/endpoints/{endpoint_id}/trajectory")
    async def traj(endpoint_id: str, time_start: str | None = None, time_end: str | None = None, lane_start: int = 0,
                   lane_end: int = 40, cursor: str | None = None, before: str | None = None, limit: int = 500,
                   kinds: str | None = None, q: str | None = None, dispositions: str | None = None,
                   hist_day: str | None = None, engine: str = "e3"):
        m = await kx.meta_for(_db(), endpoint_id)
        if m:
            return await kx.trajectory(_db(), m, time_start=time_start, time_end=time_end, before=before, limit=limit, q=q)
        return await trajectory(engine, time_start=time_start, time_end=time_end, lane_start=max(0, lane_start),
                                lane_end=max(1, lane_end), cursor=cursor, before=before, limit=limit, kinds=kinds, q=q,
                                dispositions=dispositions, hist_day=hist_day)

    @r.get("/edr/endpoints/{endpoint_id}/trajectory/focus")
    async def focus(endpoint_id: str, raw_event_id: str | None = None, canonical_event_id: str | None = None,
                    event_iid: str | None = None, observation_id: str | None = None, event: str | None = None):
        from urllib.parse import unquote

        from edr_plane import trajectory_window as tw
        ref = unquote(event_iid or event or "") or None
        if ref and "#" not in ref:
            observation_id, ref = observation_id or ref, None
        event_iid = ref
        m = await kx.meta_for(_db(), endpoint_id)
        if m:
            return await kx.focus(_db(), m, event_iid=event_iid, observation_id=observation_id, raw_event_id=raw_event_id)
        await ensure_seeded()
        proj = await tw._projected(_db(), ident=_state["ident"], refs=_refs(_state["ident"]), docs_limit=None)
        hit = next((e for e in proj["rows"] if (event_iid and e.get("event_iid") == event_iid)
                    or (observation_id and e.get("observation_id") == observation_id)
                    or (raw_event_id and (e.get("provenance") or {}).get("raw_event_id") == raw_event_id)
                    or (canonical_event_id and (e.get("provenance") or {}).get("canonical_event_id") == canonical_event_id)), None)
        if not hit:
            return {"state": "OBSERVATION_NOT_RESOLVED", "focus": None}
        ms = tw._row_ms(hit)
        return {"state": "FOCUS_RESOLVED", "focus": {
            "event_iid": hit["event_iid"], "timestamp": hit["timestamp"], "event_type": hit.get("event_type"),
            "lane_index": hit.get("lane_index"), "observation_id": hit.get("observation_id"),
            "window": {"time_start": ps._iso(ms - 30 * ps.M), "time_end": ps._iso(ms + 30 * ps.M)}}}

    @r.get("/edr/endpoints/{endpoint_id}/trajectory/hours")
    async def hours(endpoint_id: str, day: str):
        from edr_plane import trajectory_window as tw
        d0 = tw.instant_ms(f"{day}T00:00:00Z")
        if d0 is None:
            raise HTTPException(422, "day must be YYYY-MM-DD")
        m = await kx.meta_for(_db(), endpoint_id)
        if m:
            ms = [x["ms"] for x in await kx._rows(_db(), m["device"], d0, d0 + ps.D - 1)]
        else:
            await ensure_seeded()
            proj = await tw._projected(_db(), ident=_state["ident"], refs=_refs(_state["ident"]), docs_limit=None)
            ms = [v for v in (tw._row_ms(x) for x in proj["rows"]) if v is not None and d0 <= v < d0 + ps.D]
        counts = [0] * 24
        for v in ms:
            counts[(v - d0) // ps.H] += 1
        return {"day": day, "hours": counts, "basis": "OBSERVATIONS_PER_HOUR_IN_RETAINED_EVIDENCE",
                "note": "0 = no observation retained for that hour; not proof the sensor was offline"}

    @r.get("/e3/preview/stale-trace")
    async def stale_trace(observation_id: str | None = None, limit: int = 500):
        from .stale_trace import trace
        meta = await ensure_seeded()
        return await trace(_db(), _state["ident"], _refs(_state["ident"]), observation_id=observation_id,
                           now_ms=int(time.time() * 1000), limit=limit) | {"dataset_ref_ms": meta["ref_ms"]}

    @r.get("/e3/preview/deeplink-cases")
    async def deeplink_cases():
        from edr_plane import trajectory_window as tw
        await ensure_seeded()
        db = _db()
        rows = (await tw._projected(db, ident=_state["ident"], refs=_refs(_state["ident"]), docs_limit=None))["rows"]
        rows = sorted((r for r in rows if tw._row_ms(r) is not None), key=tw._row_chrono)
        late = None
        async for d in db[tw.COLLECTION].find({}, {"_id": 0, "observation_id": 1, "event.ts": 1, "ingest_time": 1}):
            a, b = tw.instant_ms(d["event"]["ts"]), tw.instant_ms(d.get("ingest_time"))
            if a and b and b - a > 2 * ps.H:
                late = d["observation_id"]
                break
        by_obs = {r.get("observation_id"): r["event_iid"] for r in rows}
        old = next((r for r in rows if tw._row_ms(r) < rows[-1]["timestamp_instant_ms"] - 20 * ps.D), rows[0])
        return {"newest": rows[-1]["event_iid"], "deep_historical": old["event_iid"],
                "late_arrived": by_obs.get(late), "nonexistent": "obs_000000000000#0000000000"}

    @r.post("/e3/preview/reseed")
    async def reseed():
        meta = await ensure_seeded(force=True)
        return {k: meta[k] for k in ("ref_ms", "count", "label", "source")}

    @r.post("/e3/preview/seed-platforms")
    async def seed_platforms():
        from . import platform_seed as pls
        ref = int(time.time() * 1000) // 60_000 * 60_000
        stage = _db().client[os.environ["E3_PREVIEW_DB"] + "_linux_stage"]
        out = {"linux": await pls.seed_linux(_db(), stage, ref), "macos": await pls.seed_mac(_db(), ref)}
        await _db().client.drop_database(stage.name)
        return out

    @r.get("/xdr/rbac/session-context")
    async def session_context():
        return {"data": {"principal": {"email": "preview-analyst@e3.preview", "role": "PREVIEW_ANALYST"},
                         "tenant_scope": {"authorized": True, "authority_scope": "CUSTOMER", "all_tenants": False,
                                          "tenant_ids": [ps.TENANT], "explicit_tenant": None},
                         "customers": [tenant], "authorized_customers": [tenant],
                         "active_customer": {"value": ps.TENANT, "basis": "SINGLE_AUTHORIZED_TENANT"},
                         "edr_tenant_boundary": "PREVIEW_SYNTHETIC"}}

    @r.get("/edr/context")
    async def edr_context(endpoint_id: str | None = None, incident_id: str | None = None):
        return {"endpoint": {"hostname": ps.HOST, "endpoint_id": ps.ENDPOINT}, "incident": None}

    return r


def mount_if_enabled(app) -> bool:
    if os.environ.get(FLAG) != "1":
        return False
    app.include_router(build_router())
    return True
