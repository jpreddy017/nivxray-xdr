"""Threat Intelligence router — /api/threat-intel/*"""
from __future__ import annotations
import asyncio
import re
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException

from deps import db, get_current_user, require_admin, load_osint_keys
from feeds import SOURCES as FEED_SOURCES, sync_source

router = APIRouter()


async def _ensure_iocs_indexes():
    """Ensure indexes on the iocs collection."""
    try:
        await db.iocs.create_index([("kind", 1), ("value", 1), ("source", 1)],
                                    unique=True, name="uniq_ioc")
        await db.iocs.create_index([("source", 1)])
        await db.iocs.create_index([("severity", 1)])
        await db.iocs.create_index([("last_seen", -1)])
    except Exception:
        pass


@router.get("/threat-intel/sources")
async def ti_sources(user=Depends(get_current_user)):
    keys = await load_osint_keys()
    meta_docs = {m["_id"]: m async for m in db.ti_source_meta.find({})}
    out = []
    for s in FEED_SOURCES:
        needs = s.get("needs_key")
        configured = (needs is None) or bool(keys.get(needs))
        m = meta_docs.get(s["id"]) or {}
        out.append({
            **s, "configured": configured,
            "last_sync": m.get("last_sync"),
            "last_status": m.get("last_status"),
            "last_new": m.get("last_new", 0),
            "last_updated": m.get("last_updated", 0),
            "last_error": m.get("last_error"),
            "total_indicators": m.get("total_indicators", 0),
        })
    return out


@router.get("/threat-intel/stats")
async def ti_stats(user=Depends(get_current_user)):
    total = await db.iocs.count_documents({})
    critical = await db.iocs.count_documents({"severity": "critical"})
    high = await db.iocs.count_documents({"severity": "high"})
    medium = await db.iocs.count_documents({"severity": "medium"})
    low = await db.iocs.count_documents({"severity": "low"})
    by_kind = {}
    for k in ("ip", "domain", "url", "md5", "sha1", "sha256"):
        by_kind[k] = await db.iocs.count_documents({"kind": k})
    return {"total": total, "critical": critical, "high": high,
            "medium": medium, "low": low, "by_kind": by_kind}


async def _apply_iocs(iocs: List[Dict[str, Any]], source_id: str) -> Dict[str, int]:
    """Upsert a batch of IOC docs."""
    new_count = 0
    upd_count = 0
    for doc in iocs:
        key = {"kind": doc["kind"], "value": doc["value"], "source": source_id}
        existing = await db.iocs.find_one(key, {"_id": 1})
        update = {
            "$set": {"severity": doc["severity"], "tags": doc["tags"],
                     "extra": doc["extra"], "last_seen": doc["last_seen"]},
            "$setOnInsert": {"first_seen": doc["first_seen"]},
        }
        r = await db.iocs.update_one(key, update, upsert=True)
        if r.upserted_id is not None or existing is None:
            new_count += 1
        else:
            upd_count += 1
    return {"new": new_count, "updated": upd_count}


@router.post("/threat-intel/sync/{source_id}")
async def ti_sync_one(source_id: str, user=Depends(require_admin)):
    src = next((s for s in FEED_SOURCES if s["id"] == source_id), None)
    if not src:
        raise HTTPException(status_code=404, detail="Unknown source")
    if not src.get("bulk"):
        raise HTTPException(status_code=400, detail="This source is lookup-only (no bulk feed)")
    keys = await load_osint_keys()
    result = await sync_source(source_id, keys)
    ts = datetime.now(timezone.utc).isoformat()
    if result.get("error"):
        await db.ti_source_meta.update_one(
            {"_id": source_id},
            {"$set": {"last_sync": ts, "last_status": "error", "last_error": result["error"]}},
            upsert=True,
        )
        return {"ok": False, "error": result["error"], "source": source_id}
    counts = await _apply_iocs(result["iocs"], source_id)
    total = await db.iocs.count_documents({"source": source_id})
    await db.ti_source_meta.update_one(
        {"_id": source_id},
        {"$set": {"last_sync": ts, "last_status": "ok", "last_error": None,
                  "last_new": counts["new"], "last_updated": counts["updated"],
                  "total_indicators": total}},
        upsert=True,
    )
    return {"ok": True, "source": source_id, "fetched": len(result["iocs"]),
            **counts, "total_indicators": total}


@router.post("/threat-intel/sync-all")
async def ti_sync_all(user=Depends(require_admin)):
    keys = await load_osint_keys()
    bulk_sources = [s for s in FEED_SOURCES if s.get("bulk")]

    async def _one(src):
        return src["id"], await sync_source(src["id"], keys)

    results = await asyncio.gather(*[_one(s) for s in bulk_sources], return_exceptions=True)
    summary = []
    ts = datetime.now(timezone.utc).isoformat()
    for r in results:
        if isinstance(r, Exception):
            summary.append({"source": "?", "error": str(r), "ok": False})
            continue
        sid, res = r
        if res.get("error"):
            await db.ti_source_meta.update_one(
                {"_id": sid},
                {"$set": {"last_sync": ts, "last_status": "error", "last_error": res["error"]}},
                upsert=True,
            )
            summary.append({"source": sid, "ok": False, "error": res["error"]})
            continue
        counts = await _apply_iocs(res["iocs"], sid)
        total = await db.iocs.count_documents({"source": sid})
        await db.ti_source_meta.update_one(
            {"_id": sid},
            {"$set": {"last_sync": ts, "last_status": "ok", "last_error": None,
                      "last_new": counts["new"], "last_updated": counts["updated"],
                      "total_indicators": total}},
            upsert=True,
        )
        summary.append({"source": sid, "ok": True, "fetched": len(res["iocs"]),
                        **counts, "total_indicators": total})
    return {"results": summary, "ts": ts}


@router.get("/threat-intel/iocs")
async def ti_iocs(user=Depends(get_current_user), q: str = "", kind: str = "",
                  source: str = "", severity: str = "", limit: int = 100, skip: int = 0):
    query: Dict[str, Any] = {}
    if kind: query["kind"] = kind
    if source: query["source"] = source
    if severity: query["severity"] = severity
    if q:
        query["value"] = {"$regex": re.escape(q), "$options": "i"}
    cur = db.iocs.find(query, {"_id": 0}).sort("last_seen", -1).skip(max(0, skip)).limit(max(1, min(500, limit)))
    docs = await cur.to_list(limit)
    total = await db.iocs.count_documents(query)
    return {"total": total, "items": docs}


@router.get("/threat-intel/lookup/{value}")
async def ti_lookup(value: str, user=Depends(get_current_user)):
    """Return every stored IOC that matches this exact value (across all sources)."""
    docs = await db.iocs.find({"value": value}, {"_id": 0}).to_list(50)
    return {"value": value, "hits": docs}
