"""Knowledge Base router — /api/kb/*.

Endpoints
---------
POST /api/kb/rebuild            → rebuild the caller's KB from their history
GET  /api/kb/entries            → paginated + filterable list
GET  /api/kb/entries/{slug}     → full entry (with sample refs)
DELETE /api/kb/entries/{slug}
GET  /api/kb/search?q=...       → full-text search over KB
GET  /api/kb/stats              → user-scoped KB summary

All endpoints are user-scoped (KB rows carry `user_email`).
"""
from __future__ import annotations
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from deps import db, get_current_user
from knowledge_base.builder import rebuild_for_user

router = APIRouter()
log = logging.getLogger("nivxray")

_INDEX_READY = False


async def _ensure_indexes() -> None:
    global _INDEX_READY
    if _INDEX_READY:
        return
    coll = db.kb_entries
    try:
        await coll.create_index([("user_email", 1), ("fingerprint", 1)],
                                unique=True, name="uniq_user_fp")
        await coll.create_index([("user_email", 1), ("last_seen", -1)],
                                name="user_recency")
        await coll.create_index("mitre_ids")
        await coll.create_index("severity")
        await coll.create_index(
            [("title", "text"), ("summary", "text"), ("mitre_ids", "text")],
            name="kb_text_search",
        )
        _INDEX_READY = True
    except Exception as e:
        log.warning("kb index setup: %s", e)
        _INDEX_READY = True


def _serialize(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    out = dict(doc)
    out["id"] = str(out.pop("_id"))
    return out


# ─── Rebuild ─────────────────────────────────────────────────────────────
class RebuildIn(BaseModel):
    limit: int = 500              # cap over investigation history
    synth: bool = True            # if False: deterministic fallback (no LLM)


@router.post("/kb/rebuild", tags=["kb"])
async def rebuild_kb(body: RebuildIn = RebuildIn(), user=Depends(get_current_user)) -> Dict[str, Any]:
    """Rebuild the KB for the caller's investigation history.

    Idempotent: existing entries are refreshed in place. `first_seen` preserved.
    """
    await _ensure_indexes()
    started = datetime.now(timezone.utc)
    result = await rebuild_for_user(user["email"], limit=body.limit, synth=body.synth)
    result["took_ms"] = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    result["user_email"] = user["email"]
    return result


# ─── List / filter ───────────────────────────────────────────────────────
@router.get("/kb/entries", tags=["kb"])
async def list_entries(
    q: str = "",
    severity: str = "",
    mitre: str = "",
    verdict: str = "",
    limit: int = 40,
    skip: int = 0,
    user=Depends(get_current_user),
) -> Dict[str, Any]:
    await _ensure_indexes()
    query: Dict[str, Any] = {"user_email": user["email"]}
    if q:
        query["$text"] = {"$search": q}
    if severity:
        query["severity"] = severity
    if mitre:
        query["mitre_ids"] = mitre
    if verdict:
        query["verdict"] = verdict

    cur = db.kb_entries.find(query).sort("last_seen", -1)\
        .skip(max(0, skip)).limit(max(1, min(100, limit)))
    items = [_serialize(d) async for d in cur]
    total = await db.kb_entries.count_documents(query)
    return {"total": total, "items": items, "limit": limit, "skip": skip}


# ─── Full-text search shortcut ───────────────────────────────────────────
@router.get("/kb/search", tags=["kb"])
async def search_entries(q: str = Query(..., min_length=1),
                         user=Depends(get_current_user)) -> Dict[str, Any]:
    await _ensure_indexes()
    cur = db.kb_entries.find(
        {"user_email": user["email"], "$text": {"$search": q}},
        {"score": {"$meta": "textScore"}},
    ).sort([("score", {"$meta": "textScore"})]).limit(30)
    items = [_serialize(d) async for d in cur]
    return {"query": q, "total": len(items), "items": items}


# ─── Stats ───────────────────────────────────────────────────────────────
@router.get("/kb/stats", tags=["kb"])
async def kb_stats(user=Depends(get_current_user)) -> Dict[str, Any]:
    email = user["email"]
    base = {"user_email": email}
    total = await db.kb_entries.count_documents(base)
    if total == 0:
        return {"total": 0, "by_severity": {}, "by_verdict": {}, "top_mitre": []}

    sev, verd, mitre_c = {}, {}, {}
    async for d in db.kb_entries.find(base, {"severity": 1, "verdict": 1, "mitre_ids": 1}):
        sev[d.get("severity") or "unknown"] = sev.get(d.get("severity") or "unknown", 0) + 1
        verd[d.get("verdict") or "unknown"] = verd.get(d.get("verdict") or "unknown", 0) + 1
        for m in (d.get("mitre_ids") or []):
            mitre_c[m] = mitre_c.get(m, 0) + 1
    top_mitre = sorted(mitre_c.items(), key=lambda x: -x[1])[:15]
    return {
        "total": total,
        "by_severity": sev,
        "by_verdict": verd,
        "top_mitre": [{"id": k, "count": v} for k, v in top_mitre],
    }


# ─── Get one entry (with linked investigations) ──────────────────────────
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,64}$")


@router.get("/kb/entries/{slug}", tags=["kb"])
async def get_entry(slug: str, user=Depends(get_current_user)) -> Dict[str, Any]:
    if not _SLUG_RE.match(slug):
        raise HTTPException(status_code=400, detail="invalid slug")
    doc = await db.kb_entries.find_one({"user_email": user["email"], "slug": slug})
    if not doc:
        raise HTTPException(status_code=404, detail="not found")
    return _serialize(doc)


@router.delete("/kb/entries/{slug}", tags=["kb"])
async def delete_entry(slug: str, user=Depends(get_current_user)) -> Dict[str, Any]:
    if not _SLUG_RE.match(slug):
        raise HTTPException(status_code=400, detail="invalid slug")
    r = await db.kb_entries.delete_one({"user_email": user["email"], "slug": slug})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="not found")
    return {"deleted": True}


# ─── LLM provider chain visibility ───────────────────────────────────────
@router.get("/system/llm-providers", tags=["system"])
async def llm_providers(user=Depends(get_current_user)) -> Dict[str, Any]:
    """Show the current online→offline provider chain (for UI transparency)."""
    from llm_provider import list_providers
    return {"chain": list_providers()}
