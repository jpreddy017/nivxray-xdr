"""History router — persistent investigation history + search + rehydrate.

Data model (collection: `investigations`):
    _id            : ObjectId
    user_email     : str        — investigations are user-scoped by default
    input_hash     : str        — sha256(input) for dedup (analyst re-pasting same payload)
    input_preview  : str        — first 500 chars of raw input
    input_length   : int
    chain          : list[str]  — recipe op ids in order (compact form)
    trace          : list[dict] — full per-layer trace (op, args, reason, output_preview, length)
    output_preview : str        — first 800 chars of decoded output
    output_length  : int
    engine         : str        — smart | magic | ai | custom_recipe
    confidence     : int        — 0-100
    reached_shellcode : bool
    iocs           : dict       — {urls: [], ips: [], domains: [], md5/sha1/sha256: [], ...}
    mitre          : list[dict] — [{id, technique, tactic, evidence, source}, ...]
    verdict        : dict|None  — {verdict, confidence, summary} from AI (nullable)
    tags           : list[str]  — user-set tags for grouping
    notes          : str        — user-authored freeform notes
    starred        : bool       — ⭐ pinned → survives TTL cleanup
    run_count      : int        — bumped every time same input is re-analysed
    first_seen     : datetime   — never bumped (creation)
    last_seen      : datetime   — bumped on re-runs
    ts             : datetime   — sort-key (== last_seen)

Retention policy:
    Non-starred docs expire 30 days after `last_seen` via a partial TTL index.
    Starred docs are retained forever.

Endpoints:
    POST  /api/history/record            (internal call from decode/investigate)
    GET   /api/history                    list with search + filters + pagination
    GET   /api/history/{id}               full doc for rehydrate
    PATCH /api/history/{id}               update tags/notes/starred
    DELETE /api/history/{id}
    GET   /api/history/export             download the user's full history as JSON
    POST  /api/history/import             bulk-restore a previously-exported bundle
    POST  /api/history/compare            diff two investigations by id
    GET   /api/history/stats              trends: confidence over time, engine mix, chain frequency
"""
from __future__ import annotations
import hashlib
import io
import json
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Body
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from deps import db, get_current_user

router = APIRouter()

RETENTION_DAYS = 30
_INDEX_READY = False


# ============================================================================
# Schemas
# ============================================================================
class HistoryRecordIn(BaseModel):
    input: str
    output: str = ""
    chain: List[str] = Field(default_factory=list)
    trace: List[Dict[str, Any]] = Field(default_factory=list)
    engine: Optional[str] = None
    confidence: int = 0
    reached_shellcode: bool = False
    iocs: Dict[str, Any] = Field(default_factory=dict)
    mitre: List[Dict[str, Any]] = Field(default_factory=list)
    verdict: Optional[Dict[str, Any]] = None
    tags: List[str] = Field(default_factory=list)
    notes: str = ""
    # Multi-stage chain persistence — when kind == "chain", `stages` and
    # `aggregate` carry the full multi-stage payload for rehydrate. For legacy
    # single-stage decodes, kind defaults to "single" and these fields stay empty.
    kind: str = "single"
    stages: List[Dict[str, Any]] = Field(default_factory=list)
    aggregate: Dict[str, Any] = Field(default_factory=dict)
    stage_labels: List[Optional[str]] = Field(default_factory=list)


class HistoryPatchIn(BaseModel):
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    starred: Optional[bool] = None


class HistoryImportIn(BaseModel):
    items: List[Dict[str, Any]]


class HistoryCompareIn(BaseModel):
    ids: List[str] = Field(..., min_length=2, max_length=2)


# ============================================================================
# Helpers
# ============================================================================
def _oid(v: Any) -> Optional[ObjectId]:
    try:
        return ObjectId(str(v))
    except Exception:
        return None


def _sha256(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8", errors="replace")).hexdigest()


def _serialize(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    out = dict(doc)
    out["id"] = str(out.pop("_id"))
    for k in ("first_seen", "last_seen", "ts"):
        v = out.get(k)
        if isinstance(v, datetime):
            out[k] = v.isoformat()
    return out


async def _ensure_indexes():
    """Idempotent index setup — called on first request."""
    global _INDEX_READY
    if _INDEX_READY:
        return
    coll = db.investigations
    try:
        # Dedup: one doc per (user, input_hash)
        await coll.create_index(
            [("user_email", 1), ("input_hash", 1)],
            unique=True, name="uniq_user_input",
        )
        # Sort by newest
        await coll.create_index([("user_email", 1), ("ts", -1)], name="user_ts")
        # Text search on input_preview + notes + chain + verdict summary
        await coll.create_index(
            [("input_preview", "text"), ("notes", "text"), ("tags", "text")],
            name="text_search",
        )
        # Filter facets
        await coll.create_index("iocs.urls")
        await coll.create_index("iocs.ips")
        await coll.create_index("iocs.domains")
        await coll.create_index("mitre.id")
        # TTL: expire non-starred docs 30d after last_seen
        # partial-filter-expression is critical — starred docs are retained forever
        await coll.create_index(
            "last_seen",
            expireAfterSeconds=RETENTION_DAYS * 24 * 60 * 60,
            partialFilterExpression={"starred": False},
            name="ttl_last_seen_nonstarred",
        )
        _INDEX_READY = True
    except Exception as e:
        # non-fatal — indexes may already exist from a previous shape
        import logging
        logging.getLogger("nivxray").warning("history index setup: %s", e)
        _INDEX_READY = True


async def _upsert_investigation(user_email: str, body: HistoryRecordIn) -> Dict[str, Any]:
    """Insert or update an investigation record with dedup by input_hash.

    On duplicate: bumps `run_count` and `last_seen`, keeps `first_seen` +
    existing tags/notes/starred flag, refreshes chain/verdict/iocs/confidence
    to reflect the LATEST decode result.
    """
    await _ensure_indexes()
    now = datetime.now(timezone.utc)
    h = _sha256(body.input)
    coll = db.investigations
    is_chain = (body.kind == "chain") and bool(body.stages)
    # For chain records, prune the stages payload so it fits comfortably in the
    # 16 MB BSON cap. Keep per-stage input full for restore, cap outputs to 8 KB.
    stored_stages: List[Dict[str, Any]] = []
    if is_chain:
        for s in body.stages:
            ss = dict(s)
            out = ss.get("output") or ""
            if isinstance(out, str) and len(out) > 8000:
                ss["output"] = out[:8000]
                ss["output_truncated"] = True
            stored_stages.append(ss)
    existing = await coll.find_one({"user_email": user_email, "input_hash": h})
    if existing:
        set_fields = {
            "chain": body.chain,
            "trace": body.trace,
            "output_preview": (body.output or "")[:800],
            "output_length": len(body.output or ""),
            "engine": body.engine,
            "confidence": body.confidence,
            "reached_shellcode": body.reached_shellcode,
            "iocs": body.iocs,
            "mitre": body.mitre,
            "verdict": body.verdict,
            "kind": body.kind,
            "last_seen": now,
            "ts": now,
        }
        if is_chain:
            set_fields.update({
                "stages": stored_stages,
                "aggregate": body.aggregate,
                "stage_labels": body.stage_labels,
                "stage_count": len(stored_stages),
            })
        await coll.update_one(
            {"_id": existing["_id"]},
            {"$set": set_fields, "$inc": {"run_count": 1}},
        )
        return _serialize(await coll.find_one({"_id": existing["_id"]}))
    doc = {
        "user_email": user_email,
        "input_hash": h,
        "input_preview": (body.input or "")[:500],
        "input_length": len(body.input or ""),
        "chain": body.chain,
        "trace": body.trace,
        "output_preview": (body.output or "")[:800],
        "output_length": len(body.output or ""),
        "engine": body.engine,
        "confidence": body.confidence,
        "reached_shellcode": body.reached_shellcode,
        "iocs": body.iocs,
        "mitre": body.mitre,
        "verdict": body.verdict,
        "tags": body.tags,
        "notes": body.notes,
        "starred": False,
        "run_count": 1,
        "first_seen": now,
        "last_seen": now,
        "ts": now,
        "kind": body.kind,
    }
    if is_chain:
        doc["stages"] = stored_stages
        doc["aggregate"] = body.aggregate
        doc["stage_labels"] = body.stage_labels
        doc["stage_count"] = len(stored_stages)
    r = await coll.insert_one(doc)
    doc["_id"] = r.inserted_id
    return _serialize(doc)


# Exposed helper — called from ops.decode_smart / ai.ai_auto_investigate
async def record_investigation(user_email: str, **kwargs) -> Optional[Dict[str, Any]]:
    """Fire-and-forget history recorder. Never raise — never block a decode."""
    try:
        body = HistoryRecordIn(**kwargs)
        return await _upsert_investigation(user_email, body)
    except Exception as e:
        import logging
        logging.getLogger("nivxray").warning("history record failed: %s", e)
        return None


# ============================================================================
# Endpoints
# ============================================================================
@router.get("/history")
async def list_history(
    q: str = "",
    verdict: str = "",           # Malicious | Suspicious | Benign
    engine: str = "",            # smart | magic | ai | custom_recipe
    kind: str = "",              # single | chain
    starred: Optional[bool] = None,
    shellcode: Optional[bool] = None,
    ioc: str = "",               # match against any IOC value
    mitre: str = "",             # match against MITRE technique id
    tag: str = "",
    since_days: int = 0,         # 0 = no time filter
    limit: int = 40,
    skip: int = 0,
    user=Depends(get_current_user),
):
    """Paginated history list with rich filters."""
    await _ensure_indexes()
    query: Dict[str, Any] = {"user_email": user["email"]}
    if q:
        query["$text"] = {"$search": q}
    if verdict:
        query["verdict.verdict"] = verdict
    if engine:
        query["engine"] = engine
    if kind:
        query["kind"] = kind
    if starred is not None:
        query["starred"] = starred
    if shellcode is not None:
        query["reached_shellcode"] = shellcode
    if tag:
        query["tags"] = tag
    if ioc:
        # match ANY IOC field
        query["$or"] = [
            {"iocs.urls": {"$regex": ioc, "$options": "i"}},
            {"iocs.ips": ioc},
            {"iocs.domains": {"$regex": ioc, "$options": "i"}},
            {"iocs.md5": ioc}, {"iocs.sha1": ioc}, {"iocs.sha256": ioc},
        ]
    if mitre:
        query["mitre.id"] = mitre
    if since_days > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
        query["ts"] = {"$gte": cutoff}
    cur = db.investigations.find(query).sort("ts", -1).skip(max(0, skip)).limit(max(1, min(200, limit)))
    items = [_serialize(d) async for d in cur]
    total = await db.investigations.count_documents(query)
    return {"total": total, "items": items, "limit": limit, "skip": skip}


@router.get("/history/stats")
async def history_stats(user=Depends(get_current_user)):
    """Trends & summary counts for the analyst's own history."""
    email = user["email"]
    base = {"user_email": email}
    total = await db.investigations.count_documents(base)
    starred = await db.investigations.count_documents({**base, "starred": True})
    shellcode = await db.investigations.count_documents({**base, "reached_shellcode": True})
    malicious = await db.investigations.count_documents({**base, "verdict.verdict": "Malicious"})
    # Engine mix
    engines = {}
    async for d in db.investigations.find(base, {"engine": 1}):
        e = d.get("engine") or "unknown"
        engines[e] = engines.get(e, 0) + 1
    # Confidence over last 30d
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    conf_series: List[Dict[str, Any]] = []
    async for d in db.investigations.find(
        {**base, "ts": {"$gte": cutoff}}, {"ts": 1, "confidence": 1}
    ).sort("ts", 1).limit(500):
        conf_series.append({
            "ts": d["ts"].isoformat() if isinstance(d.get("ts"), datetime) else str(d.get("ts")),
            "confidence": d.get("confidence", 0),
        })
    # Chain frequency
    chain_freq: Dict[str, int] = {}
    async for d in db.investigations.find(base, {"chain": 1}):
        key = " → ".join(d.get("chain") or []) or "(no-op)"
        chain_freq[key] = chain_freq.get(key, 0) + 1
    top_chains = sorted(chain_freq.items(), key=lambda x: -x[1])[:15]
    return {
        "total": total, "starred": starred, "shellcode": shellcode, "malicious": malicious,
        "engines": engines,
        "confidence_series": conf_series,
        "top_chains": [{"chain": k, "count": v} for k, v in top_chains],
    }


@router.get("/history/{iid}")
async def get_history(iid: str, user=Depends(get_current_user)):
    oid = _oid(iid)
    if not oid:
        raise HTTPException(status_code=400, detail="invalid id")
    doc = await db.investigations.find_one({"_id": oid, "user_email": user["email"]})
    if not doc:
        raise HTTPException(status_code=404, detail="not found")
    return _serialize(doc)


@router.patch("/history/{iid}")
async def patch_history(iid: str, body: HistoryPatchIn, user=Depends(get_current_user)):
    oid = _oid(iid)
    if not oid:
        raise HTTPException(status_code=400, detail="invalid id")
    updates: Dict[str, Any] = {}
    if body.tags is not None:
        updates["tags"] = [t.strip() for t in body.tags if t.strip()]
    if body.notes is not None:
        updates["notes"] = body.notes[:5000]
    if body.starred is not None:
        updates["starred"] = bool(body.starred)
    if not updates:
        raise HTTPException(status_code=400, detail="no fields to patch")
    r = await db.investigations.update_one(
        {"_id": oid, "user_email": user["email"]}, {"$set": updates},
    )
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="not found")
    doc = await db.investigations.find_one({"_id": oid, "user_email": user["email"]})
    return _serialize(doc)


@router.delete("/history/{iid}")
async def delete_history(iid: str, user=Depends(get_current_user)):
    oid = _oid(iid)
    if not oid:
        raise HTTPException(status_code=400, detail="invalid id")
    r = await db.investigations.delete_one({"_id": oid, "user_email": user["email"]})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="not found")
    return {"deleted": True}


@router.get("/history/export/bundle")
async def export_history(user=Depends(get_current_user)):
    """Download every investigation as a JSON bundle."""
    items = []
    async for d in db.investigations.find({"user_email": user["email"]}).sort("ts", -1):
        items.append(_serialize(d))
    payload = {
        "type": "nivxray.history.bundle",
        "version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "exported_by": user["email"],
        "count": len(items),
        "items": items,
    }
    return StreamingResponse(
        io.BytesIO(json.dumps(payload, indent=2).encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="nivxray_history_{int(datetime.now().timestamp())}.json"'},
    )


@router.post("/history/import")
async def import_history(body: HistoryImportIn, user=Depends(get_current_user)):
    """Bulk-restore a previously-exported history bundle. Skips duplicates."""
    await _ensure_indexes()
    imported, skipped = 0, 0
    for item in body.items:
        try:
            rec = HistoryRecordIn(
                input=item.get("input_preview", ""),
                output=item.get("output_preview", ""),
                chain=item.get("chain") or [],
                trace=item.get("trace") or [],
                engine=item.get("engine"),
                confidence=item.get("confidence", 0),
                reached_shellcode=bool(item.get("reached_shellcode")),
                iocs=item.get("iocs") or {},
                mitre=item.get("mitre") or [],
                verdict=item.get("verdict"),
                tags=item.get("tags") or [],
                notes=item.get("notes") or "",
                kind=item.get("kind") or "single",
                stages=item.get("stages") or [],
                aggregate=item.get("aggregate") or {},
                stage_labels=item.get("stage_labels") or [],
            )
            r = await _upsert_investigation(user["email"], rec)
            if (item.get("starred") or False) and r:
                await db.investigations.update_one(
                    {"_id": _oid(r["id"])}, {"$set": {"starred": True}},
                )
            imported += 1
        except Exception:
            skipped += 1
    return {"imported": imported, "skipped": skipped, "total_submitted": len(body.items)}


@router.post("/history/compare")
async def compare_history(body: HistoryCompareIn, user=Depends(get_current_user)):
    """Diff two investigations side-by-side (chain, IOCs, MITRE)."""
    oids = [_oid(x) for x in body.ids]
    if not all(oids):
        raise HTTPException(status_code=400, detail="invalid id(s)")
    docs = []
    for oid in oids:
        d = await db.investigations.find_one({"_id": oid, "user_email": user["email"]})
        if not d:
            raise HTTPException(status_code=404, detail=f"not found: {oid}")
        docs.append(_serialize(d))
    a, b = docs
    # simple set-diff on iocs + mitre + chain
    def _flat_iocs(x):
        out = []
        for k, v in (x.get("iocs") or {}).items():
            if isinstance(v, list):
                out.extend(f"{k}:{item}" for item in v)
        return set(out)
    a_i, b_i = _flat_iocs(a), _flat_iocs(b)
    a_m = {m.get("id") for m in (a.get("mitre") or []) if m.get("id")}
    b_m = {m.get("id") for m in (b.get("mitre") or []) if m.get("id")}
    return {
        "a": a, "b": b,
        "chain_equal": a.get("chain") == b.get("chain"),
        "shared_iocs": sorted(a_i & b_i),
        "only_in_a_iocs": sorted(a_i - b_i),
        "only_in_b_iocs": sorted(b_i - a_i),
        "shared_mitre": sorted(a_m & b_m),
        "only_in_a_mitre": sorted(a_m - b_m),
        "only_in_b_mitre": sorted(b_m - a_m),
    }
