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
    # Feb 2026 — friendly case name so History rows are identifiable as
    # "Immediate1", "Do not download into your machine", etc. Set by the
    # SAVE CASE flow and propagated to the linked history row.
    case_name: Optional[str] = None
    case_id: Optional[str] = None
    # Multi-stage chain persistence — when kind == "chain", `stages` and
    # `aggregate` carry the full multi-stage payload for rehydrate. For legacy
    # single-stage decodes, kind defaults to "single" and these fields stay empty.
    kind: str = "single"
    stages: List[Dict[str, Any]] = Field(default_factory=list)
    aggregate: Dict[str, Any] = Field(default_factory=dict)
    stage_labels: List[Optional[str]] = Field(default_factory=list)
    # ▲ IEDDE SSOT (2026-02 · Priority 1) — decision trace + canonical
    # recovery signals attached to every /decode/smart + /analyze/async
    # run. Persisted so History rehydrate can restore the full analyst
    # view (IEDDE Decision Trace panel + Recovery Status ribbon).
    iedde: Optional[Dict[str, Any]] = None
    iedde_terminal_state: Optional[str] = None
    canonical_confidence: Optional[int] = None
    canonical_confidence_reason: Optional[str] = None
    verdict_card: Optional[Dict[str, Any]] = None
    # ▲ Phase 4 · P1 · Cross-Artifact Correlation (2026-02-15)
    # Back-reference to the first-class Investigation (correlation) this
    # case belongs to. `None` = standalone case. Set by
    # /api/correlations/link (manual) or the auto-correlator on record.
    correlation_id: Optional[str] = None


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
        # Text search on input_preview + notes + tags + case_name (Feb 2026)
        await coll.create_index(
            [("input_preview", "text"), ("notes", "text"), ("tags", "text"),
             ("case_name", "text")],
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
            "input": (body.input or "")[:200_000],
            "output": (body.output or "")[:200_000],
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
        # Only overwrite case_name/case_id if the caller supplied them —
        # otherwise preserve the name from an earlier SAVE CASE tagging.
        if body.case_name:
            set_fields["case_name"] = body.case_name[:200]
        if body.case_id:
            set_fields["case_id"] = body.case_id
        # ▲ IEDDE SSOT (2026-02) — refresh on every re-run so the newest
        # trace and confidence live on the row.
        if body.iedde is not None:
            set_fields["iedde"] = body.iedde
        if body.iedde_terminal_state is not None:
            set_fields["iedde_terminal_state"] = body.iedde_terminal_state
        if body.canonical_confidence is not None:
            set_fields["canonical_confidence"] = body.canonical_confidence
        if body.canonical_confidence_reason is not None:
            set_fields["canonical_confidence_reason"] = body.canonical_confidence_reason
        if body.verdict_card is not None:
            set_fields["verdict_card"] = body.verdict_card
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
        "input": (body.input or "")[:200_000],
        "input_preview": (body.input or "")[:500],
        "input_length": len(body.input or ""),
        "chain": body.chain,
        "trace": body.trace,
        "output": (body.output or "")[:200_000],
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
        "case_name": (body.case_name or "")[:200] or None,
        "case_id": body.case_id,
        "starred": False,
        "run_count": 1,
        "first_seen": now,
        "last_seen": now,
        "ts": now,
        "kind": body.kind,
        # ▲ IEDDE SSOT · 2026-02 · Priority 1
        "iedde": body.iedde,
        "iedde_terminal_state": body.iedde_terminal_state,
        "canonical_confidence": body.canonical_confidence,
        "canonical_confidence_reason": body.canonical_confidence_reason,
        "verdict_card": body.verdict_card,
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
        rec = await _upsert_investigation(user_email, body)
        # KB Auto-Cluster (Feb 2026) — incrementally refresh the KB bucket for
        # the fingerprint this record just landed in. Runs on a background task
        # so decode latency is unaffected; synth=False keeps it LLM-free (the
        # deterministic playbook fallback is used).
        if rec and rec.get("id"):
            try:
                import asyncio
                from knowledge_base.builder import incremental_upsert_for_investigation
                asyncio.create_task(
                    incremental_upsert_for_investigation(user_email, rec["id"], synth=False)
                )
            except Exception as _kb_e:
                import logging
                logging.getLogger("nivxray").debug("kb auto-cluster hook: %s", _kb_e)

            # ▲ Phase 4 · P1 · 2026-02-15 — Master architecture §5 / §6.
            # Emit the Canonical Event Model (CEM) view and cache it on
            # the case doc for query-time convenience. This makes the
            # Investigation Engine's consumption boundary explicit.
            try:
                import asyncio as _asyncio
                _asyncio.create_task(_post_record_investigation_hook(user_email, rec["id"]))
            except Exception as _cem_e:
                import logging
                logging.getLogger("nivxray").debug("cem/auto-scan hook: %s", _cem_e)
        return rec
    except Exception as e:
        import logging
        logging.getLogger("nivxray").warning("history record failed: %s", e)
        return None


async def _post_record_investigation_hook(user_email: str, case_id: str) -> None:
    """▲ Phase 4 · P1 · 2026-02-15 — Master architecture §5 / §6.

    Runs as a background task after a case is recorded. Responsibilities:
      1. Emit the Canonical Event Model (CEM) view and cache it on the case
         doc (`case.cem`). Deterministic — no LLM.
      2. Auto-scan for cross-case correlations via the Investigation
         Engine. Cache the top-5 candidates on `case.pending_correlations`
         so the frontend can surface them without an extra round-trip.
      3. If the case is already in an Investigation, refresh the parent
         investigation's `updated_at` so it re-sorts in the list.

    Every failure mode is contained — nothing here blocks decode latency.
    """
    from bson import ObjectId
    try:
        oid = ObjectId(str(case_id))
    except Exception:
        return
    try:
        raw_case = await db.investigations.find_one({"_id": oid, "user_email": user_email})
        if not raw_case:
            return
        case_view = {**raw_case, "id": str(raw_case["_id"])}
        # 1 · CEM emit
        try:
            from services.cem import emit_cem
            cem = emit_cem(case_view)
            await db.investigations.update_one(
                {"_id": oid},
                {"$set": {"cem": cem,
                          "cem_emitted_at": datetime.now(timezone.utc)}},
            )
        except Exception as _e:
            import logging
            logging.getLogger("nivxray").debug("cem emit skipped: %s", _e)
        # 2 · Auto-scan for correlations (bounded, deterministic)
        try:
            from services.correlation_engine import scan_correlations
            suggestions = await scan_correlations(db, user_email, case_view,
                                                   limit_candidates=100)
            top = suggestions[:5]
            await db.investigations.update_one(
                {"_id": oid},
                {"$set": {"pending_correlations": top,
                          "pending_correlations_at": datetime.now(timezone.utc)}},
            )
        except Exception as _e:
            import logging
            logging.getLogger("nivxray").debug("auto-scan skipped: %s", _e)
        # 3 · If part of an investigation, bump its updated_at
        corr_id = raw_case.get("correlation_id")
        if corr_id:
            try:
                from bson import ObjectId as _OID
                await db.correlations.update_one(
                    {"_id": _OID(str(corr_id))},
                    {"$set": {"updated_at": datetime.now(timezone.utc)}},
                )
            except Exception:
                pass
    except Exception as e:
        import logging
        logging.getLogger("nivxray").warning("post_record hook failed: %s", e)



async def tag_history_with_case(user_email: str, input_text: str, case_name: str,
                                  case_id: Optional[str] = None) -> bool:
    """Attach a friendly `case_name` (and optional `case_id`) to the history
    row for the given input. Idempotent — called by /cases/save so History
    Drawer rows show the analyst-chosen name."""
    if not input_text or not case_name:
        return False
    await _ensure_indexes()
    h = _sha256(input_text)
    r = await db.investigations.update_one(
        {"user_email": user_email, "input_hash": h},
        {"$set": {"case_name": case_name[:200], "case_id": case_id}},
    )
    return r.matched_count > 0


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
    # ▲ 2026-02 · Owner enhancement · rich filters aligned with the
    # IEDDE SSOT signals persisted on every history row.
    interpreter: str = "",       # powershell | cmd | bash | python | perl | php | ruby
    terminal_state: str = "",    # canonical | binary_artifact_recovered | stability_gate | partial_recovery
    since_days: int = 0,         # 0 = no time filter
    limit: int = 40,
    skip: int = 0,
    user=Depends(get_current_user),
):
    """Paginated history list with rich filters."""
    await _ensure_indexes()
    query: Dict[str, Any] = {"user_email": user["email"]}
    if q:
        # Case-name / input / notes / tags matching. We use $or of regex
        # instead of $text so cases with a stale text-index still match.
        rgx = {"$regex": q, "$options": "i"}
        query["$or"] = [
            {"case_name":     rgx},
            {"input_preview": rgx},
            {"notes":         rgx},
            {"tags":          rgx},
        ]
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
    # ▲ IEDDE-aware filters — Interpreter is stored inside the IEDDE trace
    # (`stages[0].interpreter` / `iedde.final_interpreter`). Terminal state
    # is hoisted to the top-level `iedde_terminal_state` field on every row.
    if interpreter:
        query["$or"] = (query.get("$or") or []) + [
            {"iedde.final_interpreter": interpreter},
            {"iedde.stages.0.interpreter": interpreter},
        ]
    if terminal_state:
        query["iedde_terminal_state"] = terminal_state
    if since_days > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
        query["ts"] = {"$gte": cutoff}
    # LIST projection — omit the full `input` / `output` fields (can be large).
    # The row cards only need previews; RESTORE fetches the full doc via /history/{id}.
    # ▲ Keep the top-level IEDDE fields (iedde_terminal_state, canonical_confidence,
    # canonical_confidence_reason) AND a slim iedde subset (final_interpreter +
    # first stage.interpreter) so rich case cards can render without a per-row
    # network roundtrip. Drop the huge `iedde.stages` array — restore fetches it.
    _list_proj = {
        "input": 0, "output": 0, "trace": 0, "stages": 0, "aggregate": 0,
        "iedde.stages": 0, "iedde.canonical_output": 0,
    }
    cur = db.investigations.find(query, _list_proj).sort("ts", -1).skip(max(0, skip)).limit(max(1, min(200, limit)))
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
    result = _serialize(doc)
    # ▲ SOC EVIDENCE (Feb-2026) — regenerate verdict card + per-layer
    # metadata on rehydrate so History Playback shows the SAME analyst
    # workbench as fresh decodes. This is deterministic and stateless —
    # no history-doc migration required.
    try:
        from evidence_extractor import build_verdict_card, layer_metadata
        # The stored fields are `input_preview` / `output_preview`. Fall back
        # to them so the verdict card actually has content to score against.
        _in  = result.get("input") or result.get("input_preview") or ""
        _out = result.get("output") or result.get("output_preview") or ""
        _findings = {
            "iocs":             result.get("iocs") or {},
            "mitre_techniques": result.get("mitre") or [],
            "lolbas":           result.get("lolbas") or [],
        }
        result["verdict_card"] = build_verdict_card(
            input_text=_in,
            output_text=_out,
            chain=[{"op": s.get("op") or s if isinstance(s, str) else s.get("op"),
                    "args": s.get("args") if isinstance(s, dict) else {}}
                   for s in (result.get("chain") or [])
                   if s],
            corrupted_container=result.get("corrupted_container"),
            findings=_findings,
        )
        for t in (result.get("trace") or []):
            if isinstance(t, dict):
                t["evidence"] = layer_metadata(
                    t.get("op") or "",
                    t.get("output_preview") or "",
                    integrity_ok=("error" not in t),
                    integrity_reason=t.get("error"),
                )
    except Exception:
        pass
    # Fallback (Feb 2026) — if verdict_card regen came back empty but the
    # STORED verdict object has content (Malicious / risk_score / confidence),
    # hydrate the card from it so the top ANALYSIS VERDICT panel isn't
    # stuck on "Awaiting analysis · 0%".
    vc = result.get("verdict_card") or {}
    stored_verdict = result.get("verdict") if isinstance(result.get("verdict"), dict) else None
    if (not vc or not vc.get("verdict")) and stored_verdict and stored_verdict.get("verdict"):
        risk = stored_verdict.get("risk_score")
        conf = stored_verdict.get("confidence")
        result["verdict_card"] = {
            "verdict":    stored_verdict.get("verdict"),
            "label":      stored_verdict.get("verdict"),
            "risk_score": risk if risk is not None else conf,
            "confidence": conf if conf is not None else risk,
            "summary":    stored_verdict.get("summary"),
            "family":     stored_verdict.get("family"),
            "reasons":    (vc or {}).get("reasons") or [],
            "hydrated_from_history": True,
        }
    return result


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
