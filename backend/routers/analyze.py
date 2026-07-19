"""Analyze router — /api/analyze (sync), /api/analyze/stream (SSE),
                   /api/analyze/async, /api/analyze/status/{job_id},
                   /api/analyze/{job_id}/feedback (GET/POST),
                   /api/admin/playbooks/{id}/votes.
"""
from __future__ import annotations
import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from schemas import AnalyzeIn, PlaybookFeedbackIn
from deps import db, get_current_user, require_admin, load_osint_keys
from operations import extract_iocs, mitre_map, yara_lite_scan, risk_score
from osint import enrich_iocs
from lolbas import scan_lolbas
from corrupt_payload_detector import detect_corrupt_payload
from analysis_core import ai_describe_and_verdict, lookup_ti_hits
import models_studio as ms

router = APIRouter()
log = logging.getLogger("nivxray")


# ============================================================================
# Sync /analyze
# ============================================================================
@router.post("/analyze")
async def analyze(body: AnalyzeIn, user=Depends(get_current_user)):
    text = (body.output or "") + "\n" + body.input
    iocs = extract_iocs(text)
    mitre = mitre_map(text)
    yara = yara_lite_scan(text)
    lolbas = scan_lolbas(text)
    risk = risk_score(mitre, yara, iocs)
    ti_hits = await lookup_ti_hits(iocs)
    # Corrupt-payload detector — catches fabricated / truncated blobs so
    # analysts don't waste time comparing NivXRay's blank output to another
    # tool's hallucinated "decoded" text.
    corrupt = detect_corrupt_payload(body.input or "")

    # v1.5.8 — parallel OSINT + AI with strict per-leg timeouts.
    # Prior bug: sequential + no timeout → any slow leg blocked the entire
    # sync /analyze route (Cloudflare 524 in prod when total ran >100s).
    _OSINT_DEADLINE_S = float(os.environ.get("NIVX_OSINT_DEADLINE_S", "20"))
    _AI_DEADLINE_S    = float(os.environ.get("NIVX_AI_DEADLINE_S",    "25"))

    async def _osint_leg():
        if not body.enrich_osint:
            return None
        keys = await load_osint_keys()
        try:
            return await asyncio.wait_for(enrich_iocs(iocs, keys), timeout=_OSINT_DEADLINE_S)
        except asyncio.TimeoutError:
            return {"error": f"OSINT timed out (>{int(_OSINT_DEADLINE_S)}s) — local TI hits only"}
        except Exception as e:
            return {"error": str(e)}

    async def _ai_leg():
        if not (body.use_ai_verdict or body.describe):
            return None
        # v1.6.1 — cache the "timeout" negative result so repeated attempts
        # skip the wait entirely. TTL 10 min.
        import hashlib as _hl
        _neg_key = "neg:" + _hl.sha1(
            ((body.input or "")[:2000] + "|" + (body.output or "")[:2000]).encode("utf-8", errors="replace")
        ).hexdigest()
        try:
            _neg = await db.ai_describe_cache.find_one({"_id": _neg_key})
            if _neg:
                from datetime import datetime as _dt
                age = (_dt.utcnow() - _dt.fromisoformat(_neg["cached_at"].replace("Z",""))).total_seconds()
                if age < 600:  # 10 min TTL
                    return {"error": f"AI timed out on this exact input {int(age)}s ago — try again later or edit input"}
        except Exception:
            pass
        try:
            return await asyncio.wait_for(
                ai_describe_and_verdict(
                    body.input, body.output or "", iocs, mitre, yara, {},
                    lolbas=lolbas,
                    want_verdict=body.use_ai_verdict, want_describe=body.describe,
                ),
                timeout=_AI_DEADLINE_S,
            )
        except asyncio.TimeoutError:
            # Persist the negative result so we don't re-attempt for 10 min.
            try:
                from datetime import datetime as _dt
                await db.ai_describe_cache.update_one(
                    {"_id": _neg_key},
                    {"$set": {"response": None, "timeout": True,
                               "cached_at": _dt.utcnow().isoformat()}},
                    upsert=True,
                )
            except Exception:
                pass
            return {"error": f"AI timed out (>{int(_AI_DEADLINE_S)}s) — narrative skipped, cached for 10 min"}
        except Exception as e:
            return {"error": str(e)}

    osint_data, ai_bundle = await asyncio.gather(_osint_leg(), _ai_leg())

    ai_verdict = None
    description = None
    if ai_bundle:
        if isinstance(ai_bundle, dict) and ai_bundle.get("error"):
            if body.use_ai_verdict: ai_verdict = {"error": ai_bundle["error"]}
            if body.describe:       description = {"error": ai_bundle["error"]}
        else:
            ai_verdict = ai_bundle.get("verdict") if body.use_ai_verdict else None
            description = ai_bundle.get("description") if body.describe else None

    merged_mitre = list(mitre)
    if description and isinstance(description, dict):
        ai_mitre = description.get("mitre_techniques") or []
        seen_ids = {m["id"] for m in merged_mitre}
        for m in ai_mitre:
            if isinstance(m, dict) and m.get("id") and m["id"] not in seen_ids:
                merged_mitre.append({
                    "id": m["id"], "technique": m.get("technique", ""),
                    "tactic": m.get("tactic", ""), "evidence": m.get("evidence", ""),
                    "source": "ai",
                })
                seen_ids.add(m["id"])
        for m in merged_mitre:
            m.setdefault("source", "heuristic")

    return {
        "iocs": iocs, "mitre": merged_mitre, "yara": yara, "lolbas": lolbas, "risk": risk,
        "osint": osint_data, "ti_hits": ti_hits,
        "ai_verdict": ai_verdict, "description": description,
        "corrupt_payload": corrupt,
    }


# ============================================================================
# SSE /analyze/stream
# ============================================================================
def _sse(event: str, payload: Any) -> bytes:
    body = json.dumps(payload, default=str)
    return f"event: {event}\ndata: {body}\n\n".encode("utf-8")


@router.post("/analyze/stream")
async def analyze_stream(body: AnalyzeIn, user=Depends(get_current_user)):
    """SSE analog of /api/analyze — streams progress + partial + final result."""
    async def gen():
        try:
            yield _sse("status", {"phase": "extract", "message": "Extracting IOCs, MITRE, YARA, LOLBAS…"})
            text = (body.output or "") + "\n" + body.input
            iocs = extract_iocs(text)
            mitre = mitre_map(text)
            yara = yara_lite_scan(text)
            lolbas = scan_lolbas(text)
            risk = risk_score(mitre, yara, iocs)
            partial = {"iocs": iocs, "mitre": mitre, "yara": yara, "lolbas": lolbas, "risk": risk}
            yield _sse("partial", partial)
        except Exception as e:
            yield _sse("error", {"phase": "extract", "error": str(e)})
            return

        try:
            yield _sse("status", {"phase": "ti_hits", "message": "Cross-referencing local Threat-Intel DB…"})
            ti_hits = await lookup_ti_hits(iocs)
            yield _sse("ti_hits", ti_hits)
        except Exception as e:
            ti_hits = []
            yield _sse("error", {"phase": "ti_hits", "error": str(e)})

        yield _sse("status", {"phase": "enrich_and_ai", "message": "Running OSINT enrichment + AI analysis in parallel…"})

        # v1.5.8 — hard-cap each of the two parallel legs. Previously the loop
        # would wait until BOTH tasks finished, and a slow Claude call could
        # stretch the whole route past 90 s. Now each leg has its own strict
        # deadline; whichever legs miss it get cancelled and the pipeline
        # completes with the results it already has.
        _OSINT_DEADLINE_S = float(os.environ.get("NIVX_OSINT_DEADLINE_S", "20"))
        _AI_DEADLINE_S    = float(os.environ.get("NIVX_AI_DEADLINE_S",    "25"))

        async def _run_osint():
            if not body.enrich_osint:
                return None
            keys = await load_osint_keys()
            try:
                return await asyncio.wait_for(enrich_iocs(iocs, keys),
                                              timeout=_OSINT_DEADLINE_S)
            except asyncio.TimeoutError:
                return {"error": f"OSINT timed out (>{int(_OSINT_DEADLINE_S)}s) — falling back to local TI hits only"}

        async def _run_ai():
            if not (body.use_ai_verdict or body.describe):
                return None
            try:
                return await asyncio.wait_for(
                    ai_describe_and_verdict(
                        body.input, body.output or "", iocs, mitre, yara, {},
                        lolbas=lolbas,
                        want_verdict=body.use_ai_verdict, want_describe=body.describe,
                    ),
                    timeout=_AI_DEADLINE_S,
                )
            except asyncio.TimeoutError:
                return {"error": f"AI verdict timed out (>{int(_AI_DEADLINE_S)}s) — pipeline proceeded without LLM narrative"}

        osint_task = asyncio.create_task(_run_osint())
        ai_task = asyncio.create_task(_run_ai())
        pending = {osint_task, ai_task}
        elapsed = 0
        osint_data: Optional[Dict[str, Any]] = None
        ai_bundle: Optional[Dict[str, Any]] = None
        while pending:
            done, pending = await asyncio.wait(pending, timeout=10.0, return_when=asyncio.FIRST_COMPLETED)
            elapsed += 10
            if not done:
                yield _sse("heartbeat", {"elapsed_s": elapsed, "phase": "waiting"})
                yield b": keep-alive\n\n"
                continue
            for t in done:
                try:
                    r = t.result()
                except Exception as e:
                    if t is osint_task:
                        osint_data = {"error": str(e)}
                        yield _sse("error", {"phase": "osint", "error": str(e)})
                    else:
                        ai_bundle = None
                        yield _sse("error", {"phase": "ai", "error": str(e)})
                    continue
                if t is osint_task:
                    osint_data = r
                    yield _sse("osint", osint_data or {})
                else:
                    ai_bundle = r
                    if ai_bundle:
                        if body.use_ai_verdict and ai_bundle.get("verdict") is not None:
                            yield _sse("ai_verdict", ai_bundle.get("verdict"))
                        if body.describe and ai_bundle.get("description") is not None:
                            yield _sse("description", ai_bundle.get("description"))

        ai_verdict = ai_bundle.get("verdict") if (ai_bundle and body.use_ai_verdict) else None
        description = ai_bundle.get("description") if (ai_bundle and body.describe) else None

        merged_mitre = list(mitre)
        if description and isinstance(description, dict):
            ai_mitre = description.get("mitre_techniques") or []
            seen_ids = {m["id"] for m in merged_mitre}
            for m in ai_mitre:
                if isinstance(m, dict) and m.get("id") and m["id"] not in seen_ids:
                    merged_mitre.append({
                        "id": m["id"], "technique": m.get("technique", ""),
                        "tactic": m.get("tactic", ""), "evidence": m.get("evidence", ""),
                        "source": "ai",
                    })
                    seen_ids.add(m["id"])
            for m in merged_mitre:
                m.setdefault("source", "heuristic")

        final = {
            "iocs": iocs, "mitre": merged_mitre, "yara": yara, "lolbas": lolbas, "risk": risk,
            "osint": osint_data, "ti_hits": ti_hits,
            "ai_verdict": ai_verdict, "description": description,
        }
        yield _sse("result", final)
        yield _sse("done", {"ok": True})

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ============================================================================
# Async /analyze/async pipeline
# ============================================================================
_JOB_TTL_SEC = 60 * 15
_ANALYZE_JOBS_INDEX_READY = False


async def _ensure_jobs_indexes():
    global _ANALYZE_JOBS_INDEX_READY
    if _ANALYZE_JOBS_INDEX_READY:
        return
    try:
        await db.analyze_jobs.create_index(
            "created_at", expireAfterSeconds=_JOB_TTL_SEC, name="ttl_created_at"
        )
        _ANALYZE_JOBS_INDEX_READY = True
    except Exception as e:
        log.warning("analyze_jobs TTL index create failed: %s", e)


async def _job_get(job_id: str) -> Optional[Dict[str, Any]]:
    return await db.analyze_jobs.find_one({"_id": job_id}, {"created_at": 0})


async def _job_set(job_id: str, updates: Dict[str, Any]) -> None:
    updates = {k: v for k, v in updates.items() if not k.startswith("_")}
    updates["updated_at"] = datetime.now(timezone.utc)
    await db.analyze_jobs.update_one({"_id": job_id}, {"$set": updates}, upsert=False)


async def _job_push_error(job_id: str, phase: str, err: str) -> None:
    await db.analyze_jobs.update_one(
        {"_id": job_id},
        {"$push": {"errors": {"phase": phase, "error": err}},
         "$set": {"updated_at": datetime.now(timezone.utc)}},
    )


async def _run_analysis_job(job_id: str, body: AnalyzeIn):
    try:
        text = (body.output or "") + "\n" + body.input
        iocs = extract_iocs(text)
        mitre = mitre_map(text)
        yara = yara_lite_scan(text)
        lolbas = scan_lolbas(text)
        try:
            custom_rules = await ms._load_active_rules(db)
            custom_hits = ms.scan_custom_rules(text, custom_rules)
            for h in custom_hits:
                if h.get("model_id"):
                    await ms.increment_usage(db, h["model_id"])
            lolbas = lolbas + custom_hits
        except Exception as e:
            log.warning("custom detection rules failed: %s", e)
        risk = risk_score(mitre, yara, iocs)
        await _job_set(job_id, {
            "iocs": iocs, "mitre": mitre, "yara": yara, "lolbas": lolbas, "risk": risk,
            "phase": "ti_hits", "progress": 15,
        })

        ti_hits = await lookup_ti_hits(iocs)
        await _job_set(job_id, {
            "ti_hits": ti_hits, "phase": "enrich_and_ai", "progress": 25,
        })

        persona = await ms.get_persona(db, body.persona_id) if body.persona_id else None
        provider = await ms.get_provider(db, body.provider_id)
        playbook_block, playbooks_used = await ms.compose_playbook_prompt_with_meta(db, target="ai")
        await _job_set(job_id, {"playbooks_used": playbooks_used})
        if persona and persona.get("id"):
            await ms.increment_usage(db, persona["id"])
        if provider and provider.get("id") and body.provider_id:
            await ms.increment_usage(db, provider["id"])

        async def _run_osint():
            if not body.enrich_osint:
                return None
            keys = await load_osint_keys()
            return await enrich_iocs(iocs, keys)

        async def _run_ai():
            if not (body.use_ai_verdict or body.describe):
                return None
            return await ai_describe_and_verdict(
                body.input, body.output or "", iocs, mitre, yara, {},
                lolbas=lolbas,
                want_verdict=body.use_ai_verdict, want_describe=body.describe,
                persona=persona, provider=provider, playbook=playbook_block,
            )

        osint_task = asyncio.create_task(_run_osint())
        ai_task = asyncio.create_task(_run_ai())
        pending = {osint_task, ai_task}
        osint_data: Optional[Dict[str, Any]] = None
        ai_bundle: Optional[Dict[str, Any]] = None
        start = datetime.now(timezone.utc).timestamp()

        while pending:
            done, pending = await asyncio.wait(pending, timeout=2.0, return_when=asyncio.FIRST_COMPLETED)
            elapsed_s = int(datetime.now(timezone.utc).timestamp() - start)
            heartbeat: Dict[str, Any] = {"elapsed_s": elapsed_s}
            for t in done:
                try:
                    r = t.result()
                except Exception as e:
                    if t is osint_task:
                        osint_data = {"error": str(e)}
                        heartbeat["osint"] = osint_data
                        await _job_push_error(job_id, "osint", str(e))
                    else:
                        ai_bundle = None
                        await _job_push_error(job_id, "ai", str(e))
                    continue
                if t is osint_task:
                    osint_data = r
                    heartbeat["osint"] = osint_data
                    heartbeat["progress"] = 45
                else:
                    ai_bundle = r
                    if ai_bundle:
                        if body.use_ai_verdict and ai_bundle.get("verdict") is not None:
                            heartbeat["ai_verdict"] = ai_bundle.get("verdict")
                        if body.describe and ai_bundle.get("description") is not None:
                            heartbeat["description"] = ai_bundle.get("description")
                    heartbeat["progress"] = 90
            await _job_set(job_id, heartbeat)

        merged_mitre = list(mitre)
        description = ai_bundle.get("description") if ai_bundle else None
        if description and isinstance(description, dict):
            ai_mitre = description.get("mitre_techniques") or []
            seen_ids = {m["id"] for m in merged_mitre}
            for m in ai_mitre:
                if isinstance(m, dict) and m.get("id") and m["id"] not in seen_ids:
                    merged_mitre.append({
                        "id": m["id"], "technique": m.get("technique", ""),
                        "tactic": m.get("tactic", ""), "evidence": m.get("evidence", ""),
                        "source": "ai",
                    })
                    seen_ids.add(m["id"])
            for m in merged_mitre:
                m.setdefault("source", "heuristic")
        await _job_set(job_id, {
            "mitre": merged_mitre,
            "status": "done", "progress": 100, "phase": "complete",
        })
    except Exception as e:
        log.exception("analysis job %s failed", job_id)
        await _job_set(job_id, {"status": "error", "error": str(e), "phase": "error"})


@router.post("/analyze/async")
async def analyze_async(body: AnalyzeIn, user=Depends(get_current_user)):
    """Kick off an analysis job. Returns immediately with a job_id."""
    await _ensure_jobs_indexes()
    job_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    await db.analyze_jobs.insert_one({
        "_id": job_id, "status": "running",
        "phase": "extract", "progress": 5,
        "created_at": now, "updated_at": now,
        "requested_by": user.get("email"),
    })
    asyncio.create_task(_run_analysis_job(job_id, body))
    return {"job_id": job_id, "status": "running"}


@router.get("/analyze/status/{job_id}")
async def analyze_status(job_id: str, user=Depends(get_current_user)):
    doc = await _job_get(job_id)
    if not doc:
        raise HTTPException(status_code=404, detail="job not found or expired")
    doc["job_id"] = doc.pop("_id")
    for k in ("updated_at",):
        if isinstance(doc.get(k), datetime):
            doc[k] = doc[k].isoformat()
    return doc


@router.post("/analyze/{job_id}/feedback")
async def analyze_feedback(job_id: str, body: PlaybookFeedbackIn,
                            user=Depends(get_current_user)):
    """Record a 👍/👎 vote on the AI investigation attached to `job_id`."""
    job = await _job_get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found or expired")
    playbooks_used = job.get("playbooks_used") or []
    if not playbooks_used:
        raise HTTPException(status_code=400,
                            detail="this investigation did not apply any playbook — nothing to feedback on")
    try:
        result = await ms.record_playbook_vote(
            db, job_id, user.get("email") or "anonymous",
            playbooks_used, body.vote, body.reason,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    result["playbooks_used"] = playbooks_used
    return result


@router.get("/analyze/{job_id}/feedback")
async def analyze_feedback_get(job_id: str, user=Depends(get_current_user)):
    job = await _job_get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found or expired")
    playbooks_used = job.get("playbooks_used") or []
    vote = await ms.get_vote_for_job(db, job_id, user.get("email") or "anonymous")
    return {"job_id": job_id, "playbooks_used": playbooks_used, **vote}


@router.get("/admin/playbooks/{playbook_id}/votes")
async def playbook_votes(playbook_id: str, limit: int = 50, user=Depends(require_admin)):
    return {
        "playbook_id": playbook_id,
        "votes": await ms.list_playbook_votes(db, playbook_id, limit=limit),
    }
