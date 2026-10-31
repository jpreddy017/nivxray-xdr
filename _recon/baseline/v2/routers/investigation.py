"""v2/routers/investigation.py · Unified Investigation endpoint.

GET  /api/v2/cases/{case_id}/investigation?profile=soc_balanced
    → the complete Investigation Knowledge Graph (IKG) + verdicts +
      persistent header for the case. Every UI view reads from this.

Additive. Read-only. Flag-gated on VERDICT_ENGINE_V3.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from deps import db as _db
from v2.case_authz import engine_association, engine_case_read
from v2.flags import get as get_flag
from v2.trajectory import build_from_observations
from v2.investigation import build_investigation
from v2.investigation.explainability import why_is_this_not, list_patterns
from v2.ingestion.frame_enrich import enrich_frames_from_observations

router = APIRouter(prefix="/v2/cases", tags=["v2-investigation"])


@router.get("/{case_id}/investigation")
async def investigation(case_id: str, limit: int = 500,
                        profile: str = "soc_balanced",
                        grant: dict = Depends(engine_case_read)) -> dict:
    if not get_flag("VERDICT_ENGINE_V3").observable():
        raise HTTPException(status_code=503, detail="verdict engine v3 disabled")

    frames = await build_from_observations(_db, case_id=case_id,
                                           limit=max(1, min(limit, 5000)))
    fdicts = [f.to_dict() for f in frames]
    await enrich_frames_from_observations(_db, case_id, fdicts)
    inv = build_investigation(fdicts, case_id=case_id, profile=profile)
    payload = inv.to_dict()
    payload["ok"] = True
    payload["engine_association"] = await engine_association(_db, case_id,
                                                             grant)
    return payload


@router.get("/{case_id}/investigation/explain/{pattern_id}")
async def investigation_explain_negative(case_id: str, pattern_id: str,
                                         profile: str = "soc_balanced",
                                         grant: dict = Depends(engine_case_read)
                                         ) -> dict:
    """Deterministic "Why isn't this <pattern>?" reasoning.

    S3-B · this read carries the SAME authority as the other engine-depth
    reads (S2-mini): admin keeps its access, and any other principal may ask
    the question only about a `case_id` that IS an incident it is authorized
    for. Read-only — no profile, engine or verdict state can be changed here.
    """
    if not get_flag("VERDICT_ENGINE_V3").observable():
        raise HTTPException(status_code=503, detail="verdict engine v3 disabled")
    frames = await build_from_observations(_db, case_id=case_id, limit=500)
    fdicts = [f.to_dict() for f in frames]
    await enrich_frames_from_observations(_db, case_id, fdicts)
    inv = build_investigation(fdicts, case_id=case_id, profile=profile)
    dev = (inv.verdicts or {}).get("device") or {}
    result = why_is_this_not(pattern_id, dev)
    result["ok"] = True
    result["patterns_available"] = list_patterns()
    return result
