"""v2/routers/verdicts.py · Verdict Engine v3 endpoint.

GET  /api/v2/cases/{case_id}/verdicts?limit=200
    → { "engine": "v3", "verdicts": [ { frame_iid, score, band, breakdown, ... } ] }

GET  /api/v2/cases/{case_id}/verdicts/aggregate?limit=500
    → { "engine": "v3.1",
        "events":    { frame_iid: {...} },
        "processes": { entity_iid: {score, band, confidence, ...} },
        "chains":    { root_iid:   {score, band, confidence, ...} },
        "device":    { score, band, confidence, ... },
        "incident":  { score, band, confidence, ... } }

Read-only. Sits alongside the legacy `verdict` field on trajectory frames
— the frontend or reports may adopt v3 at their own pace.
"""
from __future__ import annotations
from collections import defaultdict
from fastapi import APIRouter, Depends, HTTPException
from deps import require_admin, db as _db
from v2.flags import get as get_flag
from v2.trajectory import build_from_observations
from v2.shadow.irg import enrich as irg_enrich
from v2.verdict import score, correlate

router = APIRouter(prefix="/v2/cases", tags=["v2-verdicts"])


@router.get("/{case_id}/verdicts")
async def verdicts(case_id: str, limit: int = 500,
                   _: dict = Depends(require_admin)) -> dict:
    if not get_flag("VERDICT_ENGINE_V3").observable():
        raise HTTPException(status_code=503, detail="verdict engine v3 disabled")

    frames = await build_from_observations(_db, case_id=case_id,
                                           limit=max(1, min(limit, 5000)))
    fdicts = [f.to_dict() for f in frames]
    fdicts = irg_enrich(fdicts)

    # Pre-compute per-entity file-write counts + entropy jumps for
    # MASS_FILE_ENCRYPTION context.
    file_writes: dict[str, int] = defaultdict(int)
    for fd in fdicts:
        if (fd.get("lane") or "").lower() == "file" and "write" in (fd.get("action") or "").lower():
            ent = (fd.get("entity") or {}).get("iid") or "?"
            file_writes[ent] += 1

    out = []
    band_counts: dict[str, int] = defaultdict(int)
    for fd in fdicts:
        ent_iid = (fd.get("entity") or {}).get("iid")
        ctx = {"file_writes_60s": file_writes.get(ent_iid, 0)}
        v = score(fd, ctx)
        band_counts[v.band] += 1
        out.append({
            "frame_iid":  fd.get("frame_iid") or fd.get("id"),
            "ts":         fd.get("ts"),
            "entity_iid": ent_iid,
            "score":      v.score,
            "band":       v.band,
            "explanation": v.explanation,
            "breakdown":   v.breakdown,
        })

    return {
        "ok":       True,
        "engine":   "v3",
        "case_id":  case_id,
        "count":    len(out),
        "bands":    dict(band_counts),
        "verdicts": out,
    }


@router.get("/{case_id}/verdicts/aggregate")
async def verdicts_aggregate(case_id: str, limit: int = 500,
                             _: dict = Depends(require_admin)) -> dict:
    """Multi-event correlation — Verdict Engine v3.1.

    Aggregates the per-event verdict up the attack graph:
        Event → Process → Chain → Device → Incident

    Uses the IRG's canonical parent/child relationships as the correlation
    substrate. Signals are de-duplicated per layer to avoid inflation.
    """
    if not get_flag("VERDICT_ENGINE_V3").observable():
        raise HTTPException(status_code=503, detail="verdict engine v3 disabled")

    frames = await build_from_observations(_db, case_id=case_id,
                                           limit=max(1, min(limit, 5000)))
    fdicts = [f.to_dict() for f in frames]
    fdicts = irg_enrich(fdicts)

    report = correlate(fdicts, case_id=case_id)
    payload = report.to_dict()
    payload["ok"] = True
    return payload
