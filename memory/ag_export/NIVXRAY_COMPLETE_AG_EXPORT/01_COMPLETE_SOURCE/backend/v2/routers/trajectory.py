"""v2/routers/trajectory.py · Device Trajectory endpoint (Phase 3d).

GET /api/v2/cases/{case_id}/trajectory/device
    - Loads shadow observations for the case.
    - Builds deterministic TrajectoryFrames.
    - Returns JSON (SSE streaming reserved for follow-up phase).

Flag-gated on TRAJECTORY_ENGINE. Read-only. Zero RC5 imports.
"""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from deps import require_admin, db as _db
from v2.flags import get as get_flag
from v2.trajectory import build_from_observations, LANES
from v2.shadow.irg import enrich as irg_enrich

router = APIRouter(prefix="/v2/cases", tags=["v2-trajectory"])


@router.get("/{case_id}/trajectory/device")
async def device_trajectory(case_id: str, limit: int = 500,
                            _: dict = Depends(require_admin)) -> dict[str, Any]:
    if not get_flag("TRAJECTORY_ENGINE").observable():
        raise HTTPException(status_code=503, detail="trajectory engine disabled")
    frames = await build_from_observations(_db, case_id=case_id,
                                           limit=max(1, min(limit, 5000)))
    frame_dicts = [f.to_dict() for f in frames]
    # P1 · Investigation Relationship Graph enrichment.
    # Every consumer (Device Trajectory, Process Ancestry, File / Registry /
    # Network Trajectory, Attack Chain, Report Generator) reads the same
    # canonical fields (entity.iid, parent.iid, root.iid, relationship.type,
    # execution.process_start/end/depth). See INVESTIGATION_RELATIONSHIP_GRAPH.md.
    frame_dicts = irg_enrich(frame_dicts)
    return {
        "ok": True,
        "case_id": case_id,
        "lanes": [{"key": l.key, "label": l.label, "order": l.order} for l in LANES],
        "frames": frame_dicts,
        "count": len(frame_dicts),
    }
