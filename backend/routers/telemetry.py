"""Rule R24 · Frontend Performance Telemetry Endpoint
───────────────────────────────────────────────────
Receives client-side render / layout / paint timings after a
workspace paints its investigation and stores them under
``workspace_cases.performance_history[]`` so every investigation
gets an immutable frontend-timing record alongside the backend
timings already emitted on ``SSOT.metadata.performance``.

Contract (POST /api/telemetry/frontend):
    {
      "case_id":            "6a5a1...",           // OR null for adhoc
      "session_id":         "ses_...",            // OR null
      "backend_ms":         131,                   // seen by client
      "layout_ms":          212,                   // graph layout cost
      "render_ms":          34,                    // React render cost
      "paint_ms":           41,                    // dom paint cost
      "total_ms":           418,                   // wall-clock end-to-end
      "renders":            3,                     // window.__NIVXRAY_TRAJ_TELEM__.renders
      "layouts":            1,                     // window.__NIVXRAY_TRAJ_TELEM__.layouts
      "behaviors_count":    9,
      "tactics_count":      7,
      "notes":              ""                     // optional freeform
    }

Response: `{"ok": true, "stored": <count>}`.

R24 guarantee: any client can POST timings even if the case was
never saved — we accept the payload and keep a rolling 500-entry
window in Mongo so ops can grep for slow analysts / bad hardware.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing   import Any, Dict, List, Optional

from fastapi   import APIRouter
from pydantic  import BaseModel, Field

from deps import db


router = APIRouter(prefix="/telemetry", tags=["telemetry"])


class FrontendTelemetry(BaseModel):
    case_id:        Optional[str] = None
    session_id:     Optional[str] = None
    backend_ms:     Optional[float] = None
    layout_ms:      Optional[float] = None
    render_ms:      Optional[float] = None
    paint_ms:       Optional[float] = None
    total_ms:       Optional[float] = None
    renders:        Optional[int]   = None
    layouts:        Optional[int]   = None
    behaviors_count: Optional[int]  = None
    tactics_count:  Optional[int]   = None
    notes:          Optional[str]   = ""


@router.post("/frontend")
async def record_frontend_telemetry(payload: FrontendTelemetry) -> Dict[str, Any]:
    """Persist a frontend timing record."""
    now = datetime.now(timezone.utc)
    doc: Dict[str, Any] = payload.model_dump(exclude_none=True)
    doc["recorded_at"] = now
    # Rolling 500-entry window per case (bounded storage).
    if doc.get("case_id"):
        await db.workspace_cases.update_one(
            {"_id": doc["case_id"]},
            {"$push": {
                "performance_history": {
                    "$each":  [doc],
                    "$slice": -500,
                },
            }},
        )
    # Also keep a global rolling collection for cross-case dashboards.
    await db.frontend_telemetry.insert_one(doc)
    # Bound the global collection at 5000 rows (soft cap).
    try:
        cnt = await db.frontend_telemetry.count_documents({})
        if cnt > 5000:
            oldest = await db.frontend_telemetry.find(
                {}, sort=[("recorded_at", 1)]
            ).limit(cnt - 5000).to_list(length=cnt)
            if oldest:
                await db.frontend_telemetry.delete_many(
                    {"_id": {"$in": [o["_id"] for o in oldest]}}
                )
    except Exception:  # pragma: no cover — best effort
        pass
    return {"ok": True, "stored": 1, "recorded_at": now.isoformat()}


@router.get("/frontend/recent")
async def recent_frontend_telemetry(limit: int = 50) -> Dict[str, Any]:
    """Return the most recent N frontend telemetry records (admin dashboard)."""
    limit = max(1, min(500, int(limit or 50)))
    docs: List[Dict[str, Any]] = await db.frontend_telemetry.find(
        {}, sort=[("recorded_at", -1)]
    ).limit(limit).to_list(length=limit)
    for d in docs:
        d["_id"] = str(d.get("_id"))
        rec = d.get("recorded_at")
        if hasattr(rec, "isoformat"):
            d["recorded_at"] = rec.isoformat()
    return {"count": len(docs), "records": docs}
