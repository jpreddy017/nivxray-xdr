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

import base64
import decimal
import uuid
from collections.abc import Mapping
from datetime import date, datetime, time, timezone
from typing   import Any, Dict, List, Optional

from bson     import Decimal128, ObjectId
from fastapi   import APIRouter
from pydantic  import BaseModel, Field

from deps import db


router = APIRouter(prefix="/telemetry", tags=["telemetry"])


def _json_safe(value: Any) -> Any:
    """Recursively coerce a stored telemetry value into a JSON-encodable one.

    A document is legal in Mongo and fatal at the response boundary: this
    endpoint returns what it read, and the previous code normalised only the
    top-level `_id` and `recorded_at`. Any other BSON value — an `ObjectId`
    nested in a sub-document, a `Decimal128`, non-UTF-8 `Binary` — reached
    FastAPI's serializer and became an unauthenticated HTTP 500 (N-3).

    Conversion rules, deliberately explicit and lossless:

      * JSON-native (`str`, `int`, `float`, `bool`, `None`) — returned as-is,
        type preserved. No numeric value is reformatted.
      * `ObjectId`           → its 24-character hex string.
      * `Decimal128`/`Decimal` → `str` of the exact decimal. NOT `float`:
        that would silently lose precision on a value the client stored.
      * `bytes`/`Binary`     → base64 (ASCII). NOT a UTF-8 decode: binary is
        not text, and guessing raises `UnicodeDecodeError` on the first
        non-UTF-8 byte.
      * `datetime`/`date`/`time` → ISO-8601, unchanged from before.
      * `UUID`               → canonical string form.
      * mappings and sequences → walked recursively; key insertion order and
        element order are preserved, so the response stays deterministic.
      * anything else (`Regex`, `Code`, `Timestamp`, `MinKey`, `DBRef`, …)
        → `str`, so a type nobody anticipated degrades to a readable value
        instead of a 500.

    Nothing is dropped, renamed or swallowed: every key present in the stored
    document is present in the output, and no exception is suppressed.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, Decimal128):
        return str(value.to_decimal())
    if isinstance(value, decimal.Decimal):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return str(value)


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
    # Same records, same order, same field names — only BSON values that the
    # response serializer cannot encode are coerced. See `_json_safe`.
    records = [_json_safe(d) for d in docs]
    return {"count": len(records), "records": records}
