"""/api/v2/parse · v2-only shadow-adapter parse endpoint (Phase 3).

**Completely independent of RC5.**  This endpoint invokes ONLY the
v2 command-line adapter + normalizer and returns a CEM v1 event.
It never imports `engine.*` and never calls any RC5 route.

Behind `NIVX_FLAG_ADAPTERS`. Returns 503 when the flag is disabled.

Reuses `require_admin` from `deps` — the only cross-namespace import
(stable, versioned utility) allowed per Round-6 conditions.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import require_admin
from v2.flags import get as get_flag
from v2.shadow import observe

router = APIRouter(prefix="/v2/parse", tags=["v2-parse"])


class ParseIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=32_768)
    case_id: str = Field(default="shadow-case-default")


class ParseOut(BaseModel):
    ok: bool
    cem_version: str
    event: dict[str, Any]


@router.post("", response_model=ParseOut)
async def parse_command_line(body: ParseIn, _: dict = Depends(require_admin)) -> Any:
    """Emit a CEM v1 event for the given command-line input.

    This is a v2-only pipeline: adapter.stream → normalizer.normalize.
    RC5 is not involved. No collection is written. Callers who want
    persistence must invoke `v2.shadow.persist(db, event)` explicitly
    (or use a future `/api/v2/observations` endpoint).
    """
    if not get_flag("ADAPTERS").observable():
        raise HTTPException(status_code=503, detail="v2 adapters disabled")
    event = observe(body.text, case_id=body.case_id)
    if event is None:
        # Should not happen when the flag is on, but guard anyway.
        raise HTTPException(status_code=500, detail="adapter produced no event")
    return ParseOut(ok=True, cem_version="v1", event=event.to_dict())
