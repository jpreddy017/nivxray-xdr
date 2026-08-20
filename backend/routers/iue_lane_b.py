"""Lane-B analyze router — POST /api/iue/lane-b/analyze.

Feature-flag-gated (`IUE_STRUCTURED_LANE=on`) endpoint that accepts a
URL and walks it through the full Lane-B pipeline (intake → acquisition
→ parsing → normalization → aggregation → IUE).  Returns the SAME T2
wire contract as Lane A — the EVIDENCE tab consumes both identically.

Fix 1 preservation:
    When the underlying acquisition returns ok=False, this endpoint
    responds with 200 and a wire that carries the ``acquisition_failure``
    envelope byte-for-byte identical to what
    ``services/die/investigation_results.render`` emits today.
"""
from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, HTTPException, Form
from pydantic import BaseModel


router = APIRouter(prefix="/iue/lane-b", tags=["iue-lane-b"])


def _flag_on() -> bool:
    return os.environ.get("IUE_STRUCTURED_LANE", "off").lower() == "on"


class URLAnalyzeBody(BaseModel):
    url: str


@router.post("/analyze")
async def analyze(body: URLAnalyzeBody):
    """Analyse a URL / domain.  Returns the T2 wire shape."""
    if not _flag_on():
        raise HTTPException(
            status_code=503,
            detail={
                "error": "iue_structured_lane_disabled",
                "hint": "Set IUE_STRUCTURED_LANE=on to enable Lane B.",
            },
        )
    if not body.url or not body.url.strip():
        raise HTTPException(
            status_code=400, detail={"error": "missing_url"},
        )

    from services.iue.lanes.url_lane import analyze_url
    return analyze_url(body.url.strip())
