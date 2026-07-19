"""Analyst Workspace API (v2) — surfaces the deterministic Orchestrator.

Endpoints
---------
POST /api/v2/analyze                   → returns full AnalystReport
POST /api/v2/analyze/report?fmt=md|json|txt → returns report in requested format
GET  /api/v2/plugins                   → list registered decoder plugins (introspection)

Design notes
------------
This router calls the plugin-based Orchestrator directly. It is the FIRST
customer-facing surface for the new engine. The legacy `/api/analyze` and
`/api/decode/smart` routes are NOT modified — they continue to serve the
legacy pipeline until the Phase G cut-over.

Backwards-compat: routes are namespaced under `/api/v2/*` so any existing
client keeps working; new frontends opt in.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from deps import get_current_user
from engine import (
    AnalysisContext,
    AnalystReport,
    Budget,
    DecoderRegistry,
    Orchestrator,
)
from engine.config import new_budget
from engine.report import to_json, to_markdown, to_text

log = logging.getLogger("nivx.routers.v2")

router = APIRouter(prefix="/v2", tags=["analyst-workspace"])


class AnalyzeV2Request(BaseModel):
    input: str = Field(..., description="Encoded / obfuscated command line or payload")
    max_depth: Optional[int] = Field(None, ge=1, le=32)
    wall_time_ms: Optional[int] = Field(None, ge=100, le=60000)
    max_branches: Optional[int] = Field(None, ge=1, le=8)


class AnalyzeV2Response(BaseModel):
    report: AnalystReport


def _build_budget(req: AnalyzeV2Request) -> Budget:
    default = new_budget()
    return Budget(
        max_depth=req.max_depth or default.max_depth,
        max_branches=req.max_branches or default.max_branches,
        wall_time_ms=req.wall_time_ms or default.wall_time_ms,
    )


@router.post("/analyze", response_model=AnalyzeV2Response)
async def analyze_v2(req: AnalyzeV2Request, user=Depends(get_current_user)):
    """Run the deterministic orchestrator and return the full AnalystReport."""
    if not req.input or not req.input.strip():
        raise HTTPException(status_code=400, detail="input must be non-empty")
    ctx = AnalysisContext(budget=_build_budget(req))
    report = Orchestrator(ctx).run(req.input)
    return AnalyzeV2Response(report=report)


@router.post("/analyze/report")
async def analyze_v2_report(
    req: AnalyzeV2Request,
    fmt: str = "md",
    user=Depends(get_current_user),
):
    """Run the orchestrator and return the report in the requested format.

    Formats:
      md  (default)  → Markdown; content-type text/markdown
      json           → JSON; content-type application/json
      txt            → Plain text; content-type text/plain
    """
    if not req.input or not req.input.strip():
        raise HTTPException(status_code=400, detail="input must be non-empty")
    ctx = AnalysisContext(budget=_build_budget(req))
    report = Orchestrator(ctx).run(req.input)
    fmt_norm = fmt.lower().strip()
    if fmt_norm in ("md", "markdown"):
        body = to_markdown(report)
        media = "text/markdown; charset=utf-8"
        filename = "nivxray-analyst-report.md"
    elif fmt_norm == "json":
        body = to_json(report)
        media = "application/json"
        filename = "nivxray-analyst-report.json"
    elif fmt_norm in ("txt", "text"):
        body = to_text(report)
        media = "text/plain; charset=utf-8"
        filename = "nivxray-analyst-report.txt"
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported fmt: {fmt}")
    return Response(
        content=body,
        media_type=media,
        headers={"Content-Disposition": f'inline; filename="{filename}"'},
    )


@router.get("/plugins")
async def list_plugins(user=Depends(get_current_user)):
    """Introspection: what decoders are currently registered?"""
    plugins = []
    for p in DecoderRegistry.all():
        plugins.append({
            "id": p.id,
            "name": p.name,
            "category": p.category,
            "cost": p.cost,
            "tags": list(p.tags),
            "schema_version": p.schema_version,
        })
    plugins.sort(key=lambda x: (x["category"], x["cost"], x["id"]))
    return {"count": len(plugins), "plugins": plugins}
