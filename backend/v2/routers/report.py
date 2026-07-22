"""v2/routers/report.py · Investigation Report API (R4).

Endpoints:
    GET  /api/v2/cases/{case_id}/report        → ReportEnvelope JSON
    GET  /api/v2/cases/{case_id}/report.md     → text/markdown

Deterministic: same case + same observations → identical JSON bytes.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse

from deps import require_admin, db as _db
from v2.flags import get as get_flag
from v2.report import build_report, render_markdown

router = APIRouter(prefix="/v2/cases", tags=["v2-report"])


def _guard() -> None:
    if not get_flag("TRAJECTORY_ENGINE").observable():
        raise HTTPException(status_code=503, detail="trajectory engine disabled")


@router.get("/{case_id}/report")
async def get_report_json(case_id: str, _: dict = Depends(require_admin)) -> dict:
    _guard()
    env = await build_report(_db, case_id)
    return env.model_dump()


@router.get("/{case_id}/report.md", response_class=PlainTextResponse)
async def get_report_markdown(case_id: str, _: dict = Depends(require_admin)) -> str:
    _guard()
    env = await build_report(_db, case_id)
    return render_markdown(env)
