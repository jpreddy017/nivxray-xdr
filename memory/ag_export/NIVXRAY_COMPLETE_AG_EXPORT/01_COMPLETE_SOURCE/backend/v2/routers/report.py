"""v2/routers/report.py · Investigation Report API (R4).

Endpoints:
    GET  /api/v2/cases/{case_id}/report              → ReportEnvelope JSON
    GET  /api/v2/cases/{case_id}/report.md           → text/markdown
    GET  /api/v2/cases/{case_id}/report.pdf          → application/pdf
    GET  /api/v2/cases/{case_id}/report.stix.json    → STIX 2.1 bundle
    GET  /api/v2/cases/{case_id}/report.bundle.zip   → evidence package

Deterministic: same case + same observations → identical bytes per format.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse, Response

from deps import require_admin, db as _db
from v2.flags import get as get_flag
from v2.report import build_report, render_markdown, render_pdf
from v2.report.stix import render_stix_bytes
from v2.report.bundle import render_bundle

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


@router.get("/{case_id}/report.pdf")
async def get_report_pdf(case_id: str, _: dict = Depends(require_admin)) -> Response:
    """PDF export of the deterministic investigation report (R4 · PDF)."""
    _guard()
    env = await build_report(_db, case_id)
    pdf_bytes = render_pdf(env)
    filename = f"{case_id}.report.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Nivxray-Report-Sha256": env.signature.get("sha256", ""),
            "X-Nivxray-Report-Schema": env.schema_version,
        },
    )


@router.get("/{case_id}/report.stix.json")
async def get_report_stix(case_id: str, _: dict = Depends(require_admin)) -> Response:
    """STIX 2.1 bundle export — process/file/attack-pattern/observed-data SDOs + spawn relationships."""
    _guard()
    env = await build_report(_db, case_id)
    body = render_stix_bytes(env)
    filename = f"{case_id}.stix.json"
    return Response(
        content=body,
        media_type="application/stix+json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Nivxray-Report-Sha256": env.signature.get("sha256", ""),
            "X-Nivxray-Report-Schema": env.schema_version,
        },
    )


@router.get("/{case_id}/report.bundle.zip")
async def get_report_bundle(case_id: str, _: dict = Depends(require_admin)) -> Response:
    """Evidence package: report.json + report.md + report.pdf + bundle.stix.json + manifest.json."""
    _guard()
    env = await build_report(_db, case_id)
    zip_bytes = render_bundle(env)
    filename = f"{case_id}.evidence.zip"
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Nivxray-Report-Sha256": env.signature.get("sha256", ""),
            "X-Nivxray-Report-Schema": env.schema_version,
        },
    )

