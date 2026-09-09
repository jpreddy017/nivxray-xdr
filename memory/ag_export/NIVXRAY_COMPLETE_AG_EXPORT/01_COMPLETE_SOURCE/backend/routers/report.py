"""Round 37 · Investigation Report REST API."""
from __future__ import annotations
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, Body
from fastapi.responses import Response

from services import report as report_svc
from deps import db

router = APIRouter(prefix="/incidents", tags=["report"])


@router.get("/{incident_id}/report")
async def get_report(incident_id: str) -> Dict[str, Any]:
    """Compose the four-section Investigation Report.

    Deterministic SYSTEM composition + persisted ANALYST overlay.
    """
    return await report_svc.compose(db, incident_id)


@router.get("/{incident_id}/report/pdf")
async def get_report_pdf(incident_id: str, cover: bool = True) -> Response:
    """Round 39 · Step 5 — branded PDF projection of the report.

    Owner rule: PDF is a *projection* of the exact contract returned
    by :func:`services.report.service.compose` — never a second
    report-generation engine.  If the incident is missing, the
    renderer emits a one-page honest error PDF rather than a
    fabricated report.

    Round 43 · Optional branded cover page (default ``cover=true``).
    Set ``?cover=false`` to fall back to the exact Step 5 export.
    Page-number footers are always on.
    """
    report = await report_svc.compose(db, incident_id)
    pdf_bytes = report_svc.render_pdf(report, cover=cover)
    suffix = "" if cover else "-nocover"
    filename = f"nivxray-report-{incident_id}{suffix}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'inline; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


@router.post("/{incident_id}/report/blocks")
async def add_report_block(incident_id: str,
                                        body: Dict[str, Any] = Body(...)
                                      ) -> Dict[str, Any]:
    """Analyst adds a block to Executive / Supporting / Recommendations.

    Technical Summary blocks are REFUSED (100% evidence-derived).
    """
    section       = body.get("section")
    content       = (body.get("content") or "").strip()
    author_email  = body.get("author_email") or "unknown@nivxray.local"
    title         = body.get("title")
    priority      = body.get("priority")
    kind          = body.get("kind")
    evidence_refs = body.get("evidence_refs") or []
    if not section or section not in report_svc.SECTIONS:
        raise HTTPException(status_code=400,
                                     detail=f"invalid section: {section!r}")
    if not content:
        raise HTTPException(status_code=400,
                                     detail="content is required")
    try:
        block = await report_svc.add_block(db, incident_id, section,
                                                          content, author_email,
                                                          title=title,
                                                          priority=priority,
                                                          kind=kind,
                                                          evidence_refs=evidence_refs)
    except report_svc.TechnicalSummaryReadOnly:
        raise HTTPException(status_code=403,
                                     detail=("Technical Summary is 100 % "
                                                "evidence-derived and cannot be "
                                                "modified by an analyst."))
    return block


@router.patch("/{incident_id}/report/blocks/{block_id}")
async def edit_report_block(incident_id: str, block_id: str,
                                          body: Dict[str, Any] = Body(...)
                                        ) -> Dict[str, Any]:
    content = (body.get("content") or "").strip()
    author_email = body.get("author_email") or "unknown@nivxray.local"
    if not content:
        raise HTTPException(status_code=400,
                                     detail="content is required")
    try:
        b = await report_svc.edit_block(db, block_id, content, author_email)
    except report_svc.TechnicalSummaryReadOnly:
        raise HTTPException(status_code=403,
                                     detail=("Technical Summary blocks are "
                                                "read-only."))
    if not b:
        raise HTTPException(status_code=404, detail="block not found")
    return b


@router.delete("/{incident_id}/report/blocks/{block_id}")
async def remove_report_block(incident_id: str, block_id: str
                                              ) -> Dict[str, Any]:
    ok = await report_svc.remove_block(db, block_id)
    if not ok:
        raise HTTPException(status_code=404, detail="block not found")
    return {"removed": True, "block_id": block_id,
              "note": ("Removed from report only. Canonical evidence in the "
                          "SSOT is unaffected.")}


@router.post("/{incident_id}/report/blocks/{block_id}/suppress")
async def suppress_block(incident_id: str, block_id: str,
                                    body: Dict[str, Any] = Body(...)
                                  ) -> Dict[str, Any]:
    """Analyst hides a SYSTEM-composed block from the report without
    deleting canonical evidence.  Recorded as a suppression overlay.
    """
    section = body.get("section")
    author_email = body.get("author_email") or "unknown@nivxray.local"
    if not section or section not in report_svc.SECTIONS:
        raise HTTPException(status_code=400,
                                     detail=f"invalid section: {section!r}")
    try:
        await report_svc.suppress_system_block(db, incident_id, section,
                                                                block_id, author_email)
    except report_svc.TechnicalSummaryReadOnly:
        raise HTTPException(status_code=403,
                                     detail="Technical Summary is read-only.")
    return {"suppressed": True, "block_id": block_id, "section": section}
