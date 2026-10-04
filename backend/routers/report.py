"""Round 37 · Investigation Report REST API.

S1 (2026-06-21) · AUTHORIZATION BOUNDARY CLOSED.
This router previously carried **no authentication dependency at all**: the
composed report and its PDF projection were readable anonymously for any
incident id, and every analyst mutation (add / edit / delete / suppress a
block) was an unauthenticated write that took its author identity from the
request body.

The model is now the same one the incident record itself uses — and the same
one every other incident sub-resource uses:

    authenticated principal
      → server-resolved tenant scope (never a client-presented tenant)
      → incident belongs to that scope        (cross-tenant ⇒ 404, no
                                               disclosure of existence)
      → required permission for a MUTATION    (`incidents.update`)
      → resource / action

Actor identity is taken from the verified principal. `author_email` in a
request body is ignored: a body cannot assert who is writing.
"""
from __future__ import annotations
from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, Body
from fastapi.responses import Response

from services import report as report_svc
from deps import db, get_current_user
from routers.incidents import authorized_incident, require_incident_action

router = APIRouter(prefix="/incidents", tags=["report"])

REPORT_WRITE_PERMISSION = "incidents.update"


async def _authorized_block(incident_id: str, block_id: str) -> Dict[str, Any]:
    """A block is addressable only through the incident it belongs to.

    Without this, a principal authorized for their OWN incident could edit or
    delete a block belonging to another customer's incident simply by putting
    their incident id in the path — the block-level service functions are
    keyed on `block_id` alone.
    """
    block = await db[report_svc.REPORT_BLOCKS_COLL].find_one(
        {"block_id": block_id, "incident_id": incident_id}, {"_id": 0})
    if not block:
        raise HTTPException(status_code=404, detail="block not found")
    return block


@router.get("/{incident_id}/report")
async def get_report(incident_id: str,
                     user=Depends(get_current_user)) -> Dict[str, Any]:
    """Compose the four-section Investigation Report.

    Deterministic SYSTEM composition + persisted ANALYST overlay.
    """
    authorized_incident(incident_id, user, {"_id": 0, "id": 1})
    return await report_svc.compose(db, incident_id)


@router.get("/{incident_id}/report/pdf")
async def get_report_pdf(incident_id: str, cover: bool = True,
                         user=Depends(get_current_user)) -> Response:
    """Round 39 · Step 5 — branded PDF projection of the report.

    Owner rule: PDF is a *projection* of the exact contract returned
    by :func:`services.report.service.compose` — never a second
    report-generation engine.  If the incident is missing, the
    renderer emits a one-page honest error PDF rather than a
    fabricated report.

    Round 43 · Optional branded cover page (default ``cover=true``).
    Set ``?cover=false`` to fall back to the exact Step 5 export.
    Page-number footers are always on.

    S1 · the PDF is the same customer data in another container, so it
    carries the same authorization as the JSON contract.
    """
    authorized_incident(incident_id, user, {"_id": 0, "id": 1})
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
                                        body: Dict[str, Any] = Body(...),
                                        user=Depends(get_current_user)
                                      ) -> Dict[str, Any]:
    """Analyst adds a block to Executive / Supporting / Recommendations.

    Technical Summary blocks are REFUSED (100% evidence-derived).
    """
    authorized_incident(incident_id, user, {"_id": 0, "id": 1})
    require_incident_action(user, REPORT_WRITE_PERMISSION)
    section       = body.get("section")
    content       = (body.get("content") or "").strip()
    # S1 · attribution is an authenticated FACT, never a body claim.
    author_email  = user["email"]
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
                                          body: Dict[str, Any] = Body(...),
                                          user=Depends(get_current_user)
                                        ) -> Dict[str, Any]:
    authorized_incident(incident_id, user, {"_id": 0, "id": 1})
    require_incident_action(user, REPORT_WRITE_PERMISSION)
    await _authorized_block(incident_id, block_id)
    content = (body.get("content") or "").strip()
    author_email = user["email"]
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
async def remove_report_block(incident_id: str, block_id: str,
                                              user=Depends(get_current_user)
                                              ) -> Dict[str, Any]:
    authorized_incident(incident_id, user, {"_id": 0, "id": 1})
    require_incident_action(user, REPORT_WRITE_PERMISSION)
    await _authorized_block(incident_id, block_id)
    ok = await report_svc.remove_block(db, block_id)
    if not ok:
        raise HTTPException(status_code=404, detail="block not found")
    return {"removed": True, "block_id": block_id,
              "note": ("Removed from report only. Canonical evidence in the "
                          "SSOT is unaffected.")}


@router.post("/{incident_id}/report/blocks/{block_id}/suppress")
async def suppress_block(incident_id: str, block_id: str,
                                    body: Dict[str, Any] = Body(...),
                                    user=Depends(get_current_user)
                                  ) -> Dict[str, Any]:
    """Analyst hides a SYSTEM-composed block from the report without
    deleting canonical evidence.  Recorded as a suppression overlay.
    """
    authorized_incident(incident_id, user, {"_id": 0, "id": 1})
    require_incident_action(user, REPORT_WRITE_PERMISSION)
    section = body.get("section")
    author_email = user["email"]
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
