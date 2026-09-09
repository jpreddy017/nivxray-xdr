"""Read-only download endpoint for the 360° Workspace audit PDF.

Serves only the pre-built /app/backend/exports/NivXRay-Workspace-360-Audit.pdf
file. This is the delivery mechanism for the audit deliverable itself —
not part of the app's investigation architecture. No other files are
readable through this route.
"""
from __future__ import annotations
import os
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter(prefix="/audit")

_AUDIT_PDF = "/app/backend/exports/NivXRay-Workspace-360-Audit.pdf"
_AUDIT_MD  = "/app/memory/adr/0012-workspace-360-audit.md"
_PARTIAL_PDF = "/app/backend/exports/NivXRay-Partial-Pending-Skipped-Dead.pdf"
_PARTIAL_MD  = "/app/memory/adr/0012a-partial-pending-skipped-dead.md"


_IUE_PDF = "/app/backend/exports/NivXRay-IUE-Architecture-Audit.pdf"
_IUE_MD  = "/app/memory/adr/0013-iue-workspace-input-architecture-audit.md"


_DESIGN_PDF = "/app/backend/exports/NivXRay-Single-IUE-Convergence-Design.pdf"
_DESIGN_MD  = "/app/memory/adr/0014-single-iue-convergence-design.md"


@router.get("/iue-convergence-design.pdf")
async def download_design_pdf():
    if not os.path.exists(_DESIGN_PDF):
        raise HTTPException(404, detail={"error": "design_pdf_missing"})
    return FileResponse(
        _DESIGN_PDF,
        media_type="application/pdf",
        filename="NivXRay-Single-IUE-Convergence-Design.pdf",
    )


@router.get("/iue-convergence-design.md")
async def download_design_md():
    if not os.path.exists(_DESIGN_MD):
        raise HTTPException(404, detail={"error": "design_md_missing"})
    return FileResponse(
        _DESIGN_MD,
        media_type="text/markdown",
        filename="NivXRay-Single-IUE-Convergence-Design.md",
    )


@router.get("/iue-architecture.pdf")
async def download_iue_pdf():
    if not os.path.exists(_IUE_PDF):
        raise HTTPException(404, detail={"error": "iue_pdf_missing"})
    return FileResponse(
        _IUE_PDF,
        media_type="application/pdf",
        filename="NivXRay-IUE-Architecture-Audit.pdf",
    )


@router.get("/iue-architecture.md")
async def download_iue_md():
    if not os.path.exists(_IUE_MD):
        raise HTTPException(404, detail={"error": "iue_md_missing"})
    return FileResponse(
        _IUE_MD,
        media_type="text/markdown",
        filename="NivXRay-IUE-Architecture-Audit.md",
    )


@router.get("/workspace-360.pdf")
async def download_workspace_360_pdf():
    if not os.path.exists(_AUDIT_PDF):
        raise HTTPException(404, detail={"error": "audit_pdf_missing"})
    return FileResponse(
        _AUDIT_PDF,
        media_type="application/pdf",
        filename="NivXRay-Workspace-360-Audit.pdf",
    )


@router.get("/workspace-360.md")
async def download_workspace_360_md():
    if not os.path.exists(_AUDIT_MD):
        raise HTTPException(404, detail={"error": "audit_md_missing"})
    return FileResponse(
        _AUDIT_MD,
        media_type="text/markdown",
        filename="NivXRay-Workspace-360-Audit.md",
    )


@router.get("/partial-pending-skipped-dead.pdf")
async def download_partial_pdf():
    if not os.path.exists(_PARTIAL_PDF):
        raise HTTPException(404, detail={"error": "partial_pdf_missing"})
    return FileResponse(
        _PARTIAL_PDF,
        media_type="application/pdf",
        filename="NivXRay-Partial-Pending-Skipped-Dead.pdf",
    )


@router.get("/partial-pending-skipped-dead.md")
async def download_partial_md():
    if not os.path.exists(_PARTIAL_MD):
        raise HTTPException(404, detail={"error": "partial_md_missing"})
    return FileResponse(
        _PARTIAL_MD,
        media_type="text/markdown",
        filename="NivXRay-Partial-Pending-Skipped-Dead.md",
    )
