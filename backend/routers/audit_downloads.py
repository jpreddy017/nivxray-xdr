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
