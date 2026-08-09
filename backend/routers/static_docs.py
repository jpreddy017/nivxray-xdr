"""Static docs endpoint · serves large audit documents produced by
the platform (e.g. the Current-State Audit) via the preview URL so
the analyst can view / print / download without needing a file
server.  Content is baked at build time under
`/app/backend/static_docs/` — the endpoint just streams the bytes
with an appropriate content type.

Deliberately NO authentication: these are read-only audit artifacts
meant for the account owner.  If we ever need to gate them, move
them behind the standard `Depends(get_current_user)` decorator.
"""
from __future__ import annotations

import os
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse


router = APIRouter(prefix="/docs", tags=["docs"])

_DOCS_DIR = "/app/backend/static_docs"


@router.get("/current-state-audit")
@router.get("/current-state-audit.html")
def audit_html():
    """The Current-State Audit as print-optimised HTML.

    Open this URL in a browser and use ⌘/Ctrl + P → Save as PDF for
    a portable copy of the audit.
    """
    p = os.path.join(_DOCS_DIR, "current_state_audit.html")
    if not os.path.exists(p):
        raise HTTPException(status_code=404, detail="Audit HTML not built.")
    return FileResponse(p, media_type="text/html; charset=utf-8")


@router.get("/current-state-audit.md")
def audit_markdown():
    """Raw markdown of the Current-State Audit (for git commit / diff)."""
    p = os.path.join(_DOCS_DIR, "current_state_audit.md")
    if not os.path.exists(p):
        raise HTTPException(status_code=404, detail="Audit markdown not built.")
    with open(p, "r", encoding="utf-8") as fh:
        return PlainTextResponse(fh.read(), media_type="text/markdown; charset=utf-8")


@router.get("/audit-reconciliation")
@router.get("/audit-reconciliation.html")
def reconciliation_html():
    """Reconciliation of the original audit against current git HEAD.

    Corrects claims in the original audit that were made without
    inspecting `/app/backend/v2/` and `/app/backend/engine/`.
    Use ⌘/Ctrl + P → Save as PDF for a portable copy.
    """
    p = os.path.join(_DOCS_DIR, "audit_reconciliation.html")
    if not os.path.exists(p):
        raise HTTPException(status_code=404, detail="Reconciliation HTML not built.")
    return FileResponse(p, media_type="text/html; charset=utf-8")


@router.get("/audit-reconciliation.md")
def reconciliation_md():
    """Raw markdown of the reconciliation."""
    p = os.path.join(_DOCS_DIR, "audit_reconciliation.md")
    if not os.path.exists(p):
        raise HTTPException(status_code=404, detail="Reconciliation markdown not built.")
    with open(p, "r", encoding="utf-8") as fh:
        return PlainTextResponse(fh.read(), media_type="text/markdown; charset=utf-8")
