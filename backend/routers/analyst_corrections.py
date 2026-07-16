"""Analyst-Corrections router — /api/corrections/*.

Endpoints:
  POST   /api/corrections            → submit a correction (any surface)
  GET    /api/corrections            → list visible (own + team + global-approved)
  GET    /api/corrections/pending    → admin inbox (global-scope pending)
  POST   /api/corrections/{id}/approve   (admin)
  POST   /api/corrections/{id}/reject    (admin)
  POST   /api/corrections/{id}/rollback  (admin)  ← restore an older version
  POST   /api/corrections/{id}/revise    → author-only, submit a new version

All ownership / scoping / versioning rules live in
``backend/analyst_corrections.py`` — this router is the thin HTTP layer.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import db, get_current_user, require_admin
import analyst_corrections as corr


router = APIRouter()


# ── Pydantic bodies ────────────────────────────────────────────────
_VALID_SURFACES = {
    "threat_model", "decode", "chain", "ioc", "lolbas",
    "family", "risk", "detection", "mitigation", "note",
}


class WrongFinding(BaseModel):
    kind: str = Field(..., min_length=1, max_length=32)
    value: Optional[Any] = None
    field: Optional[str] = None


class CorrectionIn(BaseModel):
    surface: str = Field(..., min_length=1)
    wrong_finding: WrongFinding
    correct_prompt: str = Field(..., min_length=8, max_length=4000)
    tags: List[str] = []
    scope: str = "private"
    input_text: Optional[str] = None
    diagram_hash: Optional[str] = None
    revises: Optional[str] = None       # id to revise; author-only


class RejectIn(BaseModel):
    reason: str = ""


class RollbackIn(BaseModel):
    target_version: int


# ── endpoints ──────────────────────────────────────────────────────
@router.post("/corrections", tags=["corrections"])
async def submit(body: CorrectionIn, user=Depends(get_current_user)):
    if body.surface not in _VALID_SURFACES:
        raise HTTPException(400, f"surface must be one of {sorted(_VALID_SURFACES)}")
    if body.scope not in ("private", "team", "global"):
        raise HTTPException(400, "scope must be private | team | global")
    # Author-only revise gate
    if body.revises:
        prev = await db[corr.COLLECTION].find_one({"id": body.revises})
        if not prev:
            raise HTTPException(404, "revises target not found")
        if prev.get("user_email") != user["email"] and user.get("role") != "admin":
            raise HTTPException(403, "only the original author or an admin can revise")
    doc = await corr.submit_correction(
        db,
        user_email=user["email"],
        role=user.get("role") or "analyst",
        surface=body.surface,
        wrong_finding=body.wrong_finding.model_dump(exclude_none=True),
        correct_prompt=body.correct_prompt,
        tags=body.tags,
        scope=body.scope,
        input_text=body.input_text,
        diagram_hash_override=body.diagram_hash,
        revises=body.revises,
    )
    doc.pop("_id", None)
    return {"ok": True, "correction": doc}


@router.get("/corrections", tags=["corrections"])
async def list_visible(
    surface: Optional[str] = None, limit: int = 200,
    user=Depends(get_current_user),
):
    items = await corr.list_corrections(
        db, user_email=user["email"], surface=surface, limit=limit,
    )
    return {"items": items, "count": len(items)}


@router.get("/corrections/pending", tags=["corrections"])
async def list_pending(user=Depends(require_admin), limit: int = 200):
    items = await corr.list_pending_admin(db, limit=limit)
    return {"items": items, "count": len(items)}


@router.post("/corrections/{corr_id}/approve", tags=["corrections"])
async def approve(corr_id: str, user=Depends(require_admin)):
    doc = await corr.approve_correction(db, corr_id, user["email"])
    if not doc:
        raise HTTPException(404, "correction_not_found_or_already_approved")
    doc.pop("_id", None)
    return {"ok": True, "correction": doc}


@router.post("/corrections/{corr_id}/reject", tags=["corrections"])
async def reject(corr_id: str, body: RejectIn, user=Depends(require_admin)):
    doc = await corr.reject_correction(db, corr_id, user["email"], body.reason)
    if not doc:
        raise HTTPException(404, "correction_not_found")
    doc.pop("_id", None)
    return {"ok": True, "correction": doc}


@router.post("/corrections/{corr_id}/rollback", tags=["corrections"])
async def rollback(corr_id: str, body: RollbackIn, user=Depends(require_admin)):
    doc = await corr.rollback_to_version(db, corr_id, int(body.target_version), user["email"])
    if not doc:
        raise HTTPException(404, "correction_or_target_version_not_found")
    doc.pop("_id", None)
    return {"ok": True, "correction": doc}


class ApplyPreviewIn(BaseModel):
    surface: str
    input_text: str = ""
    tags: List[str] = []


@router.post("/corrections/preview", tags=["corrections"])
async def preview_applicable(body: ApplyPreviewIn, user=Depends(get_current_user)):
    """Return the corrections that WOULD be applied for a given payload +
    surface + tags — used by the frontend to show a "Learned Corrections"
    banner before / after the analysis runs."""
    items = await corr.find_applicable(
        db, user_email=user["email"], surface=body.surface,
        input_text=body.input_text, tags=body.tags,
    )
    return {"items": items, "count": len(items)}
