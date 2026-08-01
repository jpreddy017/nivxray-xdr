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
    "summary",   # 2026-02 · P1-06 · Manual Summary Override (analyst-written narrative)
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
    verdict: str = "incorrect"   # Feb-2026 v2/v3: correct|incorrect|partial|suggest
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
    if body.verdict not in ("correct", "incorrect", "partial", "suggest"):
        raise HTTPException(400, "verdict must be correct | incorrect | partial | suggest")
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
        verdict=body.verdict,
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


@router.get("/corrections/analytics", tags=["corrections", "admin"])
async def analytics(user=Depends(require_admin)):
    """Feb-2026 v3-spec: admin analytics for corrections dashboard.

    Returns totals, per-status counts, per-surface heatmap, top-reused,
    top corrected MITRE techniques, verdict distribution (FP/FN signal),
    reviewer throughput, average approval velocity, and 7-day trend.
    """
    return await corr.get_analytics(db)


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


# ─── P1-06 · Manual Summary Override (Analyst-Written Narrative) ─────
# When the auto-generated Executive Summary or Story is wrong, the
# analyst writes their own narrative and submits it here. Two things
# happen:
#   1. The correction is stored in the shared `analyst_corrections`
#      collection (same infra used by threat_model / decode / ioc
#      corrections) with `surface="summary"`.
#   2. A pointer is stored in `summary_overrides` so the CIO can be
#      re-projected with the analyst text on subsequent loads.
#
# The learner already consumes `analyst_corrections` by surface — no
# new learner needed. Future improvement: expose the analyst summary
# corpus as a fine-tuning signal for the composer.

class SummaryOverrideIn(BaseModel):
    cio_id: str = Field(..., min_length=1)
    case_id: Optional[str] = None
    analyst_summary: str = Field(..., min_length=20, max_length=8000)
    analyst_notes: Optional[str] = None
    original_executive: Optional[str] = None
    original_story: Optional[str] = None
    scope: str = "private"      # private | team | global (learner corpus)
    original_cio: Optional[Dict[str, Any]] = None  # for Learning Engine fingerprinting


@router.post("/corrections/summary-override")
async def submit_summary_override(body: SummaryOverrideIn, user=Depends(get_current_user)):
    """Persist an analyst-written summary as both a `summary` correction
    (for the learner) AND a first-class override the frontend can
    re-project on next CIO load."""
    from datetime import datetime, timezone
    import uuid as _uuid

    now = datetime.now(timezone.utc).isoformat()

    # Compute fingerprint if the frontend provided the CIO snapshot so
    # this correction can be retrieved by the Learning Engine on future
    # similar cases.
    fingerprint_snapshot: Dict[str, Any] = {}
    verdict_snapshot: Dict[str, Any] = {}
    try:
        if body.original_cio:
            from nivxforge.learning import fingerprint_cio as _fp_cio
            _fp = _fp_cio(body.original_cio)
            fingerprint_snapshot = _fp.to_dict()
            _v = (body.original_cio or {}).get("verdict") or {}
            verdict_snapshot = {
                "label": _v.get("label"),
                "confidence_pct": _v.get("confidence_pct"),
            }
    except Exception:  # noqa: BLE001
        # Non-fatal — the correction still saves even if fingerprinting fails.
        fingerprint_snapshot = {}

    # 1. Shared correction record (feeds the learner).
    correction = {
        "id": str(_uuid.uuid4()),
        "surface": "summary",
        "wrong_finding": {
            "kind": "executive_summary",
            "value": body.original_executive or body.original_story or "",
            "field": "cio.summary.executive",
        },
        "correct_prompt": body.analyst_summary,
        "tags": ["manual-summary", "x-lab"],
        "scope": body.scope,
        "verdict": "incorrect",
        "input_text": None,
        "diagram_hash": None,
        "revises": None,
        "author_email": user.get("email") or user.get("id") or "unknown",
        "created_at": now,
        "cio_id": body.cio_id,
        "case_id": body.case_id or None,
        "notes": body.analyst_notes or "",
        "fingerprint": fingerprint_snapshot,
        "verdict_snapshot": verdict_snapshot,
    }
    try:
        await db.analyst_corrections.insert_one(correction)
    except Exception:  # noqa: BLE001
        # Non-fatal — surface-level failure should not lose the override.
        pass

    # 2. First-class override so the CIO renders the analyst text
    #    on subsequent loads of the same investigation.
    override_doc = {
        "id": correction["id"],
        "cio_id": body.cio_id,
        "case_id": body.case_id or None,
        "analyst_summary": body.analyst_summary,
        "analyst_notes": body.analyst_notes or "",
        "original_executive": body.original_executive or "",
        "original_story": body.original_story or "",
        "author_email": correction["author_email"],
        "created_at": now,
        "scope": body.scope,
    }
    await db.summary_overrides.replace_one(
        {"cio_id": body.cio_id}, override_doc, upsert=True
    )

    return {
        "ok": True,
        "correction_id": correction["id"],
        "override": override_doc,
    }


@router.get("/corrections/summary-override/{cio_id}")
async def get_summary_override(cio_id: str, user=Depends(get_current_user)):
    """Return the analyst override for a given CIO, or 404."""
    doc = await db.summary_overrides.find_one({"cio_id": cio_id})
    if not doc:
        raise HTTPException(404, "no manual summary for this cio_id")
    doc.pop("_id", None)
    return doc



# ── Verdict marker (Correct / Partial / Wrong) ───────────────────────
#
# Analyst-facing feedback surface on the Investigation Ledger. Records
# the marker into the shared `analyst_corrections` collection with
# `surface="verdict-mark"` so the Learning Engine can:
#   * Weight future verdict-explanation compositions by "how often does
#     the team agree/disagree with this pattern?"
#   * Surface persistent "Wrong" clusters as candidates for new
#     deterministic rules — NEVER as a direct verdict override.
#
# IMPORTANT — this endpoint does NOT retrain the verdict engine. Verdicts
# stay deterministic. This marker is a *signal for improvement work*, not
# an override. The Learning Engine consumes it as a similarity-weighting
# and prioritisation hint, per constitution §11.

class VerdictMarkIn(BaseModel):
    cio_id: str = Field(..., description="CIO id / snapshot hash")
    case_id: Optional[str] = None
    marker: str = Field(..., description="correct | partial | wrong")
    verdict_label: Optional[str] = None
    verdict_confidence_pct: Optional[int] = None
    fingerprint: Optional[Dict[str, Any]] = None   # engine fingerprint at marker time
    notes: Optional[str] = None


@router.post("/corrections/verdict-mark", tags=["corrections"])
async def submit_verdict_mark(body: VerdictMarkIn, user=Depends(get_current_user)):
    """Persist a Correct / Partial / Wrong marker for a verdict."""
    from datetime import datetime, timezone
    import uuid as _uuid

    marker = (body.marker or "").lower().strip()
    if marker not in {"correct", "partial", "wrong"}:
        raise HTTPException(400, "marker must be one of: correct | partial | wrong")

    now = datetime.now(timezone.utc).isoformat()
    verdict_status = {"correct": "correct", "partial": "partial", "wrong": "incorrect"}[marker]
    record = {
        "id": str(_uuid.uuid4()),
        "surface": "verdict-mark",
        "wrong_finding": {
            "kind": "verdict",
            "value": body.verdict_label or "unknown",
            "field": "cio.verdict.label",
        },
        "correct_prompt": marker,   # correct | partial | wrong
        "tags": ["verdict-mark", "x-lab", marker],
        "scope": "team",
        "verdict": verdict_status,
        "input_text": None,
        "diagram_hash": None,
        "revises": None,
        "author_email": user.get("email") or user.get("id") or "unknown",
        "created_at": now,
        "cio_id": body.cio_id,
        "case_id": body.case_id,
        "fingerprint": body.fingerprint or {},
        "verdict_snapshot": {
            "label": body.verdict_label,
            "confidence_pct": body.verdict_confidence_pct,
        },
        "notes": body.notes or "",
    }
    try:
        await db.analyst_corrections.insert_one(record)
    except Exception:  # noqa: BLE001
        raise HTTPException(500, "could not persist verdict marker")
    return {"ok": True, "id": record["id"], "marker": marker}
