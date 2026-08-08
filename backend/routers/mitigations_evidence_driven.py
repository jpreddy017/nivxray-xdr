"""``POST /api/decode/mitigations/evidence_driven`` — evidence-driven
recommendations for an analyst input.

Isolated from ``/api/decode/mitigations`` (legacy).  Consumers pick
either the legacy schema (``mitigation.schema_version: 1``) or the
evidence-driven schema (``schema_version: 2``) explicitly — the two
never mix on a single call.
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from analysis_core       import deterministic_best_decode
from services.mitigation import derive_mitigations, MITIGATION_SCHEMA_VERSION
from services.mitigation.evidence_driven.engine import (
    evidence_driven_recommendations, is_engine_enabled,
)

router = APIRouter(prefix="/decode", tags=["decode"])


class _EDRRequest(BaseModel):
    input: str = Field(..., description="Raw analyst input to decode")


class _OutcomeRequest(BaseModel):
    """Structured investigation outcome — the canonical engine input.

    Consumers pass the Workspace's discovered findings; the engine
    does NOT re-analyze the original payload.  Schema is documented
    in ``services.mitigation.evidence_driven.investigation_outcome``.
    """
    outcome: Dict[str, Any] = Field(...,
        description="Workspace-produced structured findings")


@router.post("/mitigations/from_outcome")
def post_from_outcome(body: _OutcomeRequest) -> Dict[str, Any]:
    """Canonical path — reason ONLY over what the Workspace already
    discovered.  No re-analysis, no payload re-parsing."""
    if not body.outcome:
        raise HTTPException(status_code=400, detail="empty outcome")
    edr = evidence_driven_recommendations(
        investigation_outcome=body.outcome)
    return {
        "ok":                       True,
        "engine_enabled":           is_engine_enabled(),
        "evidence_recommendations": edr,
    }


@router.post("/mitigations/evidence_driven")
def post_evidence_driven(body: _EDRRequest) -> Dict[str, Any]:
    """Legacy convenience path — accepts a RAW payload and re-runs
    the deterministic decoder.  Kept for compatibility with the
    compare endpoint.  New Workspace consumers should call
    ``/mitigations/from_outcome`` instead."""
    text = (body.input or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="empty input")
    try:
        decode_result = deterministic_best_decode(text)
    except Exception as e:
        raise HTTPException(status_code=500,
                              detail=f"decode failed: {e}") from e
    edr = evidence_driven_recommendations(decode_result)
    return {
        "ok":                       True,
        "engine_enabled":           is_engine_enabled(),
        "evidence_recommendations": edr,
    }


# ══════════════════════════════════════════════════════════════════
# Permanent regression safety net · v1 vs v2 side-by-side
# ══════════════════════════════════════════════════════════════════
@router.post("/mitigations/compare")
def post_compare(body: _EDRRequest) -> Dict[str, Any]:
    """Run BOTH engines on the same input and return them side by side.

    Purpose: analysts + reviewers can eyeball the delta between the
    legacy static template (v1) and the evidence-driven engine (v2)
    for any case, so any regression during v2 rule-library expansion
    is instantly visible.  This endpoint NEVER mutates either engine
    — it just calls them both and returns the pair.
    """
    text = (body.input or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="empty input")
    try:
        decode_result = deterministic_best_decode(text)
    except Exception as e:
        raise HTTPException(status_code=500,
                              detail=f"decode failed: {e}") from e

    v1 = derive_mitigations(decode_result)
    v2 = evidence_driven_recommendations(decode_result)

    # Compact deltas the analyst can scan quickly.
    v1_ids  = _v1_ids(v1)
    v2_ids  = {r["id"] for r in (v2.get("recommendations") or [])}
    return {
        "ok": True,
        "engine_enabled": is_engine_enabled(),
        "v1": {
            "schema_version": v1.get("schema_version",
                                        MITIGATION_SCHEMA_VERSION),
            "verdict":        v1.get("verdict"),
            "immediate":      v1.get("immediate")   or [],
            "hunting":        v1.get("hunting")     or [],
            "containment":    v1.get("containment") or [],
            "hardening":      v1.get("hardening")   or [],
        },
        "v2": v2,
        "delta": {
            "v1_only_ids": sorted(v1_ids - v2_ids),
            "v2_only_ids": sorted(v2_ids - v1_ids),
            "common_ids":  sorted(v1_ids & v2_ids),
            "v1_count":    len(v1_ids),
            "v2_count":    len(v2_ids),
        },
    }


def _v1_ids(v1: Dict[str, Any]) -> set:
    """Legacy v1 payload has no ``id`` field — synthesise stable ids
    from ``{bucket}:{action}`` so the delta view can compare against
    v2's real ids.  Purely cosmetic (compare uses these only for
    the ``v1_only_ids``/``v2_only_ids`` set arithmetic)."""
    ids: set = set()
    for bucket in ("immediate", "hunting", "containment", "hardening"):
        for item in (v1.get(bucket) or []):
            if isinstance(item, dict):
                key = item.get("id") or item.get("action") or ""
            else:
                key = str(item)
            if key:
                ids.add(f"v1:{bucket}:{key}")
    return ids
