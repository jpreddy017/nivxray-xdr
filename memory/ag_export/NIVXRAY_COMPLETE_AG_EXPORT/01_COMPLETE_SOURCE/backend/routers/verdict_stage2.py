"""Stage-2 Verdict router · POST /api/verdict/stage2/compute.

Owner-locked contract (2026-08-26):
  - Additive.  Never mutates the v3.x verdict / verdict_card.
  - Deterministic.  Same canonical inputs → byte-identical output.
  - Idempotent.  Safe to call repeatedly; ``generated_at`` refreshes
    but ``fingerprint`` stays stable.
  - Additive persistence in ``workspace_cases.verdict_stage2`` when
    a ``case_id`` is supplied.  Never touches ``case.verdict`` or
    ``case.verdict_card``.
  - Feature-flagged by ``STAGE2_VERDICT`` env flag.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import get_current_user, db
from services.verdict_stage2.engine import compute_stage2, build_inputs


router = APIRouter(prefix="/verdict/stage2", tags=["verdict-stage2"])


def _flag_on() -> bool:
    return os.environ.get("STAGE2_VERDICT", "on").lower() == "on"


class Stage2ComputeBody(BaseModel):
    """Body for the on-demand Stage-2 compute endpoint.

    All fields are optional — the engine tolerates missing inputs
    (verdict simply degrades to `unknown/insufficient`).
    """
    case_id:        Optional[str]                = Field(None)
    timeline:       Optional[Dict[str, Any]]     = Field(None)
    intent:         Optional[Dict[str, Any]]     = Field(None)
    v3x_verdict_card: Optional[Dict[str, Any]]   = Field(None)
    lane_wires:     Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    persist:        bool                           = Field(False,
        description="If true and case_id is provided, persist the "
                     "additive verdict_stage2 field on the case doc.")


def _resolve_case_v3x(case_id: str) -> Dict[str, Any]:
    """Fetch v3.x verdict_card from workspace_cases.  Never mutates
    the case; returns an empty dict if absent."""
    try:
        case = db.workspace_cases.find_one({"id": case_id})
    except Exception:
        return {}
    if not isinstance(case, dict):
        return {}
    return case.get("verdict_card") or {}


@router.get("/status")
def status():
    """Return whether the Stage-2 engine is enabled and its schema."""
    return {
        "enabled": _flag_on(),
        "flag":    os.environ.get("STAGE2_VERDICT", "on"),
        "engine":  "stage2.v1",
        "vocabulary": {
            "labels":     ["malicious", "suspicious", "benign", "unknown"],
            "confidence": ["high", "medium", "low", "insufficient"],
        },
    }


@router.post("/compute")
async def compute(body: Stage2ComputeBody,
                    user=Depends(get_current_user)):
    """Compute a Stage-2 verdict.  Idempotent — same canonical inputs
    always produce the same fingerprint."""
    if not _flag_on():
        raise HTTPException(status_code=503,
                              detail={"error": "stage2_disabled",
                                       "hint": "Set STAGE2_VERDICT=on."})

    # If a case_id is supplied, hydrate v3.x from workspace_cases only
    # when the caller did NOT supply their own v3x_verdict_card.  This
    # supports both operational auto-compute (server-side hydration)
    # and analyst-driven compute (explicit override).
    v3x_card = body.v3x_verdict_card
    if body.case_id and not v3x_card:
        v3x_card = _resolve_case_v3x(body.case_id)

    caller_tid = (user or {}).get("tenant_id") \
                    or (user or {}).get("email") \
                    or (user or {}).get("sub")
    if not caller_tid:
        raise HTTPException(status_code=401,
                              detail={"error": "tenant_context_missing"})

    inp = build_inputs(
        case_id=body.case_id,
        tenant_id=caller_tid,
        timeline=body.timeline,
        intent=body.intent,
        v3x_verdict_card=v3x_card,
        lane_wires=body.lane_wires,
    )
    verdict = compute_stage2(inp)
    verdict_dict = verdict.to_dict()

    # Idempotent persistence — additive-only.  Never touch v3.x fields.
    persisted = False
    if body.persist and body.case_id:
        try:
            db.workspace_cases.update_one(
                {"id": body.case_id, "tenant_id": caller_tid},
                {"$set": {"verdict_stage2": verdict_dict}},
                upsert=False,
            )
            persisted = True
        except Exception:
            # Persistence failure MUST NOT hide the deterministic result.
            persisted = False

    return {"verdict_stage2": verdict_dict, "persisted": persisted}


class Stage2AutoBody(BaseModel):
    """Body for the idempotent auto-compute endpoint.  Only runs when
    ALL required inputs are available (Timeline + Intent).  If inputs
    are missing, returns 202 with `computed=False` — never fails."""
    case_id:        str
    timeline:       Optional[Dict[str, Any]]     = Field(None)
    intent:         Optional[Dict[str, Any]]     = Field(None)
    lane_wires:     Optional[List[Dict[str, Any]]] = Field(default_factory=list)


@router.post("/auto-compute")
async def auto_compute(body: Stage2AutoBody,
                        user=Depends(get_current_user)):
    """Idempotent auto-compute hook.  Persists only when inputs are
    sufficient.  Owner rule #2: MUST NOT create uncontrolled background
    recomputation — this is a route the frontend/pipeline calls when
    it believes the state changed."""
    if not _flag_on():
        raise HTTPException(status_code=503,
                              detail={"error": "stage2_disabled"})

    caller_tid = (user or {}).get("tenant_id") \
                    or (user or {}).get("email") \
                    or (user or {}).get("sub")

    # Gate: require at least a timeline OR intent OR one lane wire.
    if not (body.timeline or body.intent or body.lane_wires):
        return {"computed": False, "reason": "insufficient_inputs"}

    v3x_card = _resolve_case_v3x(body.case_id)
    inp = build_inputs(
        case_id=body.case_id,
        tenant_id=caller_tid,
        timeline=body.timeline,
        intent=body.intent,
        v3x_verdict_card=v3x_card,
        lane_wires=body.lane_wires,
    )
    verdict = compute_stage2(inp)

    # Idempotency: compare fingerprints; skip DB write if unchanged.
    existing = {}
    try:
        case = db.workspace_cases.find_one({"id": body.case_id})
        if isinstance(case, dict):
            existing = case.get("verdict_stage2") or {}
    except Exception:
        existing = {}

    unchanged = existing.get("fingerprint") == verdict.fingerprint
    verdict_dict = verdict.to_dict()

    if not unchanged:
        try:
            db.workspace_cases.update_one(
                {"id": body.case_id, "tenant_id": caller_tid},
                {"$set": {"verdict_stage2": verdict_dict}},
                upsert=False,
            )
        except Exception:
            pass

    return {"computed": True, "unchanged": unchanged,
            "verdict_stage2": verdict_dict}
