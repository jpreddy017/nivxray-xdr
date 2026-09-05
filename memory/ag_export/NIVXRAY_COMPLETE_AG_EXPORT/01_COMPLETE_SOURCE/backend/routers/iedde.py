"""IEDDE Analyze Router — Single Source of Truth for the decoding pipeline.

Route:
    POST /api/iedde/analyze     → run the full IEDDE loop (Stages 1–3)
                                   and return the deterministic decision
                                   trace + canonical output.

Contract:
    Request body:
        { "input": "<raw payload>" }

    Response body:
        {
            "input_len": int,
            "canonical_output": str,
            "iterations_executed": int,
            "terminal_state": "canonical" | "stability_gate",
            "stop_reason": str,
            "interpreter_identification": {
                "primary_interpreter": str,
                "confidence": float,
                "interpreters": [ InterpreterMatch, ... ],
                "stability_reason": str
            },
            "final_technique_inventory": {
                "techniques": [ TechniqueSignal, ... ],
                "stability_reason": str
            },
            "stages": [
                {
                    iteration, interpreter, interpreter_confidence,
                    techniques_present,
                    decision {
                        selected, selected_pass, reason, confidence,
                        remaining_candidates, key_required_deferred
                    },
                    chosen_pass, fired_transformations, changed,
                    content_len_before, content_len_after,
                    canonicality_delta, stop_reason
                },
                ...
            ]
        }

Determinism:
    Identical input → byte-identical response body (all Stage 1/2/3
    services are deterministic; the router just marshals them).

Auth:
    Same JWT contract as every other /api/* route.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from routers.auth import get_current_user
from services.interpreter_identifier import identify
from services.recipe_planner import plan_and_execute
from services.technique_detector import DetectionContext, detect_techniques

router = APIRouter(prefix="/iedde", tags=["iedde"])


class AnalyzeRequest(BaseModel):
    input: str = Field(..., description="Raw payload to analyze")
    max_iterations: int = Field(32, ge=1, le=64)


@router.post("/analyze")
async def iedde_analyze(body: AnalyzeRequest, user=Depends(get_current_user)) -> dict[str, Any]:
    if not isinstance(body.input, str) or not body.input.strip():
        raise HTTPException(status_code=400, detail="input_required")

    # Stage 1 · initial interpreter identification (also runs inside
    # the planner loop; surfacing it here gives the UI something to
    # render before the loop starts).
    initial_ident = identify(body.input)
    initial_inv = detect_techniques(
        body.input,
        DetectionContext(
            primary_interpreter=initial_ident.primary_interpreter,
            interpreters=tuple(m.interpreter for m in initial_ident.interpreters),
        ),
    )

    # Stage 3 · full discovery-driven loop.
    plan = plan_and_execute(body.input, max_iterations=body.max_iterations)

    # Final-state re-identification (loop already did this on the last
    # iteration but we re-emit here so the client doesn't have to
    # walk `stages[-1]`).
    final_ident = identify(plan.canonical_output)
    final_inv = detect_techniques(
        plan.canonical_output,
        DetectionContext(
            primary_interpreter=final_ident.primary_interpreter,
            interpreters=tuple(m.interpreter for m in final_ident.interpreters),
        ),
    )

    return {
        "input_len": len(body.input),
        "canonical_output": plan.canonical_output,
        "iterations_executed": plan.iterations_executed,
        "terminal_state": plan.terminal_state,
        "stop_reason": plan.stop_reason,
        "binary_artifact": plan.binary_artifact.to_dict() if plan.binary_artifact else None,

        # Initial (pre-loop) surface.
        "initial_interpreter_identification": initial_ident.to_dict(),
        "initial_technique_inventory": initial_inv.to_dict(),

        # Final (post-loop) surface.
        "final_interpreter_identification": final_ident.to_dict(),
        "final_technique_inventory": final_inv.to_dict(),

        # Per-iteration reasoning.
        "stages": [s.to_dict() for s in plan.stages],
    }


__all__ = ["router"]
