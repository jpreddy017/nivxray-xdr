"""Threat-Model Assessor router — /api/threat-model/*.

Deterministic engine is the source of truth. LLM enrichment (MoE panel)
runs strictly ON TOP of the deterministic report and never overrides
severities or drops findings.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import db, get_current_user
from threat_model import parse_mermaid, analyze
from reasoning.moe_panel import run_panel_async
import analyst_corrections as corr


router = APIRouter()


class ThreatModelIn(BaseModel):
    mermaid: str = Field(..., min_length=1, max_length=20_000,
                          description="Mermaid diagram (graph TD / flowchart TD)")
    tags: List[str] = []


class ThreatModelEnrichIn(BaseModel):
    mermaid: str = Field(..., min_length=1, max_length=20_000)
    session_id: Optional[str] = None
    tags: List[str] = []


@router.post("/threat-model/analyze")
async def threat_model_analyze(body: ThreatModelIn, user=Depends(get_current_user)):
    """Deterministic Mermaid → attack-path + MITRE + STRIDE report.

    Never calls an LLM. Always returns a valid report — malformed diagrams
    degrade gracefully with warnings. Also applies any DETERMINISTIC-mode
    analyst corrections (Feb-2026 corrections feature) that match the
    diagram hash or tags.
    """
    diag = parse_mermaid(body.mermaid)
    result = analyze(diag)

    # Corrections: apply deterministic overrides, expose applied set.
    applicable = await corr.find_applicable(
        db, user_email=user["email"], surface="threat_model",
        input_text=body.mermaid, tags=body.tags,
    )
    if applicable:
        corr.apply_overrides(result, applicable)
        # Only bump reuse on overrides that actually applied.
        override_ids = [
            c["id"] for c in applicable
            if c.get("apply_mode") == "override" and c.get("id")
        ]
        await corr.bump_reuse(db, override_ids)
        result["corrections_available"] = [
            {"id": c.get("id"), "confidence": c.get("confidence"),
             "apply_mode": c.get("apply_mode"), "surface": c.get("surface"),
             "correct_prompt": (c.get("correct_prompt") or "")[:400],
             "wrong_finding": c.get("wrong_finding"),
             "verdict": c.get("verdict") or "incorrect",
             "version": c.get("version"), "reuse_count": c.get("reuse_count")}
            for c in applicable
        ]
    return result


@router.post("/threat-model/enrich")
async def threat_model_enrich(body: ThreatModelEnrichIn, user=Depends(get_current_user)):
    """Deterministic report + MoE analyst panel enrichment.

    The MoE panel receives the deterministic report as EVIDENCE and produces
    analyst-grade colour on top. Its findings ARE ADDITIVE — the underlying
    deterministic report stays authoritative.

    Feb-2026: applies deterministic-override corrections to the underlying
    report AND injects a "prior analyst corrections" prompt block into the
    MoE evidence bundle so the LLM biases toward known-good interpretations.
    """
    diag = parse_mermaid(body.mermaid)
    det = analyze(diag)

    applicable = await corr.find_applicable(
        db, user_email=user["email"], surface="threat_model",
        input_text=body.mermaid, tags=body.tags,
    )
    if applicable:
        corr.apply_overrides(det, applicable)
        await corr.bump_reuse(
            db, [c["id"] for c in applicable if c.get("apply_mode") == "override"],
        )

    inject_block = corr.inject_prompt_block(applicable) if applicable else ""

    # Build an evidence bundle the MoE panel can consume — reuse the same
    # shape so no schema drift.
    ev = {
        "input": body.mermaid[:2000],
        "decoded_output": (
            f"Threat model with {det['counts']['nodes']} nodes, "
            f"{det['counts']['edges']} edges, "
            f"{det['counts']['attack_paths']} attack path(s), "
            f"risk={det['risk']['level']} ({det['risk']['score']}/100)."
            + (f"\n\n{inject_block}" if inject_block else "")
        ),
        "steps": [],   # not a decode chain
        "iocs": [],
        "mitre": [{"id": mid} for mid in det.get("mitre_summary", [])],
        "lolbins": [],
        "verdict": det["risk"],
    }
    session_id = body.session_id or f"threat-model-{user.get('email', 'anon')}"
    try:
        moe = await run_panel_async(ev, session_id=session_id)
    except Exception as e:
        moe = {"error": str(e)[:200], "provider": "unavailable",
                "reviewers": {}, "synthesis": {"verdict": det["risk"]}}

    resp = {
        "deterministic": det,   # AUTHORITATIVE
        "enrichment": moe,      # ADDITIVE — never overrides deterministic
    }
    if applicable:
        resp["corrections_available"] = [
            {"id": c.get("id"), "confidence": c.get("confidence"),
             "apply_mode": c.get("apply_mode"), "surface": c.get("surface"),
             "correct_prompt": (c.get("correct_prompt") or "")[:400],
             "wrong_finding": c.get("wrong_finding"),
             "verdict": c.get("verdict") or "incorrect",
             "version": c.get("version"), "reuse_count": c.get("reuse_count")}
            for c in applicable
        ]
    return resp


@router.get("/threat-model/example")
async def threat_model_example(user=Depends(get_current_user)):
    """Return a canonical example diagram + expected report.

    Useful for the frontend `Load Example` button.
    """
    example = """flowchart TD
  User[[EXT]] -->|HTTPS| WAF[[DMZ]]
  WAF --> LB[[DMZ]]
  LB --> API[[INT]]
  API -->|OAuth| Auth[[INT]]
  API --> Cache[[INT]]
  API --> DB[[DATA]]
  API --> Secrets[[DATA]]
  API --> LLM[[EXT]]
  Worker[[INT]] --> Queue[[INT]]
  Queue --> API
"""
    diag = parse_mermaid(example)
    return {"mermaid": example, "report": analyze(diag)}
