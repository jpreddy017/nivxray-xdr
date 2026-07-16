"""Threat-Model Assessor router — /api/threat-model/*.

Deterministic engine is the source of truth. LLM enrichment (MoE panel)
runs strictly ON TOP of the deterministic report and never overrides
severities or drops findings.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import get_current_user
from threat_model import parse_mermaid, analyze
from reasoning.moe_panel import run_panel_async


router = APIRouter()


class ThreatModelIn(BaseModel):
    mermaid: str = Field(..., min_length=1, max_length=20_000,
                          description="Mermaid diagram (graph TD / flowchart TD)")


class ThreatModelEnrichIn(BaseModel):
    mermaid: str = Field(..., min_length=1, max_length=20_000)
    session_id: Optional[str] = None


@router.post("/threat-model/analyze")
async def threat_model_analyze(body: ThreatModelIn, user=Depends(get_current_user)):
    """Deterministic Mermaid → attack-path + MITRE + STRIDE report.

    Never calls an LLM. Always returns a valid report — malformed diagrams
    degrade gracefully with warnings.
    """
    diag = parse_mermaid(body.mermaid)
    return analyze(diag)


@router.post("/threat-model/enrich")
async def threat_model_enrich(body: ThreatModelEnrichIn, user=Depends(get_current_user)):
    """Deterministic report + MoE analyst panel enrichment.

    The MoE panel receives the deterministic report as EVIDENCE and produces
    analyst-grade colour on top. Its findings ARE ADDITIVE — the underlying
    deterministic report stays authoritative.
    """
    diag = parse_mermaid(body.mermaid)
    det = analyze(diag)

    # Build an evidence bundle the MoE panel can consume — reuse the same
    # shape so no schema drift.
    ev = {
        "input": body.mermaid[:2000],
        "decoded_output": (
            f"Threat model with {det['counts']['nodes']} nodes, "
            f"{det['counts']['edges']} edges, "
            f"{det['counts']['attack_paths']} attack path(s), "
            f"risk={det['risk']['level']} ({det['risk']['score']}/100)."
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

    return {
        "deterministic": det,   # AUTHORITATIVE
        "enrichment": moe,      # ADDITIVE — never overrides deterministic
    }


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
