"""MoE Panel router — /api/moe/analyze, /api/moe/status.

Runs the 3-critic + synthesiser analyst panel over a decoded payload.
The endpoint accepts either a raw `input` (in which case we run the
deterministic decode pipeline first to build the evidence bundle) OR a
pre-built `evidence` object from an earlier decode call — this avoids
double-decoding when the workspace already has the chain in hand.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import get_current_user
from reasoning.moe_panel import run_panel_async, moe_available
from analysis_core import deterministic_best_decode
from operations import extract_iocs, mitre_map
from lolbas import scan_lolbas


router = APIRouter()


class MoeAnalyzeIn(BaseModel):
    input: Optional[str] = Field(None, description="Raw payload — will be decoded if evidence not supplied")
    evidence: Optional[Dict[str, Any]] = Field(
        None,
        description="Pre-built evidence bundle: {input, decoded_output, chain, iocs, lolbins, mitre, verdict}",
    )
    session_id: Optional[str] = Field(None, description="Correlation id for the LLM calls")


def _build_evidence_from_input(payload: str) -> Dict[str, Any]:
    """Run the deterministic pipeline to synthesise a full evidence bundle."""
    det = deterministic_best_decode(payload)
    decoded = det.get("output") or ""
    corpus = (decoded or "") + "\n" + payload
    iocs = extract_iocs(corpus)
    mitre = mitre_map(corpus)
    lolbins = scan_lolbas(corpus)
    return {
        "input": payload,
        "decoded_output": decoded,
        "chain": [s.get("op") for s in (det.get("steps") or []) if s.get("op")],
        "iocs": iocs,
        "mitre": mitre,
        "lolbins": lolbins,
        "verdict": {"engine": det.get("engine"),
                     "reached_shellcode": det.get("reached_shellcode", False)},
    }


@router.get("/moe/status")
async def moe_status(user=Depends(get_current_user)):
    """Report MoE availability + provider mode."""
    import os
    return {
        "available": moe_available(),
        "llm_configured": bool(os.environ.get("EMERGENT_LLM_KEY")),
        "provider": "hybrid" if os.environ.get("EMERGENT_LLM_KEY") else "static",
        "reviewers": ["malware_analyst", "red_team", "defensive"],
    }


@router.post("/moe/analyze")
async def moe_analyze(body: MoeAnalyzeIn, user=Depends(get_current_user)):
    """Run the MoE analyst panel.

    Priority:
      * If ``evidence`` present → use it directly (skip deterministic decode).
      * Else if ``input`` present → run deterministic decode to build evidence.
      * Else → 400.
    """
    if not body.evidence and not body.input:
        raise HTTPException(status_code=400,
                            detail="Provide either 'input' or 'evidence'.")
    evidence = body.evidence or _build_evidence_from_input(body.input)
    session_id = body.session_id or f"moe-{user.get('email', 'anon')}"
    return await run_panel_async(evidence, session_id=session_id)
