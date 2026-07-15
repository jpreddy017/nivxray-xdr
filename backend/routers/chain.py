"""Multi-stage payload chain router.

Endpoints:
  * POST /api/decode/chain              → decode + aggregate a chain of payloads
  * POST /api/decode/chain/narrative    → AI narrative on the FULL aggregate (one LLM call)
  * POST /api/decode/chain/export       → export as Markdown or JSON (STIX 2.1 = P1)
  * POST /api/decode/chain/split        → helper: auto-split blank-line-separated paste
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from deps import get_current_user
from chain_analyzer import analyze_chain, auto_split_stages

router = APIRouter()


class ChainStageIn(BaseModel):
    input: str
    label: Optional[str] = None


class ChainIn(BaseModel):
    stages: List[ChainStageIn] = Field(..., min_length=1, max_length=20)


class ChainSplitIn(BaseModel):
    text: str


class ChainNarrativeIn(BaseModel):
    stages: List[ChainStageIn]
    aggregate: Dict[str, Any]


class ChainExportIn(BaseModel):
    stages: List[Dict[str, Any]]
    aggregate: Dict[str, Any]
    format: str = "markdown"   # "markdown" | "json" | "stix"


@router.post("/decode/chain/split")
async def chain_split(body: ChainSplitIn, user=Depends(get_current_user)):
    """Auto-split a raw paste on blank-line boundaries → returns list of stage strings."""
    parts = auto_split_stages(body.text or "")
    return {"count": len(parts), "stages": parts}


@router.post("/decode/chain")
async def chain_decode(body: ChainIn, user=Depends(get_current_user)):
    """Deterministic per-stage decode + unified aggregate. No LLM."""
    stage_inputs = [s.input for s in body.stages]
    result = await analyze_chain(stage_inputs)
    result["labels"] = [s.label for s in body.stages]
    result["timestamp"] = datetime.now(timezone.utc).isoformat()
    return result


@router.post("/decode/chain/narrative")
async def chain_narrative(body: ChainNarrativeIn, user=Depends(get_current_user)):
    """Generate an AI attack-chain narrative for the WHOLE aggregate.

    ONE LLM call across the full chain — not per-stage. Uses the existing
    ai_describe_and_verdict infrastructure, feeding it the concatenated
    output + merged IOCs + kill-chain.
    """
    try:
        from analysis_core import ai_describe_and_verdict
        agg = body.aggregate or {}
        stages = body.stages or []
        # Compose a single "virtual payload" from the entire chain for the LLM
        chain_text = "\n\n───── stage boundary ─────\n\n".join(
            f"[Stage {i}]\nINPUT: {s.input[:400]}\n"
            for i, s in enumerate(stages)
        )
        result = await ai_describe_and_verdict(
            chain_text,
            agg.get("concatenated_output") or "",
            agg.get("iocs") or {},
            agg.get("mitre") or [],
            agg.get("yara") or [],
            {},
            lolbas=agg.get("lolbas") or [],
            want_verdict=True,
            want_describe=True,
        )
        return {
            "narrative": result.get("description"),
            "verdict":   result.get("verdict"),
            "family":    agg.get("family"),
            "kill_chain": agg.get("kill_chain") or [],
        }
    except Exception as e:
        return {"error": str(e)[:400]}


# ────────────────────────────────────────────────────────────────────────
# Markdown + JSON export (STIX 2.1 lives in a follow-up P1)
# ────────────────────────────────────────────────────────────────────────
def _render_markdown(stages: List[Dict[str, Any]], aggregate: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# NivXRay — Multi-Stage Payload Chain Analysis")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"**Stages:** {len(stages)}")
    fam = aggregate.get("family")
    if fam:
        lines.append(f"**Detected family:** {fam.get('family')} · confidence {fam.get('confidence')}%")
    risk = aggregate.get("risk") or {}
    if risk:
        lines.append(f"**Verdict:** {risk.get('verdict')} · {risk.get('score')}/100 ({risk.get('level')})")
    lines.append("")

    # Kill chain
    kc = aggregate.get("kill_chain") or []
    if kc:
        lines.append("## Kill Chain (MITRE ATT&CK ordering)")
        lines.append("")
        lines.append("| # | Technique | Tactic | First seen in |")
        lines.append("|---|-----------|--------|---------------|")
        for i, m in enumerate(kc, 1):
            lines.append(f"| {i} | `{m.get('id')}` {m.get('technique', '')} | {m.get('tactic', '')} | Stage {m.get('stage')} |")
        lines.append("")

    # Merged IOCs
    iocs = aggregate.get("iocs") or {}
    if any(iocs.values()):
        lines.append("## Merged Indicators of Compromise")
        for k, v in iocs.items():
            if v:
                lines.append(f"- **{k}** ({len(v)}): " + ", ".join(f"`{x}`" for x in v[:20]))
        lines.append("")

    # LOLBAS
    lolbas = aggregate.get("lolbas") or []
    if lolbas:
        lines.append("## LOLBAS abuse detected")
        for h in lolbas:
            lines.append(f"- `{h.get('binary', h.get('name', ''))}` — {h.get('desc') or h.get('description', '')}")
        lines.append("")

    # YARA
    yara = aggregate.get("yara") or []
    if yara:
        lines.append("## YARA-lite matches")
        for r in yara:
            lines.append(f"- **{r.get('rule')}** ({r.get('severity')}) — {r.get('description', r.get('desc', ''))}")
        lines.append("")

    # Per-stage detail
    lines.append("## Per-Stage Breakdown")
    for s in stages:
        lines.append("")
        lines.append(f"### Stage {s.get('stage_index')}")
        lines.append(f"- Engine: `{s.get('engine')}` · Confidence: {s.get('confidence')}/100 · reached_shellcode={s.get('reached_shellcode')}")
        if s.get("corrupt_payload"):
            lines.append(f"- ⚠ **CORRUPT PAYLOAD**: {s['corrupt_payload'].get('verdict')}")
        lines.append(f"- Input preview: `{(s.get('input_preview') or '')[:200]}`")
        lines.append("")
        lines.append("```")
        lines.append((s.get("output") or "")[:2000])
        lines.append("```")

    return "\n".join(lines)


@router.post("/decode/chain/export")
async def chain_export(body: ChainExportIn, user=Depends(get_current_user)):
    fmt = (body.format or "markdown").lower()
    if fmt in ("md", "markdown"):
        return {"format": "markdown",
                "content": _render_markdown(body.stages, body.aggregate)}
    if fmt == "json":
        return {"format": "json",
                "content": json.dumps({"stages": body.stages, "aggregate": body.aggregate},
                                      indent=2, default=str)}
    if fmt == "stix":
        # STIX 2.1 SDO/SRO generation is P1 — placeholder returns 501-style shape
        return {"format": "stix",
                "content": None,
                "note": "STIX 2.1 export is a P1 follow-up. Use markdown/json for now."}
    return {"error": f"unknown format: {fmt}"}
