"""
DIE · HTTP router
─────────────────
Analyst-facing endpoints so the frontend (and curl / tests) can query
the Decoder Intelligence Engine directly.  Read-only — DIE never
mutates state.  Every endpoint returns the standard analyze envelope
so consumers can switch languages without changing shape.
"""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter
from pydantic import BaseModel, Field

from services.die import (
    analyze,
    analyze_powershell,
    lolbas_lookup,
    LOLBAS_REGISTRY,
    extract_iocs,
    archive_recover,
    archive_recover_recursive,
    archive_detect_kind,
)
from services.die.chain import analyze_chain, looks_like_chain
from services.die.api import _analyze_single
from services.die.intent import classify_intent, classify_intent_from_analyze
from services.die.confidence import score_investigation
from services.die.narrative import generate_report
from services.die.dkp import load_patterns as dkp_load_patterns, pattern_by_id as dkp_pattern_by_id
from deps import db
import base64 as _b64

router = APIRouter(prefix="/die", tags=["die"])


class AnalyzeBody(BaseModel):
    input: str = Field(..., description="Raw command line or script to analyze.")
    language: Optional[str] = Field(
        None, description="Optional force ('powershell'|'cmd'|'javascript'|'vbscript'|'bash').")


@router.post("/analyze")
def die_analyze(body: AnalyzeBody):
    """Single-entry semantic analysis over any command-line input."""
    return {"result": analyze(body.input, language=body.language)}


class UnderstandBody(BaseModel):
    input: str = Field(..., description="Raw analyst paste to understand.")
    execute: bool = Field(True, description="When true, run the plan and record the execution trace.")


@router.post("/understand")
def die_understand(body: UnderstandBody):
    """Input Understanding Engine — classify the input, build the
    investigation plan, execute it (unless disabled) and return the
    analyst-visible trace."""
    from services.die import understand_input
    u = understand_input(body.input, execute=body.execute)
    return {"understanding": u.to_dict()}


@router.post("/powershell/ast")
def die_powershell_ast(body: AnalyzeBody):
    """Force the PowerShell semantic AST parser."""
    return {"result": analyze_powershell(body.input)}


class IocBody(BaseModel):
    input: str
    source: str = "raw"


@router.post("/iocs")
def die_iocs(body: IocBody):
    return {"iocs": extract_iocs(body.input, source=body.source)}


@router.get("/lolbas")
def die_lolbas_all():
    """List every LOLBAS entry (built-in + JSON overlay)."""
    return {
        "count": len(LOLBAS_REGISTRY),
        "entries": [{"binary": k, **v} for k, v in
                    sorted(LOLBAS_REGISTRY.items())],
    }


@router.get("/lolbas/{binary}")
def die_lolbas_one(binary: str):
    entry = lolbas_lookup(binary)
    return {"binary": binary, "entry": entry}


# ── DIE Cycle B · archive recovery ────────────────────────────────
class ArchiveBody(BaseModel):
    """Body carries base64-encoded raw bytes so archives can be posted
    over JSON without multipart plumbing."""
    b64: str = Field(..., description="Base64-encoded archive bytes.")
    name: Optional[str] = Field(None, description="Optional container name.")
    recursive: bool = Field(False, description="Descend nested archives.")
    max_depth: int = Field(3, ge=1, le=8)
    max_children: int = Field(200, ge=1, le=2000)


@router.post("/archive/recover")
def die_archive_recover(body: ArchiveBody):
    try:
        blob = _b64.b64decode(body.b64, validate=False)
    except Exception as e:
        return {"error": f"invalid base64: {e}"}
    if body.recursive:
        return {"result": archive_recover_recursive(
            blob, name=body.name,
            max_depth=body.max_depth,
            max_children=body.max_children)}
    return {"result": archive_recover(blob, name=body.name)}


@router.post("/detect-kind")
def die_detect_kind(body: ArchiveBody):
    try:
        blob = _b64.b64decode(body.b64, validate=False)
    except Exception as e:
        return {"error": f"invalid base64: {e}"}
    return {"kind": archive_detect_kind(blob), "size": len(blob)}


# ── DKP · Decoder Knowledge Pack (Phase B.2 · 2026-02-16) ─────────
@router.get("/dkp/patterns")
def die_dkp_patterns():
    """List every seeded DKP pattern (including JSON overlay)."""
    patterns = [p.to_dict() for p in dkp_load_patterns()]
    return {"count": len(patterns), "patterns": patterns}


@router.get("/dkp/patterns/{pattern_id}")
def die_dkp_pattern(pattern_id: str):
    p = dkp_pattern_by_id(pattern_id)
    return {"pattern": p.to_dict() if p else None}


# ── Chain analyzer (Phase B.2 · 2026-02-16 pm) ────────────────────
@router.post("/chain")
def die_chain(body: AnalyzeBody):
    """Explicit chain-analysis endpoint.

    Returns the full per-step walk (Discovery → Defense Evasion →
    Persistence → C2 → Impact) with each step's own AST, MITRE,
    IOCs, and DKP matches — even when the analyst wants the chain
    view for a single-step input.
    """
    return {"result": analyze_chain(body.input, analyze_fn=_analyze_single)}


# ── Attack Intent Engine (Phase B.7 · 2026-02-16 pm-late) ─────────
@router.post("/intent")
def die_intent(body: AnalyzeBody):
    """Return the Attack Intent for a raw input.

    Deterministic synthesis over the chain envelope — Primary
    Objective + confidence + evidence + MITRE + observed vs missing
    ATT&CK phases + attack progress %.
    """
    env = analyze(body.input, language=body.language)
    intent = classify_intent_from_analyze(env)
    return {"intent": intent}


# ── Case-scoped DIE (workspace_cases.input → full analyze) ────────
@router.get("/case/{case_id}")
async def die_case(case_id: str):
    """Fetch a case's raw input from the case store and return the
    full DIE analyze envelope (chain + attack intent + DKP
    matches).  Powers the Attack Story panel on the Investigation
    Story tab.

    Cases can live in the ``investigations`` collection (the primary
    case store) or ``workspace_cases`` (legacy); we probe both.
    """
    from bson import ObjectId
    from bson.errors import InvalidId
    queries = [{"id": case_id}]
    try:
        queries.append({"_id": ObjectId(case_id)})
    except InvalidId:
        pass
    case = None
    for coll in ("investigations", "workspace_cases"):
        for q in queries:
            case = await db[coll].find_one(q)
            if case and case.get("input"):
                break
        if case and case.get("input"):
            break
    if not case or not case.get("input"):
        return {"error": "case not found or input missing",
                "case_id": case_id, "envelope": None}
    env = analyze(case["input"])
    return {"case_id":  case_id,
            "input_preview": (case["input"] or "")[:512],
            "envelope": env}


# ── Investigation Confidence + 12-section Report (Phase B.4 + B.6) ─
@router.post("/confidence")
def die_confidence(body: AnalyzeBody):
    env = analyze(body.input, language=body.language)
    return {"confidence": score_investigation(env)}


@router.get("/report/{case_id}")
async def die_report(case_id: str):
    """Return the 12-section deterministic investigation report for a
    case — Executive Summary through Confidence Summary."""
    from bson import ObjectId
    from bson.errors import InvalidId
    queries = [{"id": case_id}]
    try:
        queries.append({"_id": ObjectId(case_id)})
    except InvalidId:
        pass
    case = None
    for coll in ("investigations", "workspace_cases"):
        for q in queries:
            case = await db[coll].find_one(q)
            if case and case.get("input"):
                break
        if case and case.get("input"):
            break
    if not case or not case.get("input"):
        return {"error": "case not found or input missing",
                "case_id": case_id, "report": None}
    env = analyze(case["input"])
    return {"case_id": case_id,
            "report":  generate_report(env, case_id=case_id,
                                       input_preview=(case["input"] or "")[:512])}
