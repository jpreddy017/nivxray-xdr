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
from services.die.dkp import load_patterns as dkp_load_patterns, pattern_by_id as dkp_pattern_by_id
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
