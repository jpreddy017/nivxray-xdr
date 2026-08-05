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
)

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
