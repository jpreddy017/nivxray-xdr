"""
DIE · Decoder Intelligence Engine (Phase B.1)
─────────────────────────────────────────────

Owner-locked 2026-02-16.  DIE is the deterministic analytical layer
that sits between the frozen Recipe Planner / Recursive Transformation
Engine and the Artifact Router.  Everything in this package is a
*consumer* of the SSOT — nothing here modifies the CEM, the RTE, or
the frozen v1.1 core.

Structure (Cycle A · shipping now):
    powershell_ast   — deterministic PowerShell semantic AST
    lolbas           — LOLBAS knowledge base with MITRE mapping
    ioc_semantic     — network IOC extraction with decode-stage
                       provenance
    api              — single-entry `analyze(...)` orchestration used
                       by the FastAPI router and the internal pipeline

Cycle B (next session) will add JS/Batch/VBS/Bash/Python ASTs and
recursive archive recovery (ZIP · 7z · RAR · CAB · ISO · TAR).
"""

from .api import analyze, analyze_powershell, analyze_command
from .lolbas import lolbas_lookup, LOLBAS_REGISTRY
from .ioc_semantic import extract_iocs
from .powershell_ast import parse_powershell

__all__ = [
    "analyze",
    "analyze_powershell",
    "analyze_command",
    "lolbas_lookup",
    "LOLBAS_REGISTRY",
    "extract_iocs",
    "parse_powershell",
]
