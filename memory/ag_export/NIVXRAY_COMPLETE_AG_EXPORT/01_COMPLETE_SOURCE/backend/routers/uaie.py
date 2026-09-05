"""UAIE · Engine A/B Compare + Dry-Run endpoints (Phase 3 support).

    POST /api/uaie/dry-run   { input: str }   → { ssot }
    POST /api/uaie/compare   { input: str }   → { legacy, uaie, diff }

R28 compliant: dry-run is pure orchestrator + projector.  Compare
additionally invokes the LEGACY convergence path via analysis_core so
the graph-diff gate can observe both engines side-by-side.
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from deps import get_current_user
from services.uaie.orchestrator          import Orchestrator
from services.uaie                       import plugins as _plugins_pkg
from services.uaie.ssot_projector        import project as _uaie_project
from services.uaie.legacy_ssot_adapter   import legacy_to_canonical, diff as _diff


router = APIRouter()


class CompareIn(BaseModel):
    input: str = ""


def _run_uaie(text: str) -> Dict[str, Any]:
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run((text or "").encode("utf-8", errors="replace"),
                      root_type="text")
    all_names = [p["name"] for p in _plugins_pkg.all_plugins()]
    return _uaie_project(result, root_input=text or "", root_output="",
                         all_plugin_names=all_names)


def _run_legacy(text: str) -> Dict[str, Any]:
    """Invoke the legacy analysis_core pipeline and normalise its
    output to the canonical SSOT shape.  Errors are surfaced as an
    empty canonical SSOT — never raises to the caller."""
    try:
        import analysis_core as _ac
        # analysis_core exposes convergence via analyze_full(...) in
        # newer builds; older builds via analyze(...).  Try both.
        raw = None
        for fn_name in ("analyze_full", "analyze", "run_pipeline"):
            fn = getattr(_ac, fn_name, None)
            if callable(fn):
                try:
                    raw = fn(text)
                    break
                except Exception:
                    continue
        return legacy_to_canonical(raw or {})
    except Exception:
        return legacy_to_canonical({})


@router.post("/uaie/dry-run")
async def uaie_dry_run(body: CompareIn, user=Depends(get_current_user)):
    return {"ssot": _run_uaie(body.input or "")}


@router.post("/uaie/compare")
async def uaie_compare(body: CompareIn, user=Depends(get_current_user)):
    legacy = _run_legacy(body.input or "")
    uaie   = _run_uaie(body.input or "")
    return {"legacy": legacy,
            "uaie":   uaie,
            "diff":   _diff(legacy, uaie)}
