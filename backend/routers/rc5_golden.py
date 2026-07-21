"""RC5 · Golden Corpus + Explainability Export admin endpoints."""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel

from deps import require_admin, db
from engine.golden_corpus import (
    ensure_golden_indexes, run_and_record, latest_run, COLLECTION,
)
from engine.parsers.cmd_parser import CmdParser
from engine.parsers.powershell_parser import PowerShellParser
from engine.interpreters.cmd_interpreter import CmdInterpreter
from engine.interpreters.powershell_interpreter import PowerShellInterpreter
from engine.detectors.behavior_extractor import extract_behaviors
from engine.detectors.mitre_mapper import map_behaviors_to_mitre
from engine.detectors.mitre_navigator_export import build_navigator_layer
from engine.detectors.mitre_stix_export import build_stix_bundle
from engine.detectors.lolbin_v2 import classify_lolbins
from engine.detectors.verdict_v2 import compute_verdict
from engine.detectors.explainability import compile_explanation
from engine.explain_export import export_json, export_html, export_pdf


router = APIRouter(prefix="/rc5", tags=["rc5-golden-export"])


# ---------------------------------------------------------------------------
# Golden Corpus
# ---------------------------------------------------------------------------
@router.post("/golden/run")
async def golden_run(_: dict = Depends(require_admin)) -> Dict[str, Any]:
    """Run the golden corpus once and persist the report."""
    await ensure_golden_indexes(db)
    report = await run_and_record(db)
    return report.model_dump(mode="json")


@router.get("/golden/latest")
async def golden_latest(_: dict = Depends(require_admin)) -> Dict[str, Any]:
    report = await latest_run(db)
    if not report:
        raise HTTPException(status_code=404, detail="no golden runs yet")
    return report.model_dump(mode="json")


@router.get("/golden/summary")
async def golden_summary(_: dict = Depends(require_admin)) -> Dict[str, Any]:
    """Compact summary suitable for dashboard cards."""
    report = await latest_run(db)
    if not report:
        return {"total": 0, "passed": 0, "failed": 0, "pass_rate": 0.0,
                "coverage": {}, "accuracy": {},
                "regression_count": 0,
                "newly_supported": [], "newly_failing": []}
    return {
        "run_id": report.run_id,
        "ts": report.ts.isoformat(),
        "total": report.total,
        "passed": report.passed,
        "failed": report.failed,
        "pass_rate": report.pass_rate,
        "regression_count": report.regression_count,
        "newly_supported": report.newly_supported,
        "newly_failing": report.newly_failing,
        "coverage": report.coverage,
        "accuracy": report.accuracy,
    }


@router.get("/golden/history")
async def golden_history(
    limit: int = Query(default=20, ge=1, le=200),
    _: dict = Depends(require_admin),
) -> Any:
    cur = db[COLLECTION].find({}, sort=[("ts", -1)]).limit(limit)
    out = []
    async for d in cur:
        d.pop("_id", None)
        out.append({
            "run_id": d.get("run_id"),
            "ts": d.get("ts").isoformat() if d.get("ts") else None,
            "total": d.get("total"),
            "passed": d.get("passed"),
            "failed": d.get("failed"),
            "pass_rate": d.get("pass_rate"),
            "regression_count": d.get("regression_count"),
        })
    return out


# ---------------------------------------------------------------------------
# Explainability Export
# ---------------------------------------------------------------------------
class ExportRequest(BaseModel):
    input: str
    language: Optional[str] = None
    format: str = "json"        # json | html | pdf


def _pipeline(src: str, lang: str) -> Dict[str, Any]:
    parser = PowerShellParser() if lang == "powershell" else CmdParser()
    interp = PowerShellInterpreter() if lang == "powershell" else CmdInterpreter()
    sir = parser.parse(src)
    graph = interp.interpret(sir)
    behaviors = extract_behaviors(graph)
    mitre = map_behaviors_to_mitre(behaviors)
    lolbins = classify_lolbins(graph)
    verdict = compute_verdict(behaviors, mitre, lolbins)
    explain = compile_explanation(
        original_input=src, sir=sir, graph=graph, behaviors=behaviors,
        mitre=mitre, lolbins=lolbins, verdict=verdict,
    )
    return {
        "input": src, "language": lang,
        "semantic_ir": sir.model_dump(mode="json"),
        "exec_graph": graph.model_dump(mode="json"),
        "behaviors": [b.model_dump(mode="json") for b in behaviors],
        "mitre": [m.model_dump(mode="json") for m in mitre],
        "mitre_navigator": build_navigator_layer(mitre),
        "mitre_stix": build_stix_bundle(mitre),
        "lolbins_v2": [l.model_dump(mode="json") for l in lolbins],
        "verdict_v2": verdict.model_dump(mode="json"),
        "explain": explain.model_dump(mode="json"),
    }


@router.post("/explain/export")
async def explain_export(
    payload: ExportRequest,
    _: dict = Depends(require_admin),
) -> Response:
    if not payload.input.strip():
        raise HTTPException(status_code=400, detail="input required")
    lang = (payload.language or "cmd").lower()
    fmt = (payload.format or "json").lower()
    rc5 = _pipeline(payload.input, lang)

    if fmt == "json":
        return Response(content=export_json(rc5),
                        media_type="application/json",
                        headers={"Content-Disposition":
                                 'attachment; filename="nivxray-explain.json"'})
    if fmt == "html":
        return Response(content=export_html(rc5),
                        media_type="text/html; charset=utf-8",
                        headers={"Content-Disposition":
                                 'attachment; filename="nivxray-explain.html"'})
    if fmt == "pdf":
        return Response(content=export_pdf(rc5),
                        media_type="application/pdf",
                        headers={"Content-Disposition":
                                 'attachment; filename="nivxray-explain.pdf"'})
    raise HTTPException(status_code=400,
                        detail=f"unknown format '{fmt}', use json|html|pdf")


__all__ = ["router"]
