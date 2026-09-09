"""RC5 · Phase 4.5 · `/api/rc5/parse` diagnostic endpoint.

Read-only. Deterministic. AI-free. Gated for Admin + Debug mode.

Purpose:
  Return the FULL RC5 semantic engine trace for a given CMD or PowerShell
  one-liner so QA, developers, and future UI code can see exactly what the
  deterministic pipeline produced — with no LLM involvement.

Response shape:
  {
    "api_version": "1",
    "semantic_engine_version": 1,
    "plugin_versions": { "cmd": {...}, "powershell": {...},
                         "behavior_extractor": {...} },
    "language": "cmd" | "powershell",
    "input": "<original input>",
    "semantic_ir": { …SIRTree JSON… },
    "exec_graph": { "nodes": [ …ExecNodes… ], "schema_version": 1 },
    "behaviors": [ …Behavior JSONs… ],
    "evidence_refs": { "<behavior_id>": ["<node_id>", …], … },
    "confidence_summary": { "min": .., "median": .., "max": ..,
                            "unresolved_count": .., "total": .. },
    "reconstructed_commands": [ "<one per non-unresolved node>", … ],
    "decode_chain": [ "<parser step 1>", "<step 2>", … ],
    "warnings": [ …parser warnings… ],
    "unresolved_nodes": [ { "id": "n_...", "reason": "..." }, … ],
    "processing_time_ms": <float>
  }

Gating:
  * Admin JWT required (via existing `require_admin` dep).
  * ADDITIONALLY, `RC5_DIAG_ENABLED=true` env var (or `SEMANTIC_ENGINE_V2=true`).
    In production this defaults to false; must be flipped explicitly.
  * Zero AI involvement (`--no-ai` compatible by construction — the
    endpoint never touches `emergentintegrations`).
"""
from __future__ import annotations

import os
import statistics
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from deps import require_admin
# Import plugin modules — this registers parser/interpreter/detector.
from engine.exec_graph import SCHEMA_VERSION as EXEC_SV, NodeKind
from engine.evidence_graph import EVIDENCE_GRAPH_SCHEMA_VERSION
from engine.evidence_graph_builder import build_evidence_graph_sidecar
from engine.evidence_graph_config import evidence_graph_mode
from engine.evidence_graph_observability import (
    aggregate as evidence_graph_aggregate,
    record as evidence_graph_record,
)
from engine.semantic_ir import SIR_SCHEMA_VERSION
from engine.plugin_api import get_parser, get_interpreter
from engine.parsers import cmd_parser as _cmd_parser  # noqa: F401 — register
from engine.parsers import powershell_parser as _ps_parser  # noqa: F401 — register
from engine.interpreters import cmd_interpreter as _cmd_interp  # noqa: F401
from engine.interpreters import powershell_interpreter as _ps_interp  # noqa: F401
from engine.detectors.behavior_extractor import extract_behaviors  # noqa: F401
from engine.detectors.mitre_mapper import (
    map_behaviors_to_mitre, MITRE_RULES,
)
from engine.detectors.mitre_navigator_export import (
    build_navigator_layer, NAV_LAYER_VERSION,
)
from engine.detectors.mitre_stix_export import build_stix_bundle, STIX_VERSION
from engine.detectors.lolbin_v2 import classify_lolbins
from engine.detectors.verdict_v2 import compute_verdict
from engine.detectors.explainability import compile_explanation


API_VERSION = "1"
router = APIRouter(prefix="/rc5", tags=["rc5-diag"])


# ---------------------------------------------------------------------------
# Gating
# ---------------------------------------------------------------------------
def _diag_enabled() -> bool:
    v = os.environ.get("RC5_DIAG_ENABLED", "").lower()
    if v in ("1", "true", "yes", "on"):
        return True
    # Also enabled when semantic engine v2 is on.
    v2 = os.environ.get("SEMANTIC_ENGINE_V2", "").lower()
    return v2 in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Request / Response schemas — drive OpenAPI docs
# ---------------------------------------------------------------------------
class ParseRequest(BaseModel):
    input: str = Field(..., description="Raw CMD or PowerShell one-liner / script")
    language: Optional[str] = Field(
        default=None,
        description="Force a language: 'cmd' | 'powershell'. Auto-detected when omitted.",
    )


class UnresolvedRef(BaseModel):
    id: str
    reason: str


class ConfidenceSummary(BaseModel):
    min: int
    median: int
    max: int
    unresolved_count: int
    total: int


class ParseResponse(BaseModel):
    api_version: str
    semantic_engine_version: int
    plugin_versions: Dict[str, Dict[str, Any]]
    language: str
    input: str
    semantic_ir: Dict[str, Any]
    exec_graph: Dict[str, Any]
    behaviors: List[Dict[str, Any]]
    evidence_refs: Dict[str, List[str]]
    confidence_summary: ConfidenceSummary
    reconstructed_commands: List[str]
    decode_chain: List[str]
    warnings: List[str]
    unresolved_nodes: List[UnresolvedRef]
    mitre: List[Dict[str, Any]]
    mitre_navigator: Dict[str, Any]
    mitre_stix: Dict[str, Any]
    lolbins_v2: List[Dict[str, Any]]
    verdict_v2: Dict[str, Any]
    explain: Dict[str, Any]
    # Phase 11.0/11.1 side-car. Only populated when
    # `NIVX_EVIDENCE_GRAPH=sidecar` is set. Absent in production by default.
    # NOT a verdict driver — analyst-inspection only.
    evidence_graph: Optional[Dict[str, Any]] = None
    evidence_graph_metrics: Optional[Dict[str, Any]] = None
    # Phase 11.3 · Correlation Engine side-car report. Same mode gate.
    # Zero verdict influence — describes relationships only.
    correlation: Optional[Dict[str, Any]] = None
    processing_time_ms: float


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------
_PS_HINTS = ("$", "-nop", "-nopr", "-encodedcommand", "-enc ", "-executionpolicy",
             "invoke-", "get-", "set-", "new-", "start-process", "iex ", "pwsh",
             "powershell", "[convert]::", "[system.")


def _detect_language(text: str) -> str:
    low = text.lower().strip()
    if not low:
        return "cmd"
    if low.startswith(("$", "iex ", "invoke-", "get-", "set-", "new-", "start-")):
        return "powershell"
    for h in _PS_HINTS:
        if h in low:
            return "powershell"
    return "cmd"


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------
@router.post(
    "/parse",
    response_model=ParseResponse,
    summary="RC5 diagnostic parse (Admin + Debug only)",
    description=(
        "Runs the deterministic RC5 pipeline (Normalizer → Semantic IR → "
        "Interpreter → ExecGraph → Behavior Extractor) on the supplied "
        "command-line and returns the full trace. **Never** invokes any "
        "AI / LLM. Requires an admin JWT and `RC5_DIAG_ENABLED=true` (or "
        "`SEMANTIC_ENGINE_V2=true`) in the environment. Response is "
        "byte-deterministic for a given input + engine version."
    ),
)
async def rc5_parse(
    payload: ParseRequest,
    response: Response,
    _: dict = Depends(require_admin),
) -> ParseResponse:
    if not _diag_enabled():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=("RC5 diagnostic endpoint is disabled. Set "
                    "RC5_DIAG_ENABLED=true or SEMANTIC_ENGINE_V2=true to enable."),
        )
    src = payload.input or ""
    lang = payload.language or _detect_language(src)
    if lang not in ("cmd", "powershell"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unsupported language: {lang!r}. Choose 'cmd' or 'powershell'.",
        )

    t0 = time.perf_counter()
    parser = get_parser(lang)
    interp = get_interpreter(lang)
    if parser is None or interp is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"RC5 plugin not registered for language {lang!r}",
        )
    sir = parser.parse(src)
    graph = interp.interpret(sir)
    behaviors = extract_behaviors(graph)
    mitre_mappings = map_behaviors_to_mitre(behaviors)
    lolbin_rows = classify_lolbins(graph)
    verdict = compute_verdict(behaviors, mitre_mappings, lolbin_rows)
    explanation = compile_explanation(
        original_input=src, sir=sir, graph=graph, behaviors=behaviors,
        mitre=mitre_mappings, lolbins=lolbin_rows, verdict=verdict,
    )

    # Confidence summary — over deterministic-origin nodes.
    conf_vals = [n.confidence for n in graph.nodes if n.origin == "deterministic"]
    unresolved = [n for n in graph.nodes if n.kind == NodeKind.unresolved]
    if conf_vals:
        conf_summary = ConfidenceSummary(
            min=min(conf_vals), max=max(conf_vals),
            median=int(statistics.median(conf_vals)),
            unresolved_count=len(unresolved),
            total=len(graph.nodes),
        )
    else:
        conf_summary = ConfidenceSummary(
            min=0, max=0, median=0,
            unresolved_count=len(unresolved), total=len(graph.nodes),
        )

    # Decode chain — one line per parser/interpreter step attributable.
    decode_chain: List[str] = [f"normalize:{lang}", f"parse:{lang}",
                               f"interpret:{lang}", "behavior_extract",
                               "mitre_v2", "lolbin_v2", "verdict_v2",
                               "explainability"]

    # Reconstructed commands — non-empty, non-unresolved
    reconstructed = [n.reconstructed for n in graph.nodes
                     if n.reconstructed and n.kind != NodeKind.unresolved]

    # Evidence refs — behavior_id → [node_ids]
    evidence_refs = {b.id: list(b.evidence_nodes) for b in behaviors}

    unresolved_refs = [UnresolvedRef(id=n.id, reason=str(n.args.get("reason") or ""))
                       for n in unresolved]

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)
    # X-Decode-Ms performance header (analyst-facing perf signal).
    response.headers["X-Decode-Ms"] = f"{elapsed_ms:.3f}"

    # Phase 11.0 / 11.1 · Evidence Knowledge Graph side-car.
    # Controlled by `NIVX_EVIDENCE_GRAPH` (default off in prod). The
    # graph is analyst-inspection only — never a verdict driver.
    evidence_graph_json: Optional[Dict[str, Any]] = None
    evidence_graph_metrics_json: Optional[Dict[str, Any]] = None
    # Phase 11.3 · Correlation Engine side-car (Feb-2026).
    correlation_json: Optional[Dict[str, Any]] = None
    if evidence_graph_mode() == "sidecar":
        try:
            eg_graph, eg_metrics = build_evidence_graph_sidecar(graph)
            if eg_graph is not None:
                evidence_graph_json = eg_graph.to_dict()
                # Phase 11.3 · pure-function correlation on the same
                # graph. Zero verdict influence. Any exception here is
                # silenced — analyst response must never regress.
                try:
                    from engine.correlation_engine import correlate as _corr
                    correlation_json = _corr(eg_graph).to_dict()
                except Exception:  # pragma: no cover
                    correlation_json = None
            if eg_metrics is not None:
                evidence_graph_metrics_json = eg_metrics.to_dict()
                evidence_graph_record(eg_metrics, error=False)
            else:
                evidence_graph_record(None, error=True)
        except Exception:
            evidence_graph_record(None, error=True)
            raise

    return ParseResponse(
        api_version=API_VERSION,
        semantic_engine_version=EXEC_SV,
        plugin_versions={
            "semantic_ir":         {"schema_version": SIR_SCHEMA_VERSION},
            "exec_graph":          {"schema_version": EXEC_SV},
            "cmd_parser":          {"name": "cmd",        "schema_version": SIR_SCHEMA_VERSION},
            "cmd_interpreter":     {"name": "cmd",        "schema_version": EXEC_SV},
            "powershell_parser":   {"name": "powershell", "schema_version": SIR_SCHEMA_VERSION},
            "powershell_interpreter": {"name": "powershell", "schema_version": EXEC_SV},
            "behavior_extractor":  {"schema_version": EXEC_SV},
            "mitre_mapper":        {"schema_version": EXEC_SV,
                                    "rule_count": len(MITRE_RULES)},
            "mitre_navigator":     {"schema_version": NAV_LAYER_VERSION},
            "mitre_stix":          {"schema_version": STIX_VERSION},
            "lolbin_v2":           {"schema_version": EXEC_SV},
            "verdict_v2":          {"schema_version": EXEC_SV},
            "explainability":      {"schema_version": EXEC_SV},
            "evidence_graph":      {"schema_version": EVIDENCE_GRAPH_SCHEMA_VERSION,
                                    "mode": evidence_graph_mode()},
        },
        language=lang,
        input=src,
        semantic_ir=sir.model_dump(mode="json"),
        exec_graph=graph.model_dump(mode="json"),
        behaviors=[b.model_dump(mode="json") for b in behaviors],
        evidence_refs=evidence_refs,
        confidence_summary=conf_summary,
        reconstructed_commands=reconstructed,
        decode_chain=decode_chain,
        warnings=list(sir.warnings or []),
        unresolved_nodes=unresolved_refs,
        mitre=[m.model_dump(mode="json") for m in mitre_mappings],
        mitre_navigator=build_navigator_layer(mitre_mappings),
        mitre_stix=build_stix_bundle(mitre_mappings),
        lolbins_v2=[r.model_dump(mode="json") for r in lolbin_rows],
        verdict_v2=verdict.model_dump(mode="json"),
        explain=explanation.model_dump(mode="json"),
        evidence_graph=evidence_graph_json,
        evidence_graph_metrics=evidence_graph_metrics_json,
        correlation=correlation_json,
        processing_time_ms=elapsed_ms,
    )


@router.get(
    "/status",
    summary="RC5 diagnostic status (Admin only)",
    description="Reports whether the diagnostic endpoint is enabled + engine version.",
)
async def rc5_status(_: dict = Depends(require_admin)) -> Dict[str, Any]:
    return {
        "api_version": API_VERSION,
        "semantic_engine_version": EXEC_SV,
        "diag_enabled": _diag_enabled(),
        "flag_semantic_engine_v2": os.environ.get("SEMANTIC_ENGINE_V2", "").lower() in ("1","true","yes","on"),
        "supported_languages": ["cmd", "powershell"],
        "evidence_graph": {
            "mode": evidence_graph_mode(),
            "schema_version": EVIDENCE_GRAPH_SCHEMA_VERSION,
        },
    }


@router.get(
    "/evidence-graph/metrics",
    summary="RC5 Evidence Graph observability (Admin only)",
    description=(
        "Rolling in-memory telemetry for the Evidence Knowledge Graph "
        "side-car: p50/p95 build time, peak memory, mean node/edge "
        "counts, integrity-error total, and success rate over the "
        "current window. Operational only — NEVER influences verdicts."
    ),
)
async def rc5_evidence_graph_metrics(_: dict = Depends(require_admin)) -> Dict[str, Any]:
    snap = evidence_graph_aggregate()
    return {
        "api_version": API_VERSION,
        "mode": evidence_graph_mode(),
        "schema_version": EVIDENCE_GRAPH_SCHEMA_VERSION,
        **snap.to_dict(),
    }
