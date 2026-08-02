"""Investigation Lab endpoints — Timeline · Attack Chain · Correlation
· Full Pipeline (X-Lab observational surface).

Owner directive 2026-02-XX: Phase 2 backend is complete. These
endpoints are the analyst / engineering read-only surface over the
locked schema-1.0 pipeline. No stage may add inference beyond what
its predecessor already validated.

    ┌───────────┐   ┌─────┐   ┌───────┐   ┌──────────┐   ┌───────────────┐
    │ Telemetry │──▶│ CEM │──▶│ Graph │──▶│ Timeline │──▶│ Attack Chain  │──┐
    └───────────┘   └─────┘   └───────┘   └──────────┘   └───────────────┘  │
                                                                             ▼
                                                                    ┌──────────────┐
                                                                    │ Correlation  │
                                                                    └──────────────┘

Endpoints:
    POST /v2/timeline/preview        — Timeline only
    POST /v2/attack-chain/preview    — Timeline + Attack Chain
    POST /v2/correlation/preview     — Timeline + Attack Chain + Correlation
    POST /v2/pipeline/preview        — full pipeline (single response for UI)

Every response carries a Pipeline Manifest describing which modules
produced it (owner directive 2026-02-XX).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from nivxforge.investigation.pipeline.artifact_discovery import discover
from nivxforge.investigation.pipeline.attack_chain_builder import (
    SCHEMA_VERSION as ATTACK_CHAIN_SCHEMA_VERSION,
    build as build_attack_chain,
)
from nivxforge.investigation.pipeline.correlation_engine import (
    DEFAULT_MIN_EDGE_CONFIDENCE,
    SCHEMA_VERSION as CORRELATION_SCHEMA_VERSION,
    build_from_graph as build_correlation,
)
from nivxforge.investigation.pipeline.evidence_extraction import extract
from nivxforge.investigation.pipeline.graph_builder import (
    build as build_graph,
)
from nivxforge.investigation.pipeline.input_classification import (
    classify_input,
)
from nivxforge.investigation.pipeline.normalizers import normalize
from nivxforge.investigation.pipeline.parser import parse_input
from nivxforge.investigation.pipeline.recursive_decoder import decode
from nivxforge.investigation.pipeline.timeline_builder import (
    SCHEMA_VERSION as TIMELINE_SCHEMA_VERSION,
    build as build_timeline,
)
from nivxforge.investigation.pipeline.vendor_detection import detect_vendor


router = APIRouter()


PIPELINE_VERSION = "1.0"


# ── Shared pipeline helper ───────────────────────────────────────────

@dataclass(frozen=True)
class _PipelineRun:
    """Every artefact produced by a single pipeline invocation.

    Used by every endpoint below so no logic is duplicated across
    routes — /pipeline/preview composes exactly the same run object
    the other endpoints emit slices of.
    """
    classification: Any
    parsed: Any
    cem: Any
    graph: Any
    timeline: Any
    attack_chain: Any
    correlation: Any


def _run_pipeline(raw: str,
                   *,
                   min_edge_confidence: float
                   = DEFAULT_MIN_EDGE_CONFIDENCE) -> _PipelineRun:
    if not raw or not raw.strip():
        raise HTTPException(400, "raw payload required")
    classification = classify_input(raw)
    parsed = parse_input(raw, classification)
    cem = normalize(parsed, detect_vendor(parsed))
    artefacts = discover(cem)
    decoded_layers = decode(artefacts)
    evidence = extract(cem, artefacts, decoded_layers)
    graph = build_graph(cem, evidence)
    timeline = build_timeline(cem, graph)
    attack_chain = build_attack_chain(timeline, graph)
    correlation = build_correlation(
        timeline, attack_chain, graph,
        min_edge_confidence=min_edge_confidence,
    )
    return _PipelineRun(
        classification=classification, parsed=parsed, cem=cem,
        graph=graph, timeline=timeline,
        attack_chain=attack_chain, correlation=correlation,
    )


def _manifest(modules: list[str],
               *,
               min_edge_confidence: Optional[float] = None,
               ) -> Dict[str, Any]:
    """Pipeline Manifest attached to every lab response.

    `generated_at` is intentionally an ISO timestamp — it is the ONLY
    non-deterministic field in the response and is present so audit
    consumers can distinguish separate invocations. Everything else
    downstream (Timeline / Attack Chain / Correlation payloads) is
    byte-identical given the same input.
    """
    m: Dict[str, Any] = {
        "pipeline_version": PIPELINE_VERSION,
        "schema_versions": {
            "timeline":     TIMELINE_SCHEMA_VERSION,
            "attack_chain": ATTACK_CHAIN_SCHEMA_VERSION,
            "correlation":  CORRELATION_SCHEMA_VERSION,
        },
        "modules": modules,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "deterministic": True,
    }
    if min_edge_confidence is not None:
        m["min_edge_confidence"] = min_edge_confidence
    return m


def _cem_summary(run: _PipelineRun) -> Dict[str, Any]:
    return {
        "vendor": run.cem.vendor,
        "vendor_route": run.cem.vendor_route,
        "event_count": len(run.cem.events),
        "incident_count": len(run.cem.incidents),
    }


def _classification_dict(run: _PipelineRun) -> Dict[str, Any]:
    return {
        "kind": run.classification.kind,
        "confidence": run.classification.confidence,
        "hint": run.classification.hint,
    }


def _graph_summary(run: _PipelineRun) -> Dict[str, Any]:
    return {
        "node_count": len(run.graph.nodes),
        "edge_count": len(run.graph.edges),
        "kinds": sorted({n.kind for n in run.graph.nodes}),
    }


# ── /v2/timeline/preview ─────────────────────────────────────────────

class TimelinePreviewRequest(BaseModel):
    raw: str = Field(..., description="Raw telemetry payload (any format)")
    include_graph: bool = Field(
        default=False,
        description=("If true, include the underlying InvestigationGraph "
                     "slice used to render the timeline."),
    )
    include_attack_chain: bool = Field(
        default=False,
        description=("If true, also derive the AttackChain over "
                     "the timeline."),
    )


@router.post("/v2/timeline/preview")
def timeline_preview(req: TimelinePreviewRequest) -> Dict[str, Any]:
    """Render the Investigation Graph as a chronological Timeline."""
    run = _run_pipeline(req.raw)
    modules = ["parser", "cem", "graph", "timeline"]
    payload: Dict[str, Any] = {
        "manifest": _manifest(modules),
        "input_classification": _classification_dict(run),
        "cem": _cem_summary(run),
        "graph_summary": _graph_summary(run),
        "timeline": run.timeline.to_dict(),
    }
    if req.include_graph:
        payload["graph"] = run.graph.to_dict()
    if req.include_attack_chain:
        payload["attack_chain"] = run.attack_chain.to_dict()
        payload["manifest"]["modules"] = modules + ["attack_chain"]
    return payload


# ── /v2/attack-chain/preview ────────────────────────────────────────

class AttackChainPreviewRequest(BaseModel):
    raw: str = Field(..., description="Raw telemetry payload (any format)")


@router.post("/v2/attack-chain/preview")
def attack_chain_preview(req: AttackChainPreviewRequest) -> Dict[str, Any]:
    """Render the Attack Chain — deterministic causal edges."""
    run = _run_pipeline(req.raw)
    return {
        "manifest": _manifest(
            ["parser", "cem", "graph", "timeline", "attack_chain"]),
        "cem": _cem_summary(run),
        "timeline_summary": {
            "entry_count": len(run.timeline.entries),
            "unknown_time_count": run.timeline.unknown_time_count,
        },
        "attack_chain": run.attack_chain.to_dict(),
    }


# ── /v2/correlation/preview ─────────────────────────────────────────

class CorrelationPreviewRequest(BaseModel):
    raw: str = Field(..., description="Raw telemetry payload (any format)")
    min_edge_confidence: float = Field(
        default=DEFAULT_MIN_EDGE_CONFIDENCE,
        ge=0.0, le=1.0,
        description=("Minimum RELATIONSHIP confidence for an AttackEdge "
                     "to bridge a cluster."),
    )


@router.post("/v2/correlation/preview")
def correlation_preview(req: CorrelationPreviewRequest) -> Dict[str, Any]:
    """Render IncidentClusters — connected-components over
    AttackEdges above the confidence threshold. Produces incidents,
    never new events."""
    run = _run_pipeline(req.raw,
                         min_edge_confidence=req.min_edge_confidence)
    return {
        "manifest": _manifest(
            ["parser", "cem", "graph", "timeline",
             "attack_chain", "correlation"],
            min_edge_confidence=req.min_edge_confidence,
        ),
        "cem": _cem_summary(run),
        "timeline_summary": {
            "entry_count": len(run.timeline.entries),
            "unknown_time_count": run.timeline.unknown_time_count,
        },
        "attack_chain_summary": {
            "edge_count": len(run.attack_chain.edges),
            "edge_kinds": run.attack_chain.edge_kinds,
        },
        "correlation": run.correlation.to_dict(),
    }


# ── /v2/pipeline/preview — everything at once (Inspector-UI driver) ─

class FullPipelinePreviewRequest(BaseModel):
    raw: str = Field(..., description="Raw telemetry payload (any format)")
    min_edge_confidence: float = Field(
        default=DEFAULT_MIN_EDGE_CONFIDENCE,
        ge=0.0, le=1.0,
        description=("Threshold applied when building the Correlation."),
    )
    include_graph: bool = Field(
        default=False,
        description=("Include the full InvestigationGraph payload. "
                     "Off by default because it can be verbose on "
                     "large inputs."),
    )


@router.post("/v2/pipeline/preview")
def pipeline_preview(req: FullPipelinePreviewRequest) -> Dict[str, Any]:
    """Run the full investigation pipeline and return every stage's
    canonical output plus a Pipeline Manifest.

    This endpoint is the single driver for the Inspector UI. It does
    NOT duplicate any logic — it composes the same outputs the
    individual endpoints emit slices of, guaranteed via the shared
    `_run_pipeline` helper.
    """
    run = _run_pipeline(req.raw,
                         min_edge_confidence=req.min_edge_confidence)
    payload: Dict[str, Any] = {
        "manifest": _manifest(
            ["parser", "cem", "graph", "timeline",
             "attack_chain", "correlation"],
            min_edge_confidence=req.min_edge_confidence,
        ),
        "input_classification": _classification_dict(run),
        "cem": _cem_summary(run),
        "graph_summary": _graph_summary(run),
        "timeline": run.timeline.to_dict(),
        "attack_chain": run.attack_chain.to_dict(),
        "correlation": run.correlation.to_dict(),
    }
    if req.include_graph:
        payload["graph"] = run.graph.to_dict()
    return payload
