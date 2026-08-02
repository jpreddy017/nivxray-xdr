"""Timeline Preview — Stage 9 engineering surface (X-Lab observational).

Purpose (owner directive 2026-02-XX / Phase 2):
    Expose the deterministic Investigation Graph → Timeline projection
    for engineering and analyst validation. This is the *renderer* over
    validated evidence — never invents, guesses, or synthesises events.

Endpoint (all under /api):
    POST /v2/timeline/preview  → run the full production pipeline
                                  (classify → parse → normalize →
                                   discover → decode → extract →
                                   graph → timeline) on a raw telemetry
                                   payload and return the Timeline plus
                                   its supporting graph slice.

Isolation contract:
    * Read-only. Nothing here mutates state.
    * Not wired into the Workspace analyst UI.
    * Kept parallel to /v2/semantic/preview so lab utilities live
      together and are trivial to gate off if needed.
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from nivxforge.investigation.pipeline.artifact_discovery import discover
from nivxforge.investigation.pipeline.attack_chain_builder import (
    build as build_attack_chain,
)
from nivxforge.investigation.pipeline.correlation_engine import (
    DEFAULT_MIN_EDGE_CONFIDENCE,
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
    build as build_timeline,
)
from nivxforge.investigation.pipeline.vendor_detection import detect_vendor


router = APIRouter()


class TimelinePreviewRequest(BaseModel):
    raw: str = Field(..., description="Raw telemetry payload (any format)")
    include_graph: bool = Field(
        default=False,
        description=("If true, include the underlying InvestigationGraph "
                     "slice used to render the timeline."),
    )
    include_attack_chain: bool = Field(
        default=False,
        description=("If true, also derive the AttackChain "
                     "(parent_of / led_to / same_context edges) over "
                     "the timeline."),
    )


@router.post("/v2/timeline/preview")
def timeline_preview(req: TimelinePreviewRequest) -> Dict[str, Any]:
    """Render the Investigation Graph as a chronological Timeline.

    This is the analyst-friendly projection of validated evidence.
    No inference happens in this endpoint; every entry is grounded in
    a CEM event_id and links only to nodes that already exist in the
    Investigation Graph.
    """
    if not req.raw or not req.raw.strip():
        raise HTTPException(400, "raw payload required")

    classification = classify_input(req.raw)
    parsed = parse_input(req.raw, classification)
    cem = normalize(parsed, detect_vendor(parsed))
    artefacts = discover(cem)
    decoded_layers = decode(artefacts)
    evidence = extract(cem, artefacts, decoded_layers)
    graph = build_graph(cem, evidence)
    timeline = build_timeline(cem, graph)

    payload: Dict[str, Any] = {
        "input_classification": {
            "kind": classification.kind,
            "confidence": classification.confidence,
            "hint": classification.hint,
        },
        "cem": {
            "vendor": cem.vendor,
            "vendor_route": cem.vendor_route,
            "event_count": len(cem.events),
            "incident_count": len(cem.incidents),
        },
        "graph_summary": {
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "kinds": sorted({n.kind for n in graph.nodes}),
        },
        "timeline": timeline.to_dict(),
    }
    if req.include_graph:
        payload["graph"] = graph.to_dict()
    if req.include_attack_chain:
        payload["attack_chain"] = build_attack_chain(timeline, graph).to_dict()
    return payload


class AttackChainPreviewRequest(BaseModel):
    raw: str = Field(..., description="Raw telemetry payload (any format)")


@router.post("/v2/attack-chain/preview")
def attack_chain_preview(req: AttackChainPreviewRequest) -> Dict[str, Any]:
    """Render the Attack Chain — deterministic causal edges over the
    canonical Timeline.

    Every edge carries `derivation_rule[]` explaining exactly why it
    exists, and a RELATIONSHIP confidence separate from any event
    confidence. Read-only, X-Lab / observational surface only.
    """
    if not req.raw or not req.raw.strip():
        raise HTTPException(400, "raw payload required")

    classification = classify_input(req.raw)
    parsed = parse_input(req.raw, classification)
    cem = normalize(parsed, detect_vendor(parsed))
    artefacts = discover(cem)
    decoded_layers = decode(artefacts)
    evidence = extract(cem, artefacts, decoded_layers)
    graph = build_graph(cem, evidence)
    timeline = build_timeline(cem, graph)
    attack_chain = build_attack_chain(timeline, graph)

    return {
        "cem": {
            "vendor": cem.vendor,
            "vendor_route": cem.vendor_route,
            "event_count": len(cem.events),
        },
        "timeline_summary": {
            "entry_count": len(timeline.entries),
            "unknown_time_count": timeline.unknown_time_count,
        },
        "attack_chain": attack_chain.to_dict(),
    }


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
    """Render IncidentClusters — deterministic connected-components
    over the AttackChain edges. Produces incidents, never new events.

    Read-only, X-Lab / observational surface only.
    """
    if not req.raw or not req.raw.strip():
        raise HTTPException(400, "raw payload required")

    classification = classify_input(req.raw)
    parsed = parse_input(req.raw, classification)
    cem = normalize(parsed, detect_vendor(parsed))
    artefacts = discover(cem)
    decoded_layers = decode(artefacts)
    evidence = extract(cem, artefacts, decoded_layers)
    graph = build_graph(cem, evidence)
    timeline = build_timeline(cem, graph)
    attack_chain = build_attack_chain(timeline, graph)
    correlation = build_correlation(
        timeline, attack_chain, graph,
        min_edge_confidence=req.min_edge_confidence,
    )

    return {
        "cem": {
            "vendor": cem.vendor,
            "vendor_route": cem.vendor_route,
            "event_count": len(cem.events),
        },
        "timeline_summary": {
            "entry_count": len(timeline.entries),
            "unknown_time_count": timeline.unknown_time_count,
        },
        "attack_chain_summary": {
            "edge_count": len(attack_chain.edges),
            "edge_kinds": attack_chain.edge_kinds,
        },
        "correlation": correlation.to_dict(),
    }
