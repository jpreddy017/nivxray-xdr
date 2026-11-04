"""Entity Classifier API — Feb 2026.

Deterministic dotted-quad classification service. Wraps the pure
`engine.entity_classifier` module in a FastAPI router so:

    * the frontend can classify text on-the-fly (Analyst Workspace hover),
    * the Evidence Graph builder can query classifications for artefacts,
    * regression tests can pin exact classification outputs.

Zero verdict / scoring influence — this endpoint is purely observational
until Phase 11.4+ decides to promote classification signals into the
verdict pipeline.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from engine.entity_classifier import (
    classify_token,
    classify_dotted_quads,
    summarise,
    ALL_KINDS,
)
from engine.correlation_engine import correlate
from engine.evidence_graph import EvidenceGraph, EvidenceNode, EvidenceNodeKind


router = APIRouter(prefix="/rc5/entities", tags=["entity-classifier"])


class ClassifyTextRequest(BaseModel):
    """Classify every dotted-quad candidate found in ``text``."""
    text: str = Field(..., min_length=1, max_length=200_000)


class ClassifyTokenRequest(BaseModel):
    """Classify a single token, optionally with a surrounding context."""
    token: str = Field(..., min_length=1, max_length=64)
    context: str = Field("", max_length=1024)


@router.post("/classify")
async def classify_endpoint(req: ClassifyTextRequest):
    """Sweep ``text`` for dotted-quad candidates and classify each."""
    results = classify_dotted_quads(req.text)
    return {
        "count": len(results),
        "kinds": ALL_KINDS,
        "results":  [r.to_dict() for r in results],
        "summary":  summarise(results),
    }


@router.post("/classify-token")
async def classify_token_endpoint(req: ClassifyTokenRequest):
    """Classify a single token in isolation (with optional context)."""
    result = classify_token(req.token, req.context)
    return result.to_dict()


@router.get("/kinds")
async def kinds_endpoint():
    """List of classifier output categories — useful for UI filter panes."""
    return {"kinds": list(ALL_KINDS)}


# ═════════════════════════════════════════════════════════════════════
# Phase 11.3 · Correlation Engine endpoint (side-car, no verdict impact)
# ═════════════════════════════════════════════════════════════════════
class CorrelateRequest(BaseModel):
    """Correlate an evidence graph provided in the request body.

    The graph is expected to be in the JSON shape produced by
    ``EvidenceGraph.model_dump()`` (i.e. a dict with `nodes`, `edges`,
    `schema_version`). Callers that only have raw text should use
    ``/rc5/entities/classify`` and construct a graph on their side.
    """
    graph: dict = Field(..., description="Serialised EvidenceGraph payload")


@router.post("/correlate")
async def correlate_endpoint(req: CorrelateRequest):
    """Run the Phase 11.3 side-car correlation engine on the provided
    graph. Zero verdict influence — this endpoint DESCRIBES relationships
    only. Never mutates any persisted state."""
    try:
        graph = EvidenceGraph.model_validate(req.graph)
    except Exception as e:  # pragma: no cover
        return {"ok": False, "error": f"invalid graph payload: {e!s}"}
    report = correlate(graph)
    return {"ok": True, **report.to_dict()}


__all__ = ["router"]
