"""Semantic Mapping Preview — Stage 3 engineering surface.

Purpose (owner mandate 2026-02-XX): expose the deterministic Stage 3
pipeline for engineering + validation use. Not the analyst incident
UI — that comes later, after the Soak period.

Endpoint (all under /api):
    POST /v2/semantic/preview  → run Schema Understanding + Semantic
                                 Field Mapping on a raw telemetry
                                 payload and return the full result
                                 including confidence provenance.
"""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from nivxforge.investigation.pipeline.input_classification import (
    classify_input,
)
from nivxforge.investigation.pipeline.parser import parse_input
from nivxforge.investigation.pipeline.schema_understanding import (
    understand_schema,
)
from nivxforge.investigation.pipeline.semantic_alias_registry import (
    SEMANTIC_ALIAS_REGISTRY_VERSION,
    CONCEPTS,
)
from nivxforge.investigation.pipeline.semantic_field_mapper import (
    SEMANTIC_AMBIGUITY_THRESHOLD,
    SEMANTIC_MAPPING_MIN_CONFIDENCE,
    map_semantic_fields,
)


router = APIRouter()


class SemanticPreviewRequest(BaseModel):
    raw: str = Field(..., description="Raw telemetry payload (any format)")
    ambiguity_threshold: Optional[float] = Field(
        default=None,
        description="Override SEMANTIC_AMBIGUITY_THRESHOLD (0..0.5)",
    )


def _to_jsonable(obj: Any) -> Any:
    """Recursively convert dataclasses / tuples to JSON-safe forms."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(x) for x in obj]
    return obj


@router.get("/v2/semantic/registry")
def get_semantic_registry() -> Dict[str, Any]:
    """Registry metadata for the lab UI."""
    return {
        "registry_version": SEMANTIC_ALIAS_REGISTRY_VERSION,
        "concepts": list(CONCEPTS),
        "ambiguity_threshold_default": SEMANTIC_AMBIGUITY_THRESHOLD,
        "mapping_min_confidence": SEMANTIC_MAPPING_MIN_CONFIDENCE,
    }


@router.post("/v2/semantic/preview")
def semantic_preview(req: SemanticPreviewRequest) -> Dict[str, Any]:
    """Run Stage 2b + Stage 3 on raw telemetry and return everything.

    Never touches vendor detection, decoding, investigation graph,
    timeline, ATT&CK, or IOC enrichment. Engineering / validation
    surface only.
    """
    if req.raw is None:
        raise HTTPException(400, "raw payload required")
    threshold = req.ambiguity_threshold
    if threshold is not None and not (0.0 < threshold < 0.5):
        raise HTTPException(422,
            "ambiguity_threshold must be in (0.0, 0.5)")

    classification = classify_input(req.raw)
    parsed = parse_input(req.raw, classification)
    fingerprint = understand_schema(parsed)

    kwargs: Dict[str, Any] = {}
    if threshold is not None:
        kwargs["ambiguity_threshold"] = threshold
    result = map_semantic_fields(fingerprint, parsed, **kwargs)

    return {
        "input_classification": {
            "kind": classification.kind,
            "confidence": classification.confidence,
            "hint": classification.hint,
        },
        "parser": {
            "kind": parsed.kind,
            "records": len(parsed.records or []),
            "diagnostics": list(parsed.diagnostics or []),
        },
        "schema_fingerprint": _to_jsonable(fingerprint),
        "semantic_mapping": _to_jsonable(result),
        "registry_version": SEMANTIC_ALIAS_REGISTRY_VERSION,
        "settings": {
            "ambiguity_threshold": (threshold
                                     if threshold is not None
                                     else SEMANTIC_AMBIGUITY_THRESHOLD),
            "mapping_min_confidence": SEMANTIC_MAPPING_MIN_CONFIDENCE,
        },
    }
