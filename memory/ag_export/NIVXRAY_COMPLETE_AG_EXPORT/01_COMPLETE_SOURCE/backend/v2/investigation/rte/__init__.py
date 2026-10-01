"""Recursive Transformation Engine (RTE) — Phase 3 of the
Investigation Brain pipeline.

Public API:
    transform(text)   → TransformationChain

The RTE repeatedly applies deterministic transformations
(base64, gzip, char-array, format-string, IEX peel, …) until no
further transformation is applicable. Every layer is preserved and
every step emits canonical Evidence, making the output
Evidence-Graph-ready and analyst-auditable.
"""
from __future__ import annotations

from .engine import DEFAULT_MAX_DEPTH, transform
from .models import (
    Artifact,
    StopReason,
    TransformationChain,
    TransformationStep,
)

__all__ = [
    "transform",
    "DEFAULT_MAX_DEPTH",
    "Artifact",
    "TransformationChain",
    "TransformationStep",
    "StopReason",
]
