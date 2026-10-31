"""Trust Metrics · public surface.

Measures whether an analyst can rely on NivXRay's conclusions.
Every sample is a ground-truth spec written by an analyst; the
harness runs the Investigation Brain against it and produces a
scorecard on Accuracy · Honesty · Explainability · Unknown Handling.
"""
from __future__ import annotations

from .corpus import load_corpus
from .models import SampleResult, SampleSpec, TrustReport, VerdictExpected
from .runner import score

__all__ = [
    "load_corpus",
    "score",
    "SampleSpec",
    "SampleResult",
    "TrustReport",
    "VerdictExpected",
]
