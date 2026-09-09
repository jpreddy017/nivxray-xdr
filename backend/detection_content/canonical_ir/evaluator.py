"""
NivXRay XDR — Deterministic Evaluator for Canonical Intermediate Representation (NIR).
Side-effect free, deterministic, bounded evaluation with performance metrics.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Tuple

from .models import CanonicalIR, TranslationFidelity


class EvaluationResult:
    def __init__(
        self,
        matched: bool,
        content_id: str,
        execution_time_us: float,
        error: str = "",
    ):
        self.matched = matched
        self.content_id = content_id
        self.execution_time_us = execution_time_us
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "matched": self.matched,
            "content_id": self.content_id,
            "execution_time_us": self.execution_time_us,
            "error": self.error,
        }


class NIREvaluator:
    """Evaluates CanonicalIR instances against canonical evidence dictionaries."""

    @staticmethod
    def evaluate(ir: CanonicalIR, event: Dict[str, Any]) -> EvaluationResult:
        start = time.perf_counter()
        if not ir.is_promotable() and ir.fidelity == TranslationFidelity.UNSUPPORTED:
            dur_us = (time.perf_counter() - start) * 1_000_000
            return EvaluationResult(
                matched=False,
                content_id=ir.content_id,
                execution_time_us=dur_us,
                error="Rule has UNSUPPORTED fidelity and cannot be evaluated",
            )

        try:
            matched = ir.evaluate(event)
            dur_us = (time.perf_counter() - start) * 1_000_000
            return EvaluationResult(
                matched=matched,
                content_id=ir.content_id,
                execution_time_us=dur_us,
            )
        except Exception as ex:
            dur_us = (time.perf_counter() - start) * 1_000_000
            return EvaluationResult(
                matched=False,
                content_id=ir.content_id,
                execution_time_us=dur_us,
                error=f"Evaluation exception: {type(ex).__name__}: {ex}",
            )

    @staticmethod
    def evaluate_batch(rules: List[CanonicalIR], event: Dict[str, Any]) -> List[EvaluationResult]:
        return [NIREvaluator.evaluate(r, event) for r in rules]
