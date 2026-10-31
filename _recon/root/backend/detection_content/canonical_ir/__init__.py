"""
NivXRay XDR — Canonical Intermediate Representation (NIR) Package.
"""
from .nodes import (
    IRNode,
    Operator,
    BooleanOp,
    FieldCompareNode,
    BooleanLogicNode,
    TimeWindowNode,
    SequenceRefNode,
    AggregationRefNode,
    CorrelationRefNode,
)
from .models import (
    TranslationFidelity,
    UnsupportedConstruct,
    ProvenanceInfo,
    CanonicalIR,
)
from .evaluator import NIREvaluator, EvaluationResult

__all__ = [
    "IRNode",
    "Operator",
    "BooleanOp",
    "FieldCompareNode",
    "BooleanLogicNode",
    "TimeWindowNode",
    "SequenceRefNode",
    "AggregationRefNode",
    "CorrelationRefNode",
    "TranslationFidelity",
    "UnsupportedConstruct",
    "ProvenanceInfo",
    "CanonicalIR",
    "NIREvaluator",
    "EvaluationResult",
]
