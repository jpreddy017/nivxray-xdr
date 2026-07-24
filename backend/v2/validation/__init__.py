"""v2/validation — Validation Pack (Phase 4.2).

Runs every Golden Corpus dataset through the full investigation
pipeline and validates the actual investigation against the
ExpectedInvestigation contract declared on each dataset.
"""
from .runner import (
    run_dataset, run_all,
    DimensionResult, DatasetResult, ValidationSummary,
)

__all__ = [
    "run_dataset", "run_all",
    "DimensionResult", "DatasetResult", "ValidationSummary",
]
