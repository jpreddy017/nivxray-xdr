"""Trust Metrics · canonical models.

Measures whether an analyst can rely on NivXRay's conclusions, not
how many decoders exist. Every sample declares the ground truth an
experienced analyst would give; the harness runs the Investigation
Brain and scores against that ground truth.

Metrics (locked scope):
    * accuracy         — does the verdict band match the ground truth?
    * honesty          — every claim must be evidence-supported
                          (unsupported claims are HARD FAIL).
    * explainability   — every fired intent must carry canonical
                          evidence citing a real source.
    * unknown_handling — samples marked ``must_admit_unknown`` must
                          admit uncertainty (RUNTIME_DEPENDENT verdict
                          or RUNTIME_DEPENDENT intent). HARD FAIL if
                          the tool over-claims certainty.

Deliberately deferred:
    * consistency (already proven by existing determinism gates)
    * coverage    (statistically weak below 100 samples)
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class VerdictExpected(str, Enum):
    MALICIOUS         = "malicious"
    SUSPICIOUS        = "suspicious"
    RUNTIME_DEPENDENT = "runtime_dependent"
    BENIGN            = "benign"


@dataclass
class SampleSpec:
    """Ground truth for one corpus sample. Every field is what an
    experienced SOC analyst would produce for the sample."""
    id:                   str
    title:                str
    source:               str                       # provenance of the sample
    input:                str                       # raw text to analyse
    expected_verdict:     VerdictExpected
    must_fire_intents:    list[str] = field(default_factory=list)
    must_not_fire:        list[str] = field(default_factory=list)
    forbidden_words_in_verdict: list[str] = field(default_factory=list)
    must_admit_unknown:   bool = False
    notes:                str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["expected_verdict"] = self.expected_verdict.value
        return d


@dataclass
class SampleResult:
    """Per-sample outcome of the harness."""
    sample_id:          str
    passed:             bool
    verdict_actual:     str
    verdict_expected:   str
    failures:           list[str] = field(default_factory=list)
    warnings:           list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TrustReport:
    """Aggregate report — the analyst-facing scorecard."""
    total_samples:      int
    accuracy:           float                       # 0.0-1.0
    honesty:            float                       # 0.0-1.0 (unsupported-claims-free)
    explainability:     float                       # 0.0-1.0
    unknown_handling:   float                       # 0.0-1.0
    hard_failures:      int                         # unsupported claims + missed unknowns
    per_sample:         list[SampleResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["per_sample"] = [s.to_dict() for s in self.per_sample]
        return d


__all__ = [
    "SampleSpec",
    "SampleResult",
    "TrustReport",
    "VerdictExpected",
]
