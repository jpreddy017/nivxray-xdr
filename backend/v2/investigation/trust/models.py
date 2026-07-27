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
    # ── Extended ground truth (optional, per-sample) — future PRs
    # ── cannot silently degrade any of these dimensions.
    expected_confidence_band:  str | None = None    # "high"|"medium"|"low"|"unknown"
    expected_iocs:             list[dict] = field(default_factory=list)  # [{kind, value}]
    expected_mitre:            list[str]  = field(default_factory=list)  # ["T1197", …]
    expected_behaviors:        list[str]  = field(default_factory=list)  # substrings that must appear in an observed-behavior purpose
    expected_evidence:         list[str]  = field(default_factory=list)  # tags that must appear in any evidence source / observation / meta
    min_recommendations:       int | None = None
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
    # Investigation integrity — fraction of DECLARED analyst-output
    # expectations that matched. 1.0 == every declared expectation
    # held. Missing declarations are ``not asserted`` (do not lower
    # the score). Locked with user directive 2026-07-29.
    integrity_score:    float = 1.0
    integrity_total:    int = 0     # number of declared expectations
    integrity_hits:     int = 0     # number that matched

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
    # Investigation Integrity — mean of per-sample ratios (declared
    # expectations that matched / declared expectations). Protects the
    # complete analyst output, not just the verdict.
    investigation_integrity: float = 1.0
    hard_failures:      int = 0
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
