"""GATE 3 · the frozen Finding contract of the NivXForge detection fabric.

Design record: `/app/memory/production-gates/GATE_03_DETECTION_PREVENTION_FABRIC.md`.

One record shape for EVERY analyzer — deterministic rule, reputation,
static analysis, ML, behavioural, sequence, anomaly, intel — so a new
engine can be added without touching correlation, verdict or UI.

The invariants are enforced HERE, by construction, not by convention:

* `evidence_refs` must be non-empty  → "no verdict without evidence"
  cannot be violated downstream, because a finding that cites nothing
  cannot exist.
* a `score` must declare its `score_scale` → no dimensionless numbers
  reach an analyst.
* `features` must come with a `feature_digest` → every score can be
  re-derived and re-audited later (this is also what makes retrospection
  idempotent).
* an ML-class finding must carry `model_id` + `model_version` → no
  unversioned inference can ever enter the evidence chain.

A Finding is NOT a verdict. It carries no authority of its own; the
verdict plane composes findings deterministically and explainably.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AnalyzerClass(str, Enum):
    DETERMINISTIC = "DETERMINISTIC"
    REPUTATION = "REPUTATION"
    STATIC = "STATIC"
    ML = "ML"
    BEHAVIORAL = "BEHAVIORAL"
    SEQUENCE = "SEQUENCE"
    ANOMALY = "ANOMALY"
    INTEL = "INTEL"


class InferenceLocation(str, Enum):
    ENDPOINT = "ENDPOINT"
    BACKEND = "BACKEND"


class Severity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingState(str, Enum):
    EMITTED = "EMITTED"
    SUPERSEDED = "SUPERSEDED"      # replaced by a later evaluation (Gate 6)
    SUPPRESSED = "SUPPRESSED"      # an exclusion suppressed it (Gate 9)


class Outcome(str, Enum):
    """Three DIFFERENT facts. Collapsing them is how a console starts
    implying "clean" when it actually means "did not look"."""
    EVALUATED_NO_FINDING = "EVALUATED_NO_FINDING"
    NOT_EVALUATED = "NOT_EVALUATED"
    EVALUATION_FAILED = "EVALUATION_FAILED"
    FINDINGS = "FINDINGS"


def feature_digest(features: Dict[str, Any]) -> str:
    """Canonical digest of the values a score was computed from."""
    blob = json.dumps(features, sort_keys=True, separators=(",", ":"),
                      default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    tenant_id: str
    analyzer_id: str
    analyzer_class: AnalyzerClass
    analyzer_version: str
    label: str
    evidence_refs: List[str]
    observed_at: Optional[str] = None
    evaluation_time: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())

    endpoint_ref: Optional[str] = None
    model_id: Optional[str] = None
    model_version: Optional[str] = None
    score: Optional[float] = None
    score_scale: Optional[str] = None
    severity_hint: Severity = Severity.INFORMATIONAL
    features: Dict[str, Any] = Field(default_factory=dict)
    feature_digest: Optional[str] = None
    attck: List[str] = Field(default_factory=list)
    analysis_basis: str
    inference_location: InferenceLocation = InferenceLocation.BACKEND
    state: FindingState = FindingState.EMITTED
    suppressed_by: Optional[str] = None
    retrospection: Optional[Dict[str, Any]] = None
    finding_id: Optional[str] = None

    @model_validator(mode="after")
    def _enforce_contract(self) -> "Finding":
        if not self.evidence_refs or not all(self.evidence_refs):
            raise ValueError(
                "a finding must cite at least one canonical evidence "
                "reference — no verdict without evidence")
        if self.score is not None and not self.score_scale:
            raise ValueError(
                "a score must declare its scale (e.g. 'probability') — a "
                "dimensionless number is not a finding")
        if self.features and not self.feature_digest:
            object.__setattr__(self, "feature_digest",
                               feature_digest(self.features))
        if self.analyzer_class == AnalyzerClass.ML.value and not (
                self.model_id and self.model_version):
            raise ValueError(
                "an ML finding must carry model_id and model_version — "
                "unversioned inference may not enter the evidence chain")
        if self.suppressed_by and self.state != FindingState.SUPPRESSED.value:
            raise ValueError("suppressed_by requires state=SUPPRESSED")
        object.__setattr__(self, "finding_id", self.identity())
        return self

    def identity(self) -> str:
        """Content-addressed identity: re-running the same analyzer over
        the same evidence with the same features yields the SAME id, so
        re-evaluation (and retrospection) is idempotent by construction."""
        parts = [self.tenant_id, self.analyzer_id, self.analyzer_version,
                 self.model_id or "", self.model_version or "",
                 "|".join(sorted(self.evidence_refs)),
                 self.feature_digest or ""]
        return "fnd_" + hashlib.sha256(
            "\x1f".join(parts).encode("utf-8")).hexdigest()[:32]

    def to_mongo(self) -> Dict[str, Any]:
        return self.model_dump()


class Capability(BaseModel):
    """What an analyzer can evaluate — and what it cannot.

    The console renders `cannot` verbatim, which is how a surface says
    NOT_EVALUATED with a reason instead of implying "clean"."""
    model_config = ConfigDict(extra="forbid")

    evaluates: List[str]
    cannot: List[str] = Field(default_factory=list)
    requires: List[str] = Field(default_factory=list)


class EvidenceUnit(BaseModel):
    """The one analysable unit handed to every analyzer."""
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    evidence_ref: str
    endpoint_ref: Optional[str] = None
    observed_at: Optional[str] = None
    activity: Dict[str, Any] = Field(default_factory=dict)
    derivations: List[Dict[str, Any]] = Field(default_factory=list)


class AnalyzerResult(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    analyzer_id: str
    outcome: Outcome
    findings: List[Finding] = Field(default_factory=list)
    reason: Optional[str] = None

    @model_validator(mode="after")
    def _outcome_matches_content(self) -> "AnalyzerResult":
        if self.outcome == Outcome.FINDINGS.value and not self.findings:
            raise ValueError("FINDINGS declared with no finding")
        if self.outcome != Outcome.FINDINGS.value and self.findings:
            raise ValueError(f"{self.outcome} declared with findings present")
        if self.outcome in (Outcome.NOT_EVALUATED.value,
                            Outcome.EVALUATION_FAILED.value
                            ) and not self.reason:
            raise ValueError(f"{self.outcome} must state its reason")
        return self
