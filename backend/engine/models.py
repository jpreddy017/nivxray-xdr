"""Engine data models — the shared contract every layer speaks.

Design principles (vision-aligned: NivXRay as Malware Command Intelligence Platform)
--------------------------------------------------------------------------------
- Every plugin — decoder, archetype, or intelligence heuristic — emits the SAME
  shape (`PluginResult`). This turns every layer into an intelligence contributor,
  not just a byte-shuffler.
- The terminal object is `AnalystReport`, not just decoded text. It carries
  aggregated `Findings` (verdict, IOCs, MITRE, family) + `InvestigationRecommendation`s.
- Pydantic v2 is used where JSON-serialisable, self-documenting cross-layer
  contracts pay off. Plain dataclasses for hot-path runtime objects.
- `DecodeResult` and `DecodeOutcome` remain as backwards-compat aliases so existing
  code and tests keep working; new plugins should use `PluginResult` / `AnalystReport`.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Intelligence signal types (emitted by any plugin at any layer)
# ---------------------------------------------------------------------------
class MitreHint(BaseModel):
    id: str                                 # e.g. "T1059.001"
    technique: str = ""
    tactic: str = ""
    evidence: str = ""
    source: str = "heuristic"               # heuristic | archetype | family | ai


class FamilyHint(BaseModel):
    family: str                             # e.g. "Meterpreter"
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str = ""
    aka: List[str] = Field(default_factory=list)
    # RC2.1a additions — structured evidence + per-family intelligence
    evidence_items: List["EvidenceItem"] = Field(default_factory=list)
    mitre_techniques: List["MitreHint"] = Field(default_factory=list)
    yara_suggestion: Optional["YaraRuleStub"] = None
    atomic_red_hint: Optional[str] = None


class EvidenceItem(BaseModel):
    """Structured evidence entry for a family match — one row per signature hit."""
    type: str                               # "string" | "regex" | "bytes" | "opcode"
    pattern: str                            # human-readable pattern that matched
    location: str = ""                      # e.g. "layer=2/offset=0x40"
    weight: float = 0.0                     # contribution to confidence


class LolbasHit(BaseModel):
    binary: str                             # e.g. "certutil.exe"
    technique_id: Optional[str] = None
    evidence: str = ""


class TradecraftFlag(BaseModel):
    flag: str                               # e.g. "amsi-bypass", "reflective-injection"
    severity: str = "info"                  # info | low | medium | high | critical
    evidence: str = ""


class IOCBundle(BaseModel):
    urls: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    md5: List[str] = Field(default_factory=list)
    sha1: List[str] = Field(default_factory=list)
    sha256: List[str] = Field(default_factory=list)
    bitcoin_addresses: List[str] = Field(default_factory=list)
    file_paths: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# L0 output — Fingerprint
# ---------------------------------------------------------------------------
class Fingerprint(BaseModel):
    input_len: int
    printable_ratio: float = 0.0
    english_density: float = 0.0
    entropy: float = 0.0
    is_binary: bool = False
    encoding_candidates: List[Dict[str, Any]] = Field(default_factory=list)
    file_type: Optional[str] = None
    wrapper_type: Optional[str] = None
    notes: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Plugin contract (universal for L2 decoders and L3 intelligence plugins)
# ---------------------------------------------------------------------------
class DetectResult(BaseModel):
    """A plugin's confidence that it applies to the current payload."""
    confidence: float = Field(ge=0.0, le=1.0)
    why: str = ""
    args: Dict[str, Any] = Field(default_factory=dict)


class PluginResult(BaseModel):
    """The unified output shape for every plugin.

    A pure decoder (e.g. base64) sets only `output`.
    A pure intelligence plugin (e.g. meterpreter_detector) sets only signals.
    A hybrid plugin (e.g. xor-brute that also emits an IP IOC) sets both.
    """
    # Byte transform (empty for pure-intelligence plugins)
    output: str = ""
    output_is_binary: bool = False
    # Intelligence signals — any plugin at any layer may contribute
    iocs: Dict[str, List[str]] = Field(default_factory=dict)
    mitre_hints: List[MitreHint] = Field(default_factory=list)
    family_hints: List[FamilyHint] = Field(default_factory=list)
    lolbas_hits: List[LolbasHit] = Field(default_factory=list)
    tradecraft: List[TradecraftFlag] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)
    explanation: str = ""                   # optional human-readable prose


# Backwards-compat alias — kept so existing tests / callers don't break
DecodeResult = PluginResult


# ---------------------------------------------------------------------------
# Trace step (one layer of the recursive decode chain)
# ---------------------------------------------------------------------------
class TraceStep(BaseModel):
    layer: int
    decoder: str                            # canonical plugin id
    schema_version: str = "1.0"
    confidence: float
    why: str
    in_len: int
    out_len: int
    exec_ms: int
    preview: str                            # first 200 chars of decoded output
    args: Dict[str, Any] = Field(default_factory=dict)
    # Signals surfaced by this specific step (aggregated into Findings)
    sub_iocs: Dict[str, List[str]] = Field(default_factory=dict)
    mitre_hints: List[MitreHint] = Field(default_factory=list)
    family_hints: List[FamilyHint] = Field(default_factory=list)
    lolbas_hits: List[LolbasHit] = Field(default_factory=list)
    tradecraft: List[TradecraftFlag] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Investigation recommendation & rule stubs
# ---------------------------------------------------------------------------
class InvestigationRecommendation(BaseModel):
    priority: str = "medium"                # low | medium | high | critical
    action: str                             # imperative sentence for the analyst
    rationale: str = ""
    related_iocs: List[str] = Field(default_factory=list)


class SigmaRuleStub(BaseModel):
    title: str
    description: str = ""
    logsource: Dict[str, str] = Field(default_factory=dict)
    detection: Dict[str, Any] = Field(default_factory=dict)


class YaraRuleStub(BaseModel):
    name: str
    strings: List[str] = Field(default_factory=list)
    condition: str = ""
    tags: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Similar-case & family match
# ---------------------------------------------------------------------------
class FamilyMatch(BaseModel):
    family: str = "unknown"
    confidence: float = 0.0
    evidence: List[str] = Field(default_factory=list)
    alternatives: List[FamilyHint] = Field(default_factory=list)
    # RC2.1a — attached intelligence when a family plugin fires
    evidence_items: List[EvidenceItem] = Field(default_factory=list)
    mitre_techniques: List[MitreHint] = Field(default_factory=list)
    yara_suggestion: Optional[YaraRuleStub] = None
    atomic_red_hint: Optional[str] = None


class SimilarCase(BaseModel):
    case_id: str
    similarity: float                       # 0..1 Jaccard
    label: str = ""


# ---------------------------------------------------------------------------
# Findings — aggregated intelligence across all layers (single source of truth)
# ---------------------------------------------------------------------------
class Findings(BaseModel):
    verdict: str = "unknown"                # benign | suspicious | malicious | needs_review | unknown
    risk_score: int = 0                     # 0..100
    iocs: IOCBundle = Field(default_factory=IOCBundle)
    mitre_techniques: List[MitreHint] = Field(default_factory=list)
    family: FamilyMatch = Field(default_factory=FamilyMatch)
    lolbas: List[LolbasHit] = Field(default_factory=list)
    tradecraft: List[TradecraftFlag] = Field(default_factory=list)
    kill_chain_phases: List[str] = Field(default_factory=list)
    similar_cases: List[SimilarCase] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Explainable-confidence breakdown (why the final risk_score is what it is)
# ---------------------------------------------------------------------------
class RiskContribution(BaseModel):
    source: str                             # "family-match" | "mitre" | "iocs" | "tradecraft" | "lolbas"
    points: int                             # signed contribution to risk_score
    detail: str = ""                        # human-readable evidence


class ConfidenceBreakdown(BaseModel):
    total: int                              # final risk_score
    verdict: str
    contributions: List[RiskContribution] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Plugin execution report — every plugin invocation is traced, including skips
# ---------------------------------------------------------------------------
class PluginExecutionEntry(BaseModel):
    plugin: str
    layer: int
    outcome: str                            # "accepted" | "skipped" | "detect_zero" | "decode_error" | "no_improvement"
    detect_confidence: float = 0.0
    detect_reason: str = ""
    exec_ms: int = 0
    reason: str = ""                        # why skipped / accepted / errored
    signals_emitted: bool = False


class PluginExecutionReport(BaseModel):
    layers_run: int = 0
    entries: List[PluginExecutionEntry] = Field(default_factory=list)
    total_time_ms: int = 0
    budget_snapshot: Dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Terminal analyst report (was DecodeOutcome)
# ---------------------------------------------------------------------------
class AnalystReport(BaseModel):
    """The machine-readable analyst-ready intelligence report.

    Combines the decoding trace (how), the fingerprint history (what shape),
    the findings (what it means), and analyst-facing outputs (what to do).
    """
    # The "how"
    output: str
    trace: List[TraceStep] = Field(default_factory=list)
    fingerprint_history: List[Fingerprint] = Field(default_factory=list)
    terminal: str = "no-op"
    stopped_reason: str = ""
    elapsed_ms: int = 0
    engine: str = "orchestrator-v1"
    # The "what it means" — aggregated intelligence
    findings: Findings = Field(default_factory=Findings)
    # The "what to do next" — analyst-ready outputs
    executive_summary: str = ""             # deterministic; AI may enrich when enabled
    investigation_steps: List[InvestigationRecommendation] = Field(default_factory=list)
    sigma_rules: List[SigmaRuleStub] = Field(default_factory=list)
    yara_rules: List[YaraRuleStub] = Field(default_factory=list)
    # Production-hardening surface
    confidence_breakdown: ConfidenceBreakdown = Field(
        default_factory=lambda: ConfidenceBreakdown(total=0, verdict="unknown")
    )
    plugin_report: PluginExecutionReport = Field(default_factory=PluginExecutionReport)


# Backwards-compat alias
DecodeOutcome = AnalystReport


# ---------------------------------------------------------------------------
# Resolve forward references (FamilyHint → EvidenceItem/YaraRuleStub)
# ---------------------------------------------------------------------------
FamilyHint.model_rebuild()
FamilyMatch.model_rebuild()


# ---------------------------------------------------------------------------
# Runtime objects (dataclasses — fast, mutable, no per-call validation)
# ---------------------------------------------------------------------------
@dataclass
class Budget:
    """Single source of truth for orchestrator resource limits."""
    max_depth: int = 12
    max_branches: int = 3
    wall_time_ms: int = 5000
    start_ns: int = field(default_factory=time.monotonic_ns)

    def elapsed_ms(self) -> int:
        return (time.monotonic_ns() - self.start_ns) // 1_000_000

    def time_left_ms(self) -> int:
        return max(0, self.wall_time_ms - self.elapsed_ms())

    def exhausted(self, depth: int) -> Optional[str]:
        if depth >= self.max_depth:
            return f"depth_cap:{self.max_depth}"
        if self.elapsed_ms() >= self.wall_time_ms:
            return f"time_cap:{self.wall_time_ms}ms"
        return None


@dataclass
class TraceBuffer:
    """Append-only trace collector. Passed through every layer via AnalysisContext."""
    steps: List[TraceStep] = field(default_factory=list)
    fingerprints: List[Fingerprint] = field(default_factory=list)

    def add_step(self, step: TraceStep) -> None:
        self.steps.append(step)

    def add_fingerprint(self, fp: Fingerprint) -> None:
        self.fingerprints.append(fp)


@dataclass
class AnalysisContext:
    """Per-request context carried through L0-L1-L2-L3."""
    budget: Budget = field(default_factory=Budget)
    trace: TraceBuffer = field(default_factory=TraceBuffer)
    ai_enabled: bool = False
    settings: Dict[str, Any] = field(default_factory=dict)
