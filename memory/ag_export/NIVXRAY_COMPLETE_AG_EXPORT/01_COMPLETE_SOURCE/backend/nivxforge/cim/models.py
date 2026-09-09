"""ADR-0009 · Canonical Investigation Model (CIM) — Pydantic schema (v1.0).

The CIM is the *system of record* for every investigation NivXRay produces.
Every surface (Workspace, NivXForge, Reports, future CLI/API consumers)
renders the same Investigation. Endpoint responses SERIALIZE this object;
they do not own it.

Design invariants enforced by `validators.py`:
    1. `schema_version` = "1.0"
    2. Every Assessment.evidence is non-empty
    3. Every Recommendation.evidence is non-empty
    4. No orphan Evidence (every Evidence.id must be referenced somewhere)
    5. AttackTechnique list deduplicated
    6. Relationship.source/target refer to existing Entity.id
    7. stages_executed carries at least one status="completed" stage

Full spec: /app/memory/adr/0009-canonical-investigation-model.md
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, ConfigDict


# ─── Confidence enum ────────────────────────────────────────────────────────

Confidence = Literal["Confirmed", "Strongly Inferred", "Possible", "Unknown"]


# ─── Evidence · first-class object ──────────────────────────────────────────

EvidenceType = Literal[
    "ioc.ip", "ioc.domain", "ioc.url", "ioc.hash", "ioc.email",
    "decoder.layer", "decoder.transformation",
    "ti.provider_hit", "ti.family_label",
    "mitre.technique",
    "telemetry.process", "telemetry.network", "telemetry.file",
    "telemetry.registry", "telemetry.authentication", "telemetry.memory",
    "analyst.correction",
    "reasoning.inference",
    "static.pe_metadata", "static.string",
]


class EvidenceSource(BaseModel):
    """Where the evidence came from."""
    producer: str  # "decoder" | "extractor" | "ti_enrich" | "reasoning" | "analyst" | ...
    producer_version: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Evidence(BaseModel):
    """First-class evidence object · ADR-0009 §2.1.a."""
    id: str  # "EV-001" .. "EV-NNN" · dense monotonic within an investigation
    type: EvidenceType
    source: EvidenceSource
    raw_value: str
    normalized_value: Optional[str] = None
    confidence: Confidence = "Possible"
    # Cross-links populated by the composer (§2.1.a supports/contradicts)
    supports: List[str] = Field(default_factory=list)      # Assessment.id refs
    contradicts: List[str] = Field(default_factory=list)   # Assessment.id refs
    context_snippet: Optional[str] = None  # up to 120 chars (ADR-0008 §2 Stage 3)


# ─── Assessment · every conclusion traceable ─────────────────────────────────

AssessmentKind = Literal[
    "verdict", "family", "category", "behavior", "attribution", "risk",
    "capability", "impact",
]


class Assessment(BaseModel):
    """Every conclusion carries Evidence refs · ADR-0009 §2.1.b."""
    id: str  # "A-001" .. "A-NNN"
    statement: str
    kind: AssessmentKind
    confidence: Confidence
    evidence: List[str] = Field(..., min_length=1)  # MERGE-GATE: non-empty
    rationale: Optional[str] = None


# ─── AnalysisStage · adaptive-pipeline transparency ─────────────────────────

StageName = Literal[
    "normalize", "input_detect", "decode", "deobfuscate",
    "ioc_extract", "ti_enrich", "behavior", "mitre_map", "reasoning",
    "pe_static", "office_parse", "pdf_parse", "url_analyze",
    "sysmon_parse", "email_parse", "sigma_match", "yara_match",
    "verdict_gate",
]

StageStatus = Literal["completed", "skipped", "failed", "error"]


class AnalysisStage(BaseModel):
    """One capability run · ADR-0009 §2.1.c."""
    name: StageName
    status: StageStatus
    reason: Optional[str] = None
    started_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    evidence_produced: List[str] = Field(default_factory=list)  # Evidence.id refs


# ─── Recommendation · evidence-backed action ────────────────────────────────

RecommendationKind = Literal["immediate", "hunt", "harden", "escalate"]


class Recommendation(BaseModel):
    """Evidence-backed analyst action · ADR-0009 §2.1.d."""
    id: str  # "R-001" ..
    kind: RecommendationKind
    text: str
    evidence: List[str] = Field(..., min_length=1)  # MERGE-GATE: non-empty
    rationale: Optional[str] = None


# ─── Unknown · deterministically generated ──────────────────────────────────

class Unknown(BaseModel):
    """Deterministically emitted data-gap · ADR-0009 §2.2."""
    id: str  # "U-001" ..
    text: str
    rule_id: str  # rule identifier that emitted this unknown
    evidence: List[str] = Field(default_factory=list)  # optional: absent-evidence refs


# ─── Entity · hosts / files / URLs / IPs / users / hashes ───────────────────

EntityKind = Literal[
    "host", "file", "url", "domain", "ip", "hash", "user",
    "process", "registry_key", "email_addr",
]


class Entity(BaseModel):
    """Investigation entity · ADR-0009 §2.1."""
    id: str  # "E-001" ..
    kind: EntityKind
    value: str
    normalized_value: Optional[str] = None
    role: Optional[str] = None  # "source" | "target" | "observed" | "c2" | ...
    evidence: List[str] = Field(default_factory=list)  # Evidence.id refs


class Relationship(BaseModel):
    """Directed edge between entities · ADR-0009 §2.1."""
    id: str  # "REL-001" ..
    source: str  # Entity.id
    target: str  # Entity.id
    kind: str  # "connects_to" | "downloads" | "executes" | "reads" | ...
    evidence: List[str] = Field(default_factory=list)  # Evidence.id refs


# ─── Timeline / Threat Intel / ATT&CK ───────────────────────────────────────

class TimelineFact(BaseModel):
    id: str  # "T-001" ..
    at: Optional[datetime] = None
    text: str
    evidence: List[str] = Field(default_factory=list)


class ThreatIntelHit(BaseModel):
    id: str  # "TI-001" ..
    provider: str  # "virustotal" | "malwarebazaar" | ...
    label: str
    evidence: List[str] = Field(default_factory=list)


class AttackTechnique(BaseModel):
    id: str  # ATT&CK technique id e.g. "T1059.001"
    name: Optional[str] = None
    tactic: Optional[str] = None
    evidence: List[str] = Field(default_factory=list)


# ─── Executive headline ─────────────────────────────────────────────────────

class Executive(BaseModel):
    """Analyst-facing headline · references Assessment IDs."""
    verdict: str  # e.g. "Confirmed Malicious"
    confidence: Confidence
    family: Optional[str] = None
    category: Optional[str] = None
    business_impact: Optional[str] = None
    evidence_quality: Optional[str] = None
    summary: Optional[str] = None  # 1-paragraph synthesis
    references: List[str] = Field(default_factory=list)  # Assessment.id refs


# ─── Source & Provenance ────────────────────────────────────────────────────

class InvestigationSource(BaseModel):
    surface: str  # "nivxforge" | "workspace" | "api" | "cli" | ...
    endpoint: Optional[str] = None
    correlation_id: Optional[str] = None


class ProvenanceEntry(BaseModel):
    field: str  # dotted path e.g. "assessments[A-001].confidence"
    producer: str
    producer_version: Optional[str] = None


# ─── Root Investigation object ──────────────────────────────────────────────

class Investigation(BaseModel):
    """The Canonical Investigation Model · ADR-0009 §2.1."""
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    id: str
    case_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: InvestigationSource

    executive: Executive
    assessments: List[Assessment] = Field(default_factory=list)
    evidence: List[Evidence] = Field(default_factory=list)
    timeline: List[TimelineFact] = Field(default_factory=list)
    entities: List[Entity] = Field(default_factory=list)
    relationships: List[Relationship] = Field(default_factory=list)
    threat_intel: List[ThreatIntelHit] = Field(default_factory=list)
    attack: List[AttackTechnique] = Field(default_factory=list)
    stages_executed: List[AnalysisStage] = Field(default_factory=list)
    decode_chain: List[dict] = Field(default_factory=list)  # ordered decoder layers
    unknowns: List[Unknown] = Field(default_factory=list)
    recommendations: List[Recommendation] = Field(default_factory=list)
    report: Optional[dict] = None  # composed narrative (deferred to ADR-0010)
    provenance: List[ProvenanceEntry] = Field(default_factory=list)


class CIMValidationError(ValueError):
    """Raised by `validators.py` when a composed CIM violates an invariant."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
