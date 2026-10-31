"""Round 30 · IUE v0 · Understanding Artifact schemas.

Strict Pydantic v2 schemas for the six understanding artifacts emitted
by the Investigation Understanding Engine.  These artifacts are the
sole output contract of Round 30 and the sole input contract for
Round 31 (Autonomous Investigation Orchestrator).

**Determinism contract**:
  * Every artifact is a pure function of governed evidence + IKG.
  * No clock reads, no random ids, no external I/O.
  * Same evidence fingerprint → byte-identical artifact bundle.

**Honest-state contract** (§4, §6 of AUTONOMOUS_INVESTIGATION.md):
  * IUE never fabricates evidence.  When a fact is not observable, it
    is emitted as ``UNKNOWN`` or ``NOT_OBSERVED`` — never omitted
    silently, never invented as ``OBSERVED``.
"""
from __future__ import annotations

from typing import List, Optional, Literal
from pydantic import BaseModel, Field


# ── Common primitives ───────────────────────────────────────────────

EvidenceState = Literal[
    "OBSERVED",
    "SUPPORTED",
    "CORRELATED",
    "INFERRED",
    "HYPOTHESIS",
    "NOT_OBSERVED",
    "UNKNOWN",
    "CONTRADICTED",
]


class Entity(BaseModel):
    """A canonical entity extracted from evidence."""
    kind: str = Field(..., description="ipv4 | ipv6 | domain | host | user | process | file | hash | signature | protocol")
    value: str
    role: Optional[str] = Field(None, description="source | destination | trigger | context | actor | target")
    origin: str = Field(..., description="Evidence field path this entity was extracted from")


# ── Artifact 1 · Investigation Context ──────────────────────────────

class TimeWindow(BaseModel):
    start: Optional[str] = None
    end: Optional[str] = None


class InvestigationContext(BaseModel):
    """Artifact 1 — 'What incident is this, at a glance?'

    A honest snapshot of what the evidence says the incident is about:
    entities, endpoints, users, network endpoints, temporal window, and
    the current governed verdict fingerprint.  Fabricates nothing.
    """
    incident_id: str
    tenant_id: str
    trace_id: Optional[str] = None
    canonical_event_id: Optional[str] = None

    entities: List[Entity] = Field(default_factory=list)
    hosts: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    processes: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    files: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)

    time_window: TimeWindow = Field(default_factory=TimeWindow)

    severity_band: str = Field("INFORMATIONAL")
    verdict_label: Optional[str] = None
    verdict_score: Optional[int] = None
    verdict_engine: Optional[str] = None


# ── Artifact 2 · Relationships ──────────────────────────────────────

class RelationshipEdge(BaseModel):
    """A directed relationship between two entities, evidence-backed."""
    src_kind: str
    src_value: str
    relation: str = Field(
        ..., description=(
            "COMMUNICATES_WITH | TRIGGERS | CONTAINS | RESOLVES_TO | "
            "TARGETS | OBSERVED_ON | ATTRIBUTED_TO"
        )
    )
    dst_kind: str
    dst_value: str
    evidence_ref: str = Field(
        ..., description="canonical_event_id | ice_match_id | signature_id",
    )
    origin: str


class Relationships(BaseModel):
    """Artifact 2 — 'What connects to what?'

    Enumerates the concrete edges between the entities in
    ``InvestigationContext``.  Every edge is anchored to a canonical
    evidence record; nothing is inferred beyond the direct observation.
    """
    edges: List[RelationshipEdge] = Field(default_factory=list)


# ── Artifact 3 · Threat Context ─────────────────────────────────────

class SignatureRef(BaseModel):
    signature_id: str
    signature_name: Optional[str] = None
    engine: Optional[str] = None


class MitreRef(BaseModel):
    technique_id: str
    tactic_id: Optional[str] = None
    source: str = Field("evidence", description="evidence | correlation")


class ThreatContext(BaseModel):
    """Artifact 3 — 'What adversary behaviour is supported by evidence?'

    Read-only projection of the MITRE + signature + rule facts already
    present in canonical evidence / correlation matches.  IUE never
    invents MITRE attributions (§9 of AUTONOMOUS_INVESTIGATION.md).
    """
    signatures: List[SignatureRef] = Field(default_factory=list)
    mitre: List[MitreRef] = Field(default_factory=list)
    correlation_match_ids: List[str] = Field(default_factory=list)
    capability_tags: List[str] = Field(default_factory=list)
    detection_supported: bool = False


# ── Artifact 4 · Historical Context ─────────────────────────────────

class EntityHistory(BaseModel):
    entity_kind: str
    entity_value: str
    prior_incident_ids: List[str] = Field(default_factory=list)
    prior_evidence_count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class HistoricalContext(BaseModel):
    """Artifact 4 — 'Have we seen these entities before?'

    Prior sightings of the context entities across
    ``xdr_canonical_evidence`` and ``workspace_cases``.  Never invented;
    if the collection has no prior hits, the entity's history is
    honestly empty.
    """
    entity_history: List[EntityHistory] = Field(default_factory=list)


# ── Artifact 5 · Known / Unknown ────────────────────────────────────

class Fact(BaseModel):
    key: str = Field(..., description="Deterministic fact key, e.g. 'network.dst.ip'")
    value: Optional[str] = None
    state: EvidenceState
    evidence_ref: Optional[str] = None
    reason: Optional[str] = Field(
        None, description="Why this fact is in this state, plain-language",
    )


class KnownUnknown(BaseModel):
    """Artifact 5 — 'What do we know? What do we not know?'

    Explicitly enumerates every fact IUE consulted and its
    §27 evidence state: OBSERVED · NOT_OBSERVED · UNKNOWN · ...
    Empty categories are allowed; missing facts are illegal.
    """
    observed: List[Fact] = Field(default_factory=list)
    not_observed: List[Fact] = Field(default_factory=list)
    unknown: List[Fact] = Field(default_factory=list)


# ── Artifact 6 · Investigation Gaps ─────────────────────────────────

class InvestigationGap(BaseModel):
    gap_id: str = Field(..., description="Deterministic id derived from the gap key")
    key: str = Field(..., description="Machine key, e.g. 'process_lineage.absent'")
    description: str
    why_it_matters: str
    suggested_capability: Optional[str] = Field(
        None,
        description=(
            "Round 32 Capability Fabric hint · one of "
            "process_ancestry | network_pivot | identity_pivot | "
            "file_reputation | historical_correlation | mitre_expansion"
        ),
    )


class InvestigationGaps(BaseModel):
    """Artifact 6 — 'Where should the Orchestrator investigate next?'

    Enumerates gaps that the Round 31 Autonomous Investigator can close
    by invoking capabilities from Round 32.  IUE v0 does NOT rank or
    plan; it only names the gaps deterministically.
    """
    gaps: List[InvestigationGap] = Field(default_factory=list)


# ── Bundle ──────────────────────────────────────────────────────────

class IUEArtifacts(BaseModel):
    """The six understanding artifacts, always all six emitted."""
    context: InvestigationContext
    relationships: Relationships
    threat_context: ThreatContext
    historical_context: HistoricalContext
    known_unknown: KnownUnknown
    gaps: InvestigationGaps


class IUEProvenance(BaseModel):
    engine_id: str = "nivxray::iue::v0"
    engine_version: str = "0.1.0"
    trace_id: Optional[str] = None
    canonical_event_id: Optional[str] = None
    ice_match_ids: List[str] = Field(default_factory=list)
    verdict_engine: Optional[str] = None


class IUEUnderstanding(BaseModel):
    """The persisted snapshot record.

    Keyed by (tenant_id, incident_id, content_hash).  ``version``
    monotonically increases per (tenant_id, incident_id).
    ``evidence_fingerprint`` is what makes "latest valid" resolve to
    the snapshot for the *current* governed evidence, not merely the
    most-recent timestamp.
    """
    incident_id: str
    tenant_id: str
    version: int
    content_hash: str
    evidence_fingerprint: str
    ikg_version: str
    generated_at: str
    artifacts: IUEArtifacts
    provenance: IUEProvenance
    honesty_note: str = (
        "IUE v0 emits understanding, not verdicts.  Every fact is "
        "traceable to canonical evidence or correlation matches; "
        "NOT_OBSERVED and UNKNOWN are explicit, never omitted."
    )
