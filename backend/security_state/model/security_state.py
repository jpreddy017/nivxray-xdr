"""Security state entity and composite state models."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..contracts import (
    CapabilityStatus,
    EntityCategory,
    EntityRef,
    EpistemicStatus,
    ProvenanceEnvelope,
    canonical_json,
    sha256_digest,
)


@dataclass
class ObservedFact:
    """A direct, ground-truth observation with evidence provenance."""
    fact_id: str
    property_name: str
    property_value: Any
    observed_at: str
    source_sensor: str
    evidence_id: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DerivedFact:
    """A logically or causally inferred fact with explicit derivation rationale."""
    fact_id: str
    property_name: str
    property_value: Any
    derived_at: str
    rule_or_model: str
    confidence: float
    supporting_fact_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityState:
    """Immutable, deterministic representation of an enterprise entity's security state."""
    state_id: str
    tenant_id: str
    entity_ref: EntityRef
    timestamp: str
    provenance: ProvenanceEnvelope
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    classification: CapabilityStatus = CapabilityStatus.LEGITIMATE_CAPABILITY
    previous_state_hash: Optional[str] = None
    evidence_refs: List[str] = field(default_factory=list)
    observed_facts: List[ObservedFact] = field(default_factory=list)
    derived_facts: List[DerivedFact] = field(default_factory=list)
    active_capabilities: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    state_hash: str = ""

    def __post_init__(self) -> None:
        if not self.state_hash:
            self.state_hash = self.compute_hash()

    def compute_hash(self) -> str:
        """Compute deterministic SHA-256 fingerprint excluding state_hash itself."""
        payload = {
            "state_id": self.state_id,
            "tenant_id": self.tenant_id,
            "entity_ref": self.entity_ref.to_dict(),
            "timestamp": self.timestamp,
            "epistemic_status": self.epistemic_status.value,
            "classification": self.classification.value,
            "previous_state_hash": self.previous_state_hash,
            "evidence_refs": sorted(self.evidence_refs),
            "observed_facts": [f.to_dict() for f in self.observed_facts],
            "derived_facts": [f.to_dict() for f in self.derived_facts],
            "active_capabilities": sorted(self.active_capabilities),
            "assumptions": sorted(self.assumptions),
            "contradictions": sorted(self.contradictions),
            "missing_evidence": sorted(self.missing_evidence),
            "provenance": self.provenance.to_dict(),
        }
        return sha256_digest(canonical_json(payload))

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["entity_ref"] = self.entity_ref.to_dict()
        d["provenance"] = self.provenance.to_dict()
        d["epistemic_status"] = self.epistemic_status.value
        d["classification"] = self.classification.value
        d["observed_facts"] = [f.to_dict() for f in self.observed_facts]
        d["derived_facts"] = [f.to_dict() for f in self.derived_facts]
        return d


@dataclass
class EnterpriseSecuritySnapshot:
    """Consolidated multi-entity security state snapshot for an investigation case."""
    snapshot_id: str
    tenant_id: str
    case_id: str
    captured_at: str
    entity_states: Dict[str, SecurityState] = field(default_factory=dict) # entity_id -> SecurityState
    active_attack_state: str = "NO_ATTACK_EVIDENCE"
    snapshot_hash: str = ""

    def __post_init__(self) -> None:
        if not self.snapshot_hash:
            self.snapshot_hash = self.compute_hash()

    def compute_hash(self) -> str:
        payload = {
            "snapshot_id": self.snapshot_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "captured_at": self.captured_at,
            "active_attack_state": self.active_attack_state,
            "entity_hashes": {eid: s.state_hash for eid, s in sorted(self.entity_states.items())},
        }
        return sha256_digest(canonical_json(payload))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "captured_at": self.captured_at,
            "active_attack_state": self.active_attack_state,
            "snapshot_hash": self.snapshot_hash,
            "entity_states": {eid: s.to_dict() for eid, s in self.entity_states.items()},
        }
