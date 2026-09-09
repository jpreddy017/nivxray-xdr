"""Security State Transition model and engine."""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..contracts import (
    EntityRef,
    ProvenanceEnvelope,
    canonical_json,
    sha256_digest,
)
from ..model.security_state import SecurityState


@dataclass
class SecurityStateTransition:
    """Explicit record of a security state transition.
    
    Answers:
    - WHAT changed?
    - WHEN?
    - BECAUSE OF WHAT EVIDENCE?
    - WHAT CAUSED THE CHANGE?
    - WHAT SECURITY PROPERTY CHANGED?
    - WHAT NEW CAPABILITY BECAME AVAILABLE?
    - WHAT ATTACK STATE CHANGED?
    - WHAT IMPACT BECAME POSSIBLE?
    - WHAT ACTION CAN REVERSE OR CONTAIN IT?
    """
    transition_id: str
    tenant_id: str
    timestamp: str
    entity_ref: EntityRef
    from_state_hash: Optional[str]
    to_state_hash: str
    triggering_evidence_ids: List[str]
    causal_basis: str
    property_mutated: str
    provenance: ProvenanceEnvelope
    new_capability_unlocked: Optional[str] = None
    attack_state_delta: Optional[str] = None
    potential_impact_delta: Optional[str] = None
    reversal_action_id: Optional[str] = None
    transition_hash: str = ""

    def __post_init__(self) -> None:
        if not self.transition_hash:
            self.transition_hash = self.compute_hash()

    def compute_hash(self) -> str:
        payload = {
            "transition_id": self.transition_id,
            "tenant_id": self.tenant_id,
            "timestamp": self.timestamp,
            "entity_ref": self.entity_ref.to_dict(),
            "from_state_hash": self.from_state_hash,
            "to_state_hash": self.to_state_hash,
            "triggering_evidence_ids": sorted(self.triggering_evidence_ids),
            "causal_basis": self.causal_basis,
            "property_mutated": self.property_mutated,
            "new_capability_unlocked": self.new_capability_unlocked,
            "attack_state_delta": self.attack_state_delta,
            "potential_impact_delta": self.potential_impact_delta,
            "reversal_action_id": self.reversal_action_id,
            "provenance": self.provenance.to_dict(),
        }
        return sha256_digest(canonical_json(payload))

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["entity_ref"] = self.entity_ref.to_dict()
        d["provenance"] = self.provenance.to_dict()
        return d


class TransitionEngine:
    """Deterministic transition evaluator."""
    VERSION = "1.0.0"

    def compute_transition(
        self,
        before: Optional[SecurityState],
        after: SecurityState,
        triggering_evidence_ids: List[str],
        causal_basis: str,
        property_mutated: str,
        new_capability_unlocked: Optional[str] = None,
        attack_state_delta: Optional[str] = None,
        potential_impact_delta: Optional[str] = None,
        reversal_action_id: Optional[str] = None,
    ) -> SecurityStateTransition:
        """Compute and seal a verified state transition."""
        tid = f"tr-{uuid.uuid4().hex[:12]}"
        from_hash = before.state_hash if before else None
        
        prov = ProvenanceEnvelope(
            engine="TransitionEngine",
            version=self.VERSION,
            at=after.timestamp,
            upstream_evidence_ids=list(triggering_evidence_ids),
        )

        return SecurityStateTransition(
            transition_id=tid,
            tenant_id=after.tenant_id,
            timestamp=after.timestamp,
            entity_ref=after.entity_ref,
            from_state_hash=from_hash,
            to_state_hash=after.state_hash,
            triggering_evidence_ids=sorted(triggering_evidence_ids),
            causal_basis=causal_basis,
            property_mutated=property_mutated,
            new_capability_unlocked=new_capability_unlocked,
            attack_state_delta=attack_state_delta,
            potential_impact_delta=potential_impact_delta,
            reversal_action_id=reversal_action_id,
            provenance=prov,
        )
