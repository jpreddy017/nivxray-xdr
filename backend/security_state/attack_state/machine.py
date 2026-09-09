"""Attack State Machine: 18 explicit causal attack states."""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..contracts import (
    AttackState,
    ProvenanceEnvelope,
    canonical_json,
    sha256_digest,
)
from ..model.security_state import SecurityState
from ..transitions.engine import SecurityStateTransition


@dataclass
class AttackStateEvaluation:
    """State of an ongoing attack progression."""
    evaluation_id: str
    tenant_id: str
    case_id: str
    current_state: AttackState
    previous_state: Optional[AttackState]
    progression_history: List[str]
    state_justification: List[str]
    active_threat_actors: List[str]
    required_containment_objectives: List[str]
    evidence_ids: List[str]
    evaluation_hash: str = ""

    def __post_init__(self) -> None:
        if not self.evaluation_hash:
            self.evaluation_hash = self.compute_hash()

    def compute_hash(self) -> str:
        payload = {
            "evaluation_id": self.evaluation_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "current_state": self.current_state.value,
            "previous_state": self.previous_state.value if self.previous_state else None,
            "progression_history": self.progression_history,
            "state_justification": sorted(self.state_justification),
            "evidence_ids": sorted(self.evidence_ids),
        }
        return sha256_digest(canonical_json(payload))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evaluation_id": self.evaluation_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "current_state": self.current_state.value,
            "previous_state": self.previous_state.value if self.previous_state else None,
            "progression_history": self.progression_history,
            "state_justification": self.state_justification,
            "active_threat_actors": self.active_threat_actors,
            "required_containment_objectives": self.required_containment_objectives,
            "evidence_ids": self.evidence_ids,
            "evaluation_hash": self.evaluation_hash,
        }


class AttackStateMachine:
    """Deterministic finite state machine governing attack progression."""
    VERSION = "1.0.0"

    # Forward kill-chain progression order
    KILL_CHAIN_ORDER = [
        AttackState.NO_ATTACK_EVIDENCE,
        AttackState.RECONNAISSANCE,
        AttackState.INITIAL_ACCESS,
        AttackState.EXECUTION,
        AttackState.PERSISTENCE,
        AttackState.PRIVILEGE_ESCALATION,
        AttackState.DEFENSE_EVASION,
        AttackState.CREDENTIAL_ACCESS,
        AttackState.DISCOVERY,
        AttackState.LATERAL_MOVEMENT,
        AttackState.COMMAND_AND_CONTROL,
        AttackState.COLLECTION,
        AttackState.EXFILTRATION,
        AttackState.IMPACT,
    ]

    def advance_state(
        self,
        tenant_id: str,
        case_id: str,
        current_state: AttackState,
        transitions: List[SecurityStateTransition],
        entity_states: List[SecurityState],
        history: Optional[List[str]] = None,
    ) -> AttackStateEvaluation:
        """Evaluate transitions and entity capabilities to determine next attack state."""
        prog_history = list(history or [current_state.value])
        justifications: List[str] = []
        evidence_ids: set[str] = set()
        highest_state = current_state

        for t in transitions:
            evidence_ids.update(t.triggering_evidence_ids)
            if t.new_capability_unlocked:
                cap = t.new_capability_unlocked
                if "LSASS" in cap or "CREDENTIAL" in cap:
                    if self._is_higher(AttackState.CREDENTIAL_ACCESS, highest_state):
                        highest_state = AttackState.CREDENTIAL_ACCESS
                        justifications.append(f"Advanced to CREDENTIAL_ACCESS via transition {t.transition_id}: {t.causal_basis}")
                elif "PERSISTENCE" in cap:
                    if self._is_higher(AttackState.PERSISTENCE, highest_state):
                        highest_state = AttackState.PERSISTENCE
                        justifications.append(f"Advanced to PERSISTENCE via transition {t.transition_id}: {t.causal_basis}")
                elif "ADMIN_EXECUTION" in cap or "PAYLOAD_DOWNLOAD" in cap:
                    if self._is_higher(AttackState.EXECUTION, highest_state):
                        highest_state = AttackState.EXECUTION
                        justifications.append(f"Advanced to EXECUTION via transition {t.transition_id}: {t.causal_basis}")

        # Check for lateral movement
        compromised_devices = {s.entity_ref.entity_id for s in entity_states if "CAP_ADMIN_EXECUTION" in s.active_capabilities or "CAP_PERSISTENCE" in s.active_capabilities}
        if len(compromised_devices) > 1:
            if self._is_higher(AttackState.LATERAL_MOVEMENT, highest_state):
                highest_state = AttackState.LATERAL_MOVEMENT
                justifications.append(f"Advanced to LATERAL_MOVEMENT: multiple compromised devices detected ({', '.join(compromised_devices)})")

        if highest_state != current_state:
            prog_history.append(highest_state.value)

        containment_objectives = self._get_containment_objectives(highest_state)

        return AttackStateEvaluation(
            evaluation_id=f"att-eval-{uuid.uuid4().hex[:10]}",
            tenant_id=tenant_id,
            case_id=case_id,
            current_state=highest_state,
            previous_state=current_state if highest_state != current_state else None,
            progression_history=prog_history,
            state_justification=justifications or ["State stable under current evidence"],
            active_threat_actors=[],
            required_containment_objectives=containment_objectives,
            evidence_ids=sorted(list(evidence_ids)),
        )

    def _is_higher(self, candidate: AttackState, current: AttackState) -> bool:
        try:
            cand_idx = self.KILL_CHAIN_ORDER.index(candidate)
            curr_idx = self.KILL_CHAIN_ORDER.index(current)
            return cand_idx > curr_idx
        except ValueError:
            return False

    def _get_containment_objectives(self, state: AttackState) -> List[str]:
        if state in (AttackState.LATERAL_MOVEMENT, AttackState.CREDENTIAL_ACCESS):
            return ["Isolate affected host network interfaces", "Revoke active Kerberos and OAuth tokens", "Terminate suspicious dual-use execution trees"]
        elif state in (AttackState.PERSISTENCE, AttackState.EXECUTION):
            return ["Terminate unauthorized payload processes", "Remove scheduled persistence jobs", "Block payload retrieval URLs at gateway"]
        return ["Monitor entity baselines"]
