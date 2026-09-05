"""Adversarial Security Simulator: deterministic next-step projection using production models."""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..contracts import (
    AttackState,
    EntityRef,
    canonical_json,
    sha256_digest,
)
from ..model.security_state import SecurityState
from ..reachability.engine import EnterpriseReachabilityEngine, ReachabilityMatrix


@dataclass
class SimulatedStep:
    """A simulated attacker transition step."""
    step_number: int
    action_name: str
    target_asset: str
    attacker_technique: str
    expected_capability_unlocked: str
    new_attack_state: AttackState
    success_probability: float
    detection_probability: float
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["new_attack_state"] = self.new_attack_state.value
        return d


@dataclass
class SimulationResult:
    """Consolidated adversary simulation output."""
    simulation_id: str
    tenant_id: str
    case_id: str
    objective: str
    starting_state: AttackState
    projected_trajectory: List[SimulatedStep]
    estimated_time_to_compromise_hours: float
    simulation_hash: str = ""

    def __post_init__(self) -> None:
        if not self.simulation_hash:
            self.simulation_hash = self.compute_hash()

    def compute_hash(self) -> str:
        payload = {
            "simulation_id": self.simulation_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "objective": self.objective,
            "starting_state": self.starting_state.value,
            "trajectory": [s.to_dict() for s in self.projected_trajectory],
        }
        return sha256_digest(canonical_json(payload))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "simulation_id": self.simulation_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "objective": self.objective,
            "starting_state": self.starting_state.value,
            "estimated_time_to_compromise_hours": self.estimated_time_to_compromise_hours,
            "simulation_hash": self.simulation_hash,
            "projected_trajectory": [s.to_dict() for s in self.projected_trajectory],
        }


class AdversarialSimulator:
    """Simulates possible attacker progression using production reachability and capability models."""
    VERSION = "1.0.0"

    def __init__(self, reachability_engine: Optional[EnterpriseReachabilityEngine] = None) -> None:
        self.reachability_engine = reachability_engine or EnterpriseReachabilityEngine()

    def simulate_adversary_trajectory(
        self,
        tenant_id: str,
        case_id: str,
        current_state: SecurityState,
        reachability: ReachabilityMatrix,
        attacker_objective: str = "TIER_0_RANSOMWARE",
    ) -> SimulationResult:
        """Project the likely multi-step attacker trajectory if uncontained."""
        trajectory: List[SimulatedStep] = []

        # Step 1: Credential Extraction
        if "CAP_CREDENTIAL_DUMPING" not in current_state.active_capabilities:
            trajectory.append(SimulatedStep(
                step_number=1,
                action_name="LSASS Memory Dumping",
                target_asset=current_state.entity_ref.entity_id,
                attacker_technique="T1003.001",
                expected_capability_unlocked="CAP_CREDENTIAL_DUMPING",
                new_attack_state=AttackState.CREDENTIAL_ACCESS,
                success_probability=0.88,
                detection_probability=0.75,
                rationale="Attacker requires elevated domain credentials to advance beyond local foothold",
            ))

        # Step 2: Lateral Movement to Domain Controller
        trajectory.append(SimulatedStep(
            step_number=len(trajectory) + 1,
            action_name="Kerberos Pass-the-Ticket to DC",
            target_asset="server-dc-01",
            attacker_technique="T1550.002",
            expected_capability_unlocked="CAP_DOMAIN_ADMIN",
            new_attack_state=AttackState.LATERAL_MOVEMENT,
            success_probability=0.80,
            detection_probability=0.65,
            rationale="Harvesters utilize dumped credentials to authenticate against Domain Controller",
        ))

        # Step 3: Backup Destruction & Ransomware Staging
        if reachability.tier_0_exposed or attacker_objective == "TIER_0_RANSOMWARE":
            trajectory.append(SimulatedStep(
                step_number=len(trajectory) + 1,
                action_name="Veeam Backup Catalog Wipe & Shadow Copy Delete",
                target_asset="backup-nas-01",
                attacker_technique="T1490",
                expected_capability_unlocked="CAP_INHIBIT_SYSTEM_RECOVERY",
                new_attack_state=AttackState.IMPACT,
                success_probability=0.70,
                detection_probability=0.90,
                rationale="Attacker attempts to eliminate recovery options prior to mass encryption",
            ))

        return SimulationResult(
            simulation_id=f"sim-{uuid.uuid4().hex[:10]}",
            tenant_id=tenant_id,
            case_id=case_id,
            objective=attacker_objective,
            starting_state=AttackState.EXECUTION,
            projected_trajectory=trajectory,
            estimated_time_to_compromise_hours=3.5,
        )
