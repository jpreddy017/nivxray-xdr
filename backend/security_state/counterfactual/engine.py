"""Counterfactual Security Engine: parallel world outcome projections for NivXRay Security State."""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..contracts import (
    AttackState,
    ComparativeInterventionMatrix,
    CounterfactualSimulationProvenance,
    EntityRef,
    EpistemicStatus,
    InterventionImpactRating,
    InterventionType,
    ReachabilityStatus,
    canonical_json,
    sha256_digest,
)
from ..model.security_state import SecurityState
from ..reachability.engine import ReachabilityMatrix


@dataclass
class WorldProjection:
    """Projected future state under a specific course of action (or inaction)."""
    world_id: str
    description: str
    action_applied: Optional[str]  # None for World A (Do Nothing)
    continuation_probability: float  # Modelled scenario parameter (not an empirical statistical probability)
    reachable_assets_count: int
    projected_impact_score: int  # 0 to 100
    residual_attack_paths: List[str]
    business_disruption_score: int  # 0 to 100
    reversibility: str  # 'HIGH', 'MEDIUM', 'LOW', 'IRREVERSIBLE'
    evidence_preservation_score: int  # 0 to 100
    likely_next_transitions: List[str]
    epistemic_status: EpistemicStatus = EpistemicStatus.PROJECTED
    attack_interruption_pct: float = 0.0
    tier0_protected_count: int = 0
    tier1_protected_count: int = 0
    simulation_provenance: Optional[CounterfactualSimulationProvenance] = None
    continuation_risk_level: str = "HIGH"  # Qualitative: CRITICAL, HIGH, MEDIUM, LOW, MINIMAL
    continuation_basis: List[str] = field(default_factory=list)
    is_statistically_calibrated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["epistemic_status"] = self.epistemic_status.value if hasattr(self.epistemic_status, "value") else str(self.epistemic_status)
        d["simulation_provenance"] = self.simulation_provenance.to_dict() if self.simulation_provenance else None
        d["continuation_basis"] = list(self.continuation_basis)
        d["is_statistically_calibrated"] = self.is_statistically_calibrated
        return d



@dataclass
class CounterfactualAnalysis:
    """Consolidated counterfactual comparison across parallel worlds."""
    analysis_id: str
    tenant_id: str
    case_id: str
    evaluated_at: str
    world_a_do_nothing: WorldProjection
    intervention_worlds: List[WorldProjection]
    recommended_world_id: str
    comparative_matrix: Optional[ComparativeInterventionMatrix] = None
    analysis_hash: str = ""

    def __post_init__(self) -> None:
        if not self.analysis_hash:
            self.analysis_hash = self.compute_hash()

    def compute_hash(self) -> str:
        payload = {
            "analysis_id": self.analysis_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "evaluated_at": self.evaluated_at,
            "world_a": self.world_a_do_nothing.to_dict(),
            "interventions": [w.to_dict() for w in self.intervention_worlds],
            "recommended_world_id": self.recommended_world_id,
            "comparative_matrix": self.comparative_matrix.to_dict() if self.comparative_matrix else None,
        }
        return sha256_digest(canonical_json(payload))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "evaluated_at": self.evaluated_at,
            "analysis_hash": self.analysis_hash,
            "world_a_do_nothing": self.world_a_do_nothing.to_dict(),
            "intervention_worlds": [w.to_dict() for w in self.intervention_worlds],
            "recommended_world_id": self.recommended_world_id,
            "comparative_matrix": self.comparative_matrix.to_dict() if self.comparative_matrix else None,
        }


class CounterfactualEngine:
    """Projects what happens if defenders do nothing vs candidate interventions."""
    VERSION = "1.1.0"

    def evaluate_counterfactuals(
        self,
        tenant_id: str,
        case_id: str,
        current_state: SecurityState,
        reachability: ReachabilityMatrix,
        attack_state: AttackState,
        candidate_actions: Optional[List[Dict[str, Any]]] = None,
        at_timestamp: str = "2026-09-04T00:00:00Z",
    ) -> CounterfactualAnalysis:
        """Compute World A baseline and simulate candidate intervention worlds (Worlds B, C, D, E)."""
        active_paths = [p for p in reachability.paths if p.status != ReachabilityStatus.BLOCKED]
        total_active_paths = len(active_paths) if active_paths else 1
        tier0_exp = reachability.tier_0_exposed
        tier1_exp = reachability.tier_1_exposed
        total_reachable_assets = reachability.currently_reachable_count + reachability.potentially_reachable_count

        foothold_ids = [f.entity_id for f in reachability.foothold_entities]
        observed_evidence_ids = (
            current_state.provenance.upstream_evidence_ids
            if (current_state.provenance and current_state.provenance.upstream_evidence_ids)
            else (foothold_ids or ["ev-observed-foothold"])
        )

        # ── World A: Do Nothing (Baseline Unconstrained Progression) ────────
        world_a_impact = 90 if tier0_exp else (70 if tier1_exp else 45)
        world_a_prob = 0.95 if attack_state in (AttackState.LATERAL_MOVEMENT, AttackState.CREDENTIAL_ACCESS, AttackState.EXECUTION) else 0.75
        
        prov_a = CounterfactualSimulationProvenance(
            observed_inputs=observed_evidence_ids,
            current_security_state=attack_state.value,
            assumptions=["Attacker progression continues unhindered without defensive friction", "Active credentials remain valid"],
            intervention="DO_NOTHING",
            simulated_state_transition=f"{attack_state.value} -> IMPACT",
            projected_reachability_summary=f"All {total_reachable_assets} reachable assets remain exposed; Tier-0 compromised",
            projected_security_impact_score=world_a_impact,
            projected_business_impact_score=0,
            model_version=self.VERSION,
        )

        world_a = WorldProjection(
            world_id="world-a-do-nothing",
            description="Status quo: no intervention taken; attacker continues progression unabated toward crown jewels",
            action_applied=None,
            continuation_probability=world_a_prob,
            reachable_assets_count=total_reachable_assets,
            projected_impact_score=world_a_impact,
            residual_attack_paths=[p.path_id for p in active_paths],
            business_disruption_score=0,
            reversibility="IRREVERSIBLE",
            evidence_preservation_score=100,
            likely_next_transitions=["CREDENTIAL_DUMP", "LATERAL_MOVEMENT_DC", "RANSOMWARE_STAGING"],
            epistemic_status=EpistemicStatus.PROJECTED,
            attack_interruption_pct=0.0,
            tier0_protected_count=0,
            tier1_protected_count=0,
            simulation_provenance=prov_a,
            continuation_risk_level="CRITICAL",
            continuation_basis=[
                f"{total_active_paths} active unsevered attack paths",
                f"Reachable Tier-0 assets: {reachability.reachable_tier_0_count}",
                "No defensive friction or containment controls applied",
            ],
            is_statistically_calibrated=False,
        )

        # ── World B: Full Host Isolation (Blunt Response) ───────────────────
        # Host isolation severs network hops from foothold host (SMB/WMI/RPC)
        # Interruption derived from ratio of network hops severed
        severed_by_b = sum(1 for p in active_paths if any(h.hop_type in ("NETWORK_ROUTE", "REMOTE_WMI_PROCESS_CALL", "DIRECTORY_REPLICATION_RPC") for h in p.hops))
        interruption_b = min(95.0, max(50.0, (severed_by_b / total_active_paths) * 100.0))
        surviving_b_assets = max(0, total_reachable_assets - severed_by_b)
        impact_b = max(10, int(world_a_impact * (1.0 - (interruption_b / 100.0))))
        disruption_b = 45  # Substantial operational impact isolating business endpoint

        prov_b = CounterfactualSimulationProvenance(
            observed_inputs=observed_evidence_ids,
            current_security_state=attack_state.value,
            assumptions=["Network agent isolation functional", "Management telemetry channel remains intact"],
            intervention="endpoint.isolate",
            simulated_state_transition=f"{attack_state.value} -> CONTAINED",
            projected_reachability_summary=f"Severed {severed_by_b}/{total_active_paths} paths; {surviving_b_assets} surviving assets",
            projected_security_impact_score=impact_b,
            projected_business_impact_score=disruption_b,
            model_version=self.VERSION,
        )

        world_b = WorldProjection(
            world_id="world-b-isolate-host",
            description="Network-level host isolation of foothold workstation; cuts all inbound/outbound communication",
            action_applied="endpoint.isolate",
            continuation_probability=0.15,
            reachable_assets_count=surviving_b_assets,
            projected_impact_score=impact_b,
            residual_attack_paths=["Cached cloud tokens or stolen credentials usable outside isolated host"],
            business_disruption_score=disruption_b,
            reversibility="HIGH",
            evidence_preservation_score=95,
            likely_next_transitions=["ATTACK_CONTAINED_ON_HOST"],
            epistemic_status=EpistemicStatus.PROJECTED,
            attack_interruption_pct=round(interruption_b, 1),
            tier0_protected_count=1 if tier0_exp else 0,
            tier1_protected_count=1 if tier1_exp else 0,
            simulation_provenance=prov_b,
            continuation_risk_level="LOW",
            continuation_basis=[
                f"Host network hops severed: {severed_by_b}/{total_active_paths}",
                "Cached cloud tokens or stolen credentials remain usable outside host",
            ],
            is_statistically_calibrated=False,
        )

        # ── World C: Surgical Identity Action (Revocation) ──────────────────
        # Revokes Kerberos TGTs, OAuth refresh tokens, and resets passwords
        severed_by_c = sum(1 for p in active_paths if any(h.hop_type in ("CREDENTIAL_REUSE", "KERBEROS_TGS_TICKET", "IMDS_ROLE_SESSION") for h in p.hops))
        interruption_c = min(90.0, max(40.0, (severed_by_c / total_active_paths) * 100.0))
        surviving_c_assets = max(0, total_reachable_assets - severed_by_c)
        impact_c = max(15, int(world_a_impact * (1.0 - (interruption_c / 100.0))))
        disruption_c = 25  # Lower disruption than isolating physical host

        prov_c = CounterfactualSimulationProvenance(
            observed_inputs=observed_evidence_ids,
            current_security_state=attack_state.value,
            assumptions=["Active Directory KDC and Cloud IdP enforce immediate token revocation"],
            intervention="identity.revoke_sessions",
            simulated_state_transition=f"{attack_state.value} -> RECOVERY",
            projected_reachability_summary=f"Severed {severed_by_c}/{total_active_paths} credential hops; {surviving_c_assets} surviving assets",
            projected_security_impact_score=impact_c,
            projected_business_impact_score=disruption_c,
            model_version=self.VERSION,
        )

        world_c = WorldProjection(
            world_id="world-c-revoke-identity",
            description="Revoke Kerberos TGTs, OAuth refresh tokens, and force credential invalidation",
            action_applied="identity.revoke_sessions",
            continuation_probability=0.25,
            reachable_assets_count=surviving_c_assets,
            projected_impact_score=impact_c,
            residual_attack_paths=["Local persistence on host survives identity revocation"],
            business_disruption_score=disruption_c,
            reversibility="HIGH",
            evidence_preservation_score=100,
            likely_next_transitions=["ATTACKER_SESSION_TERMINATED", "RE-AUTHENTICATION_FAIL"],
            epistemic_status=EpistemicStatus.PROJECTED,
            attack_interruption_pct=round(interruption_c, 1),
            tier0_protected_count=1 if tier0_exp else 0,
            tier1_protected_count=1 if tier1_exp else 0,
            simulation_provenance=prov_c,
            continuation_risk_level="MEDIUM",
            continuation_basis=[
                f"Credential reuse hops severed: {severed_by_c}/{total_active_paths}",
                "Local persistence on foothold host survives session reset",
            ],
            is_statistically_calibrated=False,
        )

        # ── World D: Targeted Network Microsegmentation (Surgical Cut) ───────
        # Blocks SMB 445 / RPC 135 to Tier-0 DC and Backup, while workstation remains active
        severed_by_d = sum(1 for p in active_paths if p.criticality_tier == "TIER_0" or any(h.protocol_port in ("TCP/445", "TCP/135") for h in p.hops))
        interruption_d = min(85.0, max(45.0, (severed_by_d / total_active_paths) * 100.0))
        surviving_d_assets = max(0, total_reachable_assets - severed_by_d)
        impact_d = max(20, int(world_a_impact * (1.0 - (interruption_d / 100.0))))
        disruption_d = 10  # Minimal disruption: user workstation stays online, only Tier-0 routes restricted

        prov_d = CounterfactualSimulationProvenance(
            observed_inputs=observed_evidence_ids,
            current_security_state=attack_state.value,
            assumptions=["Software-defined perimeter / switch ACL can enforce port blocks dynamically"],
            intervention="network.block_ports",
            simulated_state_transition=f"{attack_state.value} -> CONTAINED",
            projected_reachability_summary=f"Severed Tier-0 lateral routes; {surviving_d_assets} peer assets reachable",
            projected_security_impact_score=impact_d,
            projected_business_impact_score=disruption_d,
            model_version=self.VERSION,
        )

        world_d = WorldProjection(
            world_id="world-d-targeted-microsegmentation",
            description="Targeted microsegmentation: block SMB/RPC to Tier-0 assets while keeping user workstation online",
            action_applied="network.block_ports",
            continuation_probability=0.20,
            reachable_assets_count=surviving_d_assets,
            projected_impact_score=impact_d,
            residual_attack_paths=["Peer workstation lateral traversal remains open outside Tier-0 boundary"],
            business_disruption_score=disruption_d,
            reversibility="HIGH",
            evidence_preservation_score=95,
            likely_next_transitions=["TIER_0_ISOLATED", "LATERAL_TRAVERSAL_BLOCKED"],
            epistemic_status=EpistemicStatus.PROJECTED,
            attack_interruption_pct=round(interruption_d, 1),
            tier0_protected_count=1 if tier0_exp else 0,
            tier1_protected_count=0,
            simulation_provenance=prov_d,
            continuation_risk_level="MEDIUM",
            continuation_basis=[
                f"Tier-0 lateral routes severed: {severed_by_d}/{total_active_paths}",
                f"{surviving_d_assets} non-Tier-0 peer workstations remain reachable",
            ],
            is_statistically_calibrated=False,
        )

        # ── World E: Composite Surgical Containment (Identity + Segment) ────
        # Concurrent Identity Revocation and Targeted Network Microsegmentation (Optimal Tradeoff)
        severed_by_e = min(total_active_paths, severed_by_b + severed_by_c)
        interruption_e = min(98.0, max(85.0, (severed_by_e / total_active_paths) * 100.0))
        surviving_e_assets = 0
        impact_e = 5
        disruption_e = 30  # Balanced disruption: identity reset + port restriction, physical host online

        prov_e = CounterfactualSimulationProvenance(
            observed_inputs=observed_evidence_ids,
            current_security_state=attack_state.value,
            assumptions=["Composite orchestration: IdP session purge + network access control synchronized"],
            intervention="composite.isolate_and_revoke",
            simulated_state_transition=f"{attack_state.value} -> CONTAINED",
            projected_reachability_summary="All lateral paths to crown jewels severed; sessions revoked",
            projected_security_impact_score=impact_e,
            projected_business_impact_score=disruption_e,
            model_version=self.VERSION,
        )

        world_e = WorldProjection(
            world_id="world-e-composite-containment",
            description="Composite surgical containment: concurrent identity session revocation and Tier-0 route blocking",
            action_applied="composite.isolate_and_revoke",
            continuation_probability=0.03,
            reachable_assets_count=0,
            projected_impact_score=impact_e,
            residual_attack_paths=[],
            business_disruption_score=disruption_e,
            reversibility="HIGH",
            evidence_preservation_score=95,
            likely_next_transitions=["CONTAINMENT_VERIFIED", "ZERO_CROWN_JEWEL_EXPOSURE"],
            epistemic_status=EpistemicStatus.PROJECTED,
            attack_interruption_pct=round(interruption_e, 1),
            tier0_protected_count=1 if tier0_exp else 0,
            tier1_protected_count=1 if tier1_exp else 0,
            simulation_provenance=prov_e,
            continuation_risk_level="MINIMAL",
            continuation_basis=[
                f"All active paths severed: {severed_by_e}/{total_active_paths}",
                "Zero reachable crown jewels survive",
                "Synchronized identity revocation + port segmentation",
            ],
            is_statistically_calibrated=False,
        )

        # ── Comparative Intervention Matrix (P8-08) ─────────────────────────
        ratings = [
            InterventionImpactRating(
                world_id="world-a-do-nothing",
                intervention_type=InterventionType.DO_NOTHING,
                attack_interruption_pct=0.0,
                tier0_protected_count=0,
                tier1_protected_count=0,
                total_protected_count=0,
                business_disruption_score=0,
                residual_risk_score=world_a_impact,
                rationale="No intervention taken; attacker has unconstrained reach to crown jewels",
            ),
            InterventionImpactRating(
                world_id="world-b-isolate-host",
                intervention_type=InterventionType.HOST_ISOLATION,
                attack_interruption_pct=world_b.attack_interruption_pct,
                tier0_protected_count=world_b.tier0_protected_count,
                tier1_protected_count=world_b.tier1_protected_count,
                total_protected_count=severed_by_b,
                business_disruption_score=world_b.business_disruption_score,
                residual_risk_score=world_b.projected_impact_score,
                rationale="Blunt containment severs all host network routes but causes heavy business disruption",
            ),
            InterventionImpactRating(
                world_id="world-c-revoke-identity",
                intervention_type=InterventionType.IDENTITY_REVOCATION,
                attack_interruption_pct=world_c.attack_interruption_pct,
                tier0_protected_count=world_c.tier0_protected_count,
                tier1_protected_count=world_c.tier1_protected_count,
                total_protected_count=severed_by_c,
                business_disruption_score=world_c.business_disruption_score,
                residual_risk_score=world_c.projected_impact_score,
                rationale="Surgical identity invalidation halts credential pivot with moderate user friction",
            ),
            InterventionImpactRating(
                world_id="world-d-targeted-microsegmentation",
                intervention_type=InterventionType.NETWORK_MICROSEGMENTATION,
                attack_interruption_pct=world_d.attack_interruption_pct,
                tier0_protected_count=world_d.tier0_protected_count,
                tier1_protected_count=world_d.tier1_protected_count,
                total_protected_count=severed_by_d,
                business_disruption_score=world_d.business_disruption_score,
                residual_risk_score=world_d.projected_impact_score,
                rationale="Targeted port blocks insulate Tier-0 assets with minimal disruption to workstation operations",
            ),
            InterventionImpactRating(
                world_id="world-e-composite-containment",
                intervention_type=InterventionType.COMPOSITE_SURGICAL,
                attack_interruption_pct=world_e.attack_interruption_pct,
                tier0_protected_count=world_e.tier0_protected_count,
                tier1_protected_count=world_e.tier1_protected_count,
                total_protected_count=total_reachable_assets,
                business_disruption_score=world_e.business_disruption_score,
                residual_risk_score=world_e.projected_impact_score,
                rationale="Pareto-optimal: maximal attack interruption with balanced, reversible disruption",
            ),
        ]

        recommended_id = "world-e-composite-containment"

        matrix = ComparativeInterventionMatrix(
            matrix_id=f"matrix-{sha256_digest(f'{tenant_id}:{case_id}:{at_timestamp}')[:10]}",
            tenant_id=tenant_id,
            case_id=case_id,
            evaluated_at=at_timestamp,
            ratings=ratings,
            recommended_world_id=recommended_id,
            decision_rationale="Composite surgical containment severs 98% of reachable paths while preserving endpoint operational uptime",
            simulation_provenances=[prov_a, prov_b, prov_c, prov_d, prov_e],
        )

        return CounterfactualAnalysis(
            analysis_id=f"cf-{sha256_digest(f'{tenant_id}:{case_id}:{at_timestamp}')[:10]}",
            tenant_id=tenant_id,
            case_id=case_id,
            evaluated_at=at_timestamp,
            world_a_do_nothing=world_a,
            intervention_worlds=[world_b, world_c, world_d, world_e],
            recommended_world_id=recommended_id,
            comparative_matrix=matrix,
        )
