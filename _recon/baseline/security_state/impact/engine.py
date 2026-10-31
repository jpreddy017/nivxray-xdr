"""Impact Engine: strictly separated from Verdict Engine."""
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
from ..reachability.engine import ReachabilityMatrix


@dataclass
class ImpactDimension:
    """A scored dimension of enterprise impact."""
    name: str
    score: int  # 0 to 100
    weight: float
    description: str
    affected_entities: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ImpactScoreCard:
    """Consolidated impact assessment decoupled from verdict confidence."""
    card_id: str
    tenant_id: str
    case_id: str
    overall_impact_score: int  # 0 to 100
    blast_radius_node_count: int
    tier_0_service_exposed: bool
    ransomware_exposure_risk: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    data_exfiltration_risk: str   # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    business_service_downtime_risk: str # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    dimensions: List[ImpactDimension]
    evidence_justifications: List[str]
    regulatory_impact_scope: List[str] = field(default_factory=list)
    card_hash: str = ""

    def __post_init__(self) -> None:
        if not self.card_hash:
            self.card_hash = self.compute_hash()

    def compute_hash(self) -> str:
        payload = {
            "card_id": self.card_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "overall_impact_score": self.overall_impact_score,
            "blast_radius_node_count": self.blast_radius_node_count,
            "tier_0_service_exposed": self.tier_0_service_exposed,
            "dimensions": [d.to_dict() for d in self.dimensions],
            "evidence_justifications": sorted(self.evidence_justifications),
            "regulatory_impact_scope": sorted(self.regulatory_impact_scope),
        }
        return sha256_digest(canonical_json(payload))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "card_id": self.card_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "overall_impact_score": self.overall_impact_score,
            "blast_radius_node_count": self.blast_radius_node_count,
            "tier_0_service_exposed": self.tier_0_service_exposed,
            "ransomware_exposure_risk": self.ransomware_exposure_risk,
            "data_exfiltration_risk": self.data_exfiltration_risk,
            "business_service_downtime_risk": self.business_service_downtime_risk,
            "dimensions": [d.to_dict() for d in self.dimensions],
            "evidence_justifications": self.evidence_justifications,
            "regulatory_impact_scope": list(self.regulatory_impact_scope),
            "card_hash": self.card_hash,
        }


class ImpactEngine:
    """Evaluates business exposure and blast radius without distorting verdict."""
    VERSION = "1.1.0"

    def evaluate_impact(
        self,
        tenant_id: str,
        case_id: str,
        reachability: ReachabilityMatrix,
        compromised_entities: List[EntityRef],
    ) -> ImpactScoreCard:
        """Compute impact score card based on reachability and entity criticality."""
        blast_nodes = reachability.currently_reachable_count + reachability.potentially_reachable_count + len(compromised_entities)
        tier0 = reachability.tier_0_exposed
        tier1 = getattr(reachability, "tier_1_exposed", False)

        # Collect regulatory scopes across currently reachable paths
        reg_scopes: set[str] = set()
        for p in reachability.paths:
            if p.status.value == "CURRENTLY_REACHABLE" and getattr(p, "valuation", None):
                for scope in p.valuation.regulatory_scope:
                    reg_scopes.add(scope)

        # Dimension 1: Asset Criticality
        d_asset = ImpactDimension(
            name="Asset Criticality",
            score=95 if tier0 else (80 if tier1 else (60 if reachability.currently_reachable_count > 0 else 25)),
            weight=0.35,
            description="Tier 0 infrastructure (Domain Controllers, Backup) exposed" if tier0 else ("Tier 1 operational core assets reachable" if tier1 else "Tier 2 endpoints reachable"),
            affected_entities=[p.target_entity.entity_id for p in reachability.paths if p.criticality_tier == "TIER_0"],
        )

        # Dimension 2: Blast Radius
        d_blast = ImpactDimension(
            name="Blast Radius",
            score=min(100, blast_nodes * 15),
            weight=0.25,
            description=f"Direct lateral traversal potential encompasses {blast_nodes} connected systems",
            affected_entities=[e.entity_id for e in compromised_entities],
        )

        # Dimension 3: Ransomware Susceptibility
        rw_score = 90 if tier0 else 45
        d_rw = ImpactDimension(
            name="Ransomware Susceptibility",
            score=rw_score,
            weight=0.25,
            description="Attacker reachability intersects administrative accounts and backup repositories" if tier0 else "Local disk encryption potential limited to endpoint",
            affected_entities=[p.target_entity.entity_id for p in reachability.paths if p.target_entity.category.value == "BACKUP_SYSTEM"],
        )

        # Dimension 4: Operational Disruption
        d_disrupt = ImpactDimension(
            name="Operational Disruption",
            score=70 if tier0 else (50 if tier1 else 30),
            weight=0.15,
            description="Core business services threatened" if tier0 else ("Production transactional services threatened" if tier1 else "Limited workstation service impact"),
            affected_entities=[],
        )

        overall = int(round(
            d_asset.score * d_asset.weight +
            d_blast.score * d_blast.weight +
            d_rw.score * d_rw.weight +
            d_disrupt.score * d_disrupt.weight
        ))

        rw_risk = "CRITICAL" if rw_score >= 80 else ("HIGH" if rw_score >= 50 else "LOW")
        exfil_risk = "HIGH" if any(p.target_entity.category.value == "DATA_STORE" for p in reachability.paths) else "MEDIUM"
        down_risk = "CRITICAL" if tier0 else ("HIGH" if tier1 else "LOW")

        justifications = [
            f"Blast radius calculated as {blast_nodes} enterprise nodes",
            "Tier-0 active directory domain controller reachable" if tier0 else "Tier-0 boundary verified intact",
        ]
        if reg_scopes:
            justifications.append(f"Regulatory compliance domains exposed: {', '.join(sorted(reg_scopes))}")

        return ImpactScoreCard(
            card_id=f"impact-{uuid.uuid4().hex[:10]}",
            tenant_id=tenant_id,
            case_id=case_id,
            overall_impact_score=overall,
            blast_radius_node_count=blast_nodes,
            tier_0_service_exposed=tier0,
            ransomware_exposure_risk=rw_risk,
            data_exfiltration_risk=exfil_risk,
            business_service_downtime_risk=down_risk,
            dimensions=[d_asset, d_blast, d_rw, d_disrupt],
            evidence_justifications=justifications,
            regulatory_impact_scope=sorted(list(reg_scopes)),
        )
