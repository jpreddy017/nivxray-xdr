"""Enterprise Multidimensional Reachability Engine."""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..contracts import (
    AssetCriticalityTier,
    AssetValuation,
    DataSensitivityTier,
    EntityCategory,
    EntityRef,
    FinancialImpactCategory,
    ProvenanceEnvelope,
    ReachabilityStatus,
    canonical_json,
    sha256_digest,
)


@dataclass
class ReachabilityHop:
    """A single hop along an attacker's expansion path."""
    source_entity: EntityRef
    target_entity: EntityRef
    hop_type: str  # 'NETWORK_ROUTE', 'CREDENTIAL_REUSE', 'LOCAL_ADMIN_RIGHT', 'CLOUD_ROLE_ASSUME', 'SESSION_HIJACK'
    is_blocked_by_control: bool = False
    blocking_control_name: Optional[str] = None
    required_capability: Optional[str] = None
    required_privilege: Optional[str] = None
    protocol_port: Optional[str] = None  # e.g., 'TCP/445', 'TCP/135', 'TCP/5985', 'HTTPS/443'
    is_cut_by_intervention: bool = False
    intervention_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["source_entity"] = self.source_entity.to_dict()
        d["target_entity"] = self.target_entity.to_dict()
        return d


@dataclass
class ReachabilityPath:
    """A full traversal path from compromised source to sensitive asset."""
    path_id: str
    target_entity: EntityRef
    status: ReachabilityStatus
    hops: List[ReachabilityHop]
    criticality_tier: str  # 'TIER_0' (DC/KeyVault/Backup), 'TIER_1' (Production DB), 'TIER_2' (Workstations), 'NORMAL'
    required_prerequisites: List[str] = field(default_factory=list)
    valuation: Optional[AssetValuation] = None
    is_severed: bool = False
    severed_by_action: Optional[str] = None
    exposure_explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "target_entity": self.target_entity.to_dict(),
            "status": self.status.value,
            "criticality_tier": self.criticality_tier,
            "required_prerequisites": self.required_prerequisites,
            "hops": [h.to_dict() for h in self.hops],
            "valuation": self.valuation.to_dict() if self.valuation else None,
            "is_severed": self.is_severed,
            "severed_by_action": self.severed_by_action,
            "exposure_explanation": self.exposure_explanation,
        }


@dataclass
class ReachabilityMatrix:
    """Full enterprise reachability analysis from compromised footholds."""
    matrix_id: str
    tenant_id: str
    case_id: str
    evaluated_at: str
    foothold_entities: List[EntityRef]
    paths: List[ReachabilityPath]
    currently_reachable_count: int
    potentially_reachable_count: int
    blocked_count: int
    tier_0_exposed: bool
    tier_1_exposed: bool = False
    reachable_tier_0_count: int = 0
    reachable_tier_1_count: int = 0
    reachable_tier_2_count: int = 0
    active_capabilities_applied: List[str] = field(default_factory=list)
    provenance: Optional[ProvenanceEnvelope] = None
    matrix_hash: str = ""

    def __post_init__(self) -> None:
        if not self.matrix_hash:
            self.matrix_hash = self.compute_hash()

    def compute_hash(self) -> str:
        payload = {
            "matrix_id": self.matrix_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "evaluated_at": self.evaluated_at,
            "foothold_entities": [f.to_dict() for f in self.foothold_entities],
            "paths": [p.to_dict() for p in self.paths],
            "active_capabilities_applied": sorted(self.active_capabilities_applied),
        }
        return sha256_digest(canonical_json(payload))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "matrix_id": self.matrix_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "evaluated_at": self.evaluated_at,
            "foothold_entities": [f.to_dict() for f in self.foothold_entities],
            "paths": [p.to_dict() for p in self.paths],
            "currently_reachable_count": self.currently_reachable_count,
            "potentially_reachable_count": self.potentially_reachable_count,
            "blocked_count": self.blocked_count,
            "tier_0_exposed": self.tier_0_exposed,
            "tier_1_exposed": self.tier_1_exposed,
            "reachable_tier_0_count": self.reachable_tier_0_count,
            "reachable_tier_1_count": self.reachable_tier_1_count,
            "reachable_tier_2_count": self.reachable_tier_2_count,
            "active_capabilities_applied": list(self.active_capabilities_applied),
            "provenance": self.provenance.to_dict() if self.provenance else None,
            "matrix_hash": self.matrix_hash,
        }


class EnterpriseReachabilityEngine:
    """Computes multidimensional attacker reachability across enterprise graph."""
    VERSION = "1.1.0"

    def _get_default_valuation(
        self,
        tenant_id: str,
        entity_id: str,
        category: EntityCategory,
        tier: str,
    ) -> AssetValuation:
        """Create canonical asset valuation decoupled from network reachability."""
        tier_enum = getattr(AssetCriticalityTier, tier, AssetCriticalityTier.NORMAL)
        if tier == "TIER_0":
            return AssetValuation(
                entity_id=entity_id,
                tenant_id=tenant_id,
                tier=tier_enum,
                business_criticality_score=95,
                sensitivity=DataSensitivityTier.RESTRICTED,
                financial_category=FinancialImpactCategory.CRITICAL,
                regulatory_scope=["SOX", "PCI-DSS"],
                business_function="Identity Root / Core Enterprise Backup",
            )
        elif tier == "TIER_1":
            return AssetValuation(
                entity_id=entity_id,
                tenant_id=tenant_id,
                tier=tier_enum,
                business_criticality_score=85,
                sensitivity=DataSensitivityTier.RESTRICTED,
                financial_category=FinancialImpactCategory.HIGH,
                regulatory_scope=["PCI-DSS"],
                business_function="Production Relational Database & Transactions",
            )
        elif tier == "TIER_2":
            return AssetValuation(
                entity_id=entity_id,
                tenant_id=tenant_id,
                tier=tier_enum,
                business_criticality_score=45,
                sensitivity=DataSensitivityTier.INTERNAL,
                financial_category=FinancialImpactCategory.MEDIUM,
                regulatory_scope=[],
                business_function="Enterprise Client Endpoint",
            )
        else:
            return AssetValuation(
                entity_id=entity_id,
                tenant_id=tenant_id,
                tier=AssetCriticalityTier.NORMAL,
                business_criticality_score=15,
                sensitivity=DataSensitivityTier.PUBLIC,
                financial_category=FinancialImpactCategory.LOW,
                regulatory_scope=[],
                business_function="Non-Critical Asset",
            )

    def compute_reachability(
        self,
        tenant_id: str,
        case_id: str,
        footholds: List[EntityRef],
        harvested_credentials: List[str],
        active_capabilities: List[str],
        at_timestamp: str = "2026-09-04T00:00:00Z",
        ikg_nodes: Optional[List[Dict[str, Any]]] = None,
        ikg_edges: Optional[List[Dict[str, Any]]] = None,
        asset_valuations: Optional[Dict[str, AssetValuation]] = None,
        active_interventions: Optional[List[str]] = None,
    ) -> ReachabilityMatrix:
        """Calculate capability-conditioned reachable paths from footholds across authoritative IKG assets."""
        paths: List[ReachabilityPath] = []
        valuations = asset_valuations or {}
        interventions = set(active_interventions or [])

        # Capability detection
        has_admin_cred = any("admin" in c.lower() or "domain" in c.lower() for c in harvested_credentials)
        has_dcsync = any(c in active_capabilities for c in ("CAP_DCSYNC", "CAP_AD_REPLICATION_ABUSE", "CAP_NTDS_EXTRACTION", "CAP_GOLDEN_TICKET"))
        has_kerberoasting = "CAP_KERBEROASTING" in active_capabilities or "CAP_ASREP_ROASTING" in active_capabilities
        has_lateral = any(c in active_capabilities for c in ("CAP_LATERAL_MOVEMENT", "CAP_MULTI_HOST_TRAVERSAL"))
        has_backup_destruction = any(c in active_capabilities for c in ("CAP_SHADOW_COPY_DELETION", "CAP_BACKUP_TAMPERING"))
        has_cloud = any(c in active_capabilities for c in ("CAP_CLOUD_METADATA_ACCESS", "CAP_CLOUD_TOKEN_THEFT", "CAP_CLOUD_PRIV_ESC"))

        def is_hop_cut_by_intervention(
            source_id: str,
            target_id: str,
            hop_type: str,
            port: Optional[str] = None,
        ) -> tuple[bool, Optional[str]]:
            # Host isolation cuts all network hops originating or terminating at isolated host
            if f"endpoint.isolate:{source_id}" in interventions or "endpoint.isolate" in interventions:
                return True, "endpoint.isolate"
            # Identity revocation cuts credential reuse, TGS/TGT tickets, and Cloud OAuth tokens
            if hop_type in ("CREDENTIAL_REUSE", "KERBEROS_TGS_TICKET", "DIRECTORY_REPLICATION_RPC", "IMDS_ROLE_SESSION"):
                if any("identity.revoke" in i for i in interventions):
                    return True, "identity.revoke_sessions"
            # Targeted microsegmentation / port block
            if f"network.block_ports:{target_id}" in interventions or "network.microsegmentation" in interventions:
                return True, "network.block_ports"
            if port and any(port in i for i in interventions):
                return True, "network.block_ports"
            return False, None

        for foothold in footholds:
            # Target 1: Domain Controller (Tier 0)
            dc_id = "server-dc-01"
            dc_entity = EntityRef(
                category=EntityCategory.SERVER,
                entity_id=dc_id,
                tenant_id=tenant_id,
                display_name="Primary Domain Controller (dc-01.corp)",
            )
            dc_val = valuations.get(dc_id, self._get_default_valuation(tenant_id, dc_id, EntityCategory.SERVER, "TIER_0"))

            dc_hop_cut, dc_cut_action = is_hop_cut_by_intervention(
                foothold.entity_id, dc_id, "DIRECTORY_REPLICATION_RPC" if has_dcsync else ("CREDENTIAL_REUSE" if has_admin_cred else "NETWORK_ROUTE"), "TCP/445"
            )

            if dc_hop_cut:
                dc_status = ReachabilityStatus.BLOCKED
                dc_hop = ReachabilityHop(
                    source_entity=foothold,
                    target_entity=dc_entity,
                    hop_type="DIRECTORY_REPLICATION_RPC" if has_dcsync else "NETWORK_ROUTE",
                    is_blocked_by_control=True,
                    blocking_control_name=f"Intervention {dc_cut_action}",
                    protocol_port="TCP/445",
                    is_cut_by_intervention=True,
                    intervention_id=dc_cut_action,
                )
            elif has_dcsync:
                dc_status = ReachabilityStatus.CURRENTLY_REACHABLE
                dc_hop = ReachabilityHop(
                    source_entity=foothold,
                    target_entity=dc_entity,
                    hop_type="DIRECTORY_REPLICATION_RPC",
                    required_capability="CAP_DCSYNC",
                    protocol_port="TCP/135",
                )
            elif has_admin_cred:
                dc_status = ReachabilityStatus.CURRENTLY_REACHABLE
                dc_hop = ReachabilityHop(
                    source_entity=foothold,
                    target_entity=dc_entity,
                    hop_type="CREDENTIAL_REUSE",
                    required_privilege="Domain Admin",
                    protocol_port="TCP/445",
                )
            elif has_kerberoasting or "CAP_CREDENTIAL_DUMPING" in active_capabilities:
                dc_status = ReachabilityStatus.POTENTIALLY_REACHABLE
                dc_hop = ReachabilityHop(
                    source_entity=foothold,
                    target_entity=dc_entity,
                    hop_type="LOCAL_ADMIN_RIGHT",
                    required_capability="CAP_CREDENTIAL_DUMPING",
                    protocol_port="TCP/445",
                )
            else:
                dc_status = ReachabilityStatus.BLOCKED
                dc_hop = ReachabilityHop(
                    source_entity=foothold,
                    target_entity=dc_entity,
                    hop_type="NETWORK_ROUTE",
                    is_blocked_by_control=True,
                    blocking_control_name="Tier-0 Network Microsegmentation",
                    protocol_port="TCP/445",
                )

            paths.append(ReachabilityPath(
                path_id=f"path-{foothold.entity_id}-{dc_id}",
                target_entity=dc_entity,
                status=dc_status,
                hops=[dc_hop],
                criticality_tier="TIER_0",
                required_prerequisites=["Domain Admin Kerberos Ticket"] if dc_status != ReachabilityStatus.CURRENTLY_REACHABLE else [],
                valuation=dc_val,
                is_severed=dc_hop_cut,
                severed_by_action=dc_cut_action,
                exposure_explanation="Domain Controller reachable via directory replication or admin credentials" if dc_status == ReachabilityStatus.CURRENTLY_REACHABLE else "Path to Domain Controller secured or segmented",
            ))

            # Target 2: Immutable Backup Storage (Tier 0)
            backup_id = "backup-nas-01"
            backup_entity = EntityRef(
                category=EntityCategory.BACKUP_SYSTEM,
                entity_id=backup_id,
                tenant_id=tenant_id,
                display_name="Veeam Immutable Backup Repository",
            )
            backup_val = valuations.get(backup_id, self._get_default_valuation(tenant_id, backup_id, EntityCategory.BACKUP_SYSTEM, "TIER_0"))

            bk_hop_cut, bk_cut_action = is_hop_cut_by_intervention(
                foothold.entity_id, backup_id, "VSS_BACKUP_CATALOG_PURGE" if has_backup_destruction else "CLOUD_ROLE_ASSUME", "TCP/445"
            )

            if bk_hop_cut:
                backup_status = ReachabilityStatus.BLOCKED
                bk_hop = ReachabilityHop(
                    source_entity=foothold,
                    target_entity=backup_entity,
                    hop_type="VSS_BACKUP_CATALOG_PURGE" if has_backup_destruction else "CLOUD_ROLE_ASSUME",
                    is_blocked_by_control=True,
                    blocking_control_name=f"Intervention {bk_cut_action}",
                    protocol_port="TCP/445",
                    is_cut_by_intervention=True,
                    intervention_id=bk_cut_action,
                )
            else:
                backup_status = (
                    ReachabilityStatus.CURRENTLY_REACHABLE
                    if (has_backup_destruction or has_admin_cred or has_dcsync)
                    else ReachabilityStatus.BLOCKED
                )
                bk_hop = ReachabilityHop(
                    source_entity=foothold,
                    target_entity=backup_entity,
                    hop_type="VSS_BACKUP_CATALOG_PURGE" if has_backup_destruction else "CLOUD_ROLE_ASSUME",
                    is_blocked_by_control=not (has_backup_destruction or has_admin_cred or has_dcsync),
                    blocking_control_name="Backup MFA Air-Gap" if not (has_backup_destruction or has_admin_cred or has_dcsync) else None,
                    required_capability="CAP_SHADOW_COPY_DELETION" if has_backup_destruction else None,
                    protocol_port="TCP/445",
                )

            paths.append(ReachabilityPath(
                path_id=f"path-{foothold.entity_id}-{backup_id}",
                target_entity=backup_entity,
                status=backup_status,
                hops=[bk_hop],
                criticality_tier="TIER_0",
                required_prerequisites=["Backup Management MFA bypass"] if backup_status != ReachabilityStatus.CURRENTLY_REACHABLE else [],
                valuation=backup_val,
                is_severed=bk_hop_cut,
                severed_by_action=bk_cut_action,
                exposure_explanation="Backup repository exposed to shadow copy purge" if backup_status == ReachabilityStatus.CURRENTLY_REACHABLE else "Backup repository air-gap intact",
            ))

            # Target 3: Core Database Server (Tier 1)
            db_id = "db-prod-sql-01"
            db_entity = EntityRef(
                category=EntityCategory.DATA_STORE,
                entity_id=db_id,
                tenant_id=tenant_id,
                display_name="Production Customer Database (MSSQL)",
            )
            db_val = valuations.get(db_id, self._get_default_valuation(tenant_id, db_id, EntityCategory.DATA_STORE, "TIER_1"))

            db_hop_cut, db_cut_action = is_hop_cut_by_intervention(
                foothold.entity_id, db_id, "KERBEROS_TGS_TICKET" if has_kerberoasting else "NETWORK_ROUTE", "TCP/1433"
            )

            if db_hop_cut:
                db_status = ReachabilityStatus.BLOCKED
                db_hop = ReachabilityHop(
                    source_entity=foothold,
                    target_entity=db_entity,
                    hop_type="KERBEROS_TGS_TICKET" if has_kerberoasting else "NETWORK_ROUTE",
                    is_blocked_by_control=True,
                    blocking_control_name=f"Intervention {db_cut_action}",
                    protocol_port="TCP/1433",
                    is_cut_by_intervention=True,
                    intervention_id=db_cut_action,
                )
            else:
                db_status = (
                    ReachabilityStatus.CURRENTLY_REACHABLE
                    if (has_admin_cred or has_dcsync or has_kerberoasting)
                    else ReachabilityStatus.POTENTIALLY_REACHABLE
                )
                db_hop = ReachabilityHop(
                    source_entity=foothold,
                    target_entity=db_entity,
                    hop_type="KERBEROS_TGS_TICKET" if has_kerberoasting else "NETWORK_ROUTE",
                    required_capability="CAP_KERBEROASTING" if has_kerberoasting else None,
                    protocol_port="TCP/1433",
                )

            paths.append(ReachabilityPath(
                path_id=f"path-{foothold.entity_id}-{db_id}",
                target_entity=db_entity,
                status=db_status,
                hops=[db_hop],
                criticality_tier="TIER_1",
                valuation=db_val,
                is_severed=db_hop_cut,
                severed_by_action=db_cut_action,
                exposure_explanation="Database reachable via Kerberoasting / Service Principal Name abuse" if db_status == ReachabilityStatus.CURRENTLY_REACHABLE else "Database protected by session/network controls",
            ))

            # Target 4: Cloud Enterprise Data Vault (Tier 0)
            cloud_id = "cloud-s3-vault-01"
            cloud_entity = EntityRef(
                category=EntityCategory.CLOUD_RESOURCE,
                entity_id=cloud_id,
                tenant_id=tenant_id,
                display_name="Production Cloud Storage Vault (S3/Blob)",
            )
            cloud_val = valuations.get(cloud_id, self._get_default_valuation(tenant_id, cloud_id, EntityCategory.CLOUD_RESOURCE, "TIER_0"))

            cloud_hop_cut, cloud_cut_action = is_hop_cut_by_intervention(
                foothold.entity_id, cloud_id, "IMDS_ROLE_SESSION", "HTTPS/443"
            )

            if cloud_hop_cut:
                cloud_status = ReachabilityStatus.BLOCKED
                cloud_hop = ReachabilityHop(
                    source_entity=foothold,
                    target_entity=cloud_entity,
                    hop_type="IMDS_ROLE_SESSION" if has_cloud else "IAM_FEDERATION",
                    is_blocked_by_control=True,
                    blocking_control_name=f"Intervention {cloud_cut_action}",
                    protocol_port="HTTPS/443",
                    is_cut_by_intervention=True,
                    intervention_id=cloud_cut_action,
                )
            else:
                cloud_status = ReachabilityStatus.CURRENTLY_REACHABLE if has_cloud else ReachabilityStatus.POTENTIALLY_REACHABLE
                cloud_hop = ReachabilityHop(
                    source_entity=foothold,
                    target_entity=cloud_entity,
                    hop_type="IMDS_ROLE_SESSION" if has_cloud else "IAM_FEDERATION",
                    required_capability="CAP_CLOUD_METADATA_ACCESS" if has_cloud else None,
                    protocol_port="HTTPS/443",
                )

            paths.append(ReachabilityPath(
                path_id=f"path-{foothold.entity_id}-{cloud_id}",
                target_entity=cloud_entity,
                status=cloud_status,
                hops=[cloud_hop],
                criticality_tier="TIER_0",
                valuation=cloud_val,
                is_severed=cloud_hop_cut,
                severed_by_action=cloud_cut_action,
                exposure_explanation="Cloud storage vault reachable via IMDS credential scraping" if cloud_status == ReachabilityStatus.CURRENTLY_REACHABLE else "Cloud IAM role boundary intact",
            ))

            # Dynamic Target 5: Authoritative IKG Referenced Nodes
            if ikg_nodes:
                for node in ikg_nodes:
                    node_id = node.get("id") or node.get("iid") or ""
                    node_type = node.get("type", "").lower()
                    if not node_id or node_id == foothold.entity_id:
                        continue

                    node_tier = node.get("tier", "TIER_2").upper()
                    if node_type in ("device", "host", "endpoint", "workstation", "server", "cloud_resource", "virtualization_host"):
                        node_val = valuations.get(node_id, self._get_default_valuation(tenant_id, node_id, EntityCategory.DEVICE, node_tier))
                        
                        node_hop_cut, node_cut_action = is_hop_cut_by_intervention(
                            foothold.entity_id, node_id, "REMOTE_WMI_PROCESS_CALL" if has_lateral else "NETWORK_ROUTE", "TCP/445"
                        )

                        if node_hop_cut:
                            adj_status = ReachabilityStatus.BLOCKED
                            adj_hop = ReachabilityHop(
                                source_entity=foothold,
                                target_entity=EntityRef(
                                    category=EntityCategory.DEVICE if node_type != "cloud_resource" else EntityCategory.CLOUD_RESOURCE,
                                    entity_id=node_id,
                                    tenant_id=tenant_id,
                                    display_name=node.get("name") or node_id,
                                ),
                                hop_type="REMOTE_WMI_PROCESS_CALL" if has_lateral else "NETWORK_ROUTE",
                                is_blocked_by_control=True,
                                blocking_control_name=f"Intervention {node_cut_action}",
                                protocol_port="TCP/445",
                                is_cut_by_intervention=True,
                                intervention_id=node_cut_action,
                            )
                        else:
                            adj_status = ReachabilityStatus.CURRENTLY_REACHABLE if has_lateral else ReachabilityStatus.POTENTIALLY_REACHABLE
                            adj_hop = ReachabilityHop(
                                source_entity=foothold,
                                target_entity=EntityRef(
                                    category=EntityCategory.DEVICE if node_type != "cloud_resource" else EntityCategory.CLOUD_RESOURCE,
                                    entity_id=node_id,
                                    tenant_id=tenant_id,
                                    display_name=node.get("name") or node_id,
                                ),
                                hop_type="REMOTE_WMI_PROCESS_CALL" if has_lateral else "NETWORK_ROUTE",
                                required_capability="CAP_MULTI_HOST_TRAVERSAL" if has_lateral else None,
                                protocol_port="TCP/445",
                            )

                        paths.append(ReachabilityPath(
                            path_id=f"path-{foothold.entity_id}-{node_id}",
                            target_entity=EntityRef(
                                category=EntityCategory.DEVICE if node_type != "cloud_resource" else EntityCategory.CLOUD_RESOURCE,
                                entity_id=node_id,
                                tenant_id=tenant_id,
                                display_name=node.get("name") or f"Adjacent Host {node_id}",
                            ),
                            status=adj_status,
                            hops=[adj_hop],
                            criticality_tier=node_tier,
                            required_prerequisites=["Local Admin Right / SMB Session"] if adj_status != ReachabilityStatus.CURRENTLY_REACHABLE else [],
                            valuation=node_val,
                            is_severed=node_hop_cut,
                            severed_by_action=node_cut_action,
                            exposure_explanation=f"Reachable via lateral traversal ({adj_hop.hop_type})" if adj_status == ReachabilityStatus.CURRENTLY_REACHABLE else "Path not currently active",
                        ))

        curr_count = sum(1 for p in paths if p.status == ReachabilityStatus.CURRENTLY_REACHABLE)
        pot_count = sum(1 for p in paths if p.status in (ReachabilityStatus.POTENTIALLY_REACHABLE, ReachabilityStatus.CONDITIONALLY_REACHABLE))
        block_count = sum(1 for p in paths if p.status == ReachabilityStatus.BLOCKED)
        
        tier0_exp = any(p.criticality_tier == "TIER_0" and p.status == ReachabilityStatus.CURRENTLY_REACHABLE for p in paths)
        tier1_exp = any(p.criticality_tier == "TIER_1" and p.status == ReachabilityStatus.CURRENTLY_REACHABLE for p in paths)

        t0_reach_count = sum(1 for p in paths if p.criticality_tier == "TIER_0" and p.status == ReachabilityStatus.CURRENTLY_REACHABLE)
        t1_reach_count = sum(1 for p in paths if p.criticality_tier == "TIER_1" and p.status == ReachabilityStatus.CURRENTLY_REACHABLE)
        t2_reach_count = sum(1 for p in paths if p.criticality_tier in ("TIER_2", "NORMAL") and p.status == ReachabilityStatus.CURRENTLY_REACHABLE)

        prov = ProvenanceEnvelope(
            engine="EnterpriseReachabilityEngine",
            version=self.VERSION,
            at=at_timestamp,
            upstream_evidence_ids=[f.entity_id for f in footholds],
        )

        return ReachabilityMatrix(
            matrix_id=f"reach-{sha256_digest(f'{tenant_id}:{case_id}:{at_timestamp}')[:10]}",
            tenant_id=tenant_id,
            case_id=case_id,
            evaluated_at=at_timestamp,
            foothold_entities=footholds,
            paths=paths,
            currently_reachable_count=curr_count,
            potentially_reachable_count=pot_count,
            blocked_count=block_count,
            tier_0_exposed=tier0_exp,
            tier_1_exposed=tier1_exp,
            reachable_tier_0_count=t0_reach_count,
            reachable_tier_1_count=t1_reach_count,
            reachable_tier_2_count=t2_reach_count,
            active_capabilities_applied=list(active_capabilities),
            provenance=prov,
        )
