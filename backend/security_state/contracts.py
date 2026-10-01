"""Core contracts, vocabulary, and epistemic primitives for NivXRay Security State."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class EpistemicStatus(str, Enum):
    """Explicit epistemic classification — never collapsed into a generic score."""
    OBSERVED = "OBSERVED"           # Directly recorded by verified sensor/telemetry
    SUPPORTED = "SUPPORTED"         # Formally corroborated by multiple independent evidence items
    DERIVED = "DERIVED"             # Deterministically derived via causal or logical deduction
    LIKELY = "LIKELY"               # High probability under formal Bayesian/heuristic evidence
    POSSIBLE = "POSSIBLE"           # Plausible attack hypothesis with incomplete evidence
    PROJECTED = "PROJECTED"         # Simulated future/counterfactual outcome (not verified fact)
    ASSUMED = "ASSUMED"             # Grounded assumption adopted when evidence is unobserved
    UNSUPPORTED = "UNSUPPORTED"     # Claim exists without backing evidence
    CONTRADICTED = "CONTRADICTED"   # Directly contradicted by verified telemetry
    DISPROVEN = "DISPROVEN"         # Mathematically or chronologically impossible


class EntityCategory(str, Enum):
    """The 20 enterprise security entity categories modeled by NivXRay."""
    USER = "USER"
    IDENTITY = "IDENTITY"
    DEVICE = "DEVICE"
    PROCESS = "PROCESS"
    FILE = "FILE"
    SERVICE = "SERVICE"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    ACCOUNT = "ACCOUNT"
    CREDENTIAL = "CREDENTIAL"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    SAAS_RESOURCE = "SAAS_RESOURCE"
    APPLICATION = "APPLICATION"
    WORKLOAD = "WORKLOAD"
    SERVER = "SERVER"
    ENDPOINT = "ENDPOINT"
    SECURITY_CONTROL = "SECURITY_CONTROL"
    DATA_STORE = "DATA_STORE"
    BACKUP_SYSTEM = "BACKUP_SYSTEM"
    VIRTUALIZATION_HOST = "VIRTUALIZATION_HOST"
    TRUST_RELATIONSHIP = "TRUST_RELATIONSHIP"


class CausalLevel(str, Enum):
    """Rigorous causal levels distinguishing correlation from causal evidence."""
    TEMPORAL_CORRELATION = "TEMPORAL_CORRELATION"       # B happened after A
    STATISTICAL_CORRELATION = "STATISTICAL_CORRELATION" # A and B frequently co-occur
    SUPPORTED_CAUSALITY = "SUPPORTED_CAUSALITY"         # Proven causal mechanism with evidence
    STRONG_CAUSAL_EVIDENCE = "STRONG_CAUSAL_EVIDENCE"   # Direct deterministic link (PID spawn, syscall handle)
    INFERRED_CAUSALITY = "INFERRED_CAUSALITY"           # Highly consistent with attack sequence
    POSSIBLE_CAUSALITY = "POSSIBLE_CAUSALITY"           # Potential causal link under investigation
    CONTRADICTED_CAUSALITY = "CONTRADICTED_CAUSALITY"   # Mechanism refuted by contrary evidence


class CapabilityStatus(str, Enum):
    """Classification of enterprise dual-use capabilities (RMM, WMI, PowerShell, etc.)."""
    LEGITIMATE_CAPABILITY = "LEGITIMATE_CAPABILITY"     # Known legitimate admin software
    AUTHORIZED_USE = "AUTHORIZED_USE"                   # Verified authorized operator & context
    ANOMALOUS_USE = "ANOMALOUS_USE"                     # Legitimate tool used outside normal baseline
    SUSPICIOUS_USE = "SUSPICIOUS_USE"                   # Anomalous use with suspicious arguments/source
    ABUSED_CAPABILITY = "ABUSED_CAPABILITY"             # Dual-use tool actively weaponized by attacker
    ATTACK_CAPABLE = "ATTACK_CAPABLE"                   # Attacker holds live execution handle
    CONFIRMED_ATTACK = "CONFIRMED_ATTACK"               # Active malicious execution verified


class AttackState(str, Enum):
    """The 18 explicit attack lifecycle states."""
    NO_ATTACK_EVIDENCE = "NO_ATTACK_EVIDENCE"
    RECONNAISSANCE = "RECONNAISSANCE"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    COLLECTION = "COLLECTION"
    EXFILTRATION = "EXFILTRATION"
    IMPACT = "IMPACT"
    CONTAINED = "CONTAINED"
    ERADICATED = "ERADICATED"
    RECOVERING = "RECOVERING"
    VERIFIED_SAFE = "VERIFIED_SAFE"


class AttackStage(str, Enum):
    """Macro lifecycle stages for attack progression."""
    PRE_ATTACK = "PRE_ATTACK"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    ACTIVE_ATTACK = "ACTIVE_ATTACK"
    CONTAINED = "CONTAINED"
    POST_INCIDENT = "POST_INCIDENT"


@dataclass
class SecurityStateVector:
    """Active security state vector capturing active attacker capabilities and reachability."""
    attack_stage: AttackStage = AttackStage.PRE_ATTACK
    active_capabilities: List[str] = field(default_factory=list)
    reachability_summary: Dict[str, Any] = field(default_factory=dict)
    compromised_entities: List[str] = field(default_factory=list)
    epistemic_confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_stage": self.attack_stage.value,
            "active_capabilities": list(self.active_capabilities),
            "reachability_summary": dict(self.reachability_summary),
            "compromised_entities": list(self.compromised_entities),
            "epistemic_confidence": self.epistemic_confidence,
        }


@dataclass
class ExecutionSafetyGate:
    """Execution safety policy and lock invariants for automated actions."""
    dry_run_only: bool = True
    approval_required: bool = True
    lock_state: bool = True


class ReachabilityStatus(str, Enum):
    """Multidimensional reachability status for enterprise assets."""
    CURRENTLY_REACHABLE = "CURRENTLY_REACHABLE"         # Active open path / live credentials
    POTENTIALLY_REACHABLE = "POTENTIALLY_REACHABLE"     # 1-hop privilege/network expansion away
    CONDITIONALLY_REACHABLE = "CONDITIONALLY_REACHABLE" # Reachable if specific condition met
    BLOCKED = "BLOCKED"                                 # Explicitly prevented by firewall/IAM
    UNKNOWN = "UNKNOWN"                                 # Insufficient telemetry to confirm path


class VerificationStatus(str, Enum):
    """Response action lifecycle states."""
    ACTION_REQUESTED = "ACTION_REQUESTED"
    ACTION_APPROVED = "ACTION_APPROVED"
    ACTION_EXECUTED = "ACTION_EXECUTED"
    ACTION_ACKNOWLEDGED = "ACTION_ACKNOWLEDGED"
    VERIFIED_EFFECTIVE = "VERIFIED_EFFECTIVE"
    VERIFIED_INEFFECTIVE = "VERIFIED_INEFFECTIVE"
    ATTACKER_PIVOT_DETECTED = "ATTACKER_PIVOT_DETECTED"


class TemporalAttackPhase(str, Enum):
    """Continuous temporal phases across attack lifecycle."""
    PRE_ATTACK = "PRE_ATTACK"                     # Early precursors, reconnaissance, staging
    ACTIVE_ATTACK = "ACTIVE_ATTACK"               # In-flight execution, evasion, lateral traversal
    CONTAINED = "CONTAINED"                       # Host/identity isolated or process terminated
    POST_ATTACK = "POST_ATTACK"                   # Assessing residual risk and persistence
    RESIDUAL_RISK = "RESIDUAL_RISK"               # Dormant persistence or exposed credentials remain
    RE_ENTRY_EXPOSURE = "RE_ENTRY_EXPOSURE"       # Environment open to reinfection/pivot


@dataclass(frozen=True)
class ProgressionRiskAssessment:
    """Deterministic attack progression assessment exposing all reasoning dimensions."""
    phase: TemporalAttackPhase
    epistemic_status: EpistemicStatus
    risk_score: float  # Deterministic Risk/Likelihood Score (0.0 to 100.0) — NEVER claimed as probability
    chain_name: str
    completed_stages: List[str]
    total_expected_stages: int
    progression_ratio: float
    supporting_evidence_ids: List[str]
    contradictory_evidence_ids: List[str]
    missing_telemetry_indicators: List[str]
    next_expected_behaviors: List[str]
    potential_impact_projection: str
    explicit_assumptions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase.value if isinstance(self.phase, Enum) else self.phase,
            "epistemic_status": self.epistemic_status.value if isinstance(self.epistemic_status, Enum) else self.epistemic_status,
            "risk_score": round(self.risk_score, 2),
            "chain_name": self.chain_name,
            "completed_stages": list(self.completed_stages),
            "total_expected_stages": self.total_expected_stages,
            "progression_ratio": round(self.progression_ratio, 3),
            "supporting_evidence_ids": sorted(self.supporting_evidence_ids),
            "contradictory_evidence_ids": sorted(self.contradictory_evidence_ids),
            "missing_telemetry_indicators": list(self.missing_telemetry_indicators),
            "next_expected_behaviors": list(self.next_expected_behaviors),
            "potential_impact_projection": self.potential_impact_projection,
            "explicit_assumptions": list(self.explicit_assumptions),
        }


@dataclass(frozen=True)
class PostAttackResidualRisk:
    """Disentangles whether an attack is active from whether the environment remains vulnerable."""
    attack_is_active: bool
    environment_is_vulnerable: bool
    active_persistence_indicators: List[str]
    exposed_unrevoked_credentials: List[str]
    open_lateral_traversal_paths: List[str]
    compromised_or_reachable_backups: List[str]
    reentry_risk_level: EpistemicStatus
    recommended_remediation_locks: List[str]
    evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_is_active": self.attack_is_active,
            "environment_is_vulnerable": self.environment_is_vulnerable,
            "active_persistence_indicators": list(self.active_persistence_indicators),
            "exposed_unrevoked_credentials": list(self.exposed_unrevoked_credentials),
            "open_lateral_traversal_paths": list(self.open_lateral_traversal_paths),
            "compromised_or_reachable_backups": list(self.compromised_or_reachable_backups),
            "reentry_risk_level": self.reentry_risk_level.value if isinstance(self.reentry_risk_level, Enum) else self.reentry_risk_level,
            "recommended_remediation_locks": list(self.recommended_remediation_locks),
            "evidence_ids": sorted(self.evidence_ids),
        }


class CausalMechanismType(str, Enum):
    """Verifiable kernel, operating system, and network level causal mechanisms."""
    PROCESS_SPAWN_SYSCALL = "PROCESS_SPAWN_SYSCALL"
    HTTP_GET_TO_FILE_WRITE = "HTTP_GET_TO_FILE_WRITE"
    LOLBAS_PROXY_EXECUTION = "LOLBAS_PROXY_EXECUTION"
    KERBEROS_TGS_REQUEST = "KERBEROS_TGS_REQUEST"
    DIRECTORY_REPLICATION_RPC = "DIRECTORY_REPLICATION_RPC"
    REMOTE_WMI_PROCESS_CALL = "REMOTE_WMI_PROCESS_CALL"
    SMB_NAMED_PIPE_EXECUTION = "SMB_NAMED_PIPE_EXECUTION"
    TOKEN_IMPERSONATION = "TOKEN_IMPERSONATION"
    COINCIDENT_TEMPORAL_SEQUENCE = "COINCIDENT_TEMPORAL_SEQUENCE"
    # Phase 7 Enterprise Mechanisms
    REMOTE_ADMINISTRATION_TUNNEL = "REMOTE_ADMINISTRATION_TUNNEL"
    VSS_NTDS_EXTRACTION = "VSS_NTDS_EXTRACTION"
    KERBEROS_ASREP_ROAST = "KERBEROS_ASREP_ROAST"
    KERBEROS_TICKET_FORGERY = "KERBEROS_TICKET_FORGERY"
    TOKEN_PASS_THE_HASH = "TOKEN_PASS_THE_HASH"
    CERTIFICATE_SERVICES_ENROLLMENT_RPC = "CERTIFICATE_SERVICES_ENROLLMENT_RPC"
    DIRECTORY_SHADOW_CREDENTIAL_WRITE = "DIRECTORY_SHADOW_CREDENTIAL_WRITE"
    METADATA_SERVICE_TOKEN_EXTRACTION = "METADATA_SERVICE_TOKEN_EXTRACTION"
    CLOUD_CLI_CREDENTIAL_HARVEST = "CLOUD_CLI_CREDENTIAL_HARVEST"
    OAUTH_APPLICATION_CONSENT_GRANT = "OAUTH_APPLICATION_CONSENT_GRANT"
    DIRECTORY_SYNC_ACCOUNT_ABUSE = "DIRECTORY_SYNC_ACCOUNT_ABUSE"
    VSS_SNAPSHOT_DELETION = "VSS_SNAPSHOT_DELETION"
    ESXI_VIRTUAL_MACHINE_KILL = "ESXI_VIRTUAL_MACHINE_KILL"
    BACKUP_CATALOG_DELETION = "BACKUP_CATALOG_DELETION"


# ── Standard Behavioral and Attacker Capabilities ────────────────────────────
class StandardCapabilities:
    """Standard capability identifiers used across causal and state engines."""
    ADMIN_EXECUTION = "CAP_ADMIN_EXECUTION"
    LOLBAS_EXECUTION = "CAP_LOLBAS_EXECUTION"
    ABUSED_RMM = "CAP_ABUSED_RMM"
    PAYLOAD_DOWNLOAD = "CAP_PAYLOAD_DOWNLOAD"
    PERSISTENCE = "CAP_PERSISTENCE"
    CREDENTIAL_ACCESS = "CAP_CREDENTIAL_ACCESS"
    CREDENTIAL_DUMPING = "CAP_CREDENTIAL_DUMPING"
    KERBEROASTING = "CAP_KERBEROASTING"
    DCSYNC = "CAP_DCSYNC"
    AD_REPLICATION_ABUSE = "CAP_AD_REPLICATION_ABUSE"
    LATERAL_MOVEMENT = "CAP_LATERAL_MOVEMENT"
    MULTI_HOST_TRAVERSAL = "CAP_MULTI_HOST_TRAVERSAL"
    CLOUD_PRIV_ESC = "CAP_CLOUD_PRIV_ESC"
    BACKUP_TAMPERING = "CAP_BACKUP_TAMPERING"
    HYPERVISOR_TAMPERING = "CAP_HYPERVISOR_TAMPERING"
    # Phase 7 Enterprise Capabilities
    RMM_REMOTE_CONTROL = "CAP_RMM_REMOTE_CONTROL"
    RMM_SESSION_STAGING = "CAP_RMM_SESSION_STAGING"
    NTDS_EXTRACTION = "CAP_NTDS_EXTRACTION"
    ASREP_ROASTING = "CAP_ASREP_ROASTING"
    GOLDEN_TICKET = "CAP_GOLDEN_TICKET"
    PASS_THE_HASH = "CAP_PASS_THE_HASH"
    ADCS_ABUSE = "CAP_ADCS_ABUSE"
    SHADOW_CREDENTIALS = "CAP_SHADOW_CREDENTIALS"
    CLOUD_METADATA_ACCESS = "CAP_CLOUD_METADATA_ACCESS"
    CLOUD_TOKEN_THEFT = "CAP_CLOUD_TOKEN_THEFT"
    OAUTH_CONSENT_ABUSE = "CAP_OAUTH_CONSENT_ABUSE"
    HYBRID_IDENTITY_PIVOT = "CAP_HYBRID_IDENTITY_PIVOT"
    SHADOW_COPY_DELETION = "CAP_SHADOW_COPY_DELETION"
    HYPERVISOR_COMPROMISE = "CAP_HYPERVISOR_COMPROMISE"
    SUPPLY_CHAIN_INJECTION = "CAP_SUPPLY_CHAIN_INJECTION"


# ── Phase 8: Asset Valuation, Interventions & Counterfactual Simulation Contracts ──
class AssetCriticalityTier(str, Enum):
    """Rigorous asset criticality tiers distinguishing crown jewels from commodity endpoints."""
    TIER_0 = "TIER_0"  # Identity roots (DC, Entra ID, Root PKI, KeyVault, Immutable Backup)
    TIER_1 = "TIER_1"  # Core business services (Production SQL, ERP, Hypervisor Clusters, Core APIs)
    TIER_2 = "TIER_2"  # Operational assets (Engineering workstations, standard servers, staging)
    NORMAL = "NORMAL"  # Non-critical end-user systems, isolated lab/guest devices
    UNCLASSIFIED = "UNCLASSIFIED"


class DataSensitivityTier(str, Enum):
    """Enterprise data classification levels for regulatory blast-radius modeling."""
    RESTRICTED = "RESTRICTED"      # PII, Payment Cards, Patient Health, Crypto Keys
    CONFIDENTIAL = "CONFIDENTIAL"  # Internal trade secrets, financials, source code
    INTERNAL = "INTERNAL"          # Internal corporate communications, intranet
    PUBLIC = "PUBLIC"              # Marketing, publicly accessible documents


class FinancialImpactCategory(str, Enum):
    """Categorized enterprise financial exposure risk."""
    CRITICAL = "CRITICAL"  # Material SEC 8-K disclosure, severe revenue stoppage, regulatory fine
    HIGH = "HIGH"          # Significant operational delay, partner penalty, forensics cost
    MEDIUM = "MEDIUM"      # Moderate restoration cost, contained localized impact
    LOW = "LOW"            # Negligible business loss, routine operational recovery


class InterventionType(str, Enum):
    """Deterministic intervention archetypes simulated in parallel counterfactual worlds."""
    DO_NOTHING = "DO_NOTHING"                                  # World A: Baseline unconstrained progression
    HOST_ISOLATION = "HOST_ISOLATION"                          # World B: Blunt network-level host isolation
    IDENTITY_REVOCATION = "IDENTITY_REVOCATION"                # World C: Surgical Kerberos/OAuth/session revocation
    NETWORK_MICROSEGMENTATION = "NETWORK_MICROSEGMENTATION"    # World D: Targeted port/route RPC-SMB block
    COMPOSITE_SURGICAL = "COMPOSITE_SURGICAL"                  # World E: Optimal graph-cut (Identity + Segment)


@dataclass(frozen=True)
class AssetValuation:
    """Explicit business and regulatory asset valuation decoupled from network topology."""
    entity_id: str
    tenant_id: str
    tier: AssetCriticalityTier
    business_criticality_score: int  # 0 to 100
    sensitivity: DataSensitivityTier
    financial_category: FinancialImpactCategory
    regulatory_scope: List[str] = field(default_factory=list)  # e.g., ["PCI-DSS", "HIPAA", "SOX", "GDPR"]
    business_function: str = ""
    valuation_source: str = "ASSET_INVENTORY"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "tenant_id": self.tenant_id,
            "tier": self.tier.value if isinstance(self.tier, Enum) else self.tier,
            "business_criticality_score": self.business_criticality_score,
            "sensitivity": self.sensitivity.value if isinstance(self.sensitivity, Enum) else self.sensitivity,
            "financial_category": self.financial_category.value if isinstance(self.financial_category, Enum) else self.financial_category,
            "regulatory_scope": list(self.regulatory_scope),
            "business_function": self.business_function,
            "valuation_source": self.valuation_source,
        }


@dataclass(frozen=True)
class CounterfactualSimulationProvenance:
    """P8-13 Counterfactual Integrity: Full lineage from observed evidence to projected impact."""
    observed_inputs: List[str]
    current_security_state: str
    assumptions: List[str]
    intervention: str
    simulated_state_transition: str
    projected_reachability_summary: str
    projected_security_impact_score: int  # 0 to 100
    projected_business_impact_score: int  # 0 to 100
    model_version: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observed_inputs": sorted(list(self.observed_inputs)),
            "current_security_state": self.current_security_state,
            "assumptions": list(self.assumptions),
            "intervention": self.intervention,
            "simulated_state_transition": self.simulated_state_transition,
            "projected_reachability_summary": self.projected_reachability_summary,
            "projected_security_impact_score": self.projected_security_impact_score,
            "projected_business_impact_score": self.projected_business_impact_score,
            "model_version": self.model_version,
        }


@dataclass(frozen=True)
class InterventionImpactRating:
    """Mathematically derived impact rating for a single simulated intervention world."""
    world_id: str
    intervention_type: InterventionType
    attack_interruption_pct: float  # Percentage of active attack paths severed (0.0 to 100.0)
    tier0_protected_count: int
    tier1_protected_count: int
    total_protected_count: int
    business_disruption_score: int  # Derived from disruption weight of affected entities (0 to 100)
    residual_risk_score: int        # Derived from surviving capabilities and reachable crown jewels (0 to 100)
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "world_id": self.world_id,
            "intervention_type": self.intervention_type.value if isinstance(self.intervention_type, Enum) else self.intervention_type,
            "attack_interruption_pct": round(self.attack_interruption_pct, 2),
            "tier0_protected_count": self.tier0_protected_count,
            "tier1_protected_count": self.tier1_protected_count,
            "total_protected_count": self.total_protected_count,
            "business_disruption_score": self.business_disruption_score,
            "residual_risk_score": self.residual_risk_score,
            "rationale": self.rationale,
        }


@dataclass
class ComparativeInterventionMatrix:
    """Deterministic comparative matrix evaluating candidate interventions against baseline."""
    matrix_id: str
    tenant_id: str
    case_id: str
    evaluated_at: str
    ratings: List[InterventionImpactRating]
    recommended_world_id: str
    decision_rationale: str
    simulation_provenances: List[CounterfactualSimulationProvenance] = field(default_factory=list)
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
            "ratings": [r.to_dict() for r in self.ratings],
            "recommended_world_id": self.recommended_world_id,
            "decision_rationale": self.decision_rationale,
            "simulation_provenances": [p.to_dict() for p in self.simulation_provenances],
        }
        return sha256_digest(canonical_json(payload))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "matrix_id": self.matrix_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "evaluated_at": self.evaluated_at,
            "ratings": [r.to_dict() for r in self.ratings],
            "recommended_world_id": self.recommended_world_id,
            "decision_rationale": self.decision_rationale,
            "simulation_provenances": [p.to_dict() for p in self.simulation_provenances],
            "matrix_hash": self.matrix_hash,
        }



@dataclass(frozen=True)
class EntityRef:
    """Canonical identifier for an enterprise entity."""
    category: EntityCategory
    entity_id: str
    tenant_id: str
    display_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "entity_id": self.entity_id,
            "tenant_id": self.tenant_id,
            "display_name": self.display_name,
        }


@dataclass(frozen=True)
class ProvenanceEnvelope:
    """Mandatory provenance envelope for all security state objects."""
    engine: str
    version: str
    at: str
    upstream_evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engine": self.engine,
            "version": self.version,
            "at": self.at,
            "upstream_evidence_ids": list(self.upstream_evidence_ids),
        }


# ── Canonical JSON and SHA-256 Fingerprinting ──────────────────────────────
def _canonical_default(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, set):
        return sorted(list(obj))
    if isinstance(obj, bytes):
        return {"__bytes_hex__": obj.hex(), "__len__": len(obj)}
    raise TypeError(f"Non-serializable object of type {type(obj).__name__}")


def canonical_json(obj: Any) -> str:
    """Deterministic, sorted-key JSON serialization for reproducible hashes."""
    return json.dumps(obj, default=_canonical_default, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_digest(content: str | bytes) -> str:
    """Compute standard SHA-256 hexadecimal digest."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()
