"""
NivXRay XDR — Engine Fabric Integration Contracts.
Establishes the authoritative programmatic contracts through which the
Enterprise Security Content Knowledge Fabric supplies detection logic,
adversarial models, forensic indicators, and playbooks to the complete
NivXRay intelligence and investigation engine fabric:

1.  IUE (Intelligent Understanding Engine / Input Understanding Engine)
2.  VEEE (Visual Evidence Extraction Engine)
3.  IEDDE (Intermediate Encoded/Decoded Data Extraction)
4.  UAIE (Universal Artifact Intelligence Engine)
5.  ICE (Industrial Correlation Engine)
6.  Detection Engine (SigmaEngine / YARARuntime / Native Runtimes)
7.  Correlation Engine (Multi-Stage Temporal Sequences)
8.  Threat Intelligence (IOC Lookup & Infrastructure Clustering)
9.  Threat Hunting (RuleStudioHunt Proactive Sweeps)
10. IKG (Investigation Knowledge Graph)
11. Evidence Graph (Causal Event Projections)
12. Verdict Engine (Evidence-Driven Confidence Scoring)
13. Attack Story (Narrative Incident Synthesizer)
14. Device Trajectory (Host Process Timeline Replay)
15. Negative Explainability (Why-Not-Malicious Justification)
16. Security State Machine (6-State Operational FSM)
17. Capability Engine (Adversary Capability Assessment)
18. Attack State Machine (Causal Lateral Progression)
19. Reachability Engine (Lateral Crown Jewel Access Proximity)
20. Counterfactual Engine (What-If Prevention Analysis)
21. Impact Engine (Blast Radius & Business Disruption Scoring)
22. Intervention Optimizer (Minimal Effective Containment)
23. Response Safety Gate (Exclusion Lists & Critical Infrastructure Guard)
24. Response Execution (ActionRegistry Automated Containment)
25. Verification Engine (Post-Remediation Proof of Resolution)
26. Security State Ledger (Tamper-Evident Audit Trail)
27. Adversarial Simulator (Attack Scenario Progression Replay)
28. Enterprise Content Fabric (Canonical Content Registry & Life Cycle)
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
import uuid

from .canonical_content_model import CanonicalContentObject, ContentType


class EngineStatus(str, Enum):
    IMPLEMENTED        = "IMPLEMENTED"          # Fully implemented and active in backend
    PARTIAL            = "PARTIAL"              # Partially implemented; requires scale/integration
    SCAFFOLD           = "SCAFFOLD"             # Skeleton/protocol defined; requires implementation
    MISSING            = "MISSING"              # Not yet implemented in repository
    DUPLICATE          = "DUPLICATE"            # Redundant implementation to be consolidated
    NEEDS_INTEGRATION  = "NEEDS_INTEGRATION"    # Implemented but requires bridge/wiring contract


@dataclass
class EngineMetadata:
    engine_id: str
    name: str
    classification: EngineStatus
    module_path: str
    role_in_fabric: str
    content_dependencies: List[ContentType]
    input_contract: str
    output_contract: str


# ════════════════════════════════════════════════════════════════════════════
# 1. THE 28 CANONICAL NIVXRAY ENGINES REGISTRY & RECONCILIATION
# ════════════════════════════════════════════════════════════════════════════
CANONICAL_ENGINE_REGISTRY: Dict[str, EngineMetadata] = {
    "IUE": EngineMetadata(
        engine_id="IUE",
        name="Intelligent Understanding Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/services/iue/service.py",
        role_in_fabric="Decodes, normalizes, and extracts semantic intent from raw input events and command lines.",
        content_dependencies=[ContentType.SIGMA, ContentType.BEHAVIORAL],
        input_contract="RawEventStream / TelemetryRecord",
        output_contract="IUEUnderstanding / IUEEvidence",
    ),
    "VEEE": EngineMetadata(
        engine_id="VEEE",
        name="Visual Evidence Extraction Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/services/veee/__init__.py",
        role_in_fabric="Performs OCR, layout analysis, and image classification on screenshots and document attachments.",
        content_dependencies=[ContentType.YARA, ContentType.IOC_RULE],
        input_contract="BinaryImageBytes / DocumentRaster",
        output_contract="VEEEEvidenceRecord",
    ),
    "IEDDE": EngineMetadata(
        engine_id="IEDDE",
        name="Intermediate Encoded/Decoded Data Extraction",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/workspace/convergence/decoder.py",
        role_in_fabric="Extracts multi-layered intermediate payloads and records forensic hash chains.",
        content_dependencies=[ContentType.SIGMA, ContentType.YARA],
        input_contract="EncodedPayloadBuffer",
        output_contract="IEDDETerminalState / BinaryArtifactRecovered",
    ),
    "UAIE": EngineMetadata(
        engine_id="UAIE",
        name="Universal Artifact Intelligence Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/services/uaie/orchestrator.py",
        role_in_fabric="Disassembles shellcode, parses PE/ELF headers, and evaluates static binary capabilities.",
        content_dependencies=[ContentType.YARA],
        input_contract="RawBinaryBytes / ArtifactBuffer",
        output_contract="UAIECapabilityCoverage / EvidenceSet",
    ),
    "ICE": EngineMetadata(
        engine_id="ICE",
        name="Industrial Correlation Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/detection_content/xdr_ice.py",
        role_in_fabric="Correlates derived IUE/IEDDE indicators across temporal windows using 13 operators.",
        content_dependencies=[ContentType.CORRELATION],
        input_contract="CanonicalEvidenceStream",
        output_contract="ICECompositeIncidentCandidate",
    ),
    "DetectionEngine": EngineMetadata(
        engine_id="DetectionEngine",
        name="Native Detection Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/engine/detection_engine.py",
        role_in_fabric="Executes compiled Sigma, EQL, SPL, and KQL rules against normalized telemetry streams.",
        content_dependencies=[ContentType.SIGMA, ContentType.EQL, ContentType.SPL, ContentType.KQL],
        input_contract="NormalizedEventDictionary",
        output_contract="DetectionHit / AlertRecord",
    ),
    "CorrelationEngine": EngineMetadata(
        engine_id="CorrelationEngine",
        name="Multi-Event Stateful Correlation Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/services/correlation/engine.py",
        role_in_fabric="Tracks multi-event causal progressions and stateful automaton sequences.",
        content_dependencies=[ContentType.CORRELATION],
        input_contract="OrderedDetectionStream",
        output_contract="CorrelatedIncidentStory",
    ),
    "ThreatIntelligence": EngineMetadata(
        engine_id="ThreatIntelligence",
        name="IOC & CTI Intelligence Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/services/intelligence/",
        role_in_fabric="Performs high-speed defanged lookup and threat actor infrastructure attribution.",
        content_dependencies=[ContentType.IOC_RULE, ContentType.ATTCK_MAPPING],
        input_contract="AtomicIndicatorQuery",
        output_contract="ThreatIntelEnrichmentRecord",
    ),
    "ThreatHunting": EngineMetadata(
        engine_id="ThreatHunting",
        name="RuleStudio Threat Hunting Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/routers/hunting.py",
        role_in_fabric="Executes proactive hypothesis sweeps across cold historical telemetry data stores.",
        content_dependencies=[ContentType.THREAT_HUNTING],
        input_contract="HuntingHypothesisSpec",
        output_contract="HuntFindingList / InvestigationPivot",
    ),
    "IKG": EngineMetadata(
        engine_id="IKG",
        name="Investigation Knowledge Graph",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/services/ikg/graph.py",
        role_in_fabric="Constructs causal graph edges between hosts, users, processes, files, and external IPs.",
        content_dependencies=[ContentType.BEHAVIORAL, ContentType.CORRELATION],
        input_contract="CanonicalEvidenceList",
        output_contract="IKGSubGraph / IncidentAttackStory",
    ),
    "EvidenceGraph": EngineMetadata(
        engine_id="EvidenceGraph",
        name="Evidence Traversal & Provenance Graph",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/services/investigation/graph_traversal.py",
        role_in_fabric="Traverses causal provenance backwards to identify patient zero and root cause.",
        content_dependencies=[ContentType.BEHAVIORAL],
        input_contract="SeedEvidenceNode",
        output_contract="RootCauseTrajectory",
    ),
    "VerdictEngine": EngineMetadata(
        engine_id="VerdictEngine",
        name="Evidence-Driven Verdict Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/engine/verdict_engine.py",
        role_in_fabric="Weighs cumulative positive/negative evidence to emit deterministic threat verdicts.",
        content_dependencies=[ContentType.BEHAVIORAL, ContentType.BASELINE_ANOMALY],
        input_contract="IKGAttackSubGraph",
        output_contract="VerdictCard (BENIGN / SUSPICIOUS / MALICIOUS)",
    ),
    "AttackStory": EngineMetadata(
        engine_id="AttackStory",
        name="Attack Story Narrative Synthesizer",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/services/reporting/attack_story.py",
        role_in_fabric="Synthesizes structured graph progressions into analyst-readable chronologies.",
        content_dependencies=[ContentType.ATTCK_MAPPING],
        input_contract="IKGCausalTimeline",
        output_contract="AttackStoryNarrative",
    ),
    "DeviceTrajectory": EngineMetadata(
        engine_id="DeviceTrajectory",
        name="Device Trajectory Replay Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/services/device_trajectory.py",
        role_in_fabric="Reconstructs chronological process ancestry and file modifications on an endpoint.",
        content_dependencies=[ContentType.BEHAVIORAL],
        input_contract="EndpointHostIdentifier",
        output_contract="ProcessLineageTimeline",
    ),
    "NegativeExplainability": EngineMetadata(
        engine_id="NegativeExplainability",
        name="Negative Explainability Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/services/explainability/negative.py",
        role_in_fabric="Explains why suspicious behavior was determined NOT to be an attack (false positive justification).",
        content_dependencies=[ContentType.BASELINE_ANOMALY],
        input_contract="DisputedAlertRecord",
        output_contract="NegativeJustificationReport",
    ),
    "SecurityState": EngineMetadata(
        engine_id="SecurityState",
        name="Security State Machine & Ledger",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/security_state/ledger.py",
        role_in_fabric="Tracks operational entity state across Authorized, Abused, and Confirmed Attack states.",
        content_dependencies=[ContentType.SECURITY_STATE_MAPPING],
        input_contract="StateTransitionEvent",
        output_contract="SecurityStateLedgerEntry",
    ),
    "CapabilityEngine": EngineMetadata(
        engine_id="CapabilityEngine",
        name="Adversary Capability Assessment Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/security_state/capability.py",
        role_in_fabric="Evaluates attacker proven capabilities (e.g. Credential Dumping, Code Execution, Wiper).",
        content_dependencies=[ContentType.YARA, ContentType.BEHAVIORAL],
        input_contract="VerifiedEvidenceSet",
        output_contract="ProvenCapabilityProfile",
    ),
    "AttackStateMachine": EngineMetadata(
        engine_id="AttackStateMachine",
        name="Attack State Automaton",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/security_state/attack_state.py",
        role_in_fabric="Enforces causal invariants preventing illegal transitions across intrusion phases.",
        content_dependencies=[ContentType.SECURITY_STATE_MAPPING],
        input_contract="CandidateStateTransition",
        output_contract="ValidatedStateTransitionVerdict",
    ),
    "Reachability": EngineMetadata(
        engine_id="Reachability",
        name="Lateral Reachability Proximity Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/security_state/reachability.py",
        role_in_fabric="Calculates network and credential hops between compromised host and Crown Jewels.",
        content_dependencies=[ContentType.CORRELATION],
        input_contract="HostTopologyGraph",
        output_contract="CrownJewelProximityScore",
    ),
    "Counterfactual": EngineMetadata(
        engine_id="Counterfactual",
        name="Counterfactual Causal Reasoning Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/security_state/counterfactual.py",
        role_in_fabric="Simulates 'What-If' scenarios: would intrusion have succeeded if control X were active?",
        content_dependencies=[ContentType.RESPONSE_MAPPING],
        input_contract="IntrusionScenarioGraph",
        output_contract="CounterfactualInterventionReport",
    ),
    "Impact": EngineMetadata(
        engine_id="Impact",
        name="Blast Radius & Business Impact Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/security_state/impact.py",
        role_in_fabric="Quantifies business disruption, data loss risk, and financial exposure.",
        content_dependencies=[ContentType.SECURITY_STATE_MAPPING],
        input_contract="CompromisedEntitySet",
        output_contract="ImpactSeverityAssessment",
    ),
    "Intervention": EngineMetadata(
        engine_id="Intervention",
        name="Intervention Optimization Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/security_state/intervention.py",
        role_in_fabric="Recommends the Minimal Effective Containment action with minimum operational friction.",
        content_dependencies=[ContentType.RESPONSE_MAPPING],
        input_contract="ImpactAssessment + ReachabilityScore",
        output_contract="OptimalResponsePlan",
    ),
    "ResponseSafety": EngineMetadata(
        engine_id="ResponseSafety",
        name="Response Safety & Exclusion Gate",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/services/response/safety_gate.py",
        role_in_fabric="Guarantees critical infrastructure (Domain Controllers, ICU systems) are never isolated automatically.",
        content_dependencies=[ContentType.RESPONSE_MAPPING],
        input_contract="ProposedResponseAction",
        output_contract="SafetyApprovalToken",
    ),
    "ResponseExecution": EngineMetadata(
        engine_id="ResponseExecution",
        name="Closed-Loop Response Executor",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/services/response/action_registry.py",
        role_in_fabric="Executes network isolation, process kills, credential invalidation, and file quarantine.",
        content_dependencies=[ContentType.RESPONSE_MAPPING],
        input_contract="AuthorizedActionToken",
        output_contract="ExecutionReceipt",
    ),
    "Verification": EngineMetadata(
        engine_id="Verification",
        name="Remediation Verification Engine",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/services/response/verifier.py",
        role_in_fabric="Probes endpoint post-containment to verify adversary access has been completely severed.",
        content_dependencies=[ContentType.RESPONSE_MAPPING],
        input_contract="ExecutionReceipt",
        output_contract="RemediationVerificationProof",
    ),
    "StateLedger": EngineMetadata(
        engine_id="StateLedger",
        name="Tamper-Evident Security State Ledger",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/security_state/ledger.py",
        role_in_fabric="Maintains append-only cryptographically linked audit ledger of all security transitions.",
        content_dependencies=[ContentType.SECURITY_STATE_MAPPING],
        input_contract="StateTransitionRecord",
        output_contract="SignedLedgerBlock",
    ),
    "AdversarialSimulator": EngineMetadata(
        engine_id="AdversarialSimulator",
        name="Adversarial Attack Scenario Simulator",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/services/simulation/adversarial_runner.py",
        role_in_fabric="Replays legitimate multi-stage attack scenarios to validate end-to-end XDR defenses.",
        content_dependencies=[ContentType.CORRELATION, ContentType.BEHAVIORAL],
        input_contract="AttackSimulationScenario",
        output_contract="DefenseReadinessScorecard",
    ),
    "EnterpriseContentFabric": EngineMetadata(
        engine_id="EnterpriseContentFabric",
        name="Enterprise Security Content Knowledge Fabric",
        classification=EngineStatus.IMPLEMENTED,
        module_path="backend/detection_content/",
        role_in_fabric="Acquires, translates, deduplicates, validates, and provisions detection knowledge to all engines.",
        content_dependencies=list(ContentType),
        input_contract="MultiSourceSecurityContent",
        output_contract="ValidatedCanonicalContentObject",
    ),
}


# ════════════════════════════════════════════════════════════════════════════
# 2. STRONGLY-TYPED CONTENT FEED INTEGRATION CONTRACTS
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class IUEContentFeedContract:
    """Contract: Content Fabric -> IUE (Intelligent Understanding Engine)."""
    feed_id: str
    target_engine: str = "IUE"
    active_detection_tokens: List[str] = field(default_factory=list)
    lolbas_binary_catalog: Set[str] = field(default_factory=set)
    suspicious_cli_switches: List[str] = field(default_factory=list)

    def provision_knowledge(self, content_objects: List[CanonicalContentObject]):
        for obj in content_objects:
            if obj.content_type == ContentType.SIGMA.value:
                for rf in obj.required_fields:
                    self.active_detection_tokens.append(rf)


@dataclass
class VEEEEvidenceFeedContract:
    """Contract: Content Fabric -> VEEE (Visual Evidence Extraction Engine)."""
    feed_id: str
    target_engine: str = "VEEE"
    phishing_lure_keywords: List[str] = field(default_factory=list)
    qr_code_c2_regex: List[str] = field(default_factory=list)

    def provision_knowledge(self, content_objects: List[CanonicalContentObject]):
        for obj in content_objects:
            if obj.content_type == ContentType.IOC_RULE.value:
                self.phishing_lure_keywords.append(obj.name)


@dataclass
class ICECorrelationFeedContract:
    """Contract: Content Fabric -> ICE (Industrial Correlation Engine)."""
    feed_id: str
    target_engine: str = "ICE"
    active_scenarios: List[Dict[str, Any]] = field(default_factory=list)

    def provision_scenarios(self, content_objects: List[CanonicalContentObject]):
        for obj in content_objects:
            if obj.content_type == ContentType.CORRELATION.value:
                self.active_scenarios.append({
                    "scenario_id": obj.content_id,
                    "name": obj.name,
                    "logic": obj.logic,
                })


@dataclass
class SecurityStateBridgeContract:
    """Contract: Content Fabric -> Security State Machine & Ledger."""
    feed_id: str
    target_engine: str = "SecurityState"
    state_transition_rules: List[Dict[str, Any]] = field(default_factory=list)

    def provision_state_rules(self, content_objects: List[CanonicalContentObject]):
        for obj in content_objects:
            if obj.content_type == ContentType.SECURITY_STATE_MAPPING.value:
                self.state_transition_rules.append({
                    "rule_id": obj.content_id,
                    "name": obj.name,
                    "logic": obj.logic,
                })


# Global Engine Fabric Contract Router
class EngineFabricRouter:
    """Coordinates and routes content from the Enterprise Knowledge Fabric into all 28 engines."""

    def __init__(self):
        self.iue_contract = IUEContentFeedContract(feed_id="FEED-IUE-001")
        self.veee_contract = VEEEEvidenceFeedContract(feed_id="FEED-VEEE-001")
        self.ice_contract = ICECorrelationFeedContract(feed_id="FEED-ICE-001")
        self.sec_state_contract = SecurityStateBridgeContract(feed_id="FEED-SEC-001")

    def distribute_knowledge(self, active_objects: List[CanonicalContentObject]) -> Dict[str, int]:
        self.iue_contract.provision_knowledge(active_objects)
        self.veee_contract.provision_knowledge(active_objects)
        self.ice_contract.provision_scenarios(active_objects)
        self.sec_state_contract.provision_state_rules(active_objects)

        return {
            "total_engines_registered": len(CANONICAL_ENGINE_REGISTRY),
            "implemented_engines": sum(1 for m in CANONICAL_ENGINE_REGISTRY.values() if m.classification == EngineStatus.IMPLEMENTED),
            "active_objects_distributed": len(active_objects),
        }


FABRIC_ROUTER = EngineFabricRouter()
