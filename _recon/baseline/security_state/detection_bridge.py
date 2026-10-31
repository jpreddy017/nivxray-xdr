"""
NivXRay XDR — Security-State-Aware Detection & Correlation Bridge.
Provides deterministic contextual discrimination for dual-use tools and capabilities
by combining detection matches with active Security State, Attacker Capabilities,
Reachability, and Crown Jewel Criticality.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .contracts import (
    AttackStage,
    SecurityStateVector,
    sha256_digest,
    canonical_json,
)


class CapabilityAbuseState(str, Enum):
    AUTHORIZED_ACTIVITY  = "AUTHORIZED_ACTIVITY"
    BENIGN_DUAL_USE      = "BENIGN_DUAL_USE"
    SUSPICIOUS_ANOMALY   = "SUSPICIOUS_ANOMALY"
    ABUSED_CAPABILITY    = "ABUSED_CAPABILITY"
    ATTACK_CAPABLE       = "ATTACK_CAPABLE"
    CONFIRMED_ATTACK     = "CONFIRMED_ATTACK"


@dataclass
class ContextualAssessment:
    """Deterministic, explainable security state enrichment for a detection."""
    detection_id: str
    rule_name: str
    abuse_state: CapabilityAbuseState
    escalated_severity: str
    escalated_confidence: str
    contextual_factors: List[str]
    supporting_evidence_ids: List[str]
    reachability_to_crown_jewels: bool
    target_crown_jewels: List[str]
    is_privileged_identity: bool
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["abuse_state"] = self.abuse_state.value
        return d


class SecurityStateDetectionBridge:
    """
    Bridge that contextualizes detection matches using the current Security State.
    Ensures dual-use tools (e.g., AnyDesk, PowerShell, WMI) are never treated as
    automatic attacks, but are elevated to CONFIRMED_ATTACK when combined with
    compromised capabilities, privileged credentials, and reachability.
    """

    DUAL_USE_RULES = frozenset({
        "DET-CC-001",  # RMM Tools (AnyDesk, TeamViewer, ScreenConnect)
        "DET-EX-001",  # PowerShell
        "DET-EX-004",  # WMI Process Execution
        "DET-LM-001",  # PsExec / Service Execution
        "DET-LM-002",  # WinRM
        "DET-CL-001",  # Cloud Administration / IAM Role Modification
    })

    @classmethod
    def is_dual_use_detection(cls, detection: Dict[str, Any]) -> bool:
        rule_id = detection.get("rule_id", "")
        if rule_id in cls.DUAL_USE_RULES or detection.get("is_dual_use", False):
            return True
        name = str(detection.get("name", "")).lower()
        dual_keywords = ("powershell", "rmm", "wmi", "psexec", "cloud admin", "winrm", "remote management")
        return any(k in name for k in dual_keywords)

    def assess_detection(
        self,
        *,
        detection: Dict[str, Any],
        state_vector: Optional[SecurityStateVector] = None,
        host_id: str = "",
        user_id: str = "",
        reachability_paths: Optional[List[Dict[str, Any]]] = None,
        crown_jewel_hosts: Optional[List[str]] = None,
    ) -> ContextualAssessment:
        rule_id = detection.get("rule_id", "")
        rule_name = detection.get("name", rule_id)
        base_sev = detection.get("severity", "medium")
        base_conf = detection.get("confidence", "medium")

        factors: List[str] = []
        crown_jewels = crown_jewel_hosts or ["DC-01", "BACKUP-01", "PAYMENT-DB"]
        active_caps = set(state_vector.active_capabilities if state_vector else [])
        attack_stage = state_vector.attack_stage if state_vector else AttackStage.PRE_ATTACK

        # Check privileged identity
        is_priv_user = bool(
            user_id.lower().startswith("admin")
            or user_id.lower().endswith("da")
            or "domain admin" in user_id.lower()
            or "root" in user_id.lower()
        )
        if is_priv_user:
            factors.append("Executed by high-privilege account identity")

        # Check reachability to crown jewels
        has_cj_reachability = False
        target_cjs: List[str] = []
        if reachability_paths:
            for p in reachability_paths:
                dest = str(p.get("destination_node") or p.get("target") or p.get("destination") or "")
                if dest in crown_jewels:
                    has_cj_reachability = True
                    target_cjs.append(dest)
        if has_cj_reachability:
            factors.append(f"Source host has active lateral reachability to crown jewels: {target_cjs}")

        # Check active compromised capabilities
        if "CREDENTIAL_THEFT" in active_caps or "STOLEN_TGT" in active_caps:
            factors.append("Active compromised Kerberos / token capability present in environment")

        if attack_stage in (AttackStage.ACTIVE_ATTACK, AttackStage.CONTAINED):
            factors.append(f"Security State attack stage is {attack_stage.value}")

        # ── Contextual Discrimination ─────────────────────────────────────────
        if self.is_dual_use_detection(detection):
            # Dual-use tool evaluation
            if not is_priv_user and not has_cj_reachability and len(factors) == 0:
                abuse_state = CapabilityAbuseState.BENIGN_DUAL_USE
                escalated_sev = "low"
                escalated_conf = "low"
                explanation = f"Dual-use capability {rule_name} observed with no compromised credentials or crown jewel reachability."
            elif has_cj_reachability and ("CREDENTIAL_THEFT" in active_caps or is_priv_user):
                abuse_state = CapabilityAbuseState.CONFIRMED_ATTACK
                escalated_sev = "critical"
                escalated_conf = "confirmed"
                explanation = (
                    f"Dual-use capability {rule_name} elevated to CONFIRMED_ATTACK: "
                    f"combined with privileged identity ({user_id}) and active lateral path to {target_cjs}."
                )
            else:
                abuse_state = CapabilityAbuseState.ABUSED_CAPABILITY
                escalated_sev = "high"
                escalated_conf = "high"
                explanation = f"Dual-use capability {rule_name} elevated to ABUSED_CAPABILITY based on context."
        else:
            # Explicitly malicious rules (e.g., LSASS Dump, VSS Deletion)
            if has_cj_reachability or is_priv_user:
                abuse_state = CapabilityAbuseState.CONFIRMED_ATTACK
                escalated_sev = "critical"
                escalated_conf = "confirmed"
                explanation = f"Malicious detection {rule_name} verified targeting enterprise infrastructure."
            else:
                abuse_state = CapabilityAbuseState.ATTACK_CAPABLE
                escalated_sev = base_sev
                escalated_conf = base_conf
                explanation = f"Direct malicious indicator {rule_name} observed."

        return ContextualAssessment(
            detection_id=detection.get("detection_id", rule_id),
            rule_name=rule_name,
            abuse_state=abuse_state,
            escalated_severity=escalated_sev,
            escalated_confidence=escalated_conf,
            contextual_factors=factors,
            supporting_evidence_ids=detection.get("mitre_attack", []),
            reachability_to_crown_jewels=has_cj_reachability,
            target_crown_jewels=target_cjs,
            is_privileged_identity=is_priv_user,
            explanation=explanation,
        )


# Authoritative singleton
DETECTION_BRIDGE = SecurityStateDetectionBridge()
