"""
NivXRay XDR — Phase 2.1 Security State Boundary & Dual-Use Discrimination Suite.
Enforces the fundamental architectural invariant:
  Detection != Confirmed Attack
Tests benign vs malicious context for dual-use enterprise tools:
  - PowerShell
  - RMM (AnyDesk, TeamViewer, ScreenConnect)
  - WMI
  - PsExec
  - Cloud Administration (AWS IAM / STS)
Proves Security State contextualizes detections based on reachability, credentials,
and active attacker capabilities rather than detector existence alone.
"""
import pytest
from security_state.contracts import (
    AttackStage,
    SecurityStateVector,
)
from security_state.detection_bridge import (
    CapabilityAbuseState,
    DETECTION_BRIDGE,
    SecurityStateDetectionBridge,
)


def _build_state(active_caps=None, stage=AttackStage.PRE_ATTACK) -> SecurityStateVector:
    return SecurityStateVector(
        attack_stage=stage,
        active_capabilities=active_caps or [],
        reachability_summary={"crown_jewels": ["DC-01", "BACKUP-01"]},
    )


# ── 1. PowerShell Dual-Use Discrimination ───────────────────────────────────

def test_powershell_benign_developer_vs_confirmed_attack():
    """Verify PowerShell detection is BENIGN_DUAL_USE for standard user,
    but elevated to CONFIRMED_ATTACK when combined with lateral reachability and compromised creds."""
    ps_det = {
        "rule_id": "DET-EX-001",
        "name": "PowerShell Script Execution",
        "severity": "medium",
        "confidence": "medium",
        "mitre_attack": ["T1059.001"],
    }

    # Case A: Benign workstation, regular user, no compromised capabilities, no lateral paths
    clean_state = _build_state(active_caps=[])
    assessment_benign = DETECTION_BRIDGE.assess_detection(
        detection=ps_det,
        state_vector=clean_state,
        host_id="DEV-LAPTOP-12",
        user_id="developer_bob",
        reachability_paths=[],
    )
    assert assessment_benign.abuse_state == CapabilityAbuseState.BENIGN_DUAL_USE
    assert assessment_benign.escalated_severity == "low"
    assert "no compromised credentials or crown jewel reachability" in assessment_benign.explanation

    # Case B: Admin user with compromised credentials and active lateral path to Domain Controller
    attack_state = _build_state(active_caps=["CREDENTIAL_THEFT"], stage=AttackStage.ACTIVE_ATTACK)
    reachability = [{"source_node": "DEV-LAPTOP-12", "destination_node": "DC-01", "protocol": "WMI"}]
    assessment_malicious = DETECTION_BRIDGE.assess_detection(
        detection=ps_det,
        state_vector=attack_state,
        host_id="DEV-LAPTOP-12",
        user_id="admin_da",
        reachability_paths=reachability,
    )
    assert assessment_malicious.abuse_state == CapabilityAbuseState.CONFIRMED_ATTACK
    assert assessment_malicious.escalated_severity == "critical"
    assert assessment_malicious.reachability_to_crown_jewels is True


# ── 2. RMM Dual-Use Discrimination ──────────────────────────────────────────

def test_rmm_helpdesk_vs_threat_actor_persistence():
    """Verify RMM tool (AnyDesk/TeamViewer) is contextualized by operator credentials and reachability."""
    rmm_det = {
        "rule_id": "DET-CC-001",
        "name": "Remote Monitoring and Management Tool (AnyDesk)",
        "severity": "high",
        "confidence": "high",
        "mitre_attack": ["T1219"],
    }

    # Helpdesk session on sales laptop
    assessment_helpdesk = DETECTION_BRIDGE.assess_detection(
        detection=rmm_det,
        state_vector=_build_state(),
        host_id="SALES-05",
        user_id="sales_user",
        reachability_paths=[],
    )
    assert assessment_helpdesk.abuse_state == CapabilityAbuseState.BENIGN_DUAL_USE

    # RMM on jumpbox targeting Payment DB by privileged admin
    reach_db = [{"source_node": "JUMPBOX-01", "destination_node": "PAYMENT-DB", "protocol": "RDP"}]
    assessment_attacker = DETECTION_BRIDGE.assess_detection(
        detection=rmm_det,
        state_vector=_build_state(active_caps=["TOKEN_IMPERSONATION"]),
        host_id="JUMPBOX-01",
        user_id="admin_sys",
        reachability_paths=reach_db,
        crown_jewel_hosts=["PAYMENT-DB"],
    )
    assert assessment_attacker.abuse_state == CapabilityAbuseState.CONFIRMED_ATTACK
    assert "PAYMENT-DB" in assessment_attacker.target_crown_jewels


# ── 3. WMI & PsExec Discrimination ──────────────────────────────────────────

def test_wmi_and_psexec_contextual_assessment():
    """Verify WMI and PsExec lateral movement detectors require context for CONFIRMED_ATTACK."""
    wmi_det = {
        "rule_id": "DET-EX-004",
        "name": "WMI Process Creation",
        "severity": "medium",
        "confidence": "medium",
    }
    psexec_det = {
        "rule_id": "DET-LM-001",
        "name": "PsExec Service Execution",
        "severity": "high",
        "confidence": "high",
    }

    # Standard workstation WMI query (e.g. inventory query)
    res_wmi = DETECTION_BRIDGE.assess_detection(
        detection=wmi_det,
        state_vector=_build_state(),
        host_id="WORKSTATION-01",
        user_id="regular_user",
        reachability_paths=[],
    )
    assert res_wmi.abuse_state == CapabilityAbuseState.BENIGN_DUAL_USE

    # PsExec executed by Domain Admin with lateral reachability to Backup server
    res_psexec = DETECTION_BRIDGE.assess_detection(
        detection=psexec_det,
        state_vector=_build_state(active_caps=["STOLEN_TGT"]),
        host_id="COMPROMISED-SRV",
        user_id="root_admin",
        reachability_paths=[{"destination_node": "BACKUP-01"}],
    )
    assert res_psexec.abuse_state == CapabilityAbuseState.CONFIRMED_ATTACK
    assert res_psexec.escalated_severity == "critical"


# ── 4. Cloud Administration Discrimination ──────────────────────────────────

def test_cloud_administration_discrimination():
    """Verify Cloud Administration (IAM policy update / Role Assumption) is discriminated based on context."""
    cloud_det = {
        "rule_id": "DET-CL-001",
        "name": "Cloud IAM Policy Modification",
        "severity": "medium",
        "confidence": "medium",
    }

    # Benign IAM update by regular cloud engineer without compromised credentials
    res_cloud_benign = DETECTION_BRIDGE.assess_detection(
        detection=cloud_det,
        state_vector=_build_state(),
        host_id="CLOUD-CONSOLE",
        user_id="cloud_dev",
        reachability_paths=[],
    )
    assert res_cloud_benign.abuse_state == CapabilityAbuseState.BENIGN_DUAL_USE

    # Malicious IAM elevation when environment has active credential theft and reachability to DC
    res_cloud_mal = DETECTION_BRIDGE.assess_detection(
        detection=cloud_det,
        state_vector=_build_state(active_caps=["CREDENTIAL_THEFT"]),
        host_id="CLOUD-CONSOLE",
        user_id="admin_root",
        reachability_paths=[{"destination_node": "DC-01"}],
    )
    assert res_cloud_mal.abuse_state == CapabilityAbuseState.CONFIRMED_ATTACK
