"""
NivXRay XDR — Comprehensive Test Suite for Rule, Detection, Correlation, and Playbook Expansion.

Validates:
  1. Detection Engine contract verification & promotion (resolving ENGINE_UNBOUND).
  2. Rule binding resolution to COMPATIBLE.
  3. Enterprise Detection Library: 100% pass on positive and negative fixtures.
  4. Integration of Enterprise Detection Library into evaluate_detection pipeline.
  5. Enterprise Multi-Stage Correlation Scenarios registration & operator integrity.
  6. Playbook Orchestration Engine: 11-stage deterministic lifecycle.
  7. Playbook Safety Gate & Approval Policy enforcement (dry_run & lock invariants).
  8. Initial Playbook Library: 22 enterprise playbooks valid structure and action mapping.
  9. Security-State-Aware Contextual Discrimination Bridge (dual-use RMM vs confirmed attack).
"""
from __future__ import annotations

import pytest

from detection_content.capability_contract import ContractStatus
from detection_content.contract_registry import bootstrap_verified_detection_contracts
from detection_content.rule_binding import match_rule_to_contracts
from detection_content.library import (
    ENTERPRISE_DETECTION_RULES,
    REGISTRY as DETECTION_REGISTRY,
    Platform,
    Severity,
    Tactic,
)
from detection_content.correlation_library import ENTERPRISE_CORRELATION_SCENARIOS
from detection_content.xdr_pipeline import evaluate_detection
from security_state.orchestration import (
    ENTERPRISE_PLAYBOOKS,
    ORCHESTRATOR,
    PLAYBOOK_REGISTRY,
    PlaybookStage,
)
from security_state.detection_bridge import (
    CapabilityAbuseState,
    DETECTION_BRIDGE,
)
from security_state.contracts import (
    AttackStage,
    SecurityStateVector,
    ExecutionSafetyGate,
)


# ── 1. Detection Engine Verification & Rule Binding ─────────────────────────

@pytest.mark.asyncio
async def test_contract_bootstrap_verification():
    """Verify that bootstrap_verified_detection_contracts promotes native sigma engine to EXECUTION_VERIFIED."""
    # When db is None (unit test mock), harness still evaluates and returns EXECUTION_VERIFIED
    res = await bootstrap_verified_detection_contracts(None)
    assert res["status"] == "EXECUTION_VERIFIED"
    assert res["engine_id"] == "nivxray::detection_content::nivxray_native_sigma"


def test_rule_binding_resolves_to_compatible():
    """Verify that when capability contract has detection=True and semantic domain matches, status is COMPATIBLE."""
    rule_surface = {
        "id": "test-win-proc",
        "product": "windows",
        "category": "process_creation",
    }
    mock_contracts = [
        {
            "engine_id": "nivxray::detection_content::nivxray_native_sigma",
            "classification": "DETECTION_ENGINE",
            "contract_status": ContractStatus.EXECUTION_VERIFIED.value,
            "execution": {"detection": True, "deterministic": True, "side_effect_free": True},
            "consumes": ["canonical.evidence", "process.artifact", "process_event"],
        }
    ]
    report = match_rule_to_contracts(rule_surface, mock_contracts)
    assert report["status"] == "COMPATIBLE"
    assert report["counts"]["compatible"] == 1


# ── 2. Enterprise Detection Library Verification ─────────────────────────────

def test_enterprise_detection_library_registry_coverage():
    """Verify detection library contains rules across all ATT&CK tactics."""
    summary = DETECTION_REGISTRY.summary()
    assert summary["total_rules"] >= 20
    assert len(summary["tactics_coverage"]) >= 7
    assert len(summary["platforms_coverage"]) >= 4


def test_all_enterprise_rules_positive_and_negative_fixtures():
    """Every enterprise detection rule must pass both positive and negative fixtures."""
    for rule in ENTERPRISE_DETECTION_RULES:
        assert len(rule.fixtures) >= 2, f"Rule {rule.rule_id} must have >= 2 test fixtures"
        for fix in rule.fixtures:
            res = rule.evaluate(fix.event)
            assert res == fix.should_match, (
                f"Rule {rule.rule_id} ('{rule.name}') failed fixture '{fix.name}'. "
                f"Expected {fix.should_match}, got {res}. Event: {fix.event}"
            )


def test_xdr_pipeline_evaluate_detection_dynamic_matching():
    """Verify evaluate_detection matches enterprise detection rules from canonical evidence."""
    powershell_ev = {
        "event_id": "ev-test-1",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -enc aW52b2tlLW1pbWlrYXR6",
    }
    det = evaluate_detection(powershell_ev)
    assert det["status"] == "RULE_MATCH"
    assert det["matched"] is True
    assert det["rule_id"] == "DET-EX-001"
    assert any(d["rule_id"] == "DET-EX-001" for d in det.get("detections", []))

    benign_ev = {
        "event_id": "ev-test-2",
        "Image": "notepad.exe",
        "CommandLine": "notepad.exe",
    }
    benign_det = evaluate_detection(benign_ev)
    assert benign_det["status"] == "RULE_NO_MATCH"
    assert benign_det["matched"] is False


# ── 3. Enterprise Correlation Scenarios ─────────────────────────────────────

def test_enterprise_correlation_scenarios_structure():
    """Verify that all 5 multi-stage correlation scenarios have valid operators and ATT&CK mappings."""
    assert len(ENTERPRISE_CORRELATION_SCENARIOS) == 5
    ids = {s["id"] for s in ENTERPRISE_CORRELATION_SCENARIOS}
    assert ids == {
        "CORR-ENT-001",
        "CORR-ENT-002",
        "CORR-ENT-003",
        "CORR-ENT-004",
        "CORR-ENT-005",
    }
    for s in ENTERPRISE_CORRELATION_SCENARIOS:
        assert "name" in s and "conditions" in s and "operators" in s
        assert len(s["conditions"]) >= 2
        assert len(s["attack_techniques"]) >= 2
        assert s["operators"]["type"] in ("TEMPORAL_ORDERED", "SEQUENCE", "EVENT_MATCH")


# ── 4. Playbook Orchestration Engine & Library ──────────────────────────────

def test_playbook_library_22_playbooks_catalogue():
    """Verify initial catalogue contains 22 enterprise playbooks across target domains."""
    catalogue = PLAYBOOK_REGISTRY.list_playbooks()
    assert len(catalogue) == 22
    domains = {pb["target_domain"] for pb in catalogue}
    assert "endpoint" in domains
    assert "network" in domains
    assert "identity" in domains
    assert "cloud" in domains
    assert "email" in domains
    assert "backup" in domains


def test_playbook_orchestrator_11_stage_lifecycle():
    """Verify complete 11-stage playbook orchestration lifecycle runs deterministically."""
    trace = ORCHESTRATOR.orchestrate(
        playbook_id="PB-END-01",
        incident_id="inc-test-401",
        tenant_id="test-tenant",
        dry_run=True,
    )
    assert trace.current_stage == PlaybookStage.COMPLETED
    assert trace.playbook_id == "PB-END-01"
    assert trace.is_dry_run is True
    assert trace.simulated_world_id == "WORLD_B"
    assert trace.projected_residual_risk_pct < trace.initial_residual_risk_pct
    assert len(trace.step_traces) == 2
    assert all(st.status == "SIMULATED_SUCCESS" for st in trace.step_traces)
    assert trace.verification_details["verification_status"] == "VERIFIED_PROJECTED"
    assert "evidence_state_hash" in trace.verification_details


def test_playbook_orchestrator_safety_lock_enforcement():
    """Verify that when execution lock is engaged, live execution is blocked and remains simulated."""
    locked_gate = ExecutionSafetyGate(
        gate_id="safety-gate-locked",
        tenant_id="test-tenant",
        evaluated_at="2026-09-04T00:00:00Z",
        auto_response_enabled=False,
        execution_lock_engaged=True,
        active_blockers=["LOCK_ENGAGED"],
    )
    engine = ORCHESTRATOR
    engine.safety_gate = locked_gate

    trace = engine.orchestrate(
        playbook_id="PB-RAN-01",
        incident_id="inc-ransom-99",
        dry_run=False,  # Caller asks for live, but safety lock must force simulation
    )
    assert trace.current_stage == PlaybookStage.COMPLETED
    # Steps must remain simulated because lock is engaged
    assert all(st.status == "SIMULATED_SUCCESS" for st in trace.step_traces)
    assert trace.approval_details["safety_gate_lock"] is True


# ── 5. Security-State-Aware Contextual Discrimination Bridge ────────────────

def test_security_state_bridge_benign_dual_use():
    """RMM software alone with no privileged user and no lateral path is classified as BENIGN_DUAL_USE."""
    rmm_detection = {
        "rule_id": "DET-CC-001",
        "name": "Dual-Use RMM Remote Access Tool Execution",
        "severity": "high",
        "confidence": "high",
    }
    assessment = DETECTION_BRIDGE.assess_detection(
        detection=rmm_detection,
        host_id="WKST-10",
        user_id="jdoe_helpdesk",
        reachability_paths=[],
    )
    assert assessment.abuse_state == CapabilityAbuseState.BENIGN_DUAL_USE
    assert assessment.escalated_severity == "low"


def test_security_state_bridge_confirmed_attack():
    """RMM software combined with privileged user and active reachability to Domain Controller is CONFIRMED_ATTACK."""
    rmm_detection = {
        "rule_id": "DET-CC-001",
        "name": "Dual-Use RMM Remote Access Tool Execution",
        "severity": "high",
        "confidence": "high",
    }
    mock_reachability = [
        {"destination_node": "DC-01", "hop_count": 1, "path_kind": "SMB_RPC"}
    ]
    assessment = DETECTION_BRIDGE.assess_detection(
        detection=rmm_detection,
        host_id="WKST-10",
        user_id="admin_da",
        reachability_paths=mock_reachability,
        crown_jewel_hosts=["DC-01"],
    )
    assert assessment.abuse_state == CapabilityAbuseState.CONFIRMED_ATTACK
    assert assessment.escalated_severity == "critical"
    assert assessment.escalated_confidence == "confirmed"
    assert assessment.reachability_to_crown_jewels is True
    assert "DC-01" in assessment.target_crown_jewels
