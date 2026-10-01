"""Comprehensive Validation & Determinism Test Suite for Security State Core."""
from __future__ import annotations


from security_state.contracts import (
    AttackState,
    CapabilityStatus,
    CausalLevel,
    EntityCategory,
    EntityRef,
    EpistemicStatus,
    ReachabilityStatus,
    VerificationStatus,
)
from security_state.model.security_state import (
    DerivedFact,
    ObservedFact,
    SecurityState,
)
from security_state.state_engine.engine import SecurityStateEngine
from security_state.transitions.engine import TransitionEngine
from security_state.causal.engine import CausalSecurityEngine
from security_state.capability.engine import (
    CapabilityContext,
    TrustedCapabilityAbuseEngine,
)
from security_state.attack_state.machine import AttackStateMachine
from security_state.reachability.engine import EnterpriseReachabilityEngine
from security_state.counterfactual.engine import CounterfactualEngine
from security_state.impact.engine import ImpactEngine
from security_state.intervention.optimizer import InterventionOptimizer
from security_state.response_safety.safety_gate import ResponseSafetyGate
from security_state.response_safety.verification import ResponseVerificationEngine
from security_state.ledger.ledger import SecurityStateLedger
from security_state.simulation.simulator import AdversarialSimulator


# ── Test 1: Determinism & Hash Replayability ────────────────────────────────
def test_security_state_determinism_and_replay():
    """Identical evidence and configuration MUST yield byte-identical state hashes."""
    engine = SecurityStateEngine()
    tenant = "tenant-alpha"
    entity = EntityRef(category=EntityCategory.DEVICE, entity_id="host-01", tenant_id=tenant)
    evidence = [
        {"id": "ev-1", "type": "process_spawn", "payload": {"process_name": "powershell.exe", "command_line": "powershell -enc ... downloadstring"}},
        {"id": "ev-2", "type": "schtasks", "payload": {"command_line": "schtasks /create /tn updater /tr payload.exe"}},
    ]

    state_1 = engine.evaluate_entity_state(tenant, entity, evidence, at_timestamp="2026-09-04T00:00:00Z")
    state_2 = engine.evaluate_entity_state(tenant, entity, evidence, at_timestamp="2026-09-04T00:00:00Z")

    assert state_1.state_hash == state_2.state_hash
    assert state_1.epistemic_status == EpistemicStatus.DERIVED
    assert state_1.classification == CapabilityStatus.CONFIRMED_ATTACK
    assert "CAP_PAYLOAD_DOWNLOAD" in state_1.active_capabilities
    assert "CAP_PERSISTENCE" in state_1.active_capabilities


# ── Test 2: Causal Separation from Correlation ──────────────────────────────
def test_causal_engine_separates_correlation():
    """Temporal proximity alone yields TEMPORAL_CORRELATION, while parent-child yields STRONG_CAUSAL_EVIDENCE."""
    c_engine = CausalSecurityEngine()
    
    # Event pair 1: Parent (PID 100) spawns child (PPID 100)
    events_causal = [
        {"id": "ev-1", "pid": 100, "process_name": "cmd.exe", "time_ms": 10},
        {"id": "ev-2", "pid": 200, "ppid": 100, "process_name": "powershell.exe", "time_ms": 25},
    ]
    graph_1 = c_engine.evaluate_causality("tenant-a", "case-1", events_causal)
    assert len(graph_1.edges) == 1
    assert graph_1.edges[0].causal_level == CausalLevel.STRONG_CAUSAL_EVIDENCE
    assert graph_1.edges[0].mechanism.mechanism_type == "PROCESS_SPAWN_SYSCALL"

    # Event pair 2: Unrelated processes in close time succession
    events_coincident = [
        {"id": "ev-a", "pid": 500, "process_name": "calc.exe", "time_ms": 10},
        {"id": "ev-b", "pid": 600, "ppid": 999, "process_name": "notepad.exe", "time_ms": 15},
    ]
    graph_2 = c_engine.evaluate_causality("tenant-a", "case-2", events_coincident)
    assert len(graph_2.edges) == 1
    assert graph_2.edges[0].causal_level == CausalLevel.TEMPORAL_CORRELATION


# ── Test 3: Trusted Capability Abuse (Dual-Use) ─────────────────────────────
def test_trusted_capability_abuse_evaluation():
    """Distinguishes authorized benign administrative use from weaponized abuse."""
    cap_engine = TrustedCapabilityAbuseEngine()
    tenant = "tenant-alpha"
    admin_ref = EntityRef(category=EntityCategory.IDENTITY, entity_id="admin.alice", tenant_id=tenant)
    user_ref = EntityRef(category=EntityCategory.IDENTITY, entity_id="user.bob", tenant_id=tenant)

    # Benign Admin Use
    ctx_benign = CapabilityContext(
        capability_name="powershell.exe",
        identity_ref=admin_ref,
        is_authorized_admin=True,
        source_ip_or_subnet="10.0.1.10",
        destination_ip_or_domain="corp.internal",
        timestamp="2026-09-04T10:00:00Z",
        is_within_business_hours=True,
        command_line="Get-Service | Where-Object {$_.Status -eq 'Running'}",
        parent_process="explorer.exe",
        process_privilege_level="ADMIN",
    )
    eval_benign = cap_engine.evaluate_capability(tenant, ctx_benign, ["ev-b1"])
    assert eval_benign.status == CapabilityStatus.AUTHORIZED_USE

    # Weaponized Abuse (Unauthorized user, proxy tunnel, credential targeting, off-hours)
    ctx_abused = CapabilityContext(
        capability_name="powershell.exe",
        identity_ref=user_ref,
        is_authorized_admin=False,
        source_ip_or_subnet="192.168.1.100",
        destination_ip_or_domain="dynamic-dns.xyz",
        timestamp="2026-09-04T02:30:00Z",
        is_within_business_hours=False,
        command_line="powershell.exe -enc ... sekurlsa::minidump",
        parent_process="winword.exe",
        process_privilege_level="USER",
        has_inbound_tunnel_or_proxy=True,
    )
    eval_abused = cap_engine.evaluate_capability(tenant, ctx_abused, ["ev-m1"])
    assert eval_abused.status == CapabilityStatus.CONFIRMED_ATTACK
    assert eval_abused.reversal_action_recommendation == "endpoint.terminate_process"


# ── Test 4: Attack State Machine Progression ────────────────────────────────
def test_attack_state_machine_advancement():
    """State machine advances monotonically based on verified capability transitions."""
    asm = AttackStateMachine()
    trans_engine = TransitionEngine()
    tenant = "tenant-alpha"
    entity = EntityRef(category=EntityCategory.DEVICE, entity_id="host-01", tenant_id=tenant)
    
    state_engine = SecurityStateEngine()
    s0 = state_engine.evaluate_entity_state(tenant, entity, [])
    
    # Trigger execution transition
    s1 = state_engine.evaluate_entity_state(tenant, entity, [
        {"id": "ev-ex", "type": "process", "payload": {"process_name": "powershell.exe", "command_line": "downloadstring"}}
    ], previous_state=s0)
    
    t1 = trans_engine.compute_transition(
        before=s0,
        after=s1,
        triggering_evidence_ids=["ev-ex"],
        causal_basis="SUPPORTED: Commandline payload download",
        property_mutated="active_capabilities",
        new_capability_unlocked="CAP_PAYLOAD_DOWNLOAD",
        attack_state_delta="NO_ATTACK_EVIDENCE -> EXECUTION",
    )

    eval_1 = asm.advance_state(tenant, "case-01", AttackState.NO_ATTACK_EVIDENCE, [t1], [s1])
    assert eval_1.current_state == AttackState.EXECUTION


# ── Test 5: Reachability & Decoupled Impact ──────────────────────────────────
def test_reachability_and_decoupled_impact():
    """Reachability identifies exposed Tier 0 assets; impact scores exposure without distorting verdict."""
    reach_engine = EnterpriseReachabilityEngine()
    imp_engine = ImpactEngine()
    tenant = "tenant-alpha"
    foothold = EntityRef(category=EntityCategory.DEVICE, entity_id="host-01", tenant_id=tenant)

    # Reachability with dumped admin credentials
    matrix = reach_engine.compute_reachability(
        tenant_id=tenant,
        case_id="case-100",
        footholds=[foothold],
        harvested_credentials=["DomainAdmin"],
        active_capabilities=["CAP_CREDENTIAL_DUMPING"],
    )
    assert matrix.tier_0_exposed is True
    assert matrix.currently_reachable_count > 0

    # Impact calculation
    scorecard = imp_engine.evaluate_impact(tenant, "case-100", matrix, [foothold])
    assert scorecard.tier_0_service_exposed is True
    assert scorecard.ransomware_exposure_risk == "CRITICAL"
    assert scorecard.overall_impact_score >= 80


# ── Test 6: Counterfactuals & Intervention Optimization ──────────────────────
def test_counterfactual_and_intervention_optimization():
    """Intervention optimizer severs reachability paths to produce a minimal effective plan."""
    reach_engine = EnterpriseReachabilityEngine()
    imp_engine = ImpactEngine()
    cf_engine = CounterfactualEngine()
    opt_engine = InterventionOptimizer()
    state_engine = SecurityStateEngine()
    tenant = "tenant-alpha"
    foothold = EntityRef(category=EntityCategory.DEVICE, entity_id="host-01", tenant_id=tenant)

    matrix = reach_engine.compute_reachability(tenant, "case-200", [foothold], ["admin"], ["CAP_CREDENTIAL_DUMPING"])
    impact = imp_engine.evaluate_impact(tenant, "case-200", matrix, [foothold])
    dummy_state = state_engine.evaluate_entity_state(tenant, foothold, [])
    
    cf = cf_engine.evaluate_counterfactuals(tenant, "case-200", dummy_state, matrix, AttackState.CREDENTIAL_ACCESS)
    assert cf.world_a_do_nothing.continuation_probability > 0.90

    plan = opt_engine.optimize_intervention(tenant, "case-200", matrix, impact, cf, [foothold])
    assert len(plan.actions) >= 1
    assert plan.actions[0].action_id == "endpoint.isolate"
    assert plan.projected_residual_risk_pct <= 10


# ── Test 7: Response Safety Gate & Closed-Loop Verification ─────────────────
def test_response_safety_and_verification():
    """Safety gate enforces tenant boundaries and protected asset rules; verification rejects unverified containment."""
    gate = ResponseSafetyGate()
    verifier = ResponseVerificationEngine()
    state_engine = SecurityStateEngine()
    tenant = "tenant-alpha"

    from security_state.intervention.optimizer import PlannedAction
    target_device = EntityRef(category=EntityCategory.DEVICE, entity_id="host-01", tenant_id=tenant)
    action = PlannedAction(
        step_number=1,
        action_id="endpoint.isolate",
        target_entity=target_device,
        rationale="Sever network",
        expected_path_cut="Cut all network hops",
        is_reversible=True,
    )

    # Test Safety Gate: Approved for legitimate analyst
    dec_approved = gate.evaluate_action_safety(tenant, action, ["soc:analyst"], tenant, 0.95)
    assert dec_approved.is_approved is True

    # Test Safety Gate: Rejection on cross-tenant breach attempt
    dec_rejected = gate.evaluate_action_safety(tenant, action, ["soc:analyst"], "tenant-attacker", 0.95)
    assert dec_rejected.is_approved is False
    assert any("Tenant isolation breach" in v for v in dec_rejected.policy_violations)

    # Test Verification: Re-observation confirms containment
    pre_state = state_engine.evaluate_entity_state(tenant, target_device, [])
    post_telemetry_clean = [{"type": "network_connection", "direction": "outbound", "destination_port": 443}]
    vrep_success = verifier.verify_action_efficacy(tenant, "case-300", "endpoint.isolate", "host-01", pre_state, post_telemetry_clean)
    assert vrep_success.is_containment_verified is True
    assert vrep_success.status == VerificationStatus.VERIFIED_EFFECTIVE

    # Test Verification: Attacker bypass / pivot detected
    post_telemetry_bypass = [
        {"type": "network_connection", "direction": "outbound", "destination_port": 8080, "dest_ip": "45.33.32.1"}
    ]
    vrep_fail = verifier.verify_action_efficacy(tenant, "case-300", "endpoint.isolate", "host-01", pre_state, post_telemetry_bypass)
    assert vrep_fail.is_containment_verified is False
    assert vrep_fail.status in (VerificationStatus.VERIFIED_INEFFECTIVE, VerificationStatus.ATTACKER_PIVOT_DETECTED)


# ── Test 8: Security State Ledger Cryptographic Integrity ───────────────────
def test_security_state_ledger_cryptographic_integrity():
    """Ledger maintains unbroken SHA-256 block hash chain and detects tampering."""
    ledger = SecurityStateLedger(tenant_id="tenant-alpha", case_id="case-ledger-01")
    
    b1 = ledger.append("STATE_TRANSITION", "host-01", {"prop": "privilege_escalated"})
    b2 = ledger.append("ACTION_APPROVED", "host-01", {"action": "endpoint.isolate"})
    b3 = ledger.append("CONTAINMENT_VERIFIED", "host-01", {"status": "VERIFIED_EFFECTIVE"})

    assert len(ledger.blocks) == 3
    assert ledger.verify_integrity() is True
    assert b2.previous_block_hash == b1.block_hash
    assert b3.previous_block_hash == b2.block_hash

    # Tamper test: Mutate payload of block 1
    ledger.blocks[0].payload["prop"] = "TAMPERED_CONTENT"
    assert ledger.verify_integrity() is False
