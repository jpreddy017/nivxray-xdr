"""
Unit Tests for Phase 2I/2J Engine Binding & Security State Bridge.
Verifies engine resolution (COMPATIBLE vs ENGINE_UNBOUND) and Causal Security State
contextual discrimination for dual-use technologies.
"""
import pytest
from detection_content.canonical_ir import (
    BooleanLogicNode,
    BooleanOp,
    CanonicalIR,
    FieldCompareNode,
    Operator,
    ProvenanceInfo,
    TranslationFidelity,
)
from detection_content.validation_framework import (
    BindingStatus,
    EngineBindingBridge,
    SecurityStateBridgeIntegration,
)


def _make_rule(fields: list[str], is_corr: bool = False) -> CanonicalIR:
    prov = ProvenanceInfo(source="SigmaHQ", source_id="BIND-01", license="MIT")
    return CanonicalIR(
        content_id="DET-BIND-01",
        name="Binding Rule",
        description="Testing binding",
        tactic="Execution",
        technique_id="T1059",
        platform="windows",
        severity="high",
        confidence="high",
        lane="content",
        required_fields=fields,
        root_node=FieldCompareNode("process.name", Operator.EQUALS, "cmd.exe"),
        fidelity=TranslationFidelity.EXACT,
        provenance=prov,
        is_correlation=is_corr,
    )


def test_engine_binding_compatible_detection():
    ir = _make_rule(["process.name", "process.command_line"])
    report = EngineBindingBridge.resolve_binding(ir)
    assert report.status == BindingStatus.COMPATIBLE
    assert report.engine_role == "DETECTION_ENGINE"


def test_engine_binding_correlation():
    ir_corr = _make_rule(["process.name"], is_corr=True)
    report = EngineBindingBridge.resolve_binding(ir_corr)
    assert report.status == BindingStatus.COMPATIBLE
    assert report.bound_engine_id == "nivxray::xdr::correlation"


def test_engine_binding_unbound_exotic_fields():
    ir_exotic = _make_rule(["unsupported.quantum.entropy.field"])
    report = EngineBindingBridge.resolve_binding(ir_exotic)
    assert report.status == BindingStatus.ENGINE_UNBOUND


def test_security_state_bridge_dual_use_discrimination():
    bridge = SecurityStateBridgeIntegration()

    # RMM Rule
    ir_rmm = _make_rule(["process.name"])
    ir_rmm.content_id = "DET-CC-001"
    ir_rmm.name = "AnyDesk Execution"

    # Case 1: Standard user, no crown jewel reachability -> BENIGN_DUAL_USE
    ctx_benign = bridge.contextualize(
        ir_rmm,
        match_event={},
        user_id="standard_user",
        host_id="WORKSTATION-01",
        reachability_paths=[],
    )
    assert ctx_benign["abuse_state"] == "BENIGN_DUAL_USE"
    assert ctx_benign["escalated_severity"] == "low"

    # Case 2: Domain Admin + Lateral Reachability to DC-01 -> CONFIRMED_ATTACK
    ctx_attack = bridge.contextualize(
        ir_rmm,
        match_event={},
        user_id="admin_da",
        host_id="WORKSTATION-01",
        crown_jewels=["DC-01"],
        reachability_paths=[{"target": "DC-01", "hops": 1}],
    )
    assert ctx_attack["abuse_state"] == "CONFIRMED_ATTACK"
    assert ctx_attack["escalated_severity"] == "critical"
