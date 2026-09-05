"""
NivXRay XDR — Phase 2.1 Engine Binding Failure & Invariant Test Suite.
Attempts binding against unverified, unsupported, or incomplete content:
  - missing required telemetry
  - unknown fields
  - unsupported correlation
  - unsupported aggregation
  - partial translation
  - approximate translation
  - unknown engine
  - unverified engine
  - disabled engine
Enforces FAIL CLOSED: No ENGINE_BOUND claim without executable compatibility evidence.
"""
import pytest
from detection_content.canonical_ir import (
    CanonicalIR,
    FieldCompareNode,
    Operator,
    ProvenanceInfo,
    TranslationFidelity,
    UnsupportedConstruct,
)
from detection_content.validation_framework import (
    BindingStatus,
    EngineBindingBridge,
    EngineBindingReport,
)


def _build_test_rule(
    rule_id: str = "DET-BIND-01",
    fields=None,
    fidelity=TranslationFidelity.EXACT,
    unsupported=None,
    is_correlation=False,
) -> CanonicalIR:
    node = FieldCompareNode("process.name", Operator.EQUALS, "cmd.exe")
    prov = ProvenanceInfo(
        source="Test",
        source_id="T01",
        license="Apache-2.0",
        attribution="Community",
    )
    return CanonicalIR(
        content_id=rule_id,
        name=f"Binding Test {rule_id}",
        description="Testing engine binding",
        tactic="Execution",
        technique_id="T1059",
        platform="windows",
        severity="medium",
        confidence="high",
        lane="content",
        required_fields=fields if fields is not None else ["process.name"],
        root_node=node,
        fidelity=fidelity,
        provenance=prov,
        unsupported_constructs=unsupported or [],
        is_correlation=is_correlation,
    )


def test_binding_fails_closed_on_missing_required_telemetry():
    """Rule specifying zero required telemetry fields must return ENGINE_UNBOUND."""
    ir = _build_test_rule(fields=[])
    report = EngineBindingBridge.resolve_binding(ir)

    assert report.status == BindingStatus.ENGINE_UNBOUND
    assert "missing required telemetry" in report.reasons[0].lower()


def test_binding_fails_closed_on_unknown_telemetry_fields():
    """Rule with telemetry fields unknown to active engine contracts must return ENGINE_UNBOUND."""
    ir = _build_test_rule(fields=["process.name", "quantum_sensor.qubit_state"])
    report = EngineBindingBridge.resolve_binding(ir)

    assert report.status == BindingStatus.ENGINE_UNBOUND
    assert "not covered" in report.reasons[0].lower()


def test_binding_fails_closed_on_partial_and_approximate_fidelity():
    """Rules with PARTIAL or APPROXIMATE fidelity cannot be bound; must return UNSUPPORTED."""
    ir_partial = _build_test_rule(fidelity=TranslationFidelity.PARTIAL)
    report_partial = EngineBindingBridge.resolve_binding(ir_partial)
    assert report_partial.status == BindingStatus.UNSUPPORTED

    ir_approx = _build_test_rule(fidelity=TranslationFidelity.APPROXIMATE)
    report_approx = EngineBindingBridge.resolve_binding(ir_approx)
    assert report_approx.status == BindingStatus.UNSUPPORTED


def test_binding_fails_closed_on_fatal_unsupported_constructs():
    """Rules with fatal unsupported constructs (e.g. rex, eval) must return UNSUPPORTED."""
    fatal_u = UnsupportedConstruct("spl_rex", "rex (?<val>.*)", "Unsupported regex extraction", fatal=True)
    ir = _build_test_rule(unsupported=[fatal_u])
    report = EngineBindingBridge.resolve_binding(ir)

    assert report.status == BindingStatus.UNSUPPORTED
    assert "fatal unsupported constructs" in report.reasons[0].lower()


def test_binding_fails_closed_on_unknown_target_engine():
    """Attempting binding against an unknown engine returns ENGINE_UNBOUND."""
    ir = _build_test_rule()
    report = EngineBindingBridge.resolve_binding(ir, target_engine_id="nivxray::nonexistent_engine")

    assert report.status == BindingStatus.ENGINE_UNBOUND
    assert "unverified or unknown" in report.reasons[0].lower()


def test_binding_fails_closed_on_unverified_engine_contract():
    """Attempting binding against an engine with status CONTRACT_DECLARED (not EXECUTION_VERIFIED) fails."""
    ir = _build_test_rule()
    declared_contract = [
        {
            "engine_id": "nivxray::candidate_experimental_engine",
            "contract_status": "CONTRACT_DECLARED",  # Not EXECUTION_VERIFIED
            "enabled": True,
        }
    ]
    report = EngineBindingBridge.resolve_binding(
        ir,
        target_engine_id="nivxray::candidate_experimental_engine",
        available_contracts=declared_contract,
    )

    assert report.status == BindingStatus.ENGINE_UNBOUND
    assert "not verified" in report.reasons[0].lower()


def test_binding_fails_closed_on_disabled_engine():
    """Attempting binding against a disabled engine contract fails closed."""
    ir = _build_test_rule()
    disabled_contract = [
        {
            "engine_id": "nivxray::legacy_engine",
            "contract_status": "EXECUTION_VERIFIED",
            "enabled": False,  # Disabled
        }
    ]
    report = EngineBindingBridge.resolve_binding(
        ir,
        target_engine_id="nivxray::legacy_engine",
        available_contracts=disabled_contract,
    )

    assert report.status == BindingStatus.ENGINE_UNBOUND
    assert "disabled" in report.reasons[0].lower()


def test_binding_succeeds_only_for_verified_contracts_with_executable_evidence():
    """Binding succeeds with status COMPATIBLE only when all criteria are satisfied."""
    ir = _build_test_rule(fields=["process.name", "process.command_line"])
    report = EngineBindingBridge.resolve_binding(ir)

    assert report.status == BindingStatus.COMPATIBLE
    assert report.bound_engine_id == EngineBindingBridge.ENTERPRISE_LIBRARY_ENGINE
    assert report.engine_role == "DETECTION_ENGINE"
