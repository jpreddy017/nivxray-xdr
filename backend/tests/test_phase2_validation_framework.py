"""
Unit Tests for Phase 2F/2H Quality Validation Framework & Validation Tiers.
Verifies programmatic gates: Schema, License & Provenance, Telemetry, Fixtures,
Determinism, and Performance (< 5ms).
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
    QualityValidationFramework,
    ValidationGates,
    ValidationTier,
)


def _build_test_ir(license_name: str = "Apache-2.0") -> CanonicalIR:
    node = FieldCompareNode("process.name", Operator.EQUALS, "powershell.exe")
    prov = ProvenanceInfo(
        source="SigmaHQ",
        source_id="TEST-GATE-01",
        license=license_name,
        attribution="Community",
    )
    return CanonicalIR(
        content_id="DET-GATE-01",
        name="Gate Test Rule",
        description="Testing validation gates",
        tactic="Execution",
        technique_id="T1059",
        platform="windows",
        severity="high",
        confidence="high",
        lane="content",
        required_fields=["process.name"],
        root_node=node,
        fidelity=TranslationFidelity.EXACT,
        provenance=prov,
    )


def test_schema_gate_pass_and_fail():
    ir = _build_test_ir()
    res = ValidationGates.check_schema(ir)
    assert res.passed is True

    # Incomplete schema
    ir_bad = _build_test_ir()
    ir_bad.name = ""
    res_bad = ValidationGates.check_schema(ir_bad)
    assert res_bad.passed is False
    assert "name" in res_bad.reasons[0]


def test_license_provenance_gate_permissive_vs_rejected():
    # Permissive: Apache-2.0, MIT, DRL-1.1
    ir_ok = _build_test_ir("Apache-2.0")
    assert ValidationGates.check_license_provenance(ir_ok).passed is True

    ir_mit = _build_test_ir("MIT")
    assert ValidationGates.check_license_provenance(ir_mit).passed is True

    # Rejected: GPLv3, Proprietary
    ir_gpl = _build_test_ir("GPLv3")
    assert ValidationGates.check_license_provenance(ir_gpl).passed is False

    ir_prop = _build_test_ir("Proprietary Vendor EULA")
    assert ValidationGates.check_license_provenance(ir_prop).passed is False


def test_fixture_gate_positive_negative_verification():
    ir = _build_test_ir()
    pos = {"process": {"name": "powershell.exe"}}
    neg = {"process": {"name": "cmd.exe"}}

    res = ValidationGates.check_fixtures(ir, pos, neg)
    assert res.passed is True

    # Broken positive fixture (asserts True, returns False)
    bad_pos = {"process": {"name": "calc.exe"}}
    res_bad = ValidationGates.check_fixtures(ir, bad_pos, neg)
    assert res_bad.passed is False


def test_performance_gate_under_5ms():
    ir = _build_test_ir()
    ev = {"process": {"name": "powershell.exe"}}
    res = ValidationGates.check_performance(ir, ev, max_latency_ms=5.0)
    assert res.passed is True
    assert res.metrics["avg_latency_ms"] < 5.0


def test_multi_tier_validation_flow():
    ir = _build_test_ir()
    pos = {"process": {"name": "powershell.exe"}}
    neg = {"process": {"name": "cmd.exe"}}

    # Tier 1 (Structural)
    t1 = QualityValidationFramework.validate_tier_1(ir, pos, neg)
    assert t1.passed is True
    assert t1.tier == ValidationTier.TIER_1_STRUCTURAL

    # Tier 2 (Behavioral)
    t2 = QualityValidationFramework.validate_tier_2(ir, pos, neg)
    assert t2.passed is True
    assert t2.tier == ValidationTier.TIER_2_BEHAVIORAL

    # Tier 3 (Runtime)
    t3 = QualityValidationFramework.validate_tier_3(ir, pos, neg)
    assert t3.passed is True
    assert t3.tier == ValidationTier.TIER_3_RUNTIME
