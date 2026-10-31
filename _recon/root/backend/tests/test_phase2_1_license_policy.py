"""
NivXRay XDR — Phase 2.1 License Policy Model Validation Suite.
Audits the decoupled license policy gate:
- Separates identification from organizational policy:
    LICENSE_IDENTIFIED
    LICENSE_UNKNOWN
    ATTRIBUTION_REQUIRED
    POLICY_ALLOWED
    POLICY_RESTRICTED
    REVIEW_REQUIRED
- Proves GPL / Copyleft is NOT hardcoded as universally invalid;
  it is governed by the organization's configurable LicensePolicy.
- Preserves license provenance and author attribution.
- Avoids making intrinsic legal conclusions.
"""
import pytest
from detection_content.canonical_ir import (
    CanonicalIR,
    FieldCompareNode,
    Operator,
    ProvenanceInfo,
    TranslationFidelity,
)
from detection_content.validation_framework import (
    ValidationGates,
    LicensePolicy,
    LicenseStatus,
)


def _build_rule_with_license(license_name: str, attribution: str = "Author Name") -> CanonicalIR:
    node = FieldCompareNode("process.name", Operator.EQUALS, "cmd.exe")
    prov = ProvenanceInfo(
        source="ExternalRepo",
        source_id="EXT-100",
        license=license_name,
        attribution=attribution,
    )
    return CanonicalIR(
        content_id="DET-LIC-001",
        name="License Test Rule",
        description="Testing license policy separation",
        tactic="Execution",
        technique_id="T1059",
        platform="windows",
        severity="medium",
        confidence="high",
        lane="content",
        required_fields=["process.name"],
        root_node=node,
        fidelity=TranslationFidelity.EXACT,
        provenance=prov,
    )


def test_license_identification_vs_policy_allowed():
    """Permissive licenses (Apache-2.0, MIT, DRL-1.1) evaluate as IDENTIFIED and POLICY_ALLOWED."""
    for lic in ("Apache-2.0", "MIT", "BSD-3-Clause", "DRL-1.1"):
        ir = _build_rule_with_license(lic)
        evaluation = ValidationGates.evaluate_license(ir)

        assert evaluation["identification_status"] == LicenseStatus.LICENSE_IDENTIFIED.value
        assert evaluation["policy_status"] == LicenseStatus.POLICY_ALLOWED.value
        assert evaluation["attribution_required"] is True

        res = ValidationGates.check_license_provenance(ir)
        assert res.passed is True


def test_gpl_governed_by_organizational_policy_not_intrinsic_truth():
    """GPL is NOT universally invalid: under default enterprise policy it is POLICY_RESTRICTED,
    but under an open-source or custom organization policy, it can be POLICY_ALLOWED."""
    ir_gpl = _build_rule_with_license("GPL-3.0")

    # 1. Under default enterprise policy:
    eval_default = ValidationGates.evaluate_license(ir_gpl)
    assert eval_default["identification_status"] == LicenseStatus.LICENSE_IDENTIFIED.value
    assert eval_default["policy_status"] == LicenseStatus.POLICY_RESTRICTED.value
    # Does NOT claim "GPL is illegal" - reason states organizational policy
    assert "restricted by organizational policy" in eval_default["reason"]

    # 2. Under a customized policy that permits GPL:
    custom_policy = LicensePolicy(
        allowed_licenses={"apache-2.0", "mit", "gpl-3.0", "gplv3"},
        restricted_licenses={"proprietary", "commercial"},
        review_licenses=set(),
    )
    eval_custom = ValidationGates.evaluate_license(ir_gpl, policy=custom_policy)
    assert eval_custom["identification_status"] == LicenseStatus.LICENSE_IDENTIFIED.value
    assert eval_custom["policy_status"] == LicenseStatus.POLICY_ALLOWED.value

    # Gate passes with custom policy
    res_custom = ValidationGates.check_license_provenance(ir_gpl, policy=custom_policy)
    assert res_custom.passed is True


def test_unknown_license_triggers_review_required():
    """Unrecognized or absent licenses trigger LICENSE_UNKNOWN and REVIEW_REQUIRED."""
    for bad_lic in ("", "unknown", "None", "Custom-Internal-Unspecified"):
        ir = _build_rule_with_license(bad_lic)
        eval_res = ValidationGates.evaluate_license(ir)

        if bad_lic in ("", "unknown", "None"):
            assert eval_res["identification_status"] == LicenseStatus.LICENSE_UNKNOWN.value
        assert eval_res["policy_status"] == LicenseStatus.REVIEW_REQUIRED.value

        res = ValidationGates.check_license_provenance(ir)
        assert res.passed is False
        assert "review required" in res.reasons[0].lower()


def test_attribution_required_gate_enforcement():
    """Licenses requiring attribution fail if author attribution is omitted."""
    ir_no_attr = _build_rule_with_license("Apache-2.0", attribution="")
    res = ValidationGates.check_license_provenance(ir_no_attr)
    assert res.passed is False
    assert "attribution" in res.reasons[0].lower()
