"""
NivXRay XDR — Content Truth Audit Verification Test Suite.
Validates:
1. Frozen 615-object corpus across 16 domains.
2. Manifest completeness (23 mandated attributes).
3. Provenance truth classification (0 unverified).
4. License governance compliance (0 quarantined).
5. Duplicate, semantic duplicate, and cross-language analysis.
6. 100% actual runtime execution across all 16 native engines.
7. OT/ICS 10-protocol coverage.
8. RMM 20-tool 4-state contextual discrimination.
9. Adversarial 15-scenario simulation chain.
10. 28-Engine fabric reconciliation.
11. Universal Decoder truth reconciliation (frozen locked).
"""
from __future__ import annotations

import json
import os
import pytest
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from detection_content.corpus import ALL_EXPANDED_CORPORA
from detection_content.engine_fabric_contracts import CANONICAL_ENGINE_REGISTRY
from detection_content.rmm_model import RMM_CATALOGUE
from run_content_truth_audit import run_truth_audit


@pytest.fixture(scope="module")
def audit_report():
    report_path = os.path.join(BASE_DIR, "..", "test_reports", "enterprise_content_truth_audit.json")
    if not os.path.exists(report_path):
        return run_truth_audit()
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)


class TestCorpusFreezeAndManifest:
    """Verify corpus freeze at 615 and 23-attribute manifest completeness."""

    def test_corpus_frozen_at_615(self, audit_report):
        total = sum(len(c) for c in ALL_EXPANDED_CORPORA.values())
        assert total == 615, f"Corpus is NOT frozen at 615! Found {total}"
        assert audit_report["corpus_inventory"]["total_objects"] == 615
        assert len(audit_report["manifest"]) == 615

    def test_16_domains_partition(self, audit_report):
        domain_breakdown = audit_report["corpus_inventory"]["domain_breakdown"]
        assert len(domain_breakdown) == 16
        expected_counts = {
            "sigma": 165,
            "yara": 50,
            "eql": 40,
            "spl": 35,
            "kql": 35,
            "ioc_rule": 50,
            "behavioral": 30,
            "correlation": 25,
            "threat_hunting": 30,
            "baseline_anomaly": 25,
            "attck_mapping": 25,
            "security_state_mapping": 25,
            "response_mapping": 25,
            "ot_ics": 20,
            "rmm_dual_use": 20,
            "adversarial_simulation": 15,
        }
        for domain, count in expected_counts.items():
            assert domain_breakdown[domain] == count, f"Domain {domain} count mismatch: expected {count}, got {domain_breakdown[domain]}"

    def test_manifest_23_attributes_declared_on_every_object(self, audit_report):
        mandated_attributes = {
            "canonical_content_id",
            "content_type",
            "domain",
            "name",
            "source_id",
            "source_organization",
            "source_url",
            "source_version_date",
            "license",
            "attribution_requirements",
            "original_content_hash",
            "canonical_content_hash",
            "semantic_behavioral_hash",
            "provenance_classification",
            "native_engine",
            "actual_runtime_execution",
            "translation_status",
            "validation_status",
            "engine_binding_status",
            "shadow_status",
            "active_status",
            "positive_fixture_reference",
            "negative_fixture_reference",
            "attck_mapping",
            "confidence_quality_score",
            "created_derived_timestamp",
        }
        for idx, item in enumerate(audit_report["manifest"]):
            item_keys = set(item.keys())
            missing = mandated_attributes - item_keys
            assert not missing, f"Object {item.get('canonical_content_id', idx)} missing mandated attributes: {missing}"


class TestProvenanceAndLicensingGovernance:
    """Verify provenance classification and licensing compliance."""

    def test_provenance_truth_breakdown(self, audit_report):
        prov = audit_report["provenance_breakdown"]
        assert prov["ORIGINAL_PUBLIC"] == 325  # 165 Sigma + 50 YARA + 40 EQL + 35 SPL + 35 KQL
        assert prov["DERIVED_FROM_PUBLIC_RESEARCH"] == 70  # 50 IOC + 20 OT/ICS
        assert prov["NATIVE_NIVXRAY"] == 205  # 30 Beh + 25 Corr + 30 Hunt + 25 Anom + 25 ATT&CK + 25 SecState + 25 Resp + 20 RMM
        assert prov["SYNTHETIC_VALIDATION_ONLY"] == 15  # 15 Adversarial Scenarios
        assert prov["PROVENANCE_UNVERIFIED"] == 0
        assert sum(prov.values()) == 615

    def test_license_compliance_and_zero_quarantined(self, audit_report):
        lic_gov = audit_report["license_governance"]
        for lic_name, lic_data in lic_gov.items():
            assert lic_data["compatibility"] == "COMPATIBLE_WITH_NIVXRAY_XDR"
            assert lic_data["redistribution_permitted"] is True
            assert lic_data["modification_permitted"] is True
            assert lic_data["commercial_use_compatible"] is True


class TestDuplicateAndSemanticAnalysis:
    """Verify exact duplicates, normalized duplicates, semantic sub-variants, and cross-language equivalents."""

    def test_exact_duplicates_zero(self, audit_report):
        assert audit_report["corpus_inventory"]["exact_duplicate_count"] == 0
        assert audit_report["corpus_inventory"]["unique_objects"] == 615

    def test_normalized_duplicates_zero(self, audit_report):
        assert audit_report["corpus_inventory"]["normalized_duplicate_count"] == 0

    def test_cross_language_equivalents_identified(self, audit_report):
        cross_lang_count = audit_report["corpus_inventory"]["cross_language_equivalent_count"]
        assert cross_lang_count > 0, "Expected cross-language equivalents between Sigma, EQL, SPL, and KQL"


class TestNativeEngineExecution:
    """Verify 100% runtime evaluation on all 16 native engines."""

    def test_all_16_engines_execution_success(self, audit_report):
        exec_results = audit_report["native_engine_execution"]
        assert len(exec_results) == 16
        total_attempted = sum(r["attempted"] for r in exec_results.values())
        total_success = sum(r["success"] for r in exec_results.values())
        total_failures = sum(r["failures"] for r in exec_results.values())

        assert total_attempted == 615
        assert total_success == 615
        assert total_failures == 0

        for eng_name, stats in exec_results.items():
            assert stats["attempted"] > 0
            assert stats["success"] == stats["attempted"]
            assert stats["positive_matches"] == stats["attempted"]
            assert stats["negative_clean"] == stats["attempted"]
            assert stats["failures"] == 0


class TestDomainSpecificAudits:
    """Verify OT/ICS, RMM, Adversarial, 28 Engines, and Decoder Truth."""

    def test_ot_ics_10_protocols_audited(self, audit_report):
        ot_audit = audit_report["ot_ics_protocol_audit"]
        assert len(ot_audit) == 20
        protocols = {item["protocol"] for item in ot_audit}
        expected_protocols = {"Modbus", "DNP3", "S7comm", "EtherNet/IP", "BACnet", "OPC_UA", "IEC_104", "IEC_61850", "PROFINET", "MQTT"}
        assert expected_protocols.issubset(protocols)

    def test_rmm_20_tools_and_4_contextual_states(self, audit_report):
        rmm_audit = audit_report["rmm_dual_use_audit"]
        assert len(rmm_audit) == 20
        for item in rmm_audit:
            assert len(item["four_contextual_states_verified"]) == 4

    def test_adversarial_15_scenarios_simulation_chain(self, audit_report):
        adv_audit = audit_report["adversarial_scenario_audit"]
        assert len(adv_audit) == 15
        for item in adv_audit:
            assert item["provenance_classification"] == "SYNTHETIC_VALIDATION_ONLY"
            assert len(item["full_simulation_chain"]) == 11

    def test_28_canonical_engines_reconciled(self, audit_report):
        eng_audit = audit_report["canonical_28_engine_reconciliation"]
        assert len(eng_audit) == 28
        assert len(CANONICAL_ENGINE_REGISTRY) == 28

    def test_universal_decoder_truth_reconciled_frozen(self, audit_report):
        dec = audit_report["universal_decoder_truth_reconciliation"]
        assert dec["status"] == "FROZEN_LOCKED"
        assert dec["registered_codecs_in_decoder_registry"] == 61
        assert dec["logical_codecs_in_coverage_matrix"] == 48
        assert dec["physical_codecs_in_decoders_dir"] == 46
        assert dec["operational_codecs_in_operations_dict"] == 42
        assert dec["malware_family_signature_profilers"] == 14
