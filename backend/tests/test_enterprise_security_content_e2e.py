"""
NivXRay XDR — Enterprise Security Content E2E Validation Test Suite
Tests:
1. Canonical content model (13 content types, categories, 31 attributes, lifecycle states).
2. First-class YARA engine (wildcard byte matching, PE magic, regex, canonical evidence generation).
3. Artifact-First Analysis Router (entropy, file format dispatch, payload discovery, decoder gating, Security State bridge).
4. RMM Trusted Capability Abuse Model (14 tools across 12 contextual dimensions).
5. Translation fidelity & semantic preservation (Sigma, YARA, EQL, SPL, KQL, IOC, etc.).
6. Programmatic Quality Gates (15 gates) and Deduplication engine.
7. Live end-to-end pipeline execution verifying zero unsupported rules.
"""
from __future__ import annotations

import json
import pytest
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from detection_content.canonical_content_model import (
    build_canonical_content,
    CanonicalContentObject,
    ContentCategory,
    ContentLifecycleState,
    ContentSource,
    ContentType,
    get_content_category,
)
from detection_content.yara_engine import (
    YaraExecutionEngine,
    YaraParser,
    YaraRule,
    YaraRuleMatch,
    YARA_ENGINE,
)
from detection_content.artifact_router import (
    ArtifactAnalysisReport,
    ArtifactRouter,
    compute_shannon_entropy,
)
from detection_content.rmm_model import (
    CapabilityAbuseState,
    ContextualAssessment,
    RMMCapabilityEvaluator,
    RMM_CATALOGUE,
)
from detection_content.translation.manager import TRANSLATION_MANAGER
from detection_content.deduplication.engine import (
    DeduplicationVerdict,
    SemanticDeduplicationEngine,
    SemanticRelationship,
)
from detection_content.validation_framework.gates import ValidationGates
from run_enterprise_content_pipeline import run_enterprise_pipeline


class TestCanonicalContentModel:
    """Verify Canonical Content Model contracts, attributes, and lifecycle."""

    def test_13_content_types_present(self):
        expected_types = {
            ContentType.SIGMA,
            ContentType.YARA,
            ContentType.EQL,
            ContentType.SPL,
            ContentType.KQL,
            ContentType.IOC_RULE,
            ContentType.BEHAVIORAL,
            ContentType.CORRELATION,
            ContentType.THREAT_HUNTING,
            ContentType.BASELINE_ANOMALY,
            ContentType.ATTCK_MAPPING,
            ContentType.SECURITY_STATE_MAPPING,
            ContentType.RESPONSE_MAPPING,
        }
        actual_types = set(ContentType)
        assert expected_types == actual_types, f"Mismatch in content types: {actual_types ^ expected_types}"

    def test_content_categories_partition(self):
        for ct in ContentType:
            cat = get_content_category(ct)
            assert isinstance(cat, ContentCategory), f"Type {ct} returned invalid category {cat}"

    def test_canonical_content_object_creation_and_hash(self):
        obj = build_canonical_content(
            content_id="SIG-001",
            name="Test Sigma Rule",
            content_type=ContentType.SIGMA,
            description="Test rule description",
            source=ContentSource.SIGMAHQ,
            source_id="sigma-rule-uuid",
            license="Apache-2.0",
            platform=["windows"],
            severity="high",
            confidence=0.92,
            mitre_attack=[{"id": "T1059.001", "tactic": "execution"}],
            kill_chain=["execution"],
            logic={"selection": {"CommandLine|contains": "mimikatz"}},
        )
        assert obj.content_id == "SIG-001"
        assert obj.category == ContentCategory.DETECTION.value
        assert obj.status == ContentLifecycleState.DISCOVERED.value
        assert len(obj.semantic_equivalence) == 64  # SHA-256

        # Transition lifecycle
        assert obj.transition(ContentLifecycleState.PARSED) is True
        assert obj.status == ContentLifecycleState.PARSED.value


class TestFirstClassYaraEngine:
    """Verify native YARA engine with wildcard hex, PE magic, and canonical evidence."""

    def test_yara_parser_and_hex_wildcard_matching(self):
        rule_source = """
        rule CobaltStrike_Beacon_Pattern {
            meta:
                author = "NivXRay Detection Engineering"
                description = "Detects Cobalt Strike beacon memory/file pattern"
                severity = "critical"
                cve = "CVE-2022-9999"
            strings:
                $magic = { 4D 5A }
                $beacon_hex = { 68 74 74 70 3F ?? ?? 2E }
                $beacon_str = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x"
            condition:
                $magic at 0 and ($beacon_hex or $beacon_str)
        }
        """
        rule = YaraParser.parse_rule_text(rule_source)
        assert rule is not None
        assert rule.name == "CobaltStrike_Beacon_Pattern"
        assert len(rule.strings) == 3

        # Positive test payload: MZ header + matching hex pattern
        # { 68 74 74 70 3F ?? ?? 2E } => "http?" + 2 wildcard bytes + "."
        payload = b"MZ\x90\x00\x03\x00\x00\x00http?AB.test_c2_data_stream_extra"
        match = rule.evaluate(payload)
        assert match is not None

        engine = YaraExecutionEngine()
        engine.register_rule(rule)
        matches = engine.scan_artifact(payload, filename="sample.exe")
        assert len(matches) == 1
        m = matches[0]
        assert m.rule_name == "CobaltStrike_Beacon_Pattern"

        ev = m.to_evidence(payload, filename="sample.exe")
        assert ev["evidence_type"] == "artifact_yara_detection"
        assert ev["yara_match"]["rule_name"] == "CobaltStrike_Beacon_Pattern"
        assert len(ev["artifact"]["sha256"]) == 64
        assert ev["artifact"]["filename"] == "sample.exe"

    def test_yara_negative_payload(self):
        payload = b"Random clean text without PE magic or beacon signatures."
        engine = YaraExecutionEngine()
        matches = engine.scan_artifact(payload, filename="clean.txt")
        assert len(matches) == 0


class TestArtifactRouter:
    """Verify Artifact-First routing, entropy analysis, and decoder invocation."""

    def test_artifact_routing_and_entropy(self):
        # PE binary simulation
        pe_content = b"MZ" + b"\x00" * 200 + b"This program cannot be run in DOS mode."
        report1 = ArtifactRouter.route_and_analyze(pe_content, filename="sample.exe")
        assert report1.artifact_type == "windows_pe"
        assert report1.entropy > 0.0

        # Script with base64 encoded command (triggers payload discovery)
        script_content = b'powershell.exe -e JAB4ID0gIkV4ZWN1dGUiOw=='
        report2 = ArtifactRouter.route_and_analyze(script_content, filename="deploy.ps1")
        assert "powershell" in report2.artifact_type or "script" in report2.artifact_type
        assert len(report2.embedded_payloads_discovered) > 0
        assert report2.decoder_invoked is True


class TestRMMCapabilityAbuseModel:
    """Verify 14 RMM tools across 12 contextual dimensions."""

    def test_14_rmm_profiles_loaded(self):
        assert len(RMM_CATALOGUE) == 14
        expected_tools = [
            "AnyDesk", "ConnectWise ScreenConnect", "Atera", "Splashtop",
            "TeamViewer", "NinjaOne", "MeshCentral / MeshAgent", "RustDesk",
            "GoTo / LogMeIn", "NetSupport Manager", "SimpleHelp",
            "PDQ Deploy", "N-able", "Level.io"
        ]
        catalogue_names = [p.name for p in RMM_CATALOGUE.values()]
        for tool in expected_tools:
            assert tool in catalogue_names, f"Missing RMM tool: {tool}"

    def test_rmm_authorized_vs_abused_state(self):
        # Context 1: Normal authorized AnyDesk admin session
        verdict_norm = RMMCapabilityEvaluator.evaluate_rmm_context(
            process_name=r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe",
            command_line="AnyDesk.exe --tray",
            identity="CORP\\admin_sec",
            is_authorized_identity=True,
            install_path=r"C:\Program Files (x86)\AnyDesk",
            execution_hour=14,
            parent_process="explorer.exe",
            has_suspicious_flags=False,
            preceded_by_phishing_or_dumping=False,
            reachability_to_crown_jewels=False,
        )
        assert verdict_norm.abuse_state == CapabilityAbuseState.AUTHORIZED_ACTIVITY

        # Context 2: Unauthorized AnyDesk staged in Temp during off-hours with silent install
        verdict_attack = RMMCapabilityEvaluator.evaluate_rmm_context(
            process_name=r"C:\Users\Public\AppData\Local\Temp\AnyDesk.exe",
            command_line="AnyDesk.exe --install C:\\ProgramData\\AnyDesk --silent",
            identity="NT AUTHORITY\\SYSTEM",
            is_authorized_identity=False,
            install_path=r"C:\Users\Public\AppData\Local\Temp",
            execution_hour=2,
            parent_process="cmd.exe",
            has_suspicious_flags=True,
            preceded_by_phishing_or_dumping=True,
            reachability_to_crown_jewels=True,
            target_crown_jewels=["DC01.corp.internal"],
        )
        assert verdict_attack.abuse_state == CapabilityAbuseState.CONFIRMED_ATTACK
        assert "CONFIRMED ATTACK" in verdict_attack.explanation


class TestTranslationAndValidationGates:
    """Verify programmatic quality gates, deduplication, and translation across formats."""

    def test_sigma_translation_and_gates(self):
        sigma_yaml = """
        title: Suspicious PowerShell Download
        id: SIG-TEST-001
        status: test
        description: Detects powershell web client download
        author: NivXRay
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine|contains: 'System.Net.WebClient'
            condition: selection
        level: high
        tags:
            - attack.execution
            - attack.t1059.001
        """
        trans = TRANSLATION_MANAGER.translate(sigma_yaml, format_hint="sigma")
        assert trans.success is True
        ir = trans.ir
        assert ir.content_id.startswith("DET-SIGMA-")
        assert ir.technique_id == "T1059.001"

        # Evaluate quality gate
        pos_event = {"CommandLine": "powershell.exe (New-Object System.Net.WebClient).DownloadFile()"}
        neg_event = {"CommandLine": "notepad.exe C:\\notes.txt"}
        gate_res = ValidationGates.evaluate_quality_gate(ir, positive_event=pos_event, negative_event=neg_event)
        assert gate_res["all_passed"] is True
        assert len(gate_res["passed_gates"]) >= 6
        assert len(gate_res["failed_gates"]) == 0

    def test_deduplication_engine(self):
        dedup = SemanticDeduplicationEngine()
        sigma1 = """
        title: Whoami Execution
        id: SIG-WHOAMI-1
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Image|endswith: '\\whoami.exe'
            condition: selection
        """
        sigma2 = """
        title: Whoami Discovery Invocation
        id: SIG-WHOAMI-2
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Image|endswith: '\\whoami.exe'
            condition: selection
        """
        ir1 = TRANSLATION_MANAGER.translate(sigma1, format_hint="sigma").ir
        ir2 = TRANSLATION_MANAGER.translate(sigma2, format_hint="sigma").ir

        v1 = dedup.evaluate_candidate(ir1)
        assert v1.relationship == SemanticRelationship.UNIQUE
        dedup.index_rule(ir1)

        v2 = dedup.evaluate_candidate(ir2)
        assert v2.relationship == SemanticRelationship.DUPLICATE


class TestLiveEnterprisePipelineRunner:
    """Run full live enterprise content pipeline and assert 100% active validation."""

    def test_pipeline_execution_active_count(self):
        report = run_enterprise_pipeline()
        totals = report["totals"]
        assert totals["discovered"] >= 500
        assert totals["parsed"] == totals["discovered"]
        assert totals["license_verified"] == totals["discovered"]
        assert totals["normalized"] == totals["discovered"]
        assert totals["translated"] == totals["discovered"]
        assert totals["validated"] == totals["discovered"]
        assert totals["active"] == totals["discovered"]
        assert totals["unsupported"] == 0
        assert report["total_active_content_objects"] >= 500

    def test_expanded_16_domain_coverage(self):
        report = run_enterprise_pipeline()
        inv = report["inventory_by_content_type"]
        assert len(inv) == 16, f"Expected 16 content domains, got {len(inv)}"
        for domain_name, stats in inv.items():
            assert stats["active"] > 0, f"Domain {domain_name} has zero active rules"
            assert stats["unsupported"] == 0, f"Domain {domain_name} has unsupported rules"

    def test_ot_ics_industrial_protocol_coverage(self):
        from detection_content.corpus.ot_ics_rmm_corpus import OT_ICS_CORPUS
        assert len(OT_ICS_CORPUS) == 20
        protocols = {rule["positive_event"]["protocol"] for rule in OT_ICS_CORPUS}
        expected = {"Modbus", "DNP3", "S7comm", "EtherNet/IP", "BACnet", "OPC_UA", "IEC_104", "IEC_61850", "PROFINET", "MQTT"}
        assert expected.issubset(protocols), f"Missing industrial protocols: {expected - protocols}"

    def test_canonical_engine_fabric_reconciliation_contracts(self):
        from detection_content.engine_fabric_contracts import (
            CANONICAL_ENGINE_REGISTRY,
            IUEContentFeedContract,
            VEEEEvidenceFeedContract,
            ICECorrelationFeedContract,
            SecurityStateBridgeContract,
            EngineFabricRouter,
            EngineStatus,
        )
        assert len(CANONICAL_ENGINE_REGISTRY) == 28
        # Ensure mandatory engines are present and cataloged
        for mandatory_engine in ["IUE", "VEEE", "IEDDE", "UAIE", "ICE", "IKG", "VerdictEngine", "SecurityState"]:
            assert mandatory_engine in CANONICAL_ENGINE_REGISTRY
            assert CANONICAL_ENGINE_REGISTRY[mandatory_engine].classification in (
                EngineStatus.IMPLEMENTED,
                EngineStatus.NEEDS_INTEGRATION,
                EngineStatus.PARTIAL,
            )

        # Test distribution router across all 28 engines
        router = EngineFabricRouter()
        report = run_enterprise_pipeline()
        dist_res = router.distribute_knowledge([])
        assert dist_res["total_engines_registered"] == 28
        assert dist_res["implemented_engines"] >= 20

        # Test strongly-typed contract instances
        assert router.iue_contract.target_engine == "IUE"
        assert router.veee_contract.target_engine == "VEEE"
        assert router.ice_contract.target_engine == "ICE"
        assert router.sec_state_contract.target_engine == "SecurityState"

