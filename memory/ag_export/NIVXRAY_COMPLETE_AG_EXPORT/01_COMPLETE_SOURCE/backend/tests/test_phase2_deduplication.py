"""
Unit Tests for Phase 2E Semantic Fingerprinting & Deduplication Engine.
Verifies cross-format duplicate identification, complementary rule linking,
provenance preservation, and behavioral fingerprint determinism.
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
from detection_content.deduplication import (
    BehavioralFingerprinter,
    DeduplicationVerdict,
    SemanticDeduplicationEngine,
    SemanticRelationship,
)


def _create_rule(content_id: str, proc_name: str, cmd_arg: str, source: str = "SigmaHQ") -> CanonicalIR:
    node = BooleanLogicNode(
        BooleanOp.AND,
        [
            FieldCompareNode("process.name", Operator.EQUALS, proc_name),
            FieldCompareNode("process.command_line", Operator.CONTAINS, cmd_arg),
        ],
    )
    prov = ProvenanceInfo(
        source=source,
        source_id=f"SRC-{content_id}",
        source_url=f"https://github.com/rules/{content_id}",
        license="Apache-2.0",
        attribution="Community",
    )
    return CanonicalIR(
        content_id=content_id,
        name=f"Rule {content_id}",
        description="Testing dedup",
        tactic="Execution",
        technique_id="T1059.001",
        platform="windows",
        severity="high",
        confidence="high",
        lane="content",
        required_fields=["process.name", "process.command_line"],
        root_node=node,
        fidelity=TranslationFidelity.EXACT,
        provenance=prov,
    )


def test_fingerprint_determinism():
    rule1 = _create_rule("R1", "powershell.exe", "-enc")
    rule2 = _create_rule("R2", "powershell.exe", "-enc")

    fp1 = BehavioralFingerprinter.compute_fingerprint(rule1)
    fp2 = BehavioralFingerprinter.compute_fingerprint(rule2)

    # Identical AST and behavioral attributes must yield 100% identical semantic hash
    assert fp1["semantic_hash"] == fp2["semantic_hash"]
    assert fp1["ast_hash"] == fp2["ast_hash"]


def test_deduplication_exact_duplicate_detection():
    engine = SemanticDeduplicationEngine()

    rule_sigma = _create_rule("DET-SIGMA-001", "powershell.exe", "-enc", source="SigmaHQ")
    engine.index_rule(rule_sigma)

    # Incoming rule from Splunk with exact same logic
    rule_splunk = _create_rule("DET-SPLUNK-001", "powershell.exe", "-enc", source="Splunk STRT")

    verdict = engine.evaluate_candidate(rule_splunk)
    assert verdict.relationship == SemanticRelationship.DUPLICATE
    assert verdict.matched_rule_id == "DET-SIGMA-001"
    assert verdict.similarity_score == 1.0

    # Verify provenance retained from BOTH sources
    assert len(verdict.shared_sources) == 2
    sources = [s.source for s in verdict.shared_sources]
    assert "SigmaHQ" in sources
    assert "Splunk STRT" in sources


def test_deduplication_unique_rule():
    engine = SemanticDeduplicationEngine()
    rule1 = _create_rule("R1", "powershell.exe", "-enc")
    engine.index_rule(rule1)

    rule_novel = _create_rule("R_NEW", "vssadmin.exe", "delete shadows")
    rule_novel.technique_id = "T1490"
    rule_novel.tactic = "Impact"

    verdict = engine.evaluate_candidate(rule_novel)
    assert verdict.relationship == SemanticRelationship.UNIQUE
    assert verdict.matched_rule_id is None
