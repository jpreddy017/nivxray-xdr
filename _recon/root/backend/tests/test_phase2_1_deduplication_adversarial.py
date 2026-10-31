"""
NivXRay XDR — Phase 2.1 Adversarial Deduplication Test Suite.
Tests rules across all relationship classifications:
- DUPLICATE: syntactically identical, semantically identical, field-alias equivalent, logically reordered
- COMPLEMENTARY: similar but materially different, overlapping field set and same technique
- RELATED: same ATT&CK tactic or different telemetry domain
- CONFLICTING: contradictory/opposing boolean conditions
- UNIQUE: novel logic
Invariants enforced:
- Never merge merely because ATT&CK IDs match
- Never discard provenance
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


def _make_rule(
    rule_id: str,
    root_node,
    fields,
    technique="T1059",
    tactic="Execution",
    platform="windows",
    source="SigmaHQ",
    source_id="SIG-01",
) -> CanonicalIR:
    prov = ProvenanceInfo(
        source=source,
        source_id=source_id,
        license="Apache-2.0",
        attribution="Community",
    )
    return CanonicalIR(
        content_id=rule_id,
        name=f"Rule {rule_id}",
        description="Testing dedup",
        tactic=tactic,
        technique_id=technique,
        platform=platform,
        severity="medium",
        confidence="high",
        lane="content",
        required_fields=fields,
        root_node=root_node,
        fidelity=TranslationFidelity.EXACT,
        provenance=prov,
    )


def test_dedup_syntactically_identical():
    """Identical rules must be classified DUPLICATE and preserve both provenances."""
    node1 = FieldCompareNode("process.name", Operator.EQUALS, "cmd.exe")
    node2 = FieldCompareNode("process.name", Operator.EQUALS, "cmd.exe")

    r1 = _make_rule("R1", node1, ["process.name"], source="Sigma", source_id="S1")
    r2 = _make_rule("R2", node2, ["process.name"], source="Splunk", source_id="SPL1")

    engine = SemanticDeduplicationEngine([r1])
    verdict = engine.evaluate_candidate(r2)

    assert verdict.relationship == SemanticRelationship.DUPLICATE
    assert verdict.matched_rule_id == "R1"
    # Never discard provenance
    assert len(verdict.shared_sources) == 2
    sources = {s.source for s in verdict.shared_sources}
    assert sources == {"Sigma", "Splunk"}


def test_dedup_field_alias_equivalent():
    """Field alias equivalent rules (e.g. image vs process.name) must be classified DUPLICATE."""
    node_canon = FieldCompareNode("process.name", Operator.EQUALS, "powershell.exe")
    node_alias = FieldCompareNode("image", Operator.EQUALS, "powershell.exe")

    r_canon = _make_rule("R-CANON", node_canon, ["process.name"])
    r_alias = _make_rule("R-ALIAS", node_alias, ["process.name"])

    engine = SemanticDeduplicationEngine([r_canon])
    verdict = engine.evaluate_candidate(r_alias)

    assert verdict.relationship == SemanticRelationship.DUPLICATE
    assert verdict.matched_rule_id == "R-CANON"


def test_dedup_logically_reordered():
    """Boolean AND/OR nodes with reordered children must yield identical hash and be DUPLICATE."""
    c1 = FieldCompareNode("process.name", Operator.EQUALS, "powershell.exe")
    c2 = FieldCompareNode("process.command_line", Operator.CONTAINS, "-enc")

    # Order (c1, c2) vs (c2, c1)
    and_node_a = BooleanLogicNode(BooleanOp.AND, [c1, c2])
    and_node_b = BooleanLogicNode(BooleanOp.AND, [c2, c1])

    ra = _make_rule("R-ORDER-A", and_node_a, ["process.name", "process.command_line"])
    rb = _make_rule("R-ORDER-B", and_node_b, ["process.name", "process.command_line"])

    engine = SemanticDeduplicationEngine([ra])
    verdict = engine.evaluate_candidate(rb)

    assert verdict.relationship == SemanticRelationship.DUPLICATE
    assert verdict.matched_rule_id == "R-ORDER-A"


def test_dedup_conflicting_predicates():
    """Rules with contradictory conditions on the same field must be classified CONFLICTING."""
    node_assert = FieldCompareNode("process.name", Operator.EQUALS, "certutil.exe")
    node_negate = FieldCompareNode("process.name", Operator.NOT_EQUALS, "certutil.exe")

    r_assert = _make_rule("R-TRUE", node_assert, ["process.name"])
    r_negate = _make_rule("R-FALSE", node_negate, ["process.name"])

    engine = SemanticDeduplicationEngine([r_assert])
    verdict = engine.evaluate_candidate(r_negate)

    assert verdict.relationship == SemanticRelationship.CONFLICTING
    assert verdict.matched_rule_id == "R-TRUE"


def test_dedup_never_merge_merely_for_same_attack_id():
    """Rules with same ATT&CK ID (T1059) but completely different behavior must NEVER be DUPLICATE."""
    node_ps = FieldCompareNode("process.name", Operator.EQUALS, "powershell.exe")
    node_bash = FieldCompareNode("process.name", Operator.EQUALS, "bash")

    r_ps = _make_rule("R-PS", node_ps, ["process.name"], technique="T1059", platform="windows")
    r_bash = _make_rule("R-BASH", node_bash, ["process.name"], technique="T1059", platform="linux")

    engine = SemanticDeduplicationEngine([r_ps])
    verdict = engine.evaluate_candidate(r_bash)

    assert verdict.relationship != SemanticRelationship.DUPLICATE
    # Cross-platform with same tactic is RELATED or UNIQUE, never DUPLICATE
    assert verdict.relationship in (SemanticRelationship.RELATED, SemanticRelationship.UNIQUE)


def test_dedup_complementary_coverage():
    """Rules with same technique and platform but different argument scopes are COMPLEMENTARY."""
    n1 = FieldCompareNode("process.command_line", Operator.CONTAINS, "downloadstring")
    n2 = FieldCompareNode("process.command_line", Operator.CONTAINS, "invoke-expression")

    r1 = _make_rule("R-ARG1", n1, ["process.command_line"], technique="T1059.001", platform="windows")
    r2 = _make_rule("R-ARG2", n2, ["process.command_line"], technique="T1059.001", platform="windows")

    engine = SemanticDeduplicationEngine([r1])
    verdict = engine.evaluate_candidate(r2)

    assert verdict.relationship == SemanticRelationship.COMPLEMENTARY
    assert verdict.matched_rule_id == "R-ARG1"
