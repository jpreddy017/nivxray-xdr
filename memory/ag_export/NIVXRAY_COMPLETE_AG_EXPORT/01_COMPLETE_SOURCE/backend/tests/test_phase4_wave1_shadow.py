"""Phase 4 Wave 1 · Read-only canonical-shadow attach tests.

Locks the owner-mandated Wave-1 contract:
  * `verdict_shadow` is attached ALONGSIDE `verdict`, never as a replacement.
  * Shadow computation NEVER raises — a failure returns `None`.
  * Rich comparison payload includes: existing verdict + canonical
    verdict + input completeness + divergence class.
  * Input Completeness reports which of the 9 InvestigationModel
    buckets were populated.
  * Divergence classifier uses `INPUT-CONTRACT-UNRESOLVED` when
    completeness < 45%.
  * `auto_investigate.py` imports `compute_shadow` and calls it at
    the right point in the pipeline.
"""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from v2.verdict.shadow import compute_shadow, _classify_divergence, \
    _completeness_class, _compute_input_completeness
from v2.investigation.model import (
    InvestigationModel, IncidentMetadata, ProcessChain, FileEvent,
    NetworkEvent, RegistryEvent, TIItem,
)


# ══════════════════════════════════════════════════════════════════
# 1. Completeness classification
# ══════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("n,expected", [
    (0, "minimal"), (1, "minimal"),
    (2, "sparse"),  (3, "sparse"),
    (4, "moderate"), (6, "moderate"),
    (7, "rich"), (9, "rich"),
])
def test_completeness_class(n, expected):
    assert _completeness_class(n) == expected


def test_input_completeness_shape():
    m = InvestigationModel()
    m.processes = [ProcessChain(process="powershell.exe",
                                       command_line="powershell -NoP -c whoami")]
    m.files = [FileEvent(path="C:\\evil.exe")]
    r = _compute_input_completeness(m)
    assert r["buckets_populated"]["process_activity"] is True
    assert r["buckets_populated"]["file_activity"] is True
    assert r["buckets_populated"]["network_activity"] is False
    assert r["populated_count"] == 2
    assert r["buckets_total"] == 9
    assert r["completeness_pct"] == round(2 / 9 * 100)
    assert r["coverage_class"] == "sparse"


# ══════════════════════════════════════════════════════════════════
# 2. Divergence classifier — owner-mandated INPUT-CONTRACT-UNRESOLVED
# ══════════════════════════════════════════════════════════════════
def test_agree_when_labels_match():
    d = _classify_divergence("Malicious", "Malicious", 90)
    assert d["class"] == "AGREE"


def test_input_contract_unresolved_when_completeness_low():
    """Owner-mandated: when completeness < 45%, disagreements must be
    marked INPUT-CONTRACT-UNRESOLVED — NOT prematurely called
    false-negatives/positives."""
    d = _classify_divergence("Malicious", "Informational", 22)
    assert d["class"] == "INPUT-CONTRACT-UNRESOLVED"


def test_intentional_scope_when_both_flagged():
    d = _classify_divergence("Malicious", "Suspicious", 75)
    assert d["class"] == "INTENTIONAL-SCOPE"


def test_potential_false_negative_when_canonical_low_but_existing_high():
    d = _classify_divergence("Malicious", "Informational", 80)
    assert d["class"] == "POTENTIAL-FALSE-NEGATIVE"


def test_potential_false_positive_when_canonical_high_but_existing_low():
    d = _classify_divergence("Undetermined", "Malicious", 80)
    assert d["class"] == "POTENTIAL-FALSE-POSITIVE"


def test_other_divergence_when_neither_axis_matches():
    d = _classify_divergence("Runtime Dependent", "Informational", 80)
    assert d["class"] == "OTHER-DIVERGENCE"


# ══════════════════════════════════════════════════════════════════
# 3. compute_shadow — never raises, returns rich payload
# ══════════════════════════════════════════════════════════════════
def _mock_cio(existing_label: str = "Suspicious",
                  add_graph_nodes: bool = False):
    """Build a minimal CIO-like object the shadow can consume.

    Uses `kind="ioc"` because the nivxforge Node literal-type
    constrains kinds. The shadow's projection is tolerant of empty
    lanes and still returns a valid payload — that's what we test."""
    from nivxforge.investigation.graph import EvidenceGraph, Node
    g = EvidenceGraph()
    if add_graph_nodes:
        g.add_node(Node(id="N-001", kind="lolbin",
                             label="powershell", value="powershell.exe",
                             confidence=0.9, provenance="test"))
        g.add_node(Node(id="N-002", kind="ioc",
                             label="https://evil.example/x",
                             value="https://evil.example/x",
                             confidence=0.9, provenance="test"))
    cio = MagicMock()
    cio.metadata = {"input_text_normalised": "powershell -EncodedCommand JAB..."}
    cio.evidence_graph = g
    cio.verdict = {"label": existing_label, "confidence_pct": 73,
                       "reason": "test"}
    return cio


def test_compute_shadow_returns_none_or_payload_never_raises():
    """Shadow must never raise — even on garbage input."""
    class _Garbage:  pass
    result = compute_shadow(_Garbage())
    # Either an error record dict or None — never an exception.
    assert result is None or isinstance(result, dict)


def test_compute_shadow_produces_full_payload_with_graph():
    cio = _mock_cio(add_graph_nodes=True)
    r = compute_shadow(cio)
    assert r is not None
    assert "shadow_engine" in r
    assert r["shadow_engine"].startswith("canonical-v2-verdict")
    assert "existing_verdict" in r
    assert r["existing_verdict"]["label"] == "Suspicious"
    assert "verdict_canonical" in r
    assert r["verdict_canonical"]["label"] in (
        "Undetermined", "Informational", "Runtime Dependent",
        "Suspicious", "Malicious",
    )
    assert "input_completeness" in r
    ic = r["input_completeness"]
    assert "buckets_populated" in ic
    assert "completeness_pct" in ic
    assert "coverage_class" in ic
    assert "divergence" in r
    assert r["divergence"]["class"] in (
        "AGREE", "INPUT-CONTRACT-UNRESOLVED", "INTENTIONAL-SCOPE",
        "POTENTIAL-FALSE-NEGATIVE", "POTENTIAL-FALSE-POSITIVE",
        "OTHER-DIVERGENCE",
    )
    assert "no consumer switch" in r["shadow_mode"]


def test_compute_shadow_deterministic():
    cio1 = _mock_cio(add_graph_nodes=True)
    cio2 = _mock_cio(add_graph_nodes=True)
    r1 = compute_shadow(cio1)
    r2 = compute_shadow(cio2)
    assert r1 is not None and r2 is not None
    assert r1["verdict_canonical"]["label"] == r2["verdict_canonical"]["label"]
    assert r1["verdict_canonical"]["confidence_pct"] == r2["verdict_canonical"]["confidence_pct"]
    assert r1["input_completeness"] == r2["input_completeness"]


# ══════════════════════════════════════════════════════════════════
# 4. Wiring — auto_investigate.py imports and calls compute_shadow
# ══════════════════════════════════════════════════════════════════
def test_auto_investigate_imports_compute_shadow():
    """The router MUST import compute_shadow from v2.verdict.shadow
    and call it. Enforced via AST — cheap, robust."""
    p = Path("/app/backend/routers/auto_investigate.py")
    tree = ast.parse(p.read_text())

    imported = False
    called   = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module == "v2.verdict.shadow" and \
                    any(n.name == "compute_shadow" for n in node.names):
                imported = True
        # Detect any Call referencing compute_shadow / _compute_shadow
        if isinstance(node, ast.Call):
            fn = node.func
            name = (fn.attr if isinstance(fn, ast.Attribute)
                        else (fn.id if isinstance(fn, ast.Name) else ""))
            if name in ("compute_shadow", "_compute_shadow"):
                called = True
    assert imported, "auto_investigate.py must import compute_shadow"
    assert called,   "auto_investigate.py must invoke compute_shadow"


def test_auto_investigate_attaches_verdict_shadow_key():
    """Contract: the router must attach the shadow result to
    `result[\"verdict_shadow\"]` (never to `result[\"verdict\"]`)."""
    src = Path("/app/backend/routers/auto_investigate.py").read_text()
    assert "verdict_shadow" in src, \
        "auto_investigate.py must attach `verdict_shadow` key"
    # Guardrail: shadow must NEVER overwrite the primary verdict field.
    # No line may write `result["verdict"] = _shadow` or similar.
    assert 'result["verdict"] = _shadow' not in src
    assert "result['verdict'] = _shadow" not in src


# ══════════════════════════════════════════════════════════════════
# 5. Shadow has no legacy-engine imports
# ══════════════════════════════════════════════════════════════════
def test_shadow_has_no_legacy_engine_imports():
    """Shadow module must not depend on any legacy verdict engine."""
    p = Path("/app/backend/v2/verdict/shadow.py")
    tree = ast.parse(p.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            assert "nivxforge.investigation.verdict_engine" not in mod
            assert "engine.detectors.verdict_v2" not in mod
            assert "v2.semantic.ps_verdict" not in mod
        elif isinstance(node, ast.Import):
            for n in node.names:
                assert "nivxforge.investigation.verdict_engine" not in n.name
                assert "engine.detectors.verdict_v2" not in n.name
                assert "v2.semantic.ps_verdict" not in n.name
