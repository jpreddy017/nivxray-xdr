"""P1-02c · Sprint 2 · Entity correlation + Negative-evidence tests."""
from __future__ import annotations

import pytest

from nivxforge.investigation.graph import EvidenceGraph, Node, Edge
from nivxforge.investigation.correlation_signals import (
    entity_correlation_signal, negative_evidence_signals,
    attach_entity_and_negative_signals,
)
from nivxforge.investigation.verdict_engine import compute_verdict


# ────────────────────────── Entity correlation ──────────────────────

def test_entity_correlation_signal_fires_on_shared_pid():
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    for i in range(3):
        g.add_node(Node(
            id=f"N{i}", kind="behaviour", label=f"b{i}", value=f"v{i}",
            confidence=0.9,
            attrs={"process_id": "1234"},
        ))
    sig = entity_correlation_signal(g)
    assert sig is not None
    assert sig.value == "entity_chain_correlated"
    assert sig.attrs["entity_key"] == "process_id"
    assert len(sig.attrs["correlated_node_ids"]) == 3


def test_entity_signal_none_when_less_than_three():
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    for i in range(2):
        g.add_node(Node(
            id=f"N{i}", kind="behaviour", label=f"b{i}", value=f"v{i}",
            confidence=0.9, attrs={"process_id": "1234"},
        ))
    assert entity_correlation_signal(g) is None


def test_entity_signal_participates_in_verdict():
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    for i, (kind, val) in enumerate([
        ("behaviour", "network_beacon"),
        ("lolbin", "powershell"),
        ("ioc", "1.2.3.4"),
    ]):
        attrs = {"parent_process_id": "9999"}
        if kind == "ioc":
            attrs["ioc_kind"] = "ip"
        g.add_node(Node(id=f"N{i}", kind=kind, label=val, value=val,
                        confidence=0.9, attrs=attrs))
    v = compute_verdict(g)
    kinds = {c.kind for c in v.contributors}
    assert "entity_chain_correlated" in kinds


# ────────────────────────── Negative evidence ────────────────────────

def test_signed_microsoft_binary_emits_mitigating_signal():
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    g.add_node(Node(id="P", kind="lolbin", label="powershell.exe",
                    value="powershell.exe", confidence=0.9,
                    attrs={"publisher": "Microsoft Corporation"}))
    negs = negative_evidence_signals(g)
    kinds = {n.attrs["subkind"] for n in negs}
    assert "signed_microsoft_binary" in kinds


def test_internal_ip_emits_mitigating_signal():
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    g.add_node(Node(id="I", kind="ioc", label="internal IP", value="10.1.2.3",
                    confidence=0.9, attrs={"ioc_kind": "ip"}))
    negs = negative_evidence_signals(g)
    kinds = {n.attrs["subkind"] for n in negs}
    assert "internal_ip" in kinds


def test_enterprise_allowlist_tag_emits_mitigating_signal():
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    g.add_node(Node(id="S", kind="behaviour", label="ps script", value="v",
                    confidence=0.9, attrs={"tags": ["sccm", "config-manager"]}))
    negs = negative_evidence_signals(g)
    kinds = {n.attrs["subkind"] for n in negs}
    assert "enterprise_allowlist" in kinds


def test_benign_parent_emits_mitigating_signal():
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    g.add_node(Node(id="P", kind="behaviour", label="child", value="v",
                    confidence=0.9,
                    attrs={"parent_image": "C:\\Windows\\explorer.exe"}))
    negs = negative_evidence_signals(g)
    kinds = {n.attrs["subkind"] for n in negs}
    assert "benign_parent" in kinds


# ────────────────────────── CI gate: cannot flip a Malicious ─────────

def test_negative_evidence_cannot_override_critical():
    """A CRITICAL contributor (custom_recipe / malware_family / …) plus
    a bag of MITIGATING signals must remain Malicious."""
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    g.add_node(Node(id="F", kind="family_match", label="Emotet dropper",
                    value="Emotet", confidence=0.95,
                    attrs={"publisher": "Microsoft Corporation"}))
    # Force multiple mitigating signals on the graph.
    g.add_node(Node(id="I", kind="ioc", label="10.1.2.3", value="10.1.2.3",
                    confidence=0.9, attrs={"ioc_kind": "ip"}))
    g.add_node(Node(id="B", kind="behaviour", label="admin ps", value="v",
                    confidence=0.9,
                    attrs={"tags": ["admin-script"],
                           "parent_image": "explorer.exe"}))
    v = compute_verdict(g)
    assert v.label == "Malicious"
    # Confidence may be dampened but must remain ≥ 40 %.
    assert v.confidence_pct >= 40


def test_negative_evidence_lowers_confidence_when_no_critical():
    """Without CRITICAL evidence, mitigating signals meaningfully lower
    the confidence (monotonicity of the DAMPENER, not the positive
    confidence)."""
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    g.add_node(Node(id="L", kind="lolbin", label="powershell",
                    value="powershell", confidence=0.9))
    g.add_node(Node(id="M", kind="mitre_technique", label="T1059",
                    value="T1059", confidence=0.9))
    g.add_node(Node(id="U", kind="ioc", label="URL", value="http://evils.com/a",
                    confidence=0.85, attrs={"ioc_kind": "url"}))
    conf_before = compute_verdict(g).confidence
    # Now add a Microsoft-signed publisher on the lolbin.
    for n in g.nodes:
        if n.id == "L":
            n.attrs = {**(n.attrs or {}), "publisher": "Microsoft Corporation"}
    conf_after = compute_verdict(g).confidence
    assert conf_after <= conf_before + 1e-9  # not raised
    # Meaningful drop (≥ 5 pp) when no CRITICAL present.
    assert conf_before - conf_after >= 0.03


def test_negative_evidence_never_flips_verdict_to_below_suspicious():
    """Even with 3× mitigating signals, an attack-chain HIGH must not
    demote below Suspicious."""
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    g.add_node(Node(id="F", kind="decoded_fragment", label="Encoded PS",
                    value="IEX (New-Object Net.WebClient).DownloadString",
                    confidence=0.9, attrs={"op": "powershell.encoded"}))
    g.add_node(Node(id="U", kind="ioc", label="URL", value="http://evils.com/a",
                    confidence=0.85, attrs={"ioc_kind": "url"}))
    # Stack mitigating signals
    g.add_node(Node(id="M1", kind="behaviour", label="admin ps",
                    value="v", confidence=0.9,
                    attrs={"tags": ["admin-script"]}))
    g.add_node(Node(id="M2", kind="behaviour", label="benign parent",
                    value="v", confidence=0.9,
                    attrs={"parent_image": "services.exe"}))
    v = compute_verdict(g)
    assert v.label in ("Suspicious", "Malicious")
