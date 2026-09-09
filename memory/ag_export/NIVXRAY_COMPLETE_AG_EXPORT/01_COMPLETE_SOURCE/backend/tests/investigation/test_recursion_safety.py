"""Recursion Safety tests — Investigation Engine Contract v1.0.

Every test here mirrors one of the executable invariants declared in
`docs/architecture/INVESTIGATION_ENGINE_CONTRACT.md`. Failure of any
test is a contract violation, not a routine unit-test regression.
"""
from __future__ import annotations

import pytest

from nivxforge.investigation.pipeline.recursion_safety import (
    DIAGNOSTIC_MARKERS, InvalidStateTransition, NoFurtherProgress,
    NonExecutablePayloadRejected, OutputGate, Payload, PayloadKind,
    PayloadState, PipelineInvariantViolation, RENDERED_MARKER,
    RecursionGuard, RenderedPayloadReentry, TerminalPayloadReentry,
    advance_state, assert_parseable, assert_terminal,
    contains_diagnostic_markers, is_rendered, scrub_diagnostics,
    stability_gate, tag_rendered,
)


# ── Invariant #3 · Rendered output is terminal ──────────────────────

def test_tag_rendered_is_idempotent():
    once = tag_rendered("hello")
    twice = tag_rendered(once)
    assert once == twice
    assert once.startswith(RENDERED_MARKER)


def test_is_rendered_detects_marker():
    assert is_rendered(tag_rendered("payload")) is True
    assert is_rendered("raw payload without marker") is False
    assert is_rendered(None) is False
    assert is_rendered(123) is False


def test_assert_terminal_refuses_rendered_payload():
    rendered = tag_rendered("previous engine output")
    with pytest.raises(RenderedPayloadReentry):
        assert_terminal(rendered, stage="parser")


def test_assert_terminal_permits_raw_input():
    # Raw inputs must pass through untouched — this is the happy path
    # for every parser / decoder in the pipeline.
    assert_terminal("cmd.exe /c whoami", stage="parser")
    assert_terminal("", stage="decoder")


# ── Invariant #4 · Recursion guard ───────────────────────────────────

def test_guard_permits_structural_progress():
    guard = RecursionGuard(stage="decoder", max_depth=4)
    guard.advance("layer 1", semantic_progress=False)
    guard.advance("layer 2", semantic_progress=False)
    guard.advance("layer 3", semantic_progress=False)
    assert guard.iterations == 3


def test_guard_stops_on_hash_equality_without_semantic_progress():
    guard = RecursionGuard(stage="decoder", max_depth=8)
    guard.advance("same payload", semantic_progress=True)
    with pytest.raises(NoFurtherProgress):
        # Same hash, no semantic progress ⇒ Invariant #4 triggers.
        guard.advance("same payload", semantic_progress=False)


def test_guard_permits_hash_equality_when_semantic_progress_true():
    """If new evidence surfaced elsewhere the payload need not
    change; the guard should NOT halt."""
    guard = RecursionGuard(stage="aggregator", max_depth=4)
    guard.advance("payload", semantic_progress=True)
    guard.advance("payload", semantic_progress=True)  # ok — evidence grew


def test_guard_stops_at_max_depth():
    guard = RecursionGuard(stage="decoder", max_depth=3)
    for i in range(3):
        guard.advance(f"layer-{i}", semantic_progress=True)
    with pytest.raises(NoFurtherProgress):
        guard.advance("layer-3", semantic_progress=True)


def test_guard_hash_ignores_object_identity():
    """Two distinct string objects with identical content must hash
    the same — determinism gate."""
    guard = RecursionGuard(stage="decoder", max_depth=4)
    guard.advance("same-value", semantic_progress=True)
    with pytest.raises(NoFurtherProgress):
        guard.advance("".join(["same", "-", "value"]),
                       semantic_progress=False)


# ── Invariant #8 · Decoder Stability Gate ───────────────────────────

def test_stability_gate_terminates_when_no_progress():
    verdict = stability_gate(
        evidence_before={"e1"}, evidence_after={"e1"},
        command_before="cmd /c a", command_after="cmd /c a",
        interpreter_before="cmd", interpreter_after="cmd",
    )
    assert verdict.stable is True
    assert "Decoder Stability Gate reached" in verdict.reason


def test_stability_gate_reports_progress_on_new_evidence():
    verdict = stability_gate(
        evidence_before={"e1"}, evidence_after={"e1", "e2"},
        command_before="cmd", command_after="cmd",
        interpreter_before="cmd", interpreter_after="cmd",
    )
    assert verdict.stable is False
    assert "new_evidence=1" in verdict.reason


def test_stability_gate_reports_progress_on_command_change():
    verdict = stability_gate(
        evidence_before=set(), evidence_after=set(),
        command_before="cmd /c a", command_after="cmd /c a && b",
        interpreter_before="cmd", interpreter_after="cmd",
    )
    assert verdict.stable is False
    assert "command_changed=True" in verdict.reason


def test_stability_gate_reports_progress_on_interpreter_change():
    verdict = stability_gate(
        evidence_before=set(), evidence_after=set(),
        command_before="x", command_after="x",
        interpreter_before="cmd", interpreter_after="powershell",
    )
    assert verdict.stable is False
    assert "interpreter_changed=True" in verdict.reason


def test_stability_gate_output_is_deterministic():
    """Same inputs must always yield byte-identical verdicts."""
    a = stability_gate(
        evidence_before={"e1", "e2"}, evidence_after={"e1", "e2"},
        command_before="  cmd  ", command_after="cmd",
        interpreter_before=None, interpreter_after=None,
    )
    b = stability_gate(
        evidence_before={"e2", "e1"}, evidence_after={"e2", "e1"},
        command_before="cmd", command_after="  cmd  ",
        interpreter_before=None, interpreter_after=None,
    )
    assert a == b


# ── Invariant #7 · Diagnostic tokens forbidden in narrative ─────────

def test_narrative_scrubs_diagnostic_markers():
    dirty = ("Investigation summary: process spawned. "
             "[ps-backtick-normalize] [ps-alias-expand] "
             "and normalizer-trace should not be in output.")
    assert contains_diagnostic_markers(dirty) is True
    cleaned = scrub_diagnostics(dirty)
    assert contains_diagnostic_markers(cleaned) is False
    # Every forbidden marker must have been replaced.
    for marker in DIAGNOSTIC_MARKERS:
        assert marker.lower() not in cleaned.lower()


def test_scrub_is_idempotent_on_clean_text():
    clean = "process cmd.exe executed COMMAND cmd /c whoami"
    assert scrub_diagnostics(clean) == clean
    assert contains_diagnostic_markers(clean) is False


def test_diagnostic_marker_detection_is_case_insensitive():
    assert contains_diagnostic_markers("PS-BackTick-Normalize done")
    assert contains_diagnostic_markers("ps-BACKTICK-normalize done")


# ── Marker registry hygiene ─────────────────────────────────────────

def test_diagnostic_markers_are_unique():
    assert len(DIAGNOSTIC_MARKERS) == len(set(DIAGNOSTIC_MARKERS))


def test_rendered_marker_is_a_non_empty_ascii_string():
    assert isinstance(RENDERED_MARKER, str)
    assert RENDERED_MARKER
    assert RENDERED_MARKER.isascii()


# ── Typed payload state machine (owner directive) ────────────────────

def test_payload_defaults_to_raw_input_state():
    p = Payload(content="cmd /c whoami", kind=PayloadKind.COMMAND)
    assert p.state == PayloadState.RAW_INPUT


def test_state_advances_monotonically():
    p = Payload(content="x", kind=PayloadKind.COMMAND)
    p2 = advance_state(p, PayloadState.NORMALIZED)
    p3 = advance_state(p2, PayloadState.DECODED)
    p4 = advance_state(p3, PayloadState.FINAL_RENDERED)
    assert p4.state == PayloadState.FINAL_RENDERED


def test_backward_state_transition_rejected():
    p = Payload(content="x", kind=PayloadKind.COMMAND,
                 state=PayloadState.DECODED)
    with pytest.raises(InvalidStateTransition):
        advance_state(p, PayloadState.NORMALIZED)


def test_same_state_transition_rejected():
    p = Payload(content="x", kind=PayloadKind.COMMAND,
                 state=PayloadState.NORMALIZED)
    with pytest.raises(InvalidStateTransition):
        advance_state(p, PayloadState.NORMALIZED)


def test_assert_parseable_accepts_executable_kinds_in_raw_state():
    for kind in (PayloadKind.COMMAND, PayloadKind.SCRIPT,
                  PayloadKind.PIPELINE, PayloadKind.TELEMETRY):
        assert_parseable(
            Payload(content="x", kind=kind), stage="parser")


def test_assert_parseable_rejects_non_executable_kinds():
    for kind in (PayloadKind.REPORT, PayloadKind.NARRATIVE,
                  PayloadKind.DIAGNOSTIC, PayloadKind.ERROR):
        with pytest.raises(NonExecutablePayloadRejected):
            assert_parseable(
                Payload(content="x", kind=kind), stage="parser")


def test_assert_parseable_rejects_final_rendered_state():
    p = Payload(content="x", kind=PayloadKind.COMMAND,
                 state=PayloadState.FINAL_RENDERED)
    with pytest.raises(TerminalPayloadReentry):
        assert_parseable(p, stage="decoder")


def test_assert_parseable_accepts_raw_strings():
    """Raw strings not carrying the marker must pass — this is the
    happy path for legacy pre-Payload code."""
    assert_parseable("cmd.exe /c whoami", stage="parser")
    assert_parseable("", stage="parser")


def test_assert_parseable_rejects_string_carrying_rendered_marker():
    payload = tag_rendered("previously rendered")
    with pytest.raises(TerminalPayloadReentry):
        assert_parseable(payload, stage="parser")


# ── Exception hierarchy ─────────────────────────────────────────────

def test_all_violations_share_base_class():
    for cls in (TerminalPayloadReentry, NonExecutablePayloadRejected,
                 NoFurtherProgress, InvalidStateTransition):
        assert issubclass(cls, PipelineInvariantViolation)


def test_legacy_alias_matches_new_exception():
    """RenderedPayloadReentry must remain equal to
    TerminalPayloadReentry so pre-existing catch clauses keep working."""
    assert RenderedPayloadReentry is TerminalPayloadReentry


# ── Central Output Gate ─────────────────────────────────────────────

def test_output_gate_scrubs_and_seals_payload():
    dirty = ("Investigation summary. [ps-backtick-normalize] "
             "process spawned.")
    gate = OutputGate()
    out = gate.emit(dirty, kind=PayloadKind.NARRATIVE,
                    source="unit-test")
    assert out.state == PayloadState.FINAL_RENDERED
    assert out.kind == PayloadKind.NARRATIVE
    assert not contains_diagnostic_markers(out.content)
    assert out.provenance["sealed_by"] == "output_gate"
    assert out.provenance["diagnostics_scrubbed"] is True


def test_output_gate_leaves_clean_content_unchanged():
    clean = "process cmd.exe executed COMMAND cmd /c whoami"
    gate = OutputGate()
    out = gate.emit(clean, kind=PayloadKind.REPORT, source="unit")
    assert out.content == clean
    assert out.provenance["diagnostics_scrubbed"] is False


def test_output_gate_refuses_executable_kinds():
    """The gate seals TERMINAL output only. Passing an executable
    kind would incorrectly mark a command as un-parseable — must
    raise instead of silently succeeding."""
    gate = OutputGate()
    for kind in (PayloadKind.COMMAND, PayloadKind.SCRIPT,
                  PayloadKind.PIPELINE, PayloadKind.TELEMETRY):
        with pytest.raises(PipelineInvariantViolation):
            gate.emit("cmd /c a", kind=kind, source="unit")


def test_output_gate_output_refused_by_parser_end_to_end():
    """Round-trip: gate seals a narrative → parser guard refuses it.
    This is the concrete manifestation of Invariant #3."""
    gate = OutputGate()
    sealed = gate.emit("engine narrative body",
                        kind=PayloadKind.NARRATIVE, source="unit")
    with pytest.raises(TerminalPayloadReentry):
        assert_parseable(sealed, stage="parser")


def test_output_gate_provenance_records_source():
    gate = OutputGate()
    out = gate.emit("narrative", kind=PayloadKind.NARRATIVE,
                    source="analyst_narrative_v2",
                    extra_provenance={"case_id": "cio-123"})
    assert out.provenance["source"] == "analyst_narrative_v2"
    assert out.provenance["case_id"] == "cio-123"
