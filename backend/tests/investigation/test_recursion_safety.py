"""Recursion Safety tests — Investigation Engine Contract v1.0.

Every test here mirrors one of the executable invariants declared in
`docs/architecture/INVESTIGATION_ENGINE_CONTRACT.md`. Failure of any
test is a contract violation, not a routine unit-test regression.
"""
from __future__ import annotations

import pytest

from nivxforge.investigation.pipeline.recursion_safety import (
    DIAGNOSTIC_MARKERS, NoFurtherProgress, RENDERED_MARKER,
    RecursionGuard, RenderedPayloadReentry,
    assert_terminal, contains_diagnostic_markers, is_rendered,
    scrub_diagnostics, stability_gate, tag_rendered,
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
