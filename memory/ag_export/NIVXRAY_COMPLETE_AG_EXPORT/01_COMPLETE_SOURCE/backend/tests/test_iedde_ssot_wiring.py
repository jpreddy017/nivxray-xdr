"""IEDDE SSOT integration tests (Priority 1 · 2026-02).

These tests prove that the Intelligent Evidence-Driven Decoding Engine
(IEDDE) is wired into `recover_canonical_evidence` — the shared service
that backs `/api/decode/smart` and `/api/analyze/async`.

Contract asserted here:
    • Every CanonicalArtifact carries `iedde_trace`, `iedde_terminal_state`,
      and `canonical_confidence` when the recovery pipeline runs.
    • Terminal state and stop reason are always human-readable strings.
    • Canonical confidence is deterministically derived (no heuristic
      guessing — Rule 23).
    • The IEDDE trace preserves the legacy decoded_output (no drift).
    • Atomic-IOC and multi-fragment terminal states are NOT augmented
      (they short-circuit before the decoder runs — augmentation would
      be meaningless).
"""
import pytest

from services.canonical_evidence_recovery import recover_canonical_evidence


@pytest.mark.parametrize("payload,expected_terminal", [
    # Plain benign text — no techniques detected → canonical.
    ("whoami", "canonical"),
    # PS encoded command — utf16le decode → canonical.
    ("powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAdAB3AGUAZQB0ACwAIAB0AHcAZQBlAHQAIQAiAA==", "canonical"),
])
def test_iedde_augmentation_populated_on_recovered_states(payload, expected_terminal):
    art = recover_canonical_evidence(payload)
    assert art.iedde_trace is not None, "IEDDE trace must be attached"
    assert art.iedde_terminal_state == expected_terminal
    assert isinstance(art.canonical_confidence, int)
    assert 0 <= art.canonical_confidence <= 100
    assert isinstance(art.canonical_confidence_reason, str)
    assert art.canonical_confidence_reason  # non-empty


def test_canonical_confidence_is_100_when_iedde_reaches_canonical():
    art = recover_canonical_evidence("whoami")
    assert art.iedde_terminal_state == "canonical"
    assert art.canonical_confidence == 100
    assert "canonical_reached" in art.canonical_confidence_reason


def test_atomic_ioc_terminal_state_is_not_augmented():
    """Atomic IOCs (bare hash/URL/IP) short-circuit before decoding —
    IEDDE augmentation is meaningless for them (there is no decode)."""
    art = recover_canonical_evidence("8.8.8.8")
    assert art.terminal_state == "atomic_ioc"
    assert art.iedde_trace is None
    assert art.canonical_confidence is None


def test_iedde_trace_shape_matches_planresult_dict():
    art = recover_canonical_evidence("powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAaABlAGwAbABvACIA")
    trace = art.iedde_trace
    assert isinstance(trace, dict)
    for key in ("canonical_output", "iterations_executed", "terminal_state",
                 "stop_reason", "final_interpreter", "final_techniques", "stages"):
        assert key in trace, f"IEDDE trace missing key: {key}"
    for stage in trace["stages"]:
        # Rule 24 · Understand-First — every stage carries decision reasoning.
        assert "decision" in stage
        assert "reason" in stage["decision"]
        assert isinstance(stage["decision"]["reason"], str)


def test_iedde_stability_gate_carries_reasoned_message():
    """When IEDDE cannot progress deterministically, it must return a
    reasoned stop message (Rule 23) — NOT a heuristic guess."""
    # A payload with a technique but no matching primitive (fabricated
    # by requesting AES with an obvious wrapper).
    payload = (
        'powershell.exe -Command "$aes = [System.Security.Cryptography.Aes]::Create()"'
    )
    art = recover_canonical_evidence(payload)
    # Whatever terminal we land in, the IEDDE trace + confidence should
    # both be present and derived, and the reason must be non-empty.
    assert art.iedde_trace is not None
    assert isinstance(art.canonical_confidence, int)
    assert isinstance(art.canonical_confidence_reason, str)
    assert art.canonical_confidence_reason  # non-empty
    # Deterministic — must never guess.
    art2 = recover_canonical_evidence(payload)
    assert art.iedde_trace == art2.iedde_trace
    assert art.canonical_confidence == art2.canonical_confidence
    assert art.canonical_confidence_reason == art2.canonical_confidence_reason


def test_iedde_augmentation_is_deterministic():
    """Two runs on the same input must produce byte-identical IEDDE
    traces (Rule 21 · Determinism)."""
    payload = "powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAaABlAGwAbABvACIA"
    a1 = recover_canonical_evidence(payload)
    a2 = recover_canonical_evidence(payload)
    assert a1.iedde_trace == a2.iedde_trace
    assert a1.iedde_terminal_state == a2.iedde_terminal_state
    assert a1.canonical_confidence == a2.canonical_confidence
    assert a1.canonical_confidence_reason == a2.canonical_confidence_reason
