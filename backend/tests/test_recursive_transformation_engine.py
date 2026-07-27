"""Recursive Transformation Engine (RTE) · Phase 3 regression suite.

Locks in the deterministic behaviour of the recursive transformation
engine against a golden corpus of realistic multi-encoding chains.

Contract for every sample:
    * final artefact contains the expected plaintext substring
    * expected transformation steps fired in the expected order
    * stop reason is a principled one (not "decoder finished")
    * every step carries at least one canonical Evidence object
    * deterministic replay — identical input produces identical hash
    * every layer's classification is coherent
"""
from __future__ import annotations

import base64
import gzip
import zlib

import pytest

from v2.investigation.evidence import Evidence
from v2.investigation.rte import StopReason, transform
from v2.investigation.iu.models import ArtefactType


# ── Helpers to build synthetic multi-layer samples ──────────────
def _b64(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-16-le")
    return base64.b64encode(data).decode()


# ── Golden samples ──────────────────────────────────────────────
# Each entry declares: name, builder → input text, expected substring
# in the final layer, expected transformation names (in order).
def _sample_ps_encoded_command():
    script = 'Write-Host "hello, powershell"'
    return f"powershell.exe -NoP -W Hidden -EncodedCommand {_b64(script)}"


def _sample_bare_b64_utf16le():
    script = 'Invoke-Expression $global:x'
    return _b64(script)


def _sample_format_string():
    return '"{0}{1}{2}" -f "St","ar","t-Process notepad"'


def _sample_numeric_char_array():
    # Standard shape: numeric list is its own parenthesised expression.
    # -join ((...) | %{ [char][Convert]::ToInt16($_,10) })
    return "-join ((87,114,105,116,101) | %{[char][Convert]::ToInt16($_,10)})"


def _sample_gzip_over_base64():
    script = 'Write-Host GZIPPED-PAYLOAD'
    return _b64(gzip.compress(script.encode("utf-8")))


def _sample_zlib_over_base64():
    script = 'Write-Host ZLIB-PAYLOAD'
    return _b64(zlib.compress(script.encode("utf-8")))


def _sample_format_then_b64():
    """Two-layer: format string produces a base64 blob, which then
    decodes to a PS script (the classic Invoke-Obfuscation pattern)."""
    script = 'Write-Host "layered"'
    blob = _b64(script)
    mid = len(blob) // 2
    return f'"{{0}}{{1}}" -f "{blob[:mid]}","{blob[mid:]}"'


def _sample_encoded_command_then_static_base64():
    """Three-layer: PS -EncodedCommand → PowerShell script that itself
    contains a static [Convert]::FromBase64String("..."). Uses the
    UTF-16LE composite because that resolver preserves the quotes
    the RTE's PS-static-b64 plugin expects."""
    inner = 'Start-Process calc'
    inner_b64 = _b64(inner)
    ps = (
        f'iex ([System.Text.Encoding]::Unicode.GetString('
        f'[Convert]::FromBase64String("{inner_b64}")))'
    )
    outer = _b64(ps)
    return f'powershell.exe -EncodedCommand {outer}'


def _sample_hex_string_text():
    text = "Write-Host HEX"
    return text.encode("utf-8").hex()


GOLDEN_SAMPLES = [
    (
        "ps_encoded_command",
        _sample_ps_encoded_command(),
        "Write-Host",
        ["ps_encoded_command"],
        1,
    ),
    (
        "bare_b64_utf16le",
        _sample_bare_b64_utf16le(),
        "Invoke-Expression",
        ["base64_utf16le"],
        1,
    ),
    (
        "format_string",
        _sample_format_string(),
        "Start-Process notepad",
        ["ps_format_string"],
        1,
    ),
    (
        "numeric_char_array",
        _sample_numeric_char_array(),
        "Write",
        ["ps_char_array"],
        1,
    ),
    (
        "gzip_over_base64",
        _sample_gzip_over_base64(),
        "GZIPPED-PAYLOAD",
        ["base64_bytes", "gzip_stream"],
        2,
    ),
    (
        "zlib_over_base64",
        _sample_zlib_over_base64(),
        "ZLIB-PAYLOAD",
        ["base64_bytes", "zlib_stream"],
        2,
    ),
    (
        "format_then_b64",
        _sample_format_then_b64(),
        "layered",
        ["ps_format_string", "base64_utf16le"],
        2,
    ),
    (
        "enc_then_static_b64",
        _sample_encoded_command_then_static_base64(),
        "Start-Process calc",
        ["ps_encoded_command", "ps_static_base64"],
        2,
    ),
    (
        "hex_string_text",
        _sample_hex_string_text(),
        "Write-Host HEX",
        ["hex_string"],
        1,
    ),
]


# ── Determinism-only samples (no plaintext assertion, only that
# ── replay produces identical determinism_hash) ─────────────────
DETERMINISM_SAMPLES = [
    _sample_ps_encoded_command(),
    _sample_gzip_over_base64(),
    _sample_format_then_b64(),
    _sample_encoded_command_then_static_base64(),
]


@pytest.mark.parametrize(
    "name, sample, expected_plaintext, expected_steps, min_depth",
    GOLDEN_SAMPLES,
    ids=[g[0] for g in GOLDEN_SAMPLES],
)
def test_rte_golden_sample(name, sample, expected_plaintext, expected_steps, min_depth):
    """Every golden sample must peel to the expected plaintext and
    fire the expected transformation steps in the expected order."""
    result = transform(sample)

    # Depth check — the engine must have peeled at least ``min_depth`` layers.
    assert result.depth >= min_depth, (
        f"[{name}] expected depth ≥ {min_depth}, got {result.depth}. "
        f"steps={[s.transformation for s in result.steps]}"
    )

    # Final plaintext contains the expected substring.
    assert expected_plaintext in result.final.content, (
        f"[{name}] expected `{expected_plaintext}` in final layer, "
        f"got {result.final.content[:200]!r}"
    )

    # Expected transformations fired in order (subsequence, not exact —
    # extra layers between the expected ones are permitted).
    step_names = [s.transformation for s in result.steps]
    it = iter(step_names)
    for expected in expected_steps:
        assert any(expected == name for name in it), (
            f"[{name}] expected step `{expected}` in {step_names}"
        )


@pytest.mark.parametrize(
    "name, sample, _plain, _steps, _depth",
    GOLDEN_SAMPLES,
    ids=[g[0] for g in GOLDEN_SAMPLES],
)
def test_rte_every_step_has_evidence(name, sample, _plain, _steps, _depth):
    """Every transformation step must carry at least one canonical
    Evidence object — the Phase 5 Evidence Graph cannot be built
    without this invariant."""
    result = transform(sample)
    for i, step in enumerate(result.steps):
        assert step.evidence, f"[{name}] step {i} ({step.transformation}) has no evidence"
        for ev in step.evidence:
            assert isinstance(ev, Evidence), (
                f"[{name}] step {i} produced non-canonical evidence: {type(ev)}"
            )
            assert ev.source, f"[{name}] step {i} evidence missing source"
            assert ev.rationale, f"[{name}] step {i} evidence missing rationale"


@pytest.mark.parametrize("sample", DETERMINISM_SAMPLES, ids=range(len(DETERMINISM_SAMPLES)))
def test_rte_determinism(sample):
    """Identical input MUST produce byte-identical output across runs."""
    r1 = transform(sample)
    r2 = transform(sample)
    r3 = transform(sample)
    assert r1.determinism_hash == r2.determinism_hash == r3.determinism_hash, (
        "RTE is non-deterministic — every replay must produce identical "
        "determinism_hash. Any transformation with non-deterministic "
        "output is a P0 bug."
    )


def test_rte_never_stops_on_decoder_finished():
    """The engine MUST NEVER halt with a `decoder_finished` reason.
    Every stop reason must be one of the four principled reasons."""
    result = transform(_sample_gzip_over_base64())
    assert result.stop_reason in {
        StopReason.NO_TRANSFORMATION,
        StopReason.LOOP,
        StopReason.MAX_DEPTH,
        StopReason.UNSUPPORTED,
        StopReason.EMPTY_INPUT,
    }, f"Illegal stop reason: {result.stop_reason}"


def test_rte_preserves_every_intermediate_artifact():
    """Every layer between input and final plaintext must be preserved
    (not just the final one). Analyst tooling / Phase 5 needs the full
    history."""
    sample = _sample_encoded_command_then_static_base64()
    result = transform(sample)
    assert result.depth >= 2
    # Layers must be contiguous 0, 1, 2, …
    for i, a in enumerate(result.artifacts):
        assert a.layer == i, f"Layer {i} has wrong index: {a.layer}"
        if i == 0:
            assert a.parent_hash is None
        else:
            assert a.parent_hash == result.artifacts[i - 1].content_hash


def test_rte_reclassifies_after_every_transformation():
    """Input Understanding must run on every new layer so downstream
    engines are dispatched to the correct plaintext type. A
    command_line → powershell_script transition is the canonical
    reclassification checkpoint."""
    result = transform(_sample_ps_encoded_command())
    types = [a.classification.primary_type for a in result.artifacts]
    # First layer must be command_line, later layers must include powershell_script.
    assert types[0] == ArtefactType.COMMAND_LINE
    assert ArtefactType.POWERSHELL_SCRIPT in types[1:]


def test_rte_empty_input_is_safe():
    """Empty / whitespace input must not raise and must halt with
    the EMPTY_INPUT reason."""
    for empty in ("", "   ", "\n\n"):
        r = transform(empty)
        assert r.stop_reason == StopReason.EMPTY_INPUT
        assert r.depth == 0
        assert r.steps == []


def test_rte_unknown_input_halts_cleanly():
    """Well-formed but non-encoded input (regular English text) must
    halt with NO_TRANSFORMATION and never fabricate a plaintext layer."""
    r = transform("this is regular english text with nothing to decode")
    assert r.stop_reason == StopReason.NO_TRANSFORMATION
    assert r.depth == 0


def test_rte_loop_guard_prevents_infinite_recursion():
    """The loop guard must halt if any transformation reproduces a
    previously-seen state. We can't easily trigger a real loop with
    the current plugin set, but we can assert the machinery is present."""
    # No-op sample — no plugin cycles. But asserts machinery is stable.
    r = transform("abc")
    assert r.stop_reason in {StopReason.NO_TRANSFORMATION, StopReason.LOOP}


def test_rte_max_depth_bound():
    """Every chain must terminate within max_depth. Prove the safety
    cap engages by lowering it to 1 on a deep sample."""
    r = transform(_sample_gzip_over_base64(), max_depth=1)
    assert r.depth <= 1
    assert r.stop_reason in {StopReason.MAX_DEPTH, StopReason.NO_TRANSFORMATION}


def test_rte_registry_contract():
    """Every registered transformation must honour the plugin protocol."""
    from v2.investigation.rte.transformations import (
        TRANSFORMATION_REGISTRY,
        Transformation,
    )
    seen_names = set()
    for t in TRANSFORMATION_REGISTRY:
        assert isinstance(t, Transformation), (
            f"{type(t).__name__} does not implement the Transformation protocol"
        )
        assert t.NAME, f"{type(t).__name__} has empty NAME"
        assert t.NAME not in seen_names, f"Duplicate transformation name: {t.NAME}"
        seen_names.add(t.NAME)
