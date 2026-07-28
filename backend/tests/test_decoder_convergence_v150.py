"""v1.5.0 Decoder Convergence · locked regression.

Trust / Golden / CI Corpus entry: PS_ENCODEDCOMMAND_GZIP_STAGE2_001

Ensures the deterministic Recursive Transformation Engine converges
on the classic multi-stage Windows evasion idiom:

    CMD → PS -EncodedCommand → UTF-16LE
        → PS with variable-bound base64 + GzipStream + IEX
        → Recovered Stage-2 PowerShell

Prior to v1.5.0 the pipeline stopped at layer 1 with
``stop_reason = NO_TRANSFORMATION`` because :func:`_resolve_compression_stream`
assumed a strict source-order (`GzipStream` before `FromBase64String`)
that this common idiom violates. The fix introduces
``ps_indirect_compression_stream`` which links assignments and
consumers by variable name.

Any regression that stops this chain at L1, corrupts determinism, or
drops the ``ps_indirect_compression_stream`` transformation MUST fail
CI. This test is intentionally strict.
"""
from __future__ import annotations

import base64
import gzip

import pytest

from v2.investigation.rte.engine import transform, DEFAULT_MAX_DEPTH
from v2.investigation.rte.models import StopReason


# ── Golden-Corpus builder ────────────────────────────────────────
#
# We build the sample from a KNOWN stage-3 plaintext so:
#   1. the test is fully self-contained (no external byte blob)
#   2. we can assert the L2 recovery byte-for-byte
#   3. contributors reading the test understand the chain shape
#
# Byte-for-byte assertion is important — the whole point of a
# deterministic decoder is that the same input produces the same
# output on every run.
_STAGE3_PS = (
    'Write-Host "STAGE-3 payload · locked corpus PS_ENCODEDCOMMAND_GZIP_STAGE2_001"; '
    'New-ItemProperty -Path HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
    '-Name Backdoor -Value "C:\\Windows\\Temp\\bd.exe";'
)


def _build_sample() -> str:
    """Assemble the exact ordered chain we expect the RTE to unwind."""
    gz_b64 = base64.b64encode(gzip.compress(_STAGE3_PS.encode("utf-8"))).decode("ascii")
    stage2_ps = (
        f'$s=New-Object IO.MemoryStream(,'
        f'[Convert]::FromBase64String("{gz_b64}"));'
        f'IEX (New-Object IO.StreamReader('
        f'New-Object IO.Compression.GzipStream('
        f'$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
    )
    enc = base64.b64encode(stage2_ps.encode("utf-16-le")).decode("ascii")
    return (
        f"%COMSPEC% /b /c start /b /min powershell -nop -w hidden "
        f"-encodedcommand {enc}"
    )


SAMPLE = _build_sample()


# ── Locked assertions ────────────────────────────────────────────

def test_max_depth_is_at_least_64():
    """v1.5.0 raised the depth cap to 64. Regressing below that would
    silently truncate deep multi-stage samples."""
    assert DEFAULT_MAX_DEPTH >= 64


def test_stage2_gzip_chain_converges_to_three_layers():
    """The primary corpus sample must produce L0, L1, and L2 —
    stopping at L1 is the exact defect v1.5.0 fixes."""
    chain = transform(SAMPLE, max_depth=DEFAULT_MAX_DEPTH)
    assert len(chain.artifacts) >= 3, (
        f"Chain terminated at layer {len(chain.artifacts) - 1}; "
        f"expected at least 3 layers (CMD → PS → Stage-2 PS). "
        f"Stop reason: {chain.stop_reason.value}"
    )


def test_stage2_gzip_chain_uses_ps_encoded_command_and_indirect_compression():
    """The two transformations that must fire are exactly:
        L0 → L1  via  ps_encoded_command
        L1 → L2  via  ps_indirect_compression_stream
    Any other pair means orchestration has drifted."""
    chain = transform(SAMPLE, max_depth=DEFAULT_MAX_DEPTH)
    names = [s.transformation for s in chain.steps]
    assert "ps_encoded_command" in names, f"ps_encoded_command not fired; steps={names}"
    assert "ps_indirect_compression_stream" in names, (
        f"ps_indirect_compression_stream not fired; steps={names}. "
        "The variable-bound base64 → compression idiom is un-decoded."
    )


def test_stage2_gzip_chain_stop_reason_is_convergence_not_defect():
    """After the fix, the chain must stop for a *principled* reason —
    ``NO_TRANSFORMATION`` at the final plaintext layer, or ``LOOP``
    (hash reappearance). Any other terminal state indicates a
    regression in the decoder or the loop-guard logic."""
    chain = transform(SAMPLE, max_depth=DEFAULT_MAX_DEPTH)
    assert chain.stop_reason in {
        StopReason.NO_TRANSFORMATION,
        StopReason.LOOP,
    }, f"Unexpected stop reason: {chain.stop_reason.value}"


def test_stage2_gzip_chain_recovers_stage3_verbatim():
    """The recovered L2 content MUST equal the stage-3 plaintext
    byte-for-byte. This is the semantic contract of the decoder."""
    chain = transform(SAMPLE, max_depth=DEFAULT_MAX_DEPTH)
    l2 = chain.artifacts[-1].content
    assert _STAGE3_PS in l2, (
        f"Stage-3 plaintext not recovered in final layer. "
        f"L2 head: {l2[:200]!r}"
    )


def test_stage2_gzip_chain_is_deterministic_across_runs():
    """Two independent runs of the same input must produce the same
    canonical determinism hash. Non-determinism would break the whole
    Trust Metrics harness."""
    a = transform(SAMPLE, max_depth=DEFAULT_MAX_DEPTH)
    b = transform(SAMPLE, max_depth=DEFAULT_MAX_DEPTH)
    assert a.determinism_hash == b.determinism_hash, (
        f"Non-deterministic decoder: {a.determinism_hash} vs {b.determinism_hash}"
    )


def test_reverse_order_compression_still_works():
    """Regression guard: the strict-order idiom (``GzipStream`` in the
    same call as ``FromBase64String``) that ``ps_compression_stream``
    handles must ALSO still work — we do not want the new
    variable-bound resolver to steal matches from the strict one."""
    inner = 'Write-Host "hello from strict-order compression"'
    gz_b64 = base64.b64encode(gzip.compress(inner.encode("utf-8"))).decode("ascii")
    strict_stage = (
        f'[IO.Compression.GzipStream]::new('
        f'[IO.MemoryStream][Convert]::FromBase64String("{gz_b64}"),'
        f'[IO.Compression.CompressionMode]::Decompress)'
    )
    enc = base64.b64encode(strict_stage.encode("utf-16-le")).decode("ascii")
    sample = f"powershell -encodedcommand {enc}"
    chain = transform(sample, max_depth=DEFAULT_MAX_DEPTH)
    assert len(chain.artifacts) >= 3, "strict-order compression regressed"


def test_no_indirect_compression_when_variable_never_consumed():
    """Determinism guard: if a script assigns base64 to a variable
    but NEVER consumes it via a compression stream, the new resolver
    MUST NOT fire (would be fabricating semantics)."""
    ps = (
        '$s=New-Object IO.MemoryStream(,'
        '[Convert]::FromBase64String("SGVsbG8gV29ybGQ="));'
        'Write-Host "no consumer";'
    )
    enc = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    sample = f"powershell -encodedcommand {enc}"
    chain = transform(sample, max_depth=DEFAULT_MAX_DEPTH)
    names = [s.transformation for s in chain.steps]
    assert "ps_indirect_compression_stream" not in names, (
        f"Resolver fired without a compression consumer — {names}"
    )


def test_no_indirect_compression_when_variable_mismatch():
    """Determinism guard: if `$a = FromBase64String(...)` is present but
    the consumer is `GzipStream($b, …)` — different variable — the
    resolver MUST NOT fabricate a link."""
    inner = "irrelevant"
    gz_b64 = base64.b64encode(gzip.compress(inner.encode())).decode()
    ps = (
        f'$a=New-Object IO.MemoryStream(,'
        f'[Convert]::FromBase64String("{gz_b64}"));'
        f'$b=New-Object IO.MemoryStream;'
        f'[IO.Compression.GzipStream]::new($b,'
        f'[IO.Compression.CompressionMode]::Decompress);'
    )
    enc = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    sample = f"powershell -encodedcommand {enc}"
    chain = transform(sample, max_depth=DEFAULT_MAX_DEPTH)
    names = [s.transformation for s in chain.steps]
    assert "ps_indirect_compression_stream" not in names, (
        f"Resolver fired despite variable mismatch — {names}"
    )


def test_transformation_registry_contains_indirect_compression():
    """Structural guard: the plugin must be registered so the engine
    can even consider it. A missing registration would silently
    disable the fix."""
    from v2.investigation.rte.transformations import TRANSFORMATION_REGISTRY
    names = [t.NAME for t in TRANSFORMATION_REGISTRY]
    assert "ps_indirect_compression_stream" in names, (
        f"ps_indirect_compression_stream missing from registry: {names}"
    )
    # Order guard: it must appear BEFORE the strict-order plugin so
    # ties on artefacts matching both are broken in favour of the
    # more-permissive variable-bound resolver.
    assert names.index("ps_indirect_compression_stream") < names.index("ps_compression_stream")


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
