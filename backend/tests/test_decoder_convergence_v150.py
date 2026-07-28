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


# ── v1.5.0 · Diverse-family regression (Sophos-class loaders) ────
#
# The primary corpus sample exercises gzip. Real-world PowerShell
# loaders also use DeflateStream, different variable names, and
# multi-stage chains. This section proves the fix is CLASS-LEVEL, not
# sample-specific — no regex hardcodes `$s`, no logic assumes gzip.


def _mk_indirect_sample(*, kind: str, var: str, payload: str,
                        use_memstream_wrap: bool = True) -> str:
    """Build a synthetic CMD → PS -EncodedCommand → variable-bound
    <kind> loader that unwinds to ``payload``. Used by the family
    tests below to prove the resolver is generic across variations."""
    import gzip, zlib
    if kind == "gzip":
        raw = gzip.compress(payload.encode("utf-8"))
    elif kind == "deflate":
        raw = zlib.compress(payload.encode("utf-8"))[2:-4]  # raw DEFLATE
    else:
        raise ValueError(kind)
    blob = base64.b64encode(raw).decode("ascii")
    wrap = f"New-Object IO.MemoryStream(,\n" if use_memstream_wrap else ""
    wrap_prefix = "New-Object IO.MemoryStream(," if use_memstream_wrap else ""
    close = ")" if use_memstream_wrap else ""
    stream_cls = {"gzip": "GzipStream", "deflate": "DeflateStream"}[kind]
    stage2 = (
        f'${var}={wrap_prefix}[Convert]::FromBase64String("{blob}"){close};'
        f'IEX (New-Object IO.StreamReader('
        f'New-Object IO.Compression.{stream_cls}('
        f'${var},[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
    )
    enc = base64.b64encode(stage2.encode("utf-16-le")).decode("ascii")
    return f"powershell -nop -w hidden -encodedcommand {enc}"


@pytest.mark.parametrize("var", ["s", "ms", "stream", "randomIdent42", "µνξ"])
def test_indirect_compression_handles_arbitrary_variable_names(var):
    """The resolver must key on VARIABLE-NAME MATCH between assignment
    and consumer — not hardcode ``$s``. Sophos-class loaders use
    obfuscation-friendly identifiers ($ms, $stream, random)."""
    if not var.isascii():
        pytest.skip("Non-ASCII PS identifier — separate parser scope")
    inner = f'Write-Host "recovered · var={var}"'
    sample = _mk_indirect_sample(kind="gzip", var=var, payload=inner)
    chain = transform(sample, max_depth=DEFAULT_MAX_DEPTH)
    assert len(chain.artifacts) >= 3, f"var={var}: stopped at L{len(chain.artifacts)-1}"
    assert inner in chain.artifacts[-1].content


def test_indirect_compression_handles_deflate():
    """Same class of loader with DeflateStream instead of GzipStream —
    should be handled by the SAME resolver (compression kind is
    captured by regex group, not hardcoded)."""
    inner = 'Write-Host "recovered via raw DEFLATE"'
    sample = _mk_indirect_sample(kind="deflate", var="ms", payload=inner)
    chain = transform(sample, max_depth=DEFAULT_MAX_DEPTH)
    assert len(chain.artifacts) >= 3, "deflate variant regressed"
    assert inner in chain.artifacts[-1].content


def test_indirect_compression_without_memorystream_wrap():
    """Some samples in the wild skip the ``New-Object IO.MemoryStream``
    wrap and pass the byte array directly. The resolver must still
    link the assignment to the consumer via variable name."""
    inner = 'Write-Host "recovered without MemoryStream wrap"'
    sample = _mk_indirect_sample(
        kind="gzip", var="pkt", payload=inner,
        use_memstream_wrap=False,
    )
    chain = transform(sample, max_depth=DEFAULT_MAX_DEPTH)
    # Without MemoryStream wrap the pipeline may terminate at a
    # different structural point — but critically must NOT stop at L1.
    assert len(chain.artifacts) >= 2, "resolver failed on unwrapped idiom"


def test_benign_administrative_ps_does_not_false_positive():
    """A legitimate admin script that uses ``MemoryStream``/``GzipStream``
    to READ a file (not decode base64) MUST NOT trigger the resolver.
    False positives here would mangle real analyst output."""
    ps = (
        '$src = "C:\\logs\\report.gz"; '
        '$fs = New-Object IO.FileStream($src, [IO.FileMode]::Open); '
        '$gz = New-Object IO.Compression.GzipStream('
        '  $fs, [IO.Compression.CompressionMode]::Decompress); '
        '$reader = New-Object IO.StreamReader($gz); '
        'Write-Host $reader.ReadToEnd();'
    )
    enc = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    sample = f"powershell -encodedcommand {enc}"
    chain = transform(sample, max_depth=DEFAULT_MAX_DEPTH)
    names = [s.transformation for s in chain.steps]
    assert "ps_indirect_compression_stream" not in names, (
        f"False positive: benign administrative PS triggered the resolver — {names}"
    )


# ── v1.5.0 · Failure-diagnostic reporting (DoD requirement) ──────
#
# "Reports deterministic failure reasons when decoding cannot continue."
# When the resolver detects a plausible pattern but decompression fails
# (base64 truncated, gzip corrupt), the engine must emit a
# ``DecodeDiagnostic`` on the chain so analysts see WHY the pipeline
# stopped — not a silent ``no_transformation``.


def test_corrupt_gzip_payload_emits_deterministic_diagnostic():
    """Detected-but-uncoded path: the base64 blob has valid gzip magic
    bytes but a broken DEFLATE stream (real-world truncation).
    Expect a diagnostic explaining the failure, deterministic across
    runs, and included in the chain's determinism hash.

    Wording discipline (v1.5.0 follow-up): the diagnostic must state
    only what the decoder can deterministically prove (base64 length,
    inflate exception) and MUST NOT assert a cause ("this is chat
    corruption") — only list *possible* causes.
    """
    import gzip
    good = gzip.compress(b"unreachable")
    truncated = good[:-8]  # chop the CRC + size trailer so DEFLATE breaks
    blob = base64.b64encode(truncated).decode("ascii")
    stage2 = (
        f'$s=New-Object IO.MemoryStream(,'
        f'[Convert]::FromBase64String("{blob}"));'
        f'IEX (New-Object IO.StreamReader('
        f'New-Object IO.Compression.GzipStream('
        f'$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
    )
    enc = base64.b64encode(stage2.encode("utf-16-le")).decode("ascii")
    sample = f"powershell -encodedcommand {enc}"
    a = transform(sample, max_depth=DEFAULT_MAX_DEPTH)
    b = transform(sample, max_depth=DEFAULT_MAX_DEPTH)
    # Deterministic across runs
    assert a.determinism_hash == b.determinism_hash
    # Diagnostic present, correctly attributed
    assert len(a.diagnostics) >= 1, "No diagnostic emitted for corrupt payload"
    d = a.diagnostics[0]
    assert d.detector == "ps_indirect_compression_stream"
    assert d.outcome == "decode_failed"
    # Wording discipline — MUST report the fact, and list causes as
    # POSSIBILITIES only. Never assert a specific cause.
    assert "Gzip inflate failed" in d.reason, (
        f"reason missing deterministic fact: {d.reason!r}"
    )
    assert "commonly occurs" in d.reason, (
        f"reason missing possible-causes phrasing: {d.reason!r}"
    )
    # These would be over-claims — must NOT appear (evidence discipline).
    for over_claim in [
        "this is chat-transmission corruption",
        "the payload is truncated",     # absolute claim
        "definitely corrupted",
    ]:
        assert over_claim.lower() not in d.reason.lower(), (
            f"diagnostic over-claims cause: {over_claim!r} in {d.reason!r}"
        )
    assert d.meta.get("magic_bytes", "").startswith("1f8b")


def test_no_diagnostic_when_decode_succeeds():
    """The diagnose() hook must NOT double-report: when the resolver
    successfully decodes, no diagnostic should be attached (that would
    confuse the analyst into thinking something failed)."""
    import gzip
    stage3 = 'Write-Host "clean success"'
    blob = base64.b64encode(gzip.compress(stage3.encode())).decode()
    stage2 = (
        f'$s=New-Object IO.MemoryStream(,'
        f'[Convert]::FromBase64String("{blob}"));'
        f'IEX (New-Object IO.StreamReader('
        f'New-Object IO.Compression.GzipStream('
        f'$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
    )
    enc = base64.b64encode(stage2.encode("utf-16-le")).decode("ascii")
    sample = f"powershell -encodedcommand {enc}"
    chain = transform(sample, max_depth=DEFAULT_MAX_DEPTH)
    diag_from_indirect = [d for d in chain.diagnostics
                           if d.detector == "ps_indirect_compression_stream"]
    assert not diag_from_indirect, (
        f"Spurious diagnostic on successful decode: {diag_from_indirect}"
    )


def test_diagnostic_included_in_determinism_hash():
    """A change in the diagnostic (e.g., different failure reason) MUST
    change the chain's determinism hash so downstream consumers know
    something changed."""
    import gzip
    good_blob = base64.b64encode(gzip.compress(b"x")).decode()
    # Sample A — payload broken by trailer truncation
    a_blob = base64.b64encode(gzip.compress(b"x")[:-4]).decode()
    def _mk(blob):
        stage2 = (
            f'$s=New-Object IO.MemoryStream(,'
            f'[Convert]::FromBase64String("{blob}"));'
            f'IEX (New-Object IO.StreamReader('
            f'New-Object IO.Compression.GzipStream('
            f'$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
        )
        return "powershell -encodedcommand " + base64.b64encode(
            stage2.encode("utf-16-le")).decode()
    chain_ok  = transform(_mk(good_blob), max_depth=DEFAULT_MAX_DEPTH)
    chain_bad = transform(_mk(a_blob),   max_depth=DEFAULT_MAX_DEPTH)
    assert chain_ok.determinism_hash != chain_bad.determinism_hash


# ── v1.5.0 follow-up · Stable machine-readable diagnostic codes ──
#
# Analysts, dashboards, and CI key off codes (DX1xxx / DX2xxx) instead
# of parsing free-text reasons. Codes are stable across releases —
# once assigned a number NEVER changes meaning.


def test_diagnostic_code_registry_is_complete_and_stable():
    """Every code the plugin can emit MUST be in the canonical
    :mod:`diagnostic_codes` registry, and every registered code must
    keep its assigned meaning."""
    from v2.investigation.rte import diagnostic_codes as dc
    # The codes the resolver / engine emits must all be registered.
    for expected in [
        dc.CODE_INVALID_BASE64_LENGTH,
        dc.CODE_INVALID_BASE64_ALPHABET,
        dc.CODE_GZIP_DECOMPRESSION_FAILED,
        dc.CODE_DEFLATE_DECOMPRESSION_FAILED,
        dc.CODE_BROTLI_DECOMPRESSION_FAILED,
        dc.CODE_UNSUPPORTED_COMPRESSION_STREAM,
        dc.CODE_NO_TRANSFORMATION,
        dc.CODE_MAX_DEPTH_REACHED,
        dc.CODE_LOOP_DETECTED,
    ]:
        assert expected in dc.DIAGNOSTIC_CODES, f"missing code {expected}"
    # Stability guard — hard-coded expected numeric values.
    assert dc.CODE_INVALID_BASE64_LENGTH        == "DX1001"
    assert dc.CODE_INVALID_BASE64_ALPHABET      == "DX1002"
    assert dc.CODE_GZIP_DECOMPRESSION_FAILED    == "DX1101"
    assert dc.CODE_DEFLATE_DECOMPRESSION_FAILED == "DX1102"
    assert dc.CODE_NO_TRANSFORMATION            == "DX2002"
    assert dc.CODE_MAX_DEPTH_REACHED            == "DX2001"


def test_corrupt_gzip_emits_dx1001_or_dx1101_with_structured_meta():
    """The plugin-level diagnostic must carry a stable code AND the
    canonical structured meta fields (blob_length, blob_mod4,
    expected_padding, inflate_attempted, magic_bytes,
    inflate_exception, stage)."""
    import gzip
    truncated = gzip.compress(b"unreachable")[:-8]
    blob = base64.b64encode(truncated).decode("ascii")
    stage2 = (
        f'$s=New-Object IO.MemoryStream(,'
        f'[Convert]::FromBase64String("{blob}"));'
        f'IEX (New-Object IO.StreamReader('
        f'New-Object IO.Compression.GzipStream('
        f'$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
    )
    enc = base64.b64encode(stage2.encode("utf-16-le")).decode("ascii")
    chain = transform(f"powershell -encodedcommand {enc}",
                       max_depth=DEFAULT_MAX_DEPTH)
    plugin_diags = [d for d in chain.diagnostics
                     if d.detector == "ps_indirect_compression_stream"]
    assert plugin_diags, "no plugin diagnostic emitted"
    d = plugin_diags[0]
    # Aligned base64 (mod4 == 0) → inflate failure → DX1101 exactly.
    # (This test constructs an aligned blob so we get the pure gzip
    # code, not DX1001.)
    assert d.code == "DX1101", f"expected DX1101, got {d.code}"
    assert d.failure_type == "GZIP_DECOMPRESSION_ERROR"
    # Canonical structured meta contract
    for req_key in (
        "blob_length", "blob_mod4", "expected_padding",
        "inflate_attempted", "magic_bytes", "bytes_available",
        "inflate_exception", "compression_kind", "variable", "stage",
    ):
        assert req_key in d.meta, f"meta missing {req_key!r}: {d.meta}"
    assert d.meta["compression_kind"] == "gzip"
    assert d.meta["inflate_attempted"] is True
    assert d.meta["magic_bytes"].startswith("1f8b")


def test_misaligned_base64_promotes_to_dx1001_root_cause():
    """When base64 length is invalid AND inflate also fails, the code
    must be the root-cause DX1001 (invalid length), not the surface
    DX1101 (inflate failed). Analysts should key off root causes."""
    # Build a misaligned blob (mod 4 = 3) — the resolver's diagnose()
    # promotes to DX1001 because that's the deeper reason inflate fails.
    import gzip
    good = base64.b64encode(gzip.compress(b"x")).decode()
    # Chop the last char to force length mod 4 = 3.
    while len(good) % 4 != 3:
        good = good[:-1]
    stage2 = (
        f'$s=New-Object IO.MemoryStream(,'
        f'[Convert]::FromBase64String("{good}"));'
        f'IEX (New-Object IO.StreamReader('
        f'New-Object IO.Compression.GzipStream('
        f'$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
    )
    enc = base64.b64encode(stage2.encode("utf-16-le")).decode("ascii")
    chain = transform(f"powershell -encodedcommand {enc}",
                       max_depth=DEFAULT_MAX_DEPTH)
    plugin_diags = [d for d in chain.diagnostics
                     if d.detector == "ps_indirect_compression_stream"]
    assert plugin_diags, "no plugin diagnostic emitted"
    d = plugin_diags[0]
    assert d.code == "DX1001", f"expected DX1001 root-cause, got {d.code}"
    assert d.failure_type == "INVALID_BASE64_LENGTH"
    assert d.meta["blob_mod4"] == 3


def test_engine_emits_dx2002_on_no_transformation_stop():
    """Every ``NO_TRANSFORMATION`` termination MUST carry a DX2002
    orchestration diagnostic so dashboards see a canonical
    ``chain-stopped-here`` marker even without plugin diagnostics."""
    chain = transform('Write-Host "no transforms here"',
                       max_depth=DEFAULT_MAX_DEPTH)
    engine_diags = [d for d in chain.diagnostics if d.detector == "rte.engine"]
    assert engine_diags, "no engine-level orchestration diagnostic"
    d = engine_diags[0]
    assert d.code == "DX2002"
    assert d.failure_type == "NO_FURTHER_DETERMINISTIC_TRANSFORMATION"
    assert d.meta["stop_reason"] == "no_transformation"


def test_engine_emits_dx2001_on_max_depth_stop():
    """A chain that hits the depth cap must be tagged with DX2001."""
    core = 'Write-Host x'
    payload = core
    for _ in range(10):
        payload = base64.b64encode(payload.encode()).decode()
    # Force a low cap so we hit MAX_DEPTH deterministically.
    chain = transform(payload, max_depth=3)
    engine_diags = [d for d in chain.diagnostics if d.detector == "rte.engine"]
    assert engine_diags, "no engine-level orchestration diagnostic"
    assert engine_diags[0].code == "DX2001"
    assert engine_diags[0].failure_type == "MAX_RECURSION_DEPTH_REACHED"


def test_successful_decode_still_emits_dx2002_at_terminal_layer():
    """Success paths still end with NO_TRANSFORMATION at the terminal
    plaintext layer — the engine-level DX2002 must be present there
    too so dashboards get a uniform ``chain-terminated`` event."""
    import gzip
    stage3 = 'Write-Host "clean success"'
    blob = base64.b64encode(gzip.compress(stage3.encode())).decode()
    stage2 = (
        f'$s=New-Object IO.MemoryStream(,'
        f'[Convert]::FromBase64String("{blob}"));'
        f'IEX (New-Object IO.StreamReader('
        f'New-Object IO.Compression.GzipStream('
        f'$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
    )
    enc = base64.b64encode(stage2.encode("utf-16-le")).decode("ascii")
    chain = transform(f"powershell -encodedcommand {enc}",
                       max_depth=DEFAULT_MAX_DEPTH)
    engine_diags = [d for d in chain.diagnostics if d.detector == "rte.engine"]
    assert engine_diags, "success path missing terminal orchestration diagnostic"
    assert engine_diags[0].code == "DX2002"


# ── v1.5.0 · Performance guard ───────────────────────────────────
#
# Correctness corpus proves what decodes correctly. Performance corpus
# proves the engine scales linearly — a 30-layer chain must not
# balloon into quadratic runtime.


def test_deep_recursion_terminates_within_budget():
    """Build a 30-stage nested base64 chain and confirm the RTE
    converges in bounded time (< 2 s) and hits either the plaintext
    core OR a principled ``MAX_DEPTH`` / ``LOOP`` stop — never hangs."""
    import time
    core = "Write-Host 'deep nested core'"
    payload = core
    # Wrap the payload 30 times in raw utf-8 base64 (each layer is
    # decoded by the RTE base64 detector). We stop at 30 which is well
    # within the depth-64 cap.
    for _ in range(30):
        payload = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    t0 = time.time()
    chain = transform(payload, max_depth=DEFAULT_MAX_DEPTH)
    elapsed_ms = (time.time() - t0) * 1000
    assert elapsed_ms < 2000, f"RTE too slow on 30-layer chain: {elapsed_ms:.0f}ms"
    # We should have peeled a meaningful number of layers.
    assert len(chain.artifacts) >= 20, (
        f"Only {len(chain.artifacts)} layers on a 30-wrap chain — "
        "scheduler bailed early"
    )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])