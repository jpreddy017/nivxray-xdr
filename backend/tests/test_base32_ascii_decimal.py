"""Regression tests — Base32 + ASCII-decimal-code stream auto-detection.

Bug context (Feb 2026): a user pasted a payload consisting solely of A-Z + 2-7
characters (Base32 alphabet). Every existing decoder path assumed Base64 and
failed. Additionally the decoded output was a stream of decimal ASCII codes
(space-separated), which needed a NEW ascii-decimal-decode op.

Both are now auto-detected by the magic-decoder candidate picker.
"""
from __future__ import annotations
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import operations, ops_extended  # noqa: F401 — register op registry
from operations import OPERATIONS
from magic_decoder import magic_decode


# ─── unit: ascii-decimal-decode op ───────────────────────────────────────
def test_ascii_decimal_decode_op_registered():
    assert "ascii-decimal-decode" in OPERATIONS


def test_ascii_decimal_decode_space_separated():
    fn = OPERATIONS["ascii-decimal-decode"]["fn"]
    # "Hello" = 72 101 108 108 111
    assert fn("72 101 108 108 111") == "Hello"


def test_ascii_decimal_decode_comma_separated():
    fn = OPERATIONS["ascii-decimal-decode"]["fn"]
    assert fn("72,101,108,108,111") == "Hello"


def test_ascii_decimal_decode_ignores_garbage():
    """Values > 255 must be skipped, not crash."""
    fn = OPERATIONS["ascii-decimal-decode"]["fn"]
    # 300 is skipped; 72=H, 101=e
    assert fn("300 72 999 101") == "He"


def test_ascii_decimal_decode_empty_input():
    fn = OPERATIONS["ascii-decimal-decode"]["fn"]
    assert fn("") == ""
    assert fn("no digits here") == ""


# ─── integration: magic_decoder detects Base32 automatically ─────────────
def test_magic_detects_base32_alone():
    payload_bytes = b"Get-Process | Select ProcessName"
    b32 = base64.b32encode(payload_bytes).decode()
    r = magic_decode(b32, max_depth=3, max_branches=6, top_n=3)
    outputs = [x.get("output", "") for x in (r.get("top_results") or [])]
    assert any("Get-Process" in o for o in outputs), \
        f"Base32 auto-detection failed. outputs={outputs}"


def test_magic_detects_ascii_decimal_alone():
    """`72 101 108 108 111 32 87 111 114 108 100` → 'Hello World'"""
    ascii_stream = " ".join(str(b) for b in b"Hello World this is nivxray")
    r = magic_decode(ascii_stream, max_depth=3, max_branches=6, top_n=3)
    outputs = [x.get("output", "") for x in (r.get("top_results") or [])]
    assert any("Hello World" in o for o in outputs), \
        f"ASCII-decimal auto-detection failed. outputs={outputs}"


def test_magic_chains_base32_then_ascii_decimal():
    """The user's Feb-2026 payload pattern: Base32 wraps a decimal ASCII stream.
    magic_decoder must peel both layers automatically."""
    inner_text = "cmd.exe /c whoami"
    ascii_stream = " ".join(str(b) for b in inner_text.encode("ascii"))
    b32 = base64.b32encode(ascii_stream.encode("ascii")).decode()
    r = magic_decode(b32, max_depth=4, max_branches=8, top_n=3)
    outputs = [x.get("output", "") for x in (r.get("top_results") or [])]
    assert any(inner_text in o for o in outputs), \
        f"Base32 → ASCII-decimal chain not peeled. outputs={[o[:80] for o in outputs]}"


def test_base32_not_misdetected_as_base64():
    """Regression: a pure Base32 payload should NOT be treated as Base64."""
    # Payload only uses A-Z + 2-7 — impossible for real base64 to happen upon by chance.
    b32 = base64.b32encode(b"secret-message-here-long").decode()
    from magic_decoder import _pick_candidates
    cands = _pick_candidates(b32)
    ops = [c["op"] for c in cands]
    # Both should be attempted, but base32-decode should come BEFORE base64-decode
    assert "base32-decode" in ops
    b32_idx = ops.index("base32-decode")
    b64_idx = ops.index("base64-decode") if "base64-decode" in ops else 999
    assert b32_idx < b64_idx, f"Base32 must be prioritised over Base64 when alphabet is A-Z2-7 only. Got: {ops}"
