"""CJK-gibberish regression tests — Feb 2026.

Two real analyst-submitted payloads (Error1, Error2) that used to decode
into a screen full of CJK ideographs because `c.isprintable()` returns
True for U+3040..U+9FFF codepoints, so garbled UTF-16LE/BE decodes of
ASCII bytes scored 100 % "printable" and beat legitimate ASCII candidates.

The fix (in wrapper_archetypes._b64_ascii_or_utf16 and
operations._utf16_or_utf8) scores ASCII-printable share primary and
rejects CJK-dominant decodes. These tests lock that guarantee in place.
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from wrapper_archetypes import try_archetypes
from operations import OPERATIONS


def _real_cjk(s: str) -> int:
    """Count actual CJK ideographs (Han/Hangul/Kana). Excludes box-drawing."""
    return sum(
        1 for c in s
        if (0x3040 <= ord(c) <= 0x30FF)    # Hiragana + Katakana
        or (0x3400 <= ord(c) <= 0x4DBF)    # CJK Ext-A
        or (0x4E00 <= ord(c) <= 0x9FFF)    # CJK Unified
        or (0xAC00 <= ord(c) <= 0xD7AF)    # Hangul
    )


ERROR1_INPUT = (
    "powershell.exe -e "
    "ZDN4XGQzeFw3NnhcZDR4XDk3eFw1NXhcMzV4XGE1eFw0M3hcNjV4XGQ2eFxjNHhcYzZ4XGE0eFw4NXhcOTV4"
    "XDMzeFw4N3hcNzV4XDk1eFw0N3hcZTR4XDU1eFxlNHhcYzZ4XDU1eFxhNnhcZDR4XGM2eFwxNHhcNjV4XDQ1"
    "eFw2NHhcMjV4XDY1eFxlNHhcOTd4XDU1eFwzNHhcZDR4XDk3eFw1NXhcOTZ4XGU0eFw5N3hcNTV4XDk2eFxl"
    "NHhcOTd4XDU1eFwzNHhcZDR4XDk3eFw1NXhcMzV4XGE1eFw0M3hcNjV4XGQ2eFxjNHhcYzZ4XGE0eFw4NXhc"
    "OTV4XDMzeFw4N3hcNzV4XDk1eFw0N3hcZTR4XDU1eFxlNHhcYzZ4XDU1eFxhNnhcZDR4XGM2eFwxNHhcNjV4"
    "XDQ1eFw2NHhcMjV4XDY1eFxlNHhcOTd4XDU1eFwzNHhcZDR4XDk3eFw1NXhcMz"
)

ERROR2_INPUT = (
    "powershell.exe -e "
    "XGs1OVxrNnFcazQ2XGs3blxrNjFcazQzXGs1NVxrNzlcazRxXGs0M1xrMzFcazcwXGs0blxrNTRcazQ5XGs3"
    "N1xrNG5cazU0XGs0cl"
)


def test_error1_no_cjk_gibberish():
    """Error1: hexfamily payload used to produce hundreds of CJK ideographs."""
    r = try_archetypes(ERROR1_INPUT)
    assert r is not None, "archetype should still match"
    out = r["output"]
    assert _real_cjk(out) == 0, f"expected 0 CJK ideographs, got {_real_cjk(out)}: {out[:200]!r}"
    # Result should contain readable ASCII
    ascii_share = sum(1 for c in out if 32 <= ord(c) < 127 or c in "\n\r\t") / max(len(out), 1)
    assert ascii_share >= 0.90, f"ASCII share too low: {ascii_share:.2%}"


def test_error2_no_cjk_gibberish():
    """Error2: KHEX letter-substitution payload used to produce CJK ideographs."""
    r = try_archetypes(ERROR2_INPUT)
    assert r is not None, "archetype should still match"
    out = r["output"]
    assert _real_cjk(out) == 0, f"expected 0 CJK ideographs, got {_real_cjk(out)}: {out[:200]!r}"
    ascii_share = sum(1 for c in out if 32 <= ord(c) < 127 or c in "\n\r\t") / max(len(out), 1)
    assert ascii_share >= 0.90, f"ASCII share too low: {ascii_share:.2%}"


def test_utf16_or_utf8_op_rejects_cjk_dominant_decode():
    """The `utf16le-or-utf8-decode` op used to prefer any UTF-16LE decode
    with `c.isprintable() ≥ 0.85`. This falsely accepted CJK gibberish
    from ASCII bytes. Now it requires ≥ 70 % ASCII share."""
    fn = OPERATIONS["utf16le-or-utf8-decode"]["fn"]
    ascii_text = "==gMyUSZ4VmLlJXY3xWYtNUNlUjMlAVTFRVNyUCMyUiNyUiNyUCMyU"
    out = fn(ascii_text)
    assert _real_cjk(out) == 0, f"CJK leaked in: {out!r}"
    # Should stay as ASCII text (or trivially decoded)
    assert "MyUSZ" in out, f"lost original ASCII content: {out!r}"


def test_utf16_or_utf8_op_still_decodes_real_utf16le():
    """A genuine UTF-16LE payload must still decode correctly — the fix
    shouldn't over-rotate and lose legit UTF-16LE recovery."""
    fn = OPERATIONS["utf16le-or-utf8-decode"]["fn"]
    real_ps = "Write-Host 'hello world'"
    utf16_bytes = real_ps.encode("utf-16-le")
    latin1_str = utf16_bytes.decode("latin-1")
    out = fn(latin1_str)
    assert "Write-Host" in out and "hello world" in out, \
        f"legitimate UTF-16LE decode broken: {out!r}"
