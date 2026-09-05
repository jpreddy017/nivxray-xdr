"""Phase-B tests · Batch 1 — base32 / rot13 / rot47."""
from __future__ import annotations

import base64
import codecs

import pytest

from engine import (
    AnalysisContext,
    Budget,
    DecoderRegistry,
    Orchestrator,
)
from engine.fingerprint_util import compute as fp


# ---------------------------------------------------------------------------
# Base32
# ---------------------------------------------------------------------------
class TestBase32:
    def test_registered(self):
        assert DecoderRegistry.get("base32-decode") is not None

    def test_roundtrip(self):
        dec = DecoderRegistry.get("base32-decode")
        s = base64.b32encode(b"powershell command line").decode()
        det = dec.detect(s, fp(s), AnalysisContext())
        assert det.confidence > 0.5
        res = dec.decode(s, det.args, AnalysisContext())
        assert res.output == "powershell command line"

    def test_case_insensitive(self):
        dec = DecoderRegistry.get("base32-decode")
        s = base64.b32encode(b"hello world lower").decode().lower()
        # Lowercase is still detectable — we uppercase before dispatch
        det = dec.detect(s, fp(s), AnalysisContext())
        # Length must still be mult-of-8 → same rule
        assert det.confidence > 0.0

    def test_orchestrator_end_to_end(self):
        s = base64.b32encode(b"the quick brown fox jumps over the lazy dog").decode()
        r = Orchestrator(AnalysisContext(budget=Budget(max_depth=4, wall_time_ms=1000))).run(s)
        assert "quick brown fox" in r.output
        assert r.trace[0].decoder == "base32-decode"


# ---------------------------------------------------------------------------
# ROT13
# ---------------------------------------------------------------------------
class TestRot13:
    def test_registered(self):
        assert DecoderRegistry.get("rot13-decode") is not None

    def test_detects_rotated_english(self):
        plain = "the quick brown fox jumps over the lazy dog with powershell"
        rot = codecs.encode(plain, "rot_13")
        dec = DecoderRegistry.get("rot13-decode")
        det = dec.detect(rot, fp(rot), AnalysisContext())
        assert det.confidence > 0.4
        res = dec.decode(rot, det.args, AnalysisContext())
        assert res.output == plain

    def test_does_not_fire_on_plain_english(self):
        plain = "the quick brown fox jumps over the lazy dog"
        dec = DecoderRegistry.get("rot13-decode")
        det = dec.detect(plain, fp(plain), AnalysisContext())
        assert det.confidence == 0.0

    def test_orchestrator_end_to_end(self):
        plain = "download the invoke expression from remote powershell script"
        rot = codecs.encode(plain, "rot_13")
        r = Orchestrator(AnalysisContext(budget=Budget(max_depth=3, wall_time_ms=1000))).run(rot)
        assert "invoke" in r.output.lower()
        assert any(s.decoder == "rot13-decode" for s in r.trace)


# ---------------------------------------------------------------------------
# ROT47
# ---------------------------------------------------------------------------
class TestRot47:
    def test_registered(self):
        assert DecoderRegistry.get("rot47-decode") is not None

    def _rot47(self, s):
        return "".join(
            chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c
            for c in s
        )

    def test_detects_rotated_english(self):
        plain = "the quick brown fox jumps over the lazy dog with powershell command"
        rot = self._rot47(plain)
        dec = DecoderRegistry.get("rot47-decode")
        det = dec.detect(rot, fp(rot), AnalysisContext())
        assert det.confidence > 0.4
        res = dec.decode(rot, det.args, AnalysisContext())
        assert res.output == plain

    def test_does_not_fire_on_plain_english(self):
        plain = "the quick brown fox jumps over the lazy dog"
        dec = DecoderRegistry.get("rot47-decode")
        det = dec.detect(plain, fp(plain), AnalysisContext())
        assert det.confidence == 0.0
