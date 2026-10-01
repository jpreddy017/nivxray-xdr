"""Phase-C tests · ascii85 / base91 plugins."""
from __future__ import annotations

import base64

from engine import AnalysisContext, Budget, DecoderRegistry, Orchestrator
from engine.fingerprint_util import compute as fp


class TestAscii85:
    def test_registered(self):
        assert DecoderRegistry.get("ascii85-decode") is not None

    def test_adobe_framed(self):
        plain = b"Hello ascii85 world with english prose payload"
        s = "<~" + base64.a85encode(plain, adobe=False).decode() + "~>"
        dec = DecoderRegistry.get("ascii85-decode")
        det = dec.detect(s, fp(s), AnalysisContext())
        assert det.confidence >= 0.9
        res = dec.decode(s, det.args, AnalysisContext())
        assert res.output == plain.decode()

    def test_unframed(self):
        plain = b"unframed ascii85 english payload with sufficient length for reliable detection"
        s = base64.a85encode(plain, adobe=False).decode()
        dec = DecoderRegistry.get("ascii85-decode")
        det = dec.detect(s, fp(s), AnalysisContext())
        assert det.confidence > 0.5
        res = dec.decode(s, det.args, AnalysisContext())
        assert res.output == plain.decode()

    def test_english_input_not_consumed(self):
        prose = "the quick brown fox jumps over the lazy dog with plenty of english words"
        dec = DecoderRegistry.get("ascii85-decode")
        det = dec.detect(prose, fp(prose), AnalysisContext())
        assert det.confidence <= 0.1


class TestBase91:
    def test_registered(self):
        assert DecoderRegistry.get("base91-decode") is not None

    def test_roundtrip(self):
        # Use the reference `base91` package as ground truth
        import base91 as _b91
        plain = b"basE91 english prose payload with enough content to survive detection"
        s = _b91.encode(plain)
        dec = DecoderRegistry.get("base91-decode")
        det = dec.detect(s, fp(s), AnalysisContext())
        assert det.confidence > 0
        res = dec.decode(s, det.args, AnalysisContext())
        assert res.output == plain.decode()

    def test_english_input_not_consumed(self):
        prose = "the quick brown fox jumps over the lazy dog with plenty of english words"
        dec = DecoderRegistry.get("base91-decode")
        det = dec.detect(prose, fp(prose), AnalysisContext())
        assert det.confidence == 0.0
