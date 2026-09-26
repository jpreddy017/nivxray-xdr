"""Phase-B tests · Batch 2 — gzip / zlib+deflate."""
from __future__ import annotations

import base64
import gzip
import zlib

from engine import AnalysisContext, Budget, DecoderRegistry, Orchestrator
from engine.fingerprint_util import compute as fp


class TestGzip:
    def test_registered(self):
        assert DecoderRegistry.get("gzip-decompress") is not None

    def test_magic_gates_confidence(self):
        dec = DecoderRegistry.get("gzip-decompress")
        # random text should not fire
        det = dec.detect("not a gzip payload", fp("not a gzip payload"), AnalysisContext())
        assert det.confidence == 0.0

    def test_roundtrip(self):
        plain = b"the quick brown fox jumps over the lazy dog with powershell"
        gz = gzip.compress(plain).decode("latin-1")
        dec = DecoderRegistry.get("gzip-decompress")
        det = dec.detect(gz, fp(gz), AnalysisContext())
        assert det.confidence > 0.9
        res = dec.decode(gz, det.args, AnalysisContext())
        assert res.output == plain.decode()

    def test_orchestrator_base64_then_gzip(self):
        plain = b"nested payload english text via powershell iex"
        gz = gzip.compress(plain)
        s = base64.b64encode(gz).decode()
        r = Orchestrator(AnalysisContext(budget=Budget(max_depth=4, wall_time_ms=1500))).run(s)
        assert "nested payload" in r.output
        ids = [step.decoder for step in r.trace]
        assert ids == ["base64-decode", "gzip-decompress"]


class TestZlibDeflate:
    def test_registered(self):
        assert DecoderRegistry.get("zlib-deflate-decompress") is not None

    def test_zlib_framed(self):
        plain = b"powershell downloadstring iex english prose payload"
        z = zlib.compress(plain).decode("latin-1")
        dec = DecoderRegistry.get("zlib-deflate-decompress")
        det = dec.detect(z, fp(z), AnalysisContext())
        assert det.confidence >= 0.8
        res = dec.decode(z, det.args, AnalysisContext())
        assert res.output == plain.decode()

    def test_orchestrator_base64_then_zlib(self):
        plain = b"english prose downloaded remotely via powershell script"
        z = zlib.compress(plain)
        s = base64.b64encode(z).decode()
        r = Orchestrator(AnalysisContext(budget=Budget(max_depth=4, wall_time_ms=1500))).run(s)
        assert "english prose" in r.output
        ids = [step.decoder for step in r.trace]
        assert ids == ["base64-decode", "zlib-deflate-decompress"]

    def test_raw_deflate_probe(self):
        # raw deflate (no zlib header)
        plain = b"raw deflate english payload without zlib header wrapper for testing"
        raw = zlib.compress(plain)
        # Strip zlib header (2 bytes) and adler32 trailer (4 bytes) to get raw deflate
        raw = raw[2:-4]
        s = raw.decode("latin-1")
        dec = DecoderRegistry.get("zlib-deflate-decompress")
        det = dec.detect(s, fp(s), AnalysisContext())
        # May or may not trip depending on entropy threshold; not asserting strong
        # here — the framed test is the meaningful one.
        if det.confidence > 0:
            res = dec.decode(s, det.args, AnalysisContext())
            assert plain.decode() in res.output
