"""Phase-A engine tests — plugin registry, orchestrator, budget, 3 pilot decoders.

These lock the Session-2 architecture in place. Every future decoder MUST NOT
break these tests.
"""
from __future__ import annotations

import base64
import time
from urllib.parse import quote

import pytest

from engine import (
    AnalysisContext,
    BaseDecoder,
    Budget,
    DecoderRegistry,
    DecodeOutcome,
    Orchestrator,
    TraceStep,
)
from engine.fingerprint_util import compute as fp_compute
from engine.models import DecodeResult, DetectResult, Fingerprint


# ---------------------------------------------------------------------------
# 1. Registry contract
# ---------------------------------------------------------------------------
class TestRegistry:
    def test_pilot_decoders_registered(self):
        ids = {d.id for d in DecoderRegistry.all()}
        assert "base64-decode" in ids
        assert "hex-decode" in ids
        assert "url-decode" in ids

    def test_candidates_ranked_by_confidence(self):
        fp = fp_compute("aGVsbG8gd29ybGQ=")  # base64 of "hello world"
        ctx = AnalysisContext()
        cands = DecoderRegistry.candidates("aGVsbG8gd29ybGQ=", fp, ctx)
        assert cands, "expected at least one candidate"
        assert cands[0][0].id == "base64-decode"
        assert cands[0][1].confidence >= 0.8

    def test_url_decoder_rejects_unrelated_input(self):
        fp = fp_compute("hello world no percents here")
        ctx = AnalysisContext()
        url = DecoderRegistry.get("url-decode")
        assert url is not None
        det = url.detect("hello world no percents here", fp, ctx)
        assert det.confidence == 0.0


# ---------------------------------------------------------------------------
# 2. Budget primitive
# ---------------------------------------------------------------------------
class TestBudget:
    def test_depth_cap(self):
        b = Budget(max_depth=3, wall_time_ms=5000)
        assert b.exhausted(0) is None
        assert b.exhausted(3) is not None
        assert "depth_cap" in b.exhausted(3)

    def test_time_cap(self):
        b = Budget(max_depth=100, wall_time_ms=1)
        time.sleep(0.01)
        assert b.exhausted(0) is not None
        assert "time_cap" in b.exhausted(0)

    def test_defaults(self):
        b = Budget()
        assert b.max_depth == 20
        assert b.max_branches == 3
        assert b.wall_time_ms == 5000


# ---------------------------------------------------------------------------
# 3. Individual decoder plugins
# ---------------------------------------------------------------------------
class TestBase64:
    def test_roundtrip_text(self):
        dec = DecoderRegistry.get("base64-decode")
        payload = base64.b64encode(b"hello world").decode()
        ctx = AnalysisContext()
        det = dec.detect(payload, fp_compute(payload), ctx)
        assert det.confidence >= 0.8
        res = dec.decode(payload, det.args, ctx)
        assert res.output == "hello world"
        assert not res.output_is_binary

    def test_padding_recovery(self):
        dec = DecoderRegistry.get("base64-decode")
        # missing padding
        s = "aGVsbG8gd29ybGQ"  # "hello world" without trailing =
        ctx = AnalysisContext()
        det = dec.detect(s, fp_compute(s), ctx)
        # Length mod 4 == 3 — decoder should accept
        res = dec.decode(s, det.args, ctx)
        assert res.output == "hello world"
        assert any("Auto-padded" in n for n in res.notes)

    def test_url_safe_variant(self):
        dec = DecoderRegistry.get("base64-decode")
        raw = b"\x00\x01\xfe\xff\xfa\x80\xa0\xb0\xc0\xd0\xe0\xf0\xff"
        s = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        ctx = AnalysisContext()
        det = dec.detect(s, fp_compute(s), ctx)
        # Should trigger urlsafe branch
        assert det.confidence > 0
        res = dec.decode(s, det.args, ctx)
        assert res.output.encode("latin-1") == raw


class TestHex:
    def test_plain_hex(self):
        dec = DecoderRegistry.get("hex-decode")
        s = b"hello".hex()
        ctx = AnalysisContext()
        det = dec.detect(s, fp_compute(s), ctx)
        assert det.confidence > 0.5
        res = dec.decode(s, det.args, ctx)
        assert res.output == "hello"

    def test_prefixed_hex(self):
        dec = DecoderRegistry.get("hex-decode")
        s = "\\x68\\x65\\x6c\\x6c\\x6f"
        ctx = AnalysisContext()
        det = dec.detect(s, fp_compute(s), ctx)
        assert det.confidence >= 0.75
        res = dec.decode(s, det.args, ctx)
        assert res.output == "hello"

    def test_rejects_odd_length(self):
        dec = DecoderRegistry.get("hex-decode")
        s = "48656c6c6"  # odd length
        det = dec.detect(s, fp_compute(s), AnalysisContext())
        assert det.confidence == 0.0


class TestUrl:
    def test_percent_decode(self):
        dec = DecoderRegistry.get("url-decode")
        s = quote("hello world & powershell")
        ctx = AnalysisContext()
        det = dec.detect(s, fp_compute(s), ctx)
        assert det.confidence > 0
        res = dec.decode(s, det.args, ctx)
        assert res.output == "hello world & powershell"

    def test_no_percent_no_fire(self):
        dec = DecoderRegistry.get("url-decode")
        det = dec.detect("nothing to decode", fp_compute("nothing to decode"), AnalysisContext())
        assert det.confidence == 0.0


# ---------------------------------------------------------------------------
# 4. Orchestrator — end-to-end recursion
# ---------------------------------------------------------------------------
class TestOrchestrator:
    def test_plaintext_no_op(self):
        r = Orchestrator().run("hello world")
        assert isinstance(r, DecodeOutcome)
        assert r.trace == []
        assert r.terminal in ("no-candidate", "english")

    def test_single_layer_base64(self):
        s = base64.b64encode(b"the quick brown fox jumps over").decode()
        r = Orchestrator().run(s)
        assert r.output == "the quick brown fox jumps over"
        assert len(r.trace) == 1
        assert r.trace[0].decoder == "base64-decode"
        assert r.terminal == "complete"

    def test_nested_base64_recursion(self):
        inner = base64.b64encode(b"payload inside two base64 wrappers").decode()
        outer = base64.b64encode(inner.encode()).decode()
        r = Orchestrator().run(outer)
        assert "payload inside two base64 wrappers" in r.output
        assert len(r.trace) >= 2
        assert all(s.decoder == "base64-decode" for s in r.trace)

    def test_b64_of_hex(self):
        plain = b"powershell iex download from remote server"
        step1 = plain.hex()
        step2 = base64.b64encode(step1.encode()).decode()
        r = Orchestrator().run(step2)
        assert "powershell" in r.output
        assert [s.decoder for s in r.trace] == ["base64-decode", "hex-decode"]

    def test_depth_cap_respected(self):
        # 8 nested base64 layers, budget only allows 3
        payload = b"deep payload english text"
        for _ in range(8):
            payload = base64.b64encode(payload)
        ctx = AnalysisContext(budget=Budget(max_depth=3, wall_time_ms=3000))
        r = Orchestrator(ctx).run(payload.decode())
        assert len(r.trace) <= 3
        assert r.terminal == "budget"
        assert "depth_cap" in r.stopped_reason

    def test_time_cap_respected(self):
        # tiny wall-time budget
        s = base64.b64encode(b"hello").decode()
        ctx = AnalysisContext(budget=Budget(max_depth=10, wall_time_ms=1))
        time.sleep(0.005)  # already over budget before we start
        r = Orchestrator(ctx).run(s)
        assert r.terminal == "budget"

    def test_trace_step_has_required_fields(self):
        s = base64.b64encode(b"hello world english text").decode()
        r = Orchestrator().run(s)
        assert r.trace
        step = r.trace[0]
        assert isinstance(step, TraceStep)
        assert step.decoder
        assert step.schema_version
        assert step.confidence > 0
        assert step.in_len == len(s)
        assert step.preview
        assert step.why

    def test_stopped_reason_populated(self):
        # payload that only decodes once
        s = base64.b64encode(b"the quick brown fox jumps over the lazy dog").decode()
        r = Orchestrator().run(s)
        assert r.stopped_reason
        assert r.terminal == "complete"


# ---------------------------------------------------------------------------
# 5. Registry isolation (custom decoder registration/unregistration)
# ---------------------------------------------------------------------------
class TestRegistryIsolation:
    def test_custom_decoder_register_and_unregister(self):
        class UpperDecoder(BaseDecoder):
            id = "upper-test"
            name = "Uppercase Test"
            category = "normalize"
            def detect(self, p, fp, ctx):
                return DetectResult(confidence=0.99 if p.islower() else 0.0, why="")
            def decode(self, p, args, ctx):
                return DecodeResult(output=p.upper())

        DecoderRegistry.register(UpperDecoder())
        try:
            assert DecoderRegistry.get("upper-test") is not None
            fp = fp_compute("hello")
            cands = DecoderRegistry.candidates("hello", fp, AnalysisContext())
            assert any(d.id == "upper-test" for d, _ in cands)
        finally:
            DecoderRegistry.unregister("upper-test")
        assert DecoderRegistry.get("upper-test") is None
