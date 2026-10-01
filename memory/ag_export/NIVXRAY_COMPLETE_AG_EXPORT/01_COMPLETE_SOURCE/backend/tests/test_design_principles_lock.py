"""Design-Principles Lock Suite — enforces the 7 permanent architectural
invariants of the NivXRay platform (locked Feb 2026).

Every principle here is a HARD contract. Any code change that breaks these
tests is a regression on the enterprise-grade guarantees promised to users.

1. Every plugin is independent, deterministic and easily testable
2. Every output is fully explainable (verdict / confidence / MITRE / family)
3. Never over-decode — stop at family-identified terminal state
4. Every execution is fully traceable (times, decisions, stop reason)
5. Memory / recursion / loop guards enabled by default
6. AI stays optional — deterministic engine works without any LLM
7. Backwards-compat aliases preserved for existing APIs
"""
from __future__ import annotations

import base64
import time

import pytest

from engine import (
    AnalysisContext,
    AnalystReport,
    Budget,
    BaseDecoder,
    ConfidenceBreakdown,
    DecodeOutcome,          # BC alias for AnalystReport
    DecodeResult,           # BC alias for PluginResult
    DecoderRegistry,
    DetectResult,
    Fingerprint,
    Orchestrator,
    PluginExecutionReport,
    PluginResult,
)
from engine.fingerprint_util import compute as fp_compute


METERPRETER_INNER_B64 = (
    "38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0qHEzqGEfI"
    "vOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uwuIuQbw1bXIF7bGF4HVsF7qHsHIv"
    "BFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXLcw3t8eagxyKV+S01GVyNLVEpNSndLb1QFJNz2yyMj"
    "IyMS3HR0dHR0Sxl1WoTc9sqHIyMjeBLqcnJJIHJyS5giIyNwc0t0qrzl3PZzyq8jIyN4EvFxSyM"
    "R46dxcXFwcXNLyHYNGNz2quWg4HNLoxAjI6rDSSdzSTx1S1ZlvaXc9nwS3HR0SdxwdUsOJTtY3"
    "Pam4yyn6SIjIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx0SSRydXNLlHTDKNz2nCMMIyM"
    "a5FYke3PKWNzc3BLcyrIiIyPK6iIjI8tM3NzcDGZ5dEUjSEwodIgEoJKXg6X5qzPHl1iO1buG+"
    "VuC6rtpnoH41qg2+GNzdpA2TdUXolH+tJ/mUO65byu/dx/NX5qstEl/1PmpWeplO0fErSN2UEZ"
    "RDmJERk1XGQNuTFlKT09CDBYNEwMLQExOU0JXSkFPRhgDbnBqZgMaDRMYA3RKTUdMVFADbXcDF"
    "Q0SGAN3UUpHRk1XDBYNExgDYWxqZhoYc3dhcQouKSP4VpuFSK7RM6YYoEWg5NP6S9kDRy7v1+9"
    "l6XvafZkG84FqmRudQNMHNVeEM9WPDUrPGzBH2tZZpMkasn6vGEqpNpUUjihiQnkd4eovJ5UwN"
    "NWBtXdWBhJ7ISLKZq6AwYNoC+D0hbjBx8myxeQl7sj9hecL1KkJuU2mb+lDhPXgV+QPHbyNyxg"
    "W2LAdGXKMGjAwRDJfHspTfpmzbTfjpGaZreF0vnnOmPUrC+QoYqNMVtUlkoRz/PZlPTWZ+1fLS"
    "6OregYTdGzqEFvmcEtE2vxec7qhtWIjS9OWgXXc9kljSyMzIyNLIyNjI3RLe4dwxtz2sJojIyM"
    "jIvpycKrEdEsjAyMjcHVLMbWqwdz2puNX5agkIuCm41bGe+DLqt7c3BIXGg0RGw0bEg0SGiMjI"
    "yMg"
)


# ═══════════════════════════════════════════════════════════════════════════
# PRINCIPLE 1 · Plugin independence, determinism, testability
# ═══════════════════════════════════════════════════════════════════════════
class TestPrinciple1_PluginIndependence:
    def test_every_plugin_declares_required_contract(self):
        """Each registered plugin must expose the full BaseDecoder contract."""
        for p in DecoderRegistry.all():
            assert isinstance(p, BaseDecoder)
            for attr in ("id", "name", "category", "cost", "schema_version"):
                assert getattr(p, attr, None) not in (None, ""), \
                    f"{p.__class__.__name__} missing '{attr}'"
            # Callable contract
            assert callable(getattr(p, "detect", None))
            assert callable(getattr(p, "decode", None))
            assert callable(getattr(p, "explain", None))

    def test_detect_is_deterministic(self):
        """Same input → same DetectResult, run twice."""
        payload = base64.b64encode(b"testing determinism english text payload").decode()
        for p in DecoderRegistry.all():
            fp = fp_compute(payload)
            r1 = p.detect(payload, fp, AnalysisContext())
            r2 = p.detect(payload, fp, AnalysisContext())
            assert r1.confidence == r2.confidence, f"{p.id} non-deterministic detect"
            assert r1.why == r2.why

    def test_decode_is_deterministic(self):
        """Same input → same PluginResult on repeated decode."""
        payload = base64.b64encode(b"deterministic decode test").decode()
        p = DecoderRegistry.get("base64-decode")
        args = {}
        r1 = p.decode(payload, args, AnalysisContext())
        r2 = p.decode(payload, args, AnalysisContext())
        assert r1.output == r2.output
        assert r1.output_is_binary == r2.output_is_binary


# ═══════════════════════════════════════════════════════════════════════════
# PRINCIPLE 2 · Every output is fully explainable
# ═══════════════════════════════════════════════════════════════════════════
class TestPrinciple2_Explainability:
    def _run(self):
        return Orchestrator(
            AnalysisContext(budget=Budget(max_depth=6, wall_time_ms=4000))
        ).run(METERPRETER_INNER_B64)

    def test_report_carries_confidence_breakdown(self):
        r = self._run()
        assert isinstance(r.confidence_breakdown, ConfidenceBreakdown)
        assert r.confidence_breakdown.total == r.findings.risk_score
        assert r.confidence_breakdown.verdict == r.findings.verdict

    def test_contributions_sum_matches_total(self):
        r = self._run()
        contribs_sum = sum(c.points for c in r.confidence_breakdown.contributions)
        # Total is capped at 100; contributions may add to more
        assert r.confidence_breakdown.total == min(100, contribs_sum)

    def test_every_contribution_has_source_and_detail(self):
        r = self._run()
        assert r.confidence_breakdown.contributions
        for c in r.confidence_breakdown.contributions:
            assert c.source, "Contribution missing source"
            assert c.detail, "Contribution missing human-readable detail"
            assert c.points > 0

    def test_every_mitre_hint_has_evidence(self):
        r = self._run()
        assert r.findings.mitre_techniques
        for h in r.findings.mitre_techniques:
            assert h.id
            assert h.evidence, f"MITRE {h.id} missing evidence"
            assert h.source, f"MITRE {h.id} missing source (heuristic/archetype/family)"

    def test_family_has_evidence_when_matched(self):
        r = self._run()
        if r.findings.family.confidence >= 0.5:
            assert r.findings.family.evidence

    def test_stopped_reason_is_always_populated(self):
        r = self._run()
        assert r.stopped_reason, "stopped_reason must be populated on every run"
        assert r.terminal, "terminal state must be set"


# ═══════════════════════════════════════════════════════════════════════════
# PRINCIPLE 3 · Never over-decode
# ═══════════════════════════════════════════════════════════════════════════
class TestPrinciple3_NoOverDecode:
    def test_stops_at_family_identified(self):
        r = Orchestrator(
            AnalysisContext(budget=Budget(max_depth=12, wall_time_ms=4000))
        ).run(METERPRETER_INNER_B64)
        assert r.terminal == "family-identified"
        # Must NOT have kept decoding beyond the xor-brute recovery
        assert len(r.trace) <= 3
        # Chain must NOT include the same plugin firing many times
        chain = [s.decoder for s in r.trace]
        # No plugin should repeat more than twice in a row
        for i in range(len(chain) - 2):
            assert not (chain[i] == chain[i + 1] == chain[i + 2]), \
                f"Same plugin fired 3× in a row: {chain[i]}"

    def test_stops_at_english_terminal(self):
        # Simple base64 of plain English → single decode → English terminal
        s = base64.b64encode(
            b"the quick brown fox jumps over the lazy dog with powershell "
            b"invoke and expression download the payload"
        ).decode()
        r = Orchestrator(
            AnalysisContext(budget=Budget(max_depth=12, wall_time_ms=2000))
        ).run(s)
        # Must stop naturally, not exhaust budget
        assert r.terminal in ("english", "complete"), (
            f"Expected english/complete, got {r.terminal}: {r.stopped_reason}"
        )
        assert len(r.trace) <= 4


# ═══════════════════════════════════════════════════════════════════════════
# PRINCIPLE 4 · Every execution is traceable
# ═══════════════════════════════════════════════════════════════════════════
class TestPrinciple4_ExecutionTraceability:
    def test_plugin_report_populated(self):
        r = Orchestrator(
            AnalysisContext(budget=Budget(max_depth=6, wall_time_ms=4000))
        ).run(METERPRETER_INNER_B64)
        rep = r.plugin_report
        assert isinstance(rep, PluginExecutionReport)
        assert rep.layers_run > 0
        assert rep.entries, "plugin_report.entries must not be empty"
        assert rep.total_time_ms >= 0
        # Budget snapshot present
        assert set(rep.budget_snapshot).issuperset(
            {"max_depth", "max_branches", "wall_time_ms", "elapsed_ms"}
        )

    def test_every_entry_has_outcome(self):
        r = Orchestrator(
            AnalysisContext(budget=Budget(max_depth=6, wall_time_ms=4000))
        ).run(METERPRETER_INNER_B64)
        allowed = {"accepted", "skipped", "detect_zero",
                   "decode_error", "no_improvement"}
        for e in r.plugin_report.entries:
            assert e.outcome in allowed, f"unknown outcome: {e.outcome}"
            assert e.plugin
            assert e.layer >= 0

    def test_trace_steps_have_timings(self):
        r = Orchestrator(
            AnalysisContext(budget=Budget(max_depth=6, wall_time_ms=4000))
        ).run(METERPRETER_INNER_B64)
        for s in r.trace:
            assert s.exec_ms >= 0
            assert s.decoder
            assert s.confidence > 0
            assert s.why


# ═══════════════════════════════════════════════════════════════════════════
# PRINCIPLE 5 · Memory / recursion / loop guards enabled by default
# ═══════════════════════════════════════════════════════════════════════════
class TestPrinciple5_SafetyGuards:
    def test_depth_cap_default(self):
        assert Budget().max_depth == 12

    def test_walltime_cap_default(self):
        assert Budget().wall_time_ms == 5000

    def test_branches_cap_default(self):
        assert Budget().max_branches == 3

    def test_pathological_input_bounded(self):
        # Adversarial: 20 layers of base64 nesting — bounded intentionally so
        # we test the guards, not the OOM killer. Real orchestrator budget is
        # what enforces the true cap in production.
        payload = b"x" * 40
        for _ in range(20):
            payload = base64.b64encode(payload)
        r = Orchestrator(AnalysisContext(budget=Budget(max_depth=5, wall_time_ms=2000))).run(
            payload.decode()
        )
        # Must terminate within budget
        assert r.elapsed_ms < 3000
        assert r.terminal in ("budget", "complete", "english", "no-candidate", "family-identified")
        assert len(r.trace) <= 5

    def test_loop_detection_prevents_same_plugin_on_same_bytes(self):
        # Even in adversarial mode, orchestrator must not fire the same plugin
        # twice on identical bytes
        r = Orchestrator(
            AnalysisContext(budget=Budget(max_depth=12, wall_time_ms=4000))
        ).run(METERPRETER_INNER_B64)
        # No trace step should be immediately followed by same-decoder + same-input
        for i in range(len(r.trace) - 1):
            if r.trace[i].decoder == r.trace[i + 1].decoder:
                # Allowed only if input actually changed
                assert r.trace[i].preview != r.trace[i + 1].preview or \
                       r.trace[i].in_len != r.trace[i + 1].in_len


# ═══════════════════════════════════════════════════════════════════════════
# PRINCIPLE 6 · AI is optional; deterministic engine works alone
# ═══════════════════════════════════════════════════════════════════════════
class TestPrinciple6_AIOptional:
    def test_orchestrator_never_imports_ai(self):
        import inspect
        from engine import orchestrator as orch_mod
        src = inspect.getsource(orch_mod)
        # No AI/LLM calls anywhere in the orchestrator source
        for banned in ("emergentintegrations", "litellm", "anthropic",
                       "openai", "claude", "gpt-", "invoke_llm"):
            assert banned not in src.lower(), (
                f"Orchestrator must not depend on '{banned}' — AI must be optional"
            )

    def test_context_ai_disabled_by_default(self):
        assert AnalysisContext().ai_enabled is False

    def test_meterpreter_solved_without_ai(self):
        # Full end-to-end recovery with AI OFF (default) — deterministic only
        ctx = AnalysisContext(ai_enabled=False)
        ctx.budget = Budget(max_depth=6, wall_time_ms=4000)
        r = Orchestrator(ctx).run(METERPRETER_INNER_B64)
        assert r.terminal == "family-identified"
        assert "149.28.81.19" in r.findings.iocs.ips
        assert r.findings.family.confidence >= 0.8
        assert r.findings.risk_score >= 70


# ═══════════════════════════════════════════════════════════════════════════
# PRINCIPLE 7 · Backwards-compat aliases preserved
# ═══════════════════════════════════════════════════════════════════════════
class TestPrinciple7_BackwardsCompat:
    def test_decode_result_alias(self):
        assert DecodeResult is PluginResult

    def test_decode_outcome_alias(self):
        assert DecodeOutcome is AnalystReport

    def test_analyst_report_carries_legacy_output_field(self):
        r = Orchestrator().run("hello world")
        assert hasattr(r, "output")
        assert isinstance(r.output, str)
