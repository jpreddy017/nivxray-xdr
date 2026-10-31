"""Corpus Regression Suite — one pytest per sample.

Locked with SOC user 2026-07-25. This suite is a permanent regression gate:
every new sample added to `tests/corpus/samples.py` becomes part of the
required-to-pass ceiling automatically.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v2.semantic.ps_semantic import analyze                           # noqa: E402
from v2.semantic.ps_recovery import recover_powershell_from_b64       # noqa: E402
from tests.corpus.samples import all_samples, CorpusSample, by_category  # noqa: E402


def _matches_outcome(expected, actual: str) -> bool:
    if isinstance(expected, (tuple, list, set)):
        return actual in expected
    return actual == expected


@pytest.mark.parametrize("s", all_samples(), ids=lambda s: f"{s.category}:{s.id}")
def test_corpus_sample(s: CorpusSample) -> None:
    exp = s.expected

    # ── Special: raw-b64 samples go through the recovery module directly ──
    if exp.get("_raw_b64"):
        rep = recover_powershell_from_b64(s.cmdline)
        assert rep.status == "ok", (
            f"[{s.id}] raw-b64 recovery must succeed; got status={rep.status}, "
            f"attempts={[a.decoder+'/'+a.status for a in rep.attempts]}")
        recovered = rep.recovered_script
        for tok in exp.get("must_contain") or []:
            assert tok.lower() in recovered.lower(), (
                f"[{s.id}] must_contain token {tok!r} missing from recovered "
                f"{recovered[:120]!r}")
        for tok in exp.get("must_not_contain") or []:
            assert tok.lower() not in recovered.lower(), (
                f"[{s.id}] must_not_contain token {tok!r} leaked into recovered")
        if exp.get("confidence"):
            assert rep.confidence_band in exp["confidence"], (
                f"[{s.id}] confidence band {rep.confidence_band!r} not in "
                f"{exp['confidence']}")
        return

    # ── Normal path: run analyze() ────────────────────────────────
    r = analyze(s.cmdline)

    # outcome
    assert _matches_outcome(exp["outcome"], r.decode_outcome), (
        f"[{s.id}] decode_outcome={r.decode_outcome!r} not in "
        f"expected={exp['outcome']!r}")

    # must_contain / must_not_contain on recovered_script
    if r.decode_outcome != "decode_error":
        recovered = (r.recovered_script or "").lower()
        for tok in exp.get("must_contain") or []:
            assert tok.lower() in recovered, (
                f"[{s.id}] must_contain token {tok!r} missing from recovered "
                f"{recovered[:160]!r}")
        for tok in exp.get("must_not_contain") or []:
            assert tok.lower() not in recovered, (
                f"[{s.id}] must_not_contain token {tok!r} unexpectedly present")

    # Behavior extraction — subset match (order-independent)
    if exp.get("behaviors"):
        got_ids = {b["id"] for b in r.behaviors_v2}
        missing = set(exp["behaviors"]) - got_ids
        assert not missing, (
            f"[{s.id}] missing behavior tags {missing}; "
            f"extracted={sorted(got_ids)}")

    # Verdict banding
    if exp.get("verdict"):
        v = r.verdict_breakdown.get("verdict")
        assert v in exp["verdict"], (
            f"[{s.id}] verdict={v!r} not in expected {exp['verdict']}")

    # MITRE — any-of match
    if exp.get("mitre_any"):
        assert any(m in r.mitre_ids for m in exp["mitre_any"]), (
            f"[{s.id}] no expected MITRE ID from {exp['mitre_any']} in "
            f"{r.mitre_ids}")

    # Confidence band (only meaningful on decode_error path, but harmless elsewhere)
    if exp.get("confidence") and r.decode_outcome == "decode_error":
        band = r.decode_error.get("confidence_band")
        assert band in exp["confidence"], (
            f"[{s.id}] confidence_band={band!r} not in {exp['confidence']}")


# ── Category coverage summary ────────────────────────────────────
def test_corpus_covers_all_five_categories() -> None:
    """Corpus must include samples from every category defined in the
    frozen taxonomy — malware families, obfuscation, defense evasion,
    downloaders, and benign."""
    cats = by_category()
    required = {"malware_families", "obfuscation", "defense_evasion",
                "downloaders", "benign"}
    missing = required - set(cats.keys())
    assert not missing, f"Corpus missing categories: {missing}"
    # Each category should have ≥ 3 samples to be a meaningful gate
    for c in required:
        assert len(cats[c]) >= 3, (
            f"Category {c!r} has only {len(cats.get(c, []))} sample(s); "
            "need ≥ 3 for meaningful coverage.")


def test_corpus_prevents_false_positives_on_benign() -> None:
    """A mature corpus MUST include enough benign samples so we can prove
    no false-positives. Benign samples MUST NEVER receive a malicious
    verdict from the v2 breakdown."""
    for s in by_category().get("benign", []):
        r = analyze(s.cmdline)
        v = r.verdict_breakdown.get("verdict")
        assert v != "malicious", (
            f"FALSE POSITIVE on benign sample {s.id!r}: verdict={v!r} "
            f"(risk={r.verdict_breakdown.get('risk_score')}); "
            f"behaviors={[b['id'] for b in r.behaviors_v2]}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
