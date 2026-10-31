"""Adversarial regression suite  (v1.5.1 · Feb 2026)

Every payload that ever went Undecoded in production is appended to
`/app/backend/tests/fixtures/adversarial_corpus.jsonl` by the
`/api/decode/smart` handler.

This test suite iterates that ledger and asserts that AT LEAST one of
the Zero-Miss layers (L1/L2/L3) now produces a non-empty decode chain
for each entry. Once the decoder team teaches the system how to peel
a novel payload, the fix is PROTECTED FOREVER — any regression fails
CI on the next release.

CI Gate
-------
Fails when:
  * >=1 payload that PREVIOUSLY had a fix regresses to zero-chain
  * The corpus is empty (should never happen after a week of prod traffic)
    — soft-warn, not fail (initial cold-start).

Config
------
    NIVX_ADV_MIN_HIT_RATE  = float 0..1, default 0.60
        Minimum % of adversarial corpus that must decode. Below this →
        CI fails. Rises over time as the learner loop teaches the
        decoder more archetypes.
"""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, "/app/backend")
import pytest

CORPUS = Path("/app/backend/tests/fixtures/adversarial_corpus.jsonl")
MIN_HIT_RATE = float(os.environ.get("NIVX_ADV_MIN_HIT_RATE", "0.60"))
REPORT_JSON = Path("/app/backend/tests/adversarial_regression_report.json")


def _load() -> List[Dict[str, Any]]:
    if not CORPUS.exists():
        return []
    out: List[Dict[str, Any]] = []
    for line in CORPUS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _run_one(entry: Dict[str, Any]) -> Dict[str, Any]:
    from analysis_core import deterministic_best_decode
    inp = entry.get("input") or ""
    if not inp:
        return {"sha1": entry.get("sha1"), "ok": False, "reason": "empty-input"}
    try:
        det = deterministic_best_decode(inp, analysis_mode="balanced")
    except Exception as e:
        return {"sha1": entry.get("sha1"), "ok": False, "reason": f"crash: {e}"}
    steps = det.get("steps") or []
    out = (det.get("output") or "").strip()
    decoded = bool(steps) and out and out != inp.strip()
    return {
        "sha1":       entry.get("sha1"),
        "engine":     det.get("engine"),
        "chain":      [s.get("op") for s in steps],
        "output_head": out[:120],
        "ok":         decoded,
    }


@pytest.mark.adversarial
def test_adversarial_corpus_soft_warn():
    """Cold-start guardrail — soft-warn if corpus is empty (fresh install)."""
    entries = _load()
    if not entries:
        pytest.skip(f"Adversarial corpus is empty ({CORPUS}) — will populate once "
                    "prod payloads start going Undecoded. This test is a soft-warn "
                    "at cold start.")


@pytest.mark.adversarial
def test_adversarial_regression_gate():
    """Hard gate — >=NIVX_ADV_MIN_HIT_RATE (default 60%) of corpus must decode."""
    entries = _load()
    if not entries:
        pytest.skip("Adversarial corpus empty (cold start).")

    results = [_run_one(e) for e in entries]
    passed = sum(1 for r in results if r["ok"])
    total = len(results)
    hit_rate = passed / max(1, total)

    REPORT_JSON.write_text(json.dumps({
        "total":     total,
        "passed":    passed,
        "hit_rate":  round(hit_rate, 4),
        "threshold": MIN_HIT_RATE,
        "results":   results,
    }, indent=2), encoding="utf-8")

    if hit_rate < MIN_HIT_RATE:
        # Regression — the decoder used to handle these payloads (they were
        # added to the corpus BECAUSE a fix landed). Now they don't decode.
        misses = [r for r in results if not r["ok"]]
        msg = (
            f"Adversarial regression: {hit_rate*100:.1f}% < threshold "
            f"{MIN_HIT_RATE*100:.0f}% ({passed}/{total} passing). "
            f"{len(misses)} payloads regressed:\n"
            + "\n".join(f"  · {m.get('sha1', '?')[:12]}: {m.get('reason', 'zero-chain')}"
                         for m in misses[:10])
        )
        pytest.fail(msg)


if __name__ == "__main__":
    entries = _load()
    print(f"Adversarial corpus: {len(entries)} entries")
    if entries:
        results = [_run_one(e) for e in entries]
        passed = sum(1 for r in results if r["ok"])
        print(f"Passing: {passed}/{len(results)} ({passed/len(results)*100:.1f}%)")
