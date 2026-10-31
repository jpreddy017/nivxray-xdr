"""CI-gated pytest wrapper for the Real-World Stress Suite.

Runs `real_world_stress_suite.run_and_report()` and enforces:
  * MITRE hit-rate >= 75 %
  * Undecoded rate <= 10 %
  * IOC recall    >= 70 %

Emits the same JSON + HTML report the CLI writes.
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, "/app/backend")

import pytest

# The suite lives inside tests/ — import directly.
sys.path.insert(0, os.path.dirname(__file__))
from real_world_stress_suite import (  # noqa: E402
    CORPUS, THRESHOLDS, check_gate, run_and_report,
)


REAL_WORLD_MARK = pytest.mark.real_world


@REAL_WORLD_MARK
def test_corpus_is_populated():
    """Guardrail — every release must ship the >=100 curated payloads."""
    assert len(CORPUS) >= 100, f"real-world corpus shrank to {len(CORPUS)} entries"
    assert all(e["min_layers"] >= 5 for e in CORPUS), "corpus contains <5-layer entries"


@REAL_WORLD_MARK
def test_ci_gate_pass():
    """The three-headed CI gate — this test is the release blocker."""
    payload = run_and_report()
    ok, fails = check_gate(payload["summary"])
    if not ok:
        # Print a helpful message so CI log shows what went wrong.
        s = payload["summary"]
        print("\n" + "=" * 60)
        print("REAL-WORLD STRESS GATE FAILED")
        print(f"  MITRE hit-rate  : {s['mitre_hit_rate']*100:.1f}%  (>= {THRESHOLDS['min_mitre_hit_rate']*100:.0f}%)")
        print(f"  Undecoded rate  : {s['undecoded_rate']*100:.1f}%  (<= {THRESHOLDS['max_undecoded_rate']*100:.0f}%)")
        print(f"  IOC recall      : {(s['ioc_recall'] or 0)*100:.1f}%  (>= {THRESHOLDS['min_ioc_recall']*100:.0f}%)")
        for f in fails:
            print(f"  X {f}")
        print("=" * 60)
    assert ok, "Real-World Stress CI gate failed: " + "; ".join(fails)
