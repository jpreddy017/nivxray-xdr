"""RC5 · Phase 9.5c · Tests for scripts/golden_delta.py.

Deterministic checks that the PR-delta reporter renders correct
markdown for the baseline, regression, and improvement scenarios.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Make scripts/ importable.
_BACKEND = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(_BACKEND / "scripts"))

import golden_delta  # type: ignore  # noqa: E402


def _mk_run(pass_rate=100.0, passed=15, total=15, regr=0,
            samples=None, mitre_cov=100.0, verdict_acc=100.0) -> dict:
    return {
        "run_id": "test",
        "ts": "2026-02-23T00:00:00Z",
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": pass_rate,
        "regression_count": regr,
        "newly_supported": [],
        "newly_failing": [],
        "coverage": {"decode": 100.0, "semantic": 100.0, "behavior": 100.0,
                     "mitre": mitre_cov, "verdict": 100.0},
        "accuracy": {"verdict": verdict_acc, "mitre": 100.0, "lolbin": 100.0,
                     "behavior": 100.0, "overall_pass_rate": pass_rate},
        "samples": samples or [
            {"sample_id": f"GC-00{i}", "input_hash": "x", "language": "cmd",
             "passed": True, "reasons": [], "got_verdict": "Benign",
             "expected_verdict": "Benign", "verdict_ok": True, "mitre_ok": True,
             "lolbin_ok": True, "behavior_ok": True,
             "decode_conf": 100, "semantic_conf": 100, "behavior_conf": 100,
             "mitre_conf": 100, "verdict_conf": 100, "weighted_conf": 100,
             "exception": None}
            for i in range(1, total + 1)
        ],
    }


def test_baseline_report_when_no_base():
    head = _mk_run()
    rpt = golden_delta.build_report(head, base=None)
    assert "initial baseline" in rpt
    assert "100.00 (baseline)" in rpt
    assert "✅ **PASS**" in rpt


def test_regression_blocks_gate():
    head = _mk_run(pass_rate=90.0, passed=13, regr=2)
    rpt = golden_delta.build_report(head, base=_mk_run())
    assert "❌ **BLOCK**" in rpt
    assert "regression" in rpt.lower() or "90.00" in rpt


def test_verdict_shift_appears_in_per_sample_deltas():
    base = _mk_run()
    head = _mk_run()
    head["samples"][0]["got_verdict"] = "Malicious"
    rpt = golden_delta.build_report(head, base=base)
    assert "verdict shift" in rpt
    assert "Benign → Malicious" in rpt


def test_pass_to_fail_flipped_sample_reported():
    base = _mk_run()
    head = _mk_run()
    head["samples"][0]["passed"] = False
    rpt = golden_delta.build_report(head, base=base)
    assert "PASS→FAIL" in rpt or "FAIL→PASS" in rpt


def test_gate_pass_when_head_stable():
    base = _mk_run(pass_rate=100.0, verdict_acc=100.0)
    head = _mk_run(pass_rate=100.0)
    rpt = golden_delta.build_report(head, base=base)
    assert "✅ **PASS**" in rpt


def test_delta_arrows_render_for_coverage_improvement():
    base = _mk_run(mitre_cov=90.0)
    head = _mk_run(mitre_cov=93.33)
    rpt = golden_delta.build_report(head, base=base)
    assert "🔺" in rpt


def test_run_script_end_to_end(tmp_path: Path):
    head = _mk_run()
    hp = tmp_path / "h.json"; hp.write_text(json.dumps(head))
    out = tmp_path / "d.md"
    rc = golden_delta.main(["--head", str(hp), "--out", str(out)])
    assert rc == 0
    body = out.read_text()
    assert "RC5 Golden Corpus" in body
    assert "✅ **PASS**" in body
