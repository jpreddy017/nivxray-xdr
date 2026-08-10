"""ADR-004 Step 1 · Phase 2 · Diff-report presence + zero-UNEXPLAINED gate.

Owner-mandated: `Zero UNEXPLAINED divergences before Phase 4 consumer
switch`. This test enforces that gate on every CI run.

Auto-regenerates the diff report if it's missing so a fresh checkout
green-checks without manual invocation.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


_REPORT = (
    Path(__file__).resolve().parent.parent
    / "corpus" / "vendor" / "v1" / "reports"
    / "step1_diff_report.json"
)


@pytest.fixture(scope="module", autouse=True)
def _ensure_report_present():
    if not _REPORT.exists():
        from tests.step1_diff_report import write_report
        write_report()


def _load():
    return json.loads(_REPORT.read_text())


def test_diff_report_present_and_shaped():
    d = _load()
    assert d["fixture_count"] == 14
    assert len(d["entries"]) == 14
    assert len(d["engines_probed"]) == 4
    for e in d["entries"]:
        assert set(e["engines"].keys()) == {
            "A_nivxforge", "B_verdict_v2", "C_v2_score", "D_ps_verdict"
        }
        # Every cell must be classified
        for eng_id in e["engines"]:
            assert eng_id in e["classification"]["per_engine"]
            assert e["classification"]["per_engine"][eng_id]["class"] in {
                "PRESERVED", "CORRECTED", "INTENTIONAL", "UNEXPLAINED",
            }


def test_diff_report_zero_unexplained_before_phase_4():
    """Owner-mandated gate: NO UNEXPLAINED entries permitted before
    Phase 4 (consumer switch). Every divergence must be classified as
    PRESERVED / CORRECTED / INTENTIONAL with a written explanation."""
    d = _load()
    unexplained = [
        (e["fixture_id"], eng)
        for e in d["entries"]
        for eng, v in e["classification"]["per_engine"].items()
        if v["class"] == "UNEXPLAINED"
    ]
    assert not unexplained, (
        f"UNEXPLAINED divergences present ({len(unexplained)}): "
        f"{unexplained}. Phase 4 (consumer switch) is BLOCKED until "
        f"every divergence is classified as PRESERVED / CORRECTED / "
        f"INTENTIONAL. Update `backend/tests/step1_diff_report.py` "
        f"classifier or `GROUND_TRUTH` to explain each divergence."
    )


def test_diff_report_totals_are_consistent():
    d = _load()
    total = sum(d["class_counts"].values())
    # 14 fixtures × 4 engines = 56 cells
    assert total == 14 * 4
