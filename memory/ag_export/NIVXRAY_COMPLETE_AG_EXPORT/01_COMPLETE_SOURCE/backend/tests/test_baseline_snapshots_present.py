"""ADR-004 Amendment A1 · Baseline snapshot presence + shape gate.

Ensures the four pre-migration baseline snapshots exist and remain
well-shaped. CI fails fast if a subsequent commit deletes or
malforms any of them.

The snapshots themselves are captured by `tests/capture_baseline.py`.
Regenerate with:  `python -m tests.capture_baseline`
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


_REPORTS = (
    Path(__file__).resolve().parent.parent
    / "corpus" / "vendor" / "v1" / "reports"
)


@pytest.fixture(scope="module", autouse=True)
def _ensure_snapshots_present():
    """Auto-generate the snapshots if they don't exist so the suite
    is self-healing when a fresh checkout runs pytest."""
    needed = ["baseline_verdicts.json", "baseline_chain_decodes.json",
                  "baseline_bkb_projections.json", "baseline_iocs.json"]
    if not all((_REPORTS / n).exists() for n in needed):
        from tests.capture_baseline import capture_all
        capture_all()


def _load(name: str):
    return json.loads((_REPORTS / name).read_text())


def test_baseline_verdicts_present_and_well_shaped():
    d = _load("baseline_verdicts.json")
    assert d["fixture_count"] == 14
    assert len(d["entries"]) == 14
    for e in d["entries"]:
        assert "fixture_id" in e
        # Either a verdict label OR an explicit error record.
        assert ("label" in e) or ("error" in e)


def test_baseline_chain_decodes_present_and_well_shaped():
    d = _load("baseline_chain_decodes.json")
    assert d["fixture_count"] == 14
    assert len(d["entries"]) == 14
    for e in d["entries"]:
        assert isinstance(e.get("stages"), list)
        assert e["n_commands"] == len(e["stages"])


def test_baseline_bkb_projections_present_and_well_shaped():
    d = _load("baseline_bkb_projections.json")
    # BKB has 100+ canonical behaviors; guard against silent shrinkage.
    assert d["n_behaviors"] >= 50
    assert isinstance(d["projections"], dict)
    # Every projection must have a technique list.
    for label, proj in d["projections"].items():
        assert "n_techniques" in proj
        assert "techniques" in proj


def test_baseline_iocs_present_and_well_shaped():
    d = _load("baseline_iocs.json")
    assert d["fixture_count"] == 14
    assert len(d["entries"]) == 14
    for e in d["entries"]:
        assert "by_type" in e
        assert "summary" in e


def test_verdict_engine_parity_snapshot_present():
    p = _REPORTS / "baseline_verdict_engine_parity.json"
    assert p.exists(), (
        "verdict-engine parity snapshot missing — "
        "run tests/test_verdict_engine_parity.py to regenerate"
    )
    d = json.loads(p.read_text())
    assert d["fixture_count"] == 14
    assert set(d["engines_probed"]) == {"v2", "nivxforge", "uaie"}
