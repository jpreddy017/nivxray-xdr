"""P0.13 · Regression Gate.

Enforces the five clauses of the coverage contract on every CI run:

    1. Evidence → Behavior         ≥ 95 %
    2. Behavior → Projection       ≥ 95 %
    3. Projection → Recommendation ≥ 70 %
    4. Reachable-Behaviors KPI     may not drop  > 2 pp vs baseline
    5. Consumer Reachability       may not drop  > 2 pp for any
                                     declared consumer vs baseline

Clauses 1-3 are HARD architectural floors.  Clauses 4-5 are drift
guards — corpus churn is allowed, silent regressions are not.

Baseline lives at ``corpus/reports/baseline.json`` — an immutable
promotion checkpoint.  ``latest.json`` is refreshed on every corpus
run.  This suite compares the two.

Run only this gate::

    pytest -m coverage_metrics -k regression_gate
"""
from __future__ import annotations

import json
import pathlib

import pytest

from routers.coverage_metrics import REGRESSION_TOLERANCE_PP


pytestmark = pytest.mark.coverage_metrics


_REPORTS = pathlib.Path(__file__).resolve().parents[1] / "corpus" / "reports"
_LATEST_PATH   = _REPORTS / "latest.json"
_BASELINE_PATH = _REPORTS / "baseline.json"


def _load(p: pathlib.Path) -> dict:
    assert p.exists(), f"required report missing: {p}"
    return json.loads(p.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def latest() -> dict:
    return _load(_LATEST_PATH)


@pytest.fixture(scope="module")
def baseline() -> dict:
    return _load(_BASELINE_PATH)


# ══════════════════════════════════════════════════════════════════
# Hard architectural floors  (clauses 1-3)
# ══════════════════════════════════════════════════════════════════
# Floors are sourced from the single-source-of-truth ``_TARGETS``
# in routers/coverage_metrics so tests never drift from the API.
from routers.coverage_metrics import _TARGETS as _COVERAGE_TARGETS  # noqa: E402

@pytest.mark.parametrize("key", sorted(_COVERAGE_TARGETS.keys()))
def test_regression_gate_hard_floor(latest: dict, key: str):
    floor = _COVERAGE_TARGETS[key]
    cov = (latest.get("coverage") or {})
    cur = float(cov.get(key, 0.0))
    assert cur >= floor, (
        f"HARD-FLOOR breach · {key} = {cur} < {floor}. "
        f"Fix the corpus/producer/rule library — this is a "
        f"non-negotiable architectural threshold.")


# ══════════════════════════════════════════════════════════════════
# Reachable-Behaviors KPI  (clause 4)
# ══════════════════════════════════════════════════════════════════
def _reachable_pct(report: dict) -> float:
    ta = report.get("traceability_aggregate") or {}
    tot = int(ta.get("total_behaviors")  or 0)
    ok  = int(ta.get("complete_chains")  or 0)
    return round(ok / tot * 100, 2) if tot else 0.0


def test_regression_gate_reachable_behaviors_tolerance(latest, baseline):
    cur  = _reachable_pct(latest)
    base = _reachable_pct(baseline)
    assert cur >= base - REGRESSION_TOLERANCE_PP, (
        f"Reachable-Behaviors KPI regressed by more than "
        f"{REGRESSION_TOLERANCE_PP} pp · baseline={base} % "
        f"→ current={cur} %. "
        f"Either fix the regression or promote a new baseline "
        f"(cp corpus/reports/latest.json corpus/reports/baseline.json).")


# ══════════════════════════════════════════════════════════════════
# Consumer Reachability  (clause 5)
# ══════════════════════════════════════════════════════════════════
def _consumer_pcts_now() -> dict:
    """Live registry snapshot — this endpoint is derived, so we call
    the same code path the API does rather than re-implementing."""
    from routers.coverage_metrics import consumer_matrix
    return consumer_matrix()["per_consumer_pct"]


def _consumer_pcts_baseline() -> dict:
    """Baseline snapshot lives beside the coverage baseline.  The
    file is generated & refreshed by the same promotion step as
    ``baseline.json``.  First-time bootstrap writes it from the
    live registry so subsequent runs have something to compare
    against — this is deterministic since the matrix is a pure
    function of the frozen contracts."""
    p = _REPORTS / "consumer_matrix_baseline.json"
    if not p.exists():
        p.write_text(json.dumps(_consumer_pcts_now(), indent=2),
                        encoding="utf-8")
    return json.loads(p.read_text(encoding="utf-8"))


def test_regression_gate_consumer_reachability_tolerance():
    cur  = _consumer_pcts_now()
    base = _consumer_pcts_baseline()
    offenders = []
    for consumer, base_pct in base.items():
        cur_pct = float(cur.get(consumer, 0.0))
        if cur_pct < float(base_pct) - REGRESSION_TOLERANCE_PP:
            offenders.append(
                f"{consumer}: {base_pct} → {cur_pct} "
                f"(Δ = {round(cur_pct - float(base_pct), 2)} pp)")
    assert not offenders, (
        "Consumer Reachability regressed for: "
        + "; ".join(offenders)
        + "  · Either fix the regression or refresh "
          "corpus/reports/consumer_matrix_baseline.json.")


# ══════════════════════════════════════════════════════════════════
# Baseline hygiene  (guards CI from silently drifting)
# ══════════════════════════════════════════════════════════════════
def test_baseline_report_is_present_and_schema_matches(latest, baseline):
    assert baseline.get("schema_version") == latest.get("schema_version"), (
        "baseline.json schema does not match latest.json — bump baseline "
        "after any schema change (ADR-001).")
