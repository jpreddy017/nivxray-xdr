"""P0.12 · Coverage Metrics API + Consumer Reachability Matrix + Reachable-Behaviors KPI.

Contract-locked via ``tests/golden/coverage_summary_v1.json``.  Shape
regressions fail loudly; value regressions are intentionally allowed
so metrics can move.

Run only this suite::

    pytest -m coverage_metrics
"""
from __future__ import annotations

import json
import pathlib
import shutil

import pytest
from fastapi.testclient import TestClient

from server import app
from services.ida.behavior_registry import build_registry


pytestmark = pytest.mark.coverage_metrics


client = TestClient(app)

_GOLDEN = json.loads(
    (pathlib.Path(__file__).parent / "golden" / "coverage_summary_v1.json")
    .read_text(encoding="utf-8"))
_REPORTS_DIR = pathlib.Path(__file__).resolve().parents[1] / "corpus" / "reports"


# ══════════════════════════════════════════════════════════════════
# /api/investigation/coverage/summary
# ══════════════════════════════════════════════════════════════════
def test_summary_returns_schema_v1_and_required_top_level():
    r = client.get("/api/investigation/coverage/summary")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["schema_version"] == _GOLDEN["schema_version"]
    for k in _GOLDEN["required_top_level"]:
        assert k in body, f"missing top-level key: {k}"


def test_summary_coverage_carries_trend_deltas():
    body = client.get("/api/investigation/coverage/summary").json()
    cov = body["coverage"]
    for k in _GOLDEN["coverage_keys"]:
        assert k in cov, f"missing coverage key: {k}"
        for f in _GOLDEN["coverage_trend_fields"]:
            assert f in cov[k], f"coverage.{k} missing field: {f}"
        # current/previous/delta must be numeric; meets_target boolean.
        assert isinstance(cov[k]["current"],  (int, float))
        assert isinstance(cov[k]["previous"], (int, float))
        assert isinstance(cov[k]["delta"],    (int, float))
        assert isinstance(cov[k]["target"],   (int, float))
        assert isinstance(cov[k]["meets_target"], bool)


def test_summary_reachable_behaviors_kpi_shape():
    body = client.get("/api/investigation/coverage/summary").json()
    rb = body["reachable_behaviors"]
    for f in _GOLDEN["reachable_behaviors_fields"]:
        assert f in rb, f"reachable_behaviors missing: {f}"
    assert rb["reachable"] >= rb["consumed_by_recommendations"] >= 0
    assert 0.0 <= rb["percent"] <= 100.0


def test_summary_dead_rule_classification_uses_fixed_taxonomy():
    body = client.get("/api/investigation/coverage/summary").json()
    drc = body["dead_rule_classification"]
    for cat in _GOLDEN["dead_rule_classification_categories"]:
        assert cat in drc, f"dead_rule_classification missing category: {cat}"


def test_summary_traceability_aggregate_shape():
    body = client.get("/api/investigation/coverage/summary").json()
    ta = body["traceability_aggregate"]
    for f in _GOLDEN["traceability_aggregate_fields"]:
        assert f in ta


def test_summary_delta_zero_when_no_previous_report_supplied():
    body = client.get("/api/investigation/coverage/summary").json()
    for k in _GOLDEN["coverage_keys"]:
        entry = body["coverage"][k]
        # Without a `previous=` arg previous defaults to current, so
        # delta must be exactly 0.0 · this is what dashboards render.
        assert entry["previous"] == entry["current"]
        assert entry["delta"] == 0.0


def test_summary_supports_previous_query_arg(tmp_path: pathlib.Path,
                                                monkeypatch: pytest.MonkeyPatch):
    """Feed a synthetic ``previous.json`` via the query arg and assert
    a non-zero delta surfaces in the response."""
    # Copy latest → previous with a lower current value so delta > 0.
    latest = json.loads((_REPORTS_DIR / "latest.json").read_text())
    prev = json.loads(json.dumps(latest))            # deep copy
    prev["coverage"]["evidence_to_behavior_pct"] = max(
        0.0, float(prev["coverage"].get("evidence_to_behavior_pct", 0.0)) - 5.0)
    prev_path = _REPORTS_DIR / "_test_prev.json"
    prev_path.write_text(json.dumps(prev), encoding="utf-8")
    try:
        r = client.get("/api/investigation/coverage/summary",
                          params={"previous": "_test_prev.json"})
        assert r.status_code == 200
        entry = r.json()["coverage"]["evidence_to_behavior"]
        assert entry["delta"] > 0.0, (
            "delta must reflect the injected previous report")
        assert entry["previous"] < entry["current"]
    finally:
        prev_path.unlink(missing_ok=True)


def test_summary_404_when_report_missing():
    r = client.get("/api/investigation/coverage/summary",
                      params={"latest": "does_not_exist_9999.json"})
    assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════
# /api/investigation/coverage/consumer_matrix
# ══════════════════════════════════════════════════════════════════
def test_consumer_matrix_returns_dense_matrix():
    r = client.get("/api/investigation/coverage/consumer_matrix")
    assert r.status_code == 200
    body = r.json()
    assert body["schema_version"] == _GOLDEN["schema_version"]
    for k in _GOLDEN["consumer_matrix_required_top_level"]:
        assert k in body, f"consumer_matrix missing: {k}"


def test_consumer_matrix_covers_full_registry():
    body = client.get("/api/investigation/coverage/consumer_matrix").json()
    assert body["total_behaviors"] == len(build_registry())
    assert len(body["matrix"]) == body["total_behaviors"]


def test_consumer_matrix_rows_are_dense_over_declared_consumers():
    body = client.get("/api/investigation/coverage/consumer_matrix").json()
    consumers = body["consumers"]
    assert consumers, "consumer_matrix has no consumers"
    for row in body["matrix"]:
        assert "behavior_type" in row
        for c in consumers:
            assert c in row, f"row missing consumer column: {c}"
            assert isinstance(row[c], bool)


def test_consumer_matrix_declares_expected_categories():
    body = client.get("/api/investigation/coverage/consumer_matrix").json()
    declared = set(body["consumers"])
    expected = set(_GOLDEN["consumer_matrix_expected_categories"])
    # All expected categories must be declared — extras are allowed
    # (registry is additive) but nothing critical may disappear.
    missing = expected - declared
    assert not missing, f"consumer_matrix dropped expected categories: {missing}"


def test_consumer_matrix_universal_consumers_are_100_percent():
    """ssot_projector / provenance_endpoint / graph_api are declared
    universal in the registry — every behavior must be reachable."""
    body = client.get("/api/investigation/coverage/consumer_matrix").json()
    for c in ("ssot_projector", "provenance_endpoint", "graph_api"):
        assert body["per_consumer_pct"][c] == 100.0, (
            f"universal consumer {c} not at 100 %")


def test_consumer_matrix_recommendation_engine_reachability_nonzero():
    """At least one behavior must reach the recommendation engine —
    otherwise the trilogy KPI is meaningless."""
    body = client.get("/api/investigation/coverage/consumer_matrix").json()
    assert body["per_consumer_pct"].get("recommendation_engine", 0.0) > 0.0


# ══════════════════════════════════════════════════════════════════
# Reports-dir resolution robustness (regression guard)
# ══════════════════════════════════════════════════════════════════
def test_reports_dir_is_module_relative(tmp_path: pathlib.Path,
                                            monkeypatch: pytest.MonkeyPatch):
    """The endpoint must work regardless of the process CWD."""
    monkeypatch.chdir(tmp_path)
    r = client.get("/api/investigation/coverage/summary")
    assert r.status_code == 200, (
        f"summary broke when CWD != backend/: {r.status_code} {r.text}")
