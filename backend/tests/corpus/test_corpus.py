"""P0-1 Corpus pytest wrapper — emits metrics; gates on regressions."""
from __future__ import annotations

import json
import pytest

from tests.corpus.scenarios import CORPUS
from tests.corpus.runner import run_scenario, aggregate


@pytest.mark.parametrize("scenario", CORPUS, ids=lambda s: s.id)
def test_scenario(scenario):
    """One node per scenario — decoder + IOC + ATT&CK-coverage +
    surface-verdict checks.  HONEST scoring:
      · Passing = decoded_layers_pass AND ioc_recall>=0.6 AND
                  attck_recall>=0.5 AND verdict_pass (for measurable
                  scenarios).
      · e2e scenarios only check the evidence-layer subset since
        incident-scoped verdicts are NOT MEASURABLE at command scope.
    """
    r = run_scenario(scenario)
    hard_fails = []
    if not r.decoded_layers_pass:
        hard_fails.append(
            f"decoded_layers actual={r.decoded_layers_actual} "
            f"< expected={r.decoded_layers_expected}")
    if not r.decoded_substrings_pass:
        hard_fails.append("decoded_substrings not found in peeled output")
    # IOC recall floor 0.6 when expected IOCs present
    if r.ioc_expected and r.ioc_recall < 0.6:
        hard_fails.append(
            f"ioc recall={r.ioc_recall:.2f} < 0.6 "
            f"actual={r.ioc_actual} expected={r.ioc_expected}")
    # ATT&CK recall floor 0.5 when expected techniques present
    if r.attck_expected and r.attck_recall < 0.5:
        hard_fails.append(
            f"attck recall={r.attck_recall:.2f} < 0.5 "
            f"actual={sorted(r.attck_actual)} expected={sorted(r.attck_expected)}")
    if r.measurable_incident_verdict and not r.verdict_pass:
        hard_fails.append(
            f"verdict actual={r.verdict_actual} != expected={r.verdict_expected}")
    if hard_fails:
        pytest.fail(f"{scenario.id}: " + " · ".join(hard_fails))


def test_corpus_aggregate_metrics(pytestconfig, tmp_path_factory):
    """Aggregate PRF + accuracies + FP/FN + NOT-MEASURABLE list.

    Emits a JSON metrics report next to the corpus for CI capture,
    and asserts operator-defined floors (owner requested honest,
    not inflated, results — floors are intentionally modest)."""
    results = [run_scenario(s) for s in CORPUS]
    agg = aggregate(results)
    print("\n\n=== NIVXRAY P0-1 CORPUS METRICS ===")
    print(json.dumps(agg, indent=2, default=str))
    # write JSON artifact so testing agent + humans can archive
    out_dir = "/app/backend/tests/corpus"
    with open(f"{out_dir}/last_metrics.json", "w") as fp:
        json.dump(agg, fp, indent=2, default=str)

    # Honest floors — set BELOW our earlier local measurements so
    # they can be raised later.  Floors are absolute PASS/FAIL gates.
    assert agg["ioc_recall"]              >= 0.60, agg
    assert agg["attck_recall"]            >= 0.60, agg
    assert agg["decoder_layer_accuracy"]  >= 0.80, agg
    assert agg["verdict_accuracy"]        >= 0.75, agg
    assert len(agg["false_negatives"])    <= 2,    agg
