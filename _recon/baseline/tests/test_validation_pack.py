"""CI release gate · Validation Pack (Phase 4.2).

This is the deterministic accuracy gate for every code change touching
ingestion, normalization, correlation, IKG, story, or the verdict engine.

Every dataset in the Golden Investigation Corpus declares an
`ExpectedInvestigation` contract. This test suite fails the build if
even one dimension regresses.

Metrics tracked:
    - Overall dataset pass rate
    - Per-dimension accuracy (Verdict, Score, FP-Guard, MITRE, Story,
      StoryText, Processes, Parent-Child, IOCs, Workspace, Report)
    - Investigation build time
"""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v2.validation import run_all, run_dataset
from v2.ingestion.golden_corpus import GOLDEN_CORPUS


def test_all_datasets_pass():
    """Every Golden Corpus dataset must pass every dimension."""
    summary = run_all()
    failed = [r.id for r in summary.results if not r.overall]
    assert not failed, (
        f"{len(failed)}/{summary.datasets_total} datasets failed: {failed}. "
        f"Per-dimension accuracy: {summary.to_dict()['dimension_accuracy']}"
    )


def test_overall_accuracy_is_100_percent():
    summary = run_all().to_dict()
    assert summary["overall_accuracy"] == 100.0, summary["overall_accuracy"]


def test_every_dimension_at_100_percent():
    """No single validation dimension may regress below 100%."""
    summary = run_all().to_dict()
    below = {k: v for k, v in summary["dimension_accuracy"].items() if v < 100.0}
    assert not below, f"regressions: {below}"


def test_benign_datasets_never_flagged_malicious():
    """Guardrail: no benign or ambiguous dataset may score malicious/critical."""
    offenders = []
    for ds_id, ds in GOLDEN_CORPUS.items():
        if ds.category not in ("benign", "ambiguous"):
            continue
        r = run_dataset(ds_id)
        if r.verdict_band.lower() in ("malicious", "critical"):
            offenders.append((ds_id, r.verdict_band, r.device_score))
    assert not offenders, f"benign-labeled datasets flagged as malicious: {offenders}"


def test_malicious_datasets_score_at_least_15():
    """Guardrail: no malicious dataset may score below 15 (would be a false negative)."""
    fns = []
    for ds_id, ds in GOLDEN_CORPUS.items():
        if ds.category != "malicious":
            continue
        r = run_dataset(ds_id)
        if r.device_score < 15:
            fns.append((ds_id, r.device_score))
    assert not fns, f"malicious datasets scored below 15 (potential FN): {fns}"


def test_investigation_is_fast():
    """Every investigation must complete within 250 ms even under CI load."""
    slow = []
    for ds_id in GOLDEN_CORPUS.keys():
        r = run_dataset(ds_id)
        if r.duration_ms > 250:
            slow.append((ds_id, r.duration_ms))
    assert not slow, f"slow investigations: {slow}"


def test_categories_populated():
    """The corpus must cover benign + suspicious + malicious + ambiguous."""
    cats = {ds.category for ds in GOLDEN_CORPUS.values()}
    assert {"benign", "suspicious", "malicious"} <= cats, cats


def test_corpus_size_at_least_30():
    """Guard against accidentally shrinking the corpus."""
    assert len(GOLDEN_CORPUS) >= 30, len(GOLDEN_CORPUS)


if __name__ == "__main__":
    import traceback
    tests = [(n, f) for n, f in list(globals().items())
             if n.startswith("test_") and callable(f)]
    ok, fail = 0, 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ✓ {name}")
            ok += 1
        except AssertionError as e:
            print(f"  ✗ {name} · AssertionError · {e}")
            fail += 1
        except Exception as e:
            print(f"  ✗ {name} · {type(e).__name__}: {e}")
            traceback.print_exc()
            fail += 1
    print(f"\n{ok}/{ok+fail} passed")
    sys.exit(0 if fail == 0 else 1)
