"""Trust Metrics · permanent regression gate.

Every future PR must maintain analyst trust. This gate fails the
build if:
    * accuracy       < 90 %
    * honesty        < 100 % (unsupported claims are zero-tolerance)
    * explainability < 100 %
    * unknown_handling < 100 %
    * any hard failures recorded

These thresholds enforce the user directive:
    "From this point forward, every new capability should be
     evaluated by a single question: Does it measurably increase
     analyst trust?"
"""
from __future__ import annotations

import os

import pytest

from v2.investigation.trust import load_corpus, score

_CORPUS_DIR = os.path.join(
    os.path.dirname(__file__), "trust_corpus"
)


@pytest.fixture(scope="module")
def report():
    samples = load_corpus(_CORPUS_DIR)
    assert samples, "trust corpus is empty — must contain ≥ 1 sample"
    return score(samples)


def test_trust_corpus_size_meets_minimum(report):
    # Locked minimum — start small, expand only after harness itself
    # is validated. Failing this means someone removed a sample.
    assert report.total_samples >= 10, (
        f"trust corpus shrank below the 10-sample minimum "
        f"(currently {report.total_samples})"
    )


def test_trust_no_hard_failures(report):
    """Unsupported claims + missed unknown-handling MUST be zero.
    This is the single most important trust metric — the tool must
    never claim something it cannot support with evidence."""
    assert report.hard_failures == 0, (
        f"{report.hard_failures} HARD failure(s) — see per-sample failures:\n"
        + "\n".join(
            f"  · {s.sample_id}: {'; '.join(s.failures)}"
            for s in report.per_sample if s.failures
        )
    )


def test_trust_accuracy(report):
    assert report.accuracy >= 0.90, (
        f"accuracy dropped below 90% (currently {report.accuracy * 100:.1f}%)"
    )


def test_trust_honesty(report):
    """Zero tolerance — every claim must be evidence-supported."""
    assert report.honesty >= 1.0, (
        f"honesty dropped below 100% (currently {report.honesty * 100:.1f}%). "
        "The tool must never make unsupported claims."
    )


def test_trust_explainability(report):
    """Zero tolerance — every fired intent must carry evidence AND be
    reachable in the evidence graph."""
    assert report.explainability >= 1.0, (
        f"explainability dropped below 100% "
        f"(currently {report.explainability * 100:.1f}%). "
        "Every conclusion must cite canonical evidence."
    )


def test_trust_unknown_handling(report):
    """Zero tolerance — samples that require admitting uncertainty
    must NOT be over-claimed."""
    assert report.unknown_handling >= 1.0, (
        f"unknown_handling dropped below 100% "
        f"(currently {report.unknown_handling * 100:.1f}%). "
        "The tool must admit uncertainty when evidence is unavailable."
    )


def test_trust_report_shape_is_stable(report):
    """The report shape is a public contract — downstream dashboards
    and PR bots depend on these keys."""
    d = report.to_dict()
    expected = {
        "total_samples", "accuracy", "honesty", "explainability",
        "unknown_handling", "hard_failures", "per_sample",
    }
    assert set(d.keys()) == expected
    for s in d["per_sample"]:
        assert set(s.keys()) >= {
            "sample_id", "passed", "verdict_actual",
            "verdict_expected", "failures", "warnings",
        }
