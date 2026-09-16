"""RC5 · Phase 9.5c+ · Golden Corpus expansion + latency instrumentation tests.

Validates:
  * The extended corpus (51+ samples) still passes at 100 %.
  * Every sample carries a positive duration_ms measurement.
  * Aggregate latency percentiles are populated in GoldenRunReport.
  * Sample identifiers include the new GC-150 … GC-257 range.
"""
from __future__ import annotations

import os

os.environ.setdefault("SEMANTIC_ENGINE_V2", "true")

from engine.golden_corpus import run_corpus, GOLDEN_CORPUS


def test_corpus_has_expanded_beyond_baseline_15():
    ids = {s["id"] for s in GOLDEN_CORPUS}
    # Base 15 still present
    assert "GC-001-echo-hi" in ids
    assert "GC-090-ps-encoded-command" in ids
    # New expansion buckets
    assert any(sid.startswith("GC-150") for sid in ids), "expected benign-enterprise bucket"
    assert any(sid.startswith("GC-200") for sid in ids), "expected malware bucket"
    assert any(sid.startswith("GC-250") for sid in ids), "expected edge-case bucket"
    assert len(GOLDEN_CORPUS) >= 40, f"corpus should be ≥ 40 samples, got {len(GOLDEN_CORPUS)}"


def test_expanded_corpus_100_percent_pass_rate():
    r = run_corpus()
    failing = [s.sample_id for s in r.samples if not s.passed]
    assert r.pass_rate == 100.0, (
        f"expected 100% pass_rate, got {r.pass_rate}% — failing: {failing}"
    )
    assert r.regression_count == 0


def test_every_sample_has_positive_duration():
    r = run_corpus()
    zero_lat = [s.sample_id for s in r.samples if s.duration_ms <= 0]
    assert not zero_lat, f"samples with non-positive duration_ms: {zero_lat}"


def test_latency_percentiles_populated():
    r = run_corpus()
    assert r.latency, "latency dict should be populated"
    for k in ("mean_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms", "total_ms"):
        assert k in r.latency, f"missing latency key: {k}"
        assert r.latency[k] > 0.0, f"non-positive latency for {k}: {r.latency[k]}"
    # Percentile ordering — deterministic invariant.
    assert r.latency["p50_ms"] <= r.latency["p95_ms"] <= r.latency["p99_ms"] <= r.latency["max_ms"]


def test_benign_enterprise_scripts_are_benign():
    """FP floor test — the enterprise-admin bucket MUST NOT rate malicious."""
    r = run_corpus()
    for s in r.samples:
        if not s.sample_id.startswith(("GC-150", "GC-151", "GC-152", "GC-153",
                                        "GC-154", "GC-155", "GC-156", "GC-157",
                                        "GC-158", "GC-159", "GC-160", "GC-161",
                                        "GC-162", "GC-163", "GC-165", "GC-166",
                                        "GC-167")):
            continue
        assert s.got_verdict in ("Benign", "Suspicious"), (
            f"{s.sample_id} rated {s.got_verdict} — benign enterprise script "
            f"must never be Malicious"
        )
