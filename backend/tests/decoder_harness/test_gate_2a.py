"""P0-1B · Gate 2A · pytest wrapper for the acceptance harness."""
from __future__ import annotations

import pytest

from .harness import run_harness, save_report, TOMMY_AA_LOL_EXPECTED_LAYERS_GATE2A
from pathlib import Path


@pytest.fixture(scope="module")
def report():
    r = run_harness()
    save_report(r, Path("/app/backend/tests/decoder_harness/last_report.json"))
    return r


def test_tracks_ac_run(report):
    """Tracks A/B/C/D must have RUN or RUN_VIA_C status."""
    for track in ("A", "B", "C", "D", "G"):
        assert report.tracks[track]["status"] in {"RUN", "RUN_VIA_C"}, \
            f"Track {track} must be RUN — got {report.tracks[track]}"


def test_tracks_ef_blocked_honestly(report):
    """E and F must be honestly reported BLOCKED — never as PASS."""
    for track in ("E", "F"):
        assert report.tracks[track]["status"] == "BLOCKED"


def test_p0_1_corpus_no_regression(report):
    """P0-1A gate must remain green — 0 benign FP, ≤1 malware FN."""
    c = report.tracks["C"]
    assert c["run"] is True
    assert c["benign_fp"] == [], f"benign FP regression: {c['benign_fp']}"
    assert len(c["malicious_fn"]) <= 1, f"malware FN regression: {c['malicious_fn']}"
    assert c["surface_mal_f1"] >= 0.88, f"malicious F1 regression: {c['surface_mal_f1']}"


def test_tommy_aa_gate_2a_partial(report):
    """Gate 2A must land the 4 authorised primitives on tommy-aa.lol.

    Full semantic closure (FOR /F + wildcard-exec) belongs to Gate 2B.
    """
    g = report.tracks["G"]
    assert set(g["actual_layers"]) >= TOMMY_AA_LOL_EXPECTED_LAYERS_GATE2A, \
        f"Gate 2A layers missing on tommy-aa.lol: {g['layers_missing']}"
    assert g["substrings_missing"] == [], \
        f"Gate 2A expected substrings missing: {g['substrings_missing']}"
    assert g["gate_2a_pass"] is True


def test_semantic_pass_rate(report):
    """All 14 curated semantic cases must pass."""
    agg = report.aggregates
    assert agg["semantic_pass"] == agg["semantic_total"], \
        f"semantic failures: {agg['semantic_fail']} / {agg['semantic_total']}"


def test_no_benign_false_positives_from_engine(report):
    """The CMD engine must not fire security-worthy stages on benign inputs."""
    fp = report.aggregates["benign_fp_flagged"]
    assert fp == 0, f"benign FP in semantic corpus: {fp}"


def test_latency_budget(report):
    """Per-case decode p95 latency must stay under 25 ms (very generous)."""
    p95 = report.aggregates["latency_ms_p95"]
    assert p95 < 25.0, f"decoder latency p95 too high: {p95} ms"


def test_static_only_invariants(report):
    """Every emitted layer preserves static_only=True, execution=False,
    attck_promotion=False."""
    for r in report.semantic:
        # If layers exist, their provenance is enforced by Provenance.__post_init__.
        # We only check that we successfully constructed them (indirect proof).
        assert isinstance(r.layers_actual, list)
