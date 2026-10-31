"""Phase 9 · Shadow-Run Delta Analyzer tests (30+)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from engine.shadow import (
    ShadowSnapshot, compute_delta_report, make_snapshot, _percentile, _rank,
)


def _snap(**k) -> ShadowSnapshot:
    base = dict(
        sample_hash="h", day="2026-02-21",
        ts=datetime(2026, 2, 21, tzinfo=timezone.utc),
        language="cmd",
    )
    base.update(k)
    return ShadowSnapshot(**base)


# ── (1-5) empty + basic ────────────────────────────────────────────
def test_empty_snapshot_list_returns_total_zero():
    r = compute_delta_report([])
    assert r == {"total": 0}


def test_report_returns_expected_keys():
    r = compute_delta_report([_snap()])
    for k in ("total", "verdict_matrix", "verdict_change_summary",
              "fp_change", "fn_change", "mitre", "lolbins",
              "behaviors", "confidence_medians",
              "reconstruction", "latency_ms",
              "graph_completeness", "parser"):
        assert k in r


def test_snapshot_immutable_extra_forbidden():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        ShadowSnapshot(
            sample_hash="h", day="2026-02-21",
            ts=datetime.now(timezone.utc), language="cmd",
            not_a_field="x",  # type: ignore
        )


def test_percentile_empty_returns_none():
    assert _percentile([], 50) is None


def test_percentile_deterministic():
    assert _percentile([100, 200, 300, 400, 500], 95) is not None


# ── (6-12) verdict change tracking ─────────────────────────────────
def test_unchanged_verdict_pair_counted():
    snaps = [_snap(rc4_verdict="Benign", rc5_verdict="Benign") for _ in range(3)]
    r = compute_delta_report(snaps)
    assert r["verdict_change_summary"]["unchanged"] == 3
    assert r["verdict_change_summary"]["upgraded"] == 0


def test_upgraded_verdict_counted():
    snaps = [_snap(rc4_verdict="Benign", rc5_verdict="Malicious")]
    r = compute_delta_report(snaps)
    assert r["verdict_change_summary"]["upgraded"] == 1


def test_downgraded_verdict_counted():
    snaps = [_snap(rc4_verdict="Critical", rc5_verdict="Suspicious")]
    r = compute_delta_report(snaps)
    assert r["verdict_change_summary"]["downgraded"] == 1


def test_fp_change_flags_benign_labelled_upgrades():
    snaps = [_snap(rc4_verdict="Benign", rc5_verdict="Malicious",
                   corpus_label="benign")]
    assert compute_delta_report(snaps)["fp_change"] == 1


def test_fn_change_flags_malicious_labelled_downgrades():
    snaps = [_snap(rc4_verdict="Malicious", rc5_verdict="Benign",
                   corpus_label="malicious")]
    assert compute_delta_report(snaps)["fn_change"] == 1


def test_fp_only_when_v5_is_malicious_or_critical():
    snaps = [_snap(rc4_verdict="Benign", rc5_verdict="Suspicious",
                   corpus_label="benign")]
    assert compute_delta_report(snaps)["fp_change"] == 0


def test_verdict_matrix_records_transitions():
    snaps = [_snap(rc4_verdict="Benign", rc5_verdict="Suspicious"),
             _snap(rc4_verdict="Benign", rc5_verdict="Suspicious"),
             _snap(rc4_verdict="Benign", rc5_verdict="Benign")]
    r = compute_delta_report(snaps)
    assert r["verdict_matrix"]["Benign"]["Suspicious"] == 2
    assert r["verdict_matrix"]["Benign"]["Benign"] == 1


# ── (13-18) mitre delta ────────────────────────────────────────────
def test_mitre_added_counted():
    snaps = [_snap(rc4_mitre=["T1105"], rc5_mitre=["T1105", "T1027"])]
    r = compute_delta_report(snaps)
    added = dict(r["mitre"]["added_top"])
    assert added.get("T1027") == 1


def test_mitre_removed_counted():
    snaps = [_snap(rc4_mitre=["T1105", "T1027"], rc5_mitre=["T1105"])]
    r = compute_delta_report(snaps)
    removed = dict(r["mitre"]["removed_top"])
    assert removed.get("T1027") == 1


def test_mitre_kept_counted():
    snaps = [_snap(rc4_mitre=["T1105"], rc5_mitre=["T1105"])]
    r = compute_delta_report(snaps)
    assert r["mitre"]["kept_total"] == 1


def test_mitre_empty_lists_no_error():
    snaps = [_snap()]
    r = compute_delta_report(snaps)
    assert r["mitre"]["kept_total"] == 0


def test_mitre_added_top_limited_to_15():
    snaps = [_snap(rc4_mitre=[], rc5_mitre=[f"T1{i:03d}" for i in range(30)])]
    r = compute_delta_report(snaps)
    assert len(r["mitre"]["added_top"]) <= 15


def test_mitre_multi_sample_aggregation():
    snaps = [
        _snap(rc4_mitre=[], rc5_mitre=["T1105"]),
        _snap(rc4_mitre=[], rc5_mitre=["T1105"]),
        _snap(rc4_mitre=[], rc5_mitre=["T1027"]),
    ]
    r = compute_delta_report(snaps)
    added = dict(r["mitre"]["added_top"])
    assert added["T1105"] == 2 and added["T1027"] == 1


# ── (19-24) LOLBIN attribution delta ───────────────────────────────
def test_lolbin_state_totals():
    snaps = [_snap(
        rc5_lolbins_executed=["certutil"],
        rc5_lolbins_expanded=["mshta"],
        rc5_lolbins_referenced=["wmic"],
    )]
    r = compute_delta_report(snaps)
    assert r["lolbins"]["executed_total"] == 1
    assert r["lolbins"]["expanded_total"] == 1
    assert r["lolbins"]["referenced_total"] == 1


def test_lolbin_new_executed_hits_vs_rc4():
    snaps = [_snap(rc4_lolbas=["certutil"],
                   rc5_lolbins_executed=["certutil", "bitsadmin"])]
    r = compute_delta_report(snaps)
    assert r["lolbins"]["new_executed_hits_vs_rc4"] == 1


def test_lolbin_missed_vs_rc4():
    snaps = [_snap(rc4_lolbas=["certutil", "bitsadmin"],
                   rc5_lolbins_executed=["certutil"])]
    r = compute_delta_report(snaps)
    assert r["lolbins"]["missed_vs_rc4"] == 1


def test_lolbin_no_diff_when_matching():
    snaps = [_snap(rc4_lolbas=["certutil"],
                   rc5_lolbins_executed=["certutil"])]
    r = compute_delta_report(snaps)
    assert r["lolbins"]["missed_vs_rc4"] == 0
    assert r["lolbins"]["new_executed_hits_vs_rc4"] == 0


def test_lolbin_state_only_executed_should_influence_verdict_comparison():
    # Even if referenced/expanded LOLBINs are present, the "vs RC4" metric
    # only compares the RC5 `executed` set.
    snaps = [_snap(rc4_lolbas=["mshta"],
                   rc5_lolbins_executed=[],
                   rc5_lolbins_referenced=["mshta"])]
    r = compute_delta_report(snaps)
    assert r["lolbins"]["missed_vs_rc4"] == 1


def test_lolbin_totals_over_multiple_snaps():
    snaps = [
        _snap(rc5_lolbins_executed=["a", "b"]),
        _snap(rc5_lolbins_executed=["c"]),
    ]
    r = compute_delta_report(snaps)
    assert r["lolbins"]["executed_total"] == 3


# ── (25-28) confidence + latency ──────────────────────────────────
def test_confidence_medians_computed_per_stage():
    snaps = [_snap(rc5_confidence={"decode": 100, "semantic_reconstruction": 90,
                                   "behavior": 80, "mitre": 70, "verdict": 100,
                                   "weighted_overall": 90}) for _ in range(3)]
    r = compute_delta_report(snaps)
    for stage in ("decode", "semantic_reconstruction", "behavior",
                  "mitre", "verdict", "weighted_overall"):
        assert stage in r["confidence_medians"]


def test_latency_regression_ratio_computed():
    snaps = [_snap(rc4_latency_ms=100, rc5_latency_ms=120)
             for _ in range(5)]
    r = compute_delta_report(snaps)
    ratio = r["latency_ms"]["rc5_regression_ratio_p95"]
    assert ratio and 1.0 < ratio < 1.5


def test_latency_percentiles_calculated():
    snaps = [_snap(rc5_latency_ms=x) for x in (10, 20, 30, 40, 50)]
    r = compute_delta_report(snaps)
    assert r["latency_ms"]["rc5_p50"] is not None


def test_parser_exceptions_counted():
    snaps = [_snap(rc4_exception="boom"),
             _snap(rc5_exception="crash"),
             _snap()]
    r = compute_delta_report(snaps)
    assert r["parser"]["rc4_exceptions"] == 1
    assert r["parser"]["rc5_exceptions"] == 1


# ── (29-34) make_snapshot builder ─────────────────────────────────
def test_make_snapshot_populates_rc5_fields():
    r5_resp = {
        "mitre": [{"technique_id": "T1105", "confidence": 90}],
        "lolbins_v2": [
            {"binary": "certutil", "state": "executed"},
            {"binary": "mshta", "state": "expanded"},
        ],
        "behaviors": [{"tactic": "command_and_control"},
                      {"tactic": "execution"}],
        "exec_graph": {"nodes": [{"kind": "ProcessNode"},
                                 {"kind": "UnresolvedNode"}]},
        "verdict_v2": {"verdict": "Malicious"},
        "explain": {"confidence_breakdown": {"decode": 100, "semantic_reconstruction": 90,
                                             "behavior": 80, "mitre": 70,
                                             "verdict": 90, "weighted_overall": 85}},
        "warnings": ["hint 1"],
    }
    snap = make_snapshot(
        original_input="curl http://x/a",
        language="cmd",
        rc4_verdict="Suspicious", rc4_mitre=["T1105"], rc4_lolbas=["curl"],
        rc4_latency_ms=100.0,
        rc5_response=r5_resp,
        rc5_latency_ms=120.0,
    )
    assert snap.rc5_verdict == "Malicious"
    assert snap.rc5_mitre == ["T1105"]
    assert snap.rc5_lolbins_executed == ["certutil"]
    assert snap.rc5_lolbins_expanded == ["mshta"]
    assert snap.rc5_behavior_count == 2
    assert snap.rc5_node_count == 2
    assert snap.rc5_unresolved_count == 1
    assert snap.rc5_confidence["weighted_overall"] == 85
    assert snap.rc5_parser_warnings == ["hint 1"]


def test_make_snapshot_hash_deterministic():
    a = make_snapshot(original_input="x", language="cmd")
    b = make_snapshot(original_input="x", language="cmd")
    assert a.sample_hash == b.sample_hash


def test_make_snapshot_hash_differs_by_input():
    a = make_snapshot(original_input="x", language="cmd")
    b = make_snapshot(original_input="y", language="cmd")
    assert a.sample_hash != b.sample_hash


def test_make_snapshot_defaults_language_correctly():
    snap = make_snapshot(original_input="", language="powershell")
    assert snap.language == "powershell"


def test_make_snapshot_records_exception():
    snap = make_snapshot(original_input="", language="cmd",
                         rc5_exception="ValueError('bad input')")
    assert snap.rc5_exception


def test_make_snapshot_no_rc5_response_yields_empty_lists():
    snap = make_snapshot(original_input="", language="cmd")
    assert snap.rc5_mitre == []
    assert snap.rc5_lolbins_executed == []


# ── (35-40) _rank helper + invariants ────────────────────────────
def test_rank_orders_tiers():
    assert _rank("Benign") < _rank("Suspicious") < _rank("Malicious") < _rank("Critical")


def test_rank_unknown_returns_minus_one():
    assert _rank(None) == -1
    assert _rank("Unknown") == -1


def test_shadow_module_no_ai_imports():
    import pathlib, re
    p = pathlib.Path(__file__).resolve().parents[4] / "engine" / "shadow.py"
    src = p.read_text(encoding="utf-8")
    stripped = re.sub(r'"""[\s\S]*?"""', "", src)
    assert "emergentintegrations" not in stripped


def test_shadow_module_no_regex_on_raw_text():
    import pathlib
    p = pathlib.Path(__file__).resolve().parents[4] / "engine" / "shadow.py"
    src = p.read_text(encoding="utf-8")
    for pat in ("re.search(", "re.match(", "re.compile("):
        assert pat not in src


def test_confidence_medians_zero_when_absent():
    snaps = [_snap()]
    r = compute_delta_report(snaps)
    assert r["confidence_medians"]["decode"] == 0


def test_verdict_matrix_handles_none_side():
    snaps = [_snap(rc4_verdict=None, rc5_verdict="Benign")]
    r = compute_delta_report(snaps)
    assert "None" in r["verdict_matrix"]
