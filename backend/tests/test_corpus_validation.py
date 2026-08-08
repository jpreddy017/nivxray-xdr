"""P0.9 · Corpus Validation Harness regression tests.

Locks the coverage-report contract:
    · Report is deterministic and versioned
    · Every layer coverage %, dead / orphan / duplicate stat is
      reproducible from the same manifest
    · Regression diff against a prior report highlights new
      dead rules / new orphan behaviors / coverage regression
"""
from __future__ import annotations

import json
import pathlib

from scripts.corpus_validation import (
    REPORT_SCHEMA_VERSION,
    run_corpus, diff_reports,
)


_MANIFEST_PATH = pathlib.Path("corpus/manifest.json")


def _manifest() -> dict:
    return json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))


# ══════════════════════════════════════════════════════════════════
# Contract · report schema
# ══════════════════════════════════════════════════════════════════
def test_report_has_stable_versioned_schema():
    r = run_corpus(_manifest())
    assert r["schema_version"] == REPORT_SCHEMA_VERSION
    # Required top-level keys.
    for k in ("corpus_size", "coverage", "behavior_frequency",
                "provenance_distribution", "recommendation_frequency",
                "dead_behavior_types", "orphan_behavior_types",
                "behaviors_missing_kill_chain_projection",
                "behaviors_missing_impact_projection",
                "dead_recommendation_rules", "unmapped_evidence_summary",
                "duplicate_behavior_hits", "mitre_techniques_seen",
                "latency_ms", "per_case"):
        assert k in r, f"missing key {k!r}"


# ══════════════════════════════════════════════════════════════════
# Behavior invariants over the seed corpus
# ══════════════════════════════════════════════════════════════════
def test_corpus_exercises_representative_provenance_kinds():
    """The seed corpus MUST exercise at least command_execution +
    lolbas_binary_reference provenance kinds (the two most common).
    Malware/CVE provenance are exercised in the P0.4 unit tests."""
    r = run_corpus(_manifest())
    prov = r["provenance_distribution"]
    assert prov.get("command_execution", 0)         >= 1
    assert prov.get("lolbas_binary_reference", 0)   >= 1


def test_coverage_percentages_within_expected_bounds():
    """Structural sanity — coverage percentages are floats 0-100."""
    r = run_corpus(_manifest())
    for k in ("evidence_to_behavior_pct",
                "behavior_to_projection_pct",
                "projection_to_recommendation_pct"):
        v = r["coverage"][k]
        assert isinstance(v, float)
        assert 0.0 <= v <= 100.0


def test_benign_case_produces_no_behaviors_and_no_recommendations():
    r = run_corpus(_manifest())
    benign = next(c for c in r["per_case"] if c["id"] == "benign_text")
    assert benign["behaviors_count"]     == 0
    assert benign["recommendation_ids"]  == []


def test_ransomware_case_fires_recovery_recommendations():
    r = run_corpus(_manifest())
    rans = next(c for c in r["per_case"]
                    if c["id"] == "ransomware_shadow_wbadmin_bcdedit")
    rec_ids = set(rans["recommendation_ids"])
    assert "erad.protect_shadow_copies" in rec_ids


def test_certutil_case_surfaces_ingress_transfer_behavior():
    r = run_corpus(_manifest())
    cu = next(c for c in r["per_case"]
                    if c["id"] == "certutil_urlcache_download")
    assert "certutil_download" in cu["behavior_types"]


def test_report_output_is_deterministic():
    a = run_corpus(_manifest())
    b = run_corpus(_manifest())
    # Latency + timestamp vary — normalize for comparison.
    for r in (a, b):
        r.pop("latency_ms", None)
        r.pop("generated_at", None)
    assert a == b, "corpus report is not deterministic"


# ══════════════════════════════════════════════════════════════════
# Regression diff
# ══════════════════════════════════════════════════════════════════
def test_diff_reports_flags_new_dead_rules():
    prev = {
        "coverage": {"evidence_to_behavior_pct": 90.0,
                      "behavior_to_projection_pct": 90.0,
                      "projection_to_recommendation_pct": 70.0},
        "dead_recommendation_rules": ["erad.rotate_credentials"],
        "orphan_behavior_types":     [],
    }
    curr = {
        "coverage": {"evidence_to_behavior_pct": 90.0,
                      "behavior_to_projection_pct": 90.0,
                      "projection_to_recommendation_pct": 65.0},
        "dead_recommendation_rules": ["erad.rotate_credentials",
                                              "harden.lolbas_allowlist"],
        "orphan_behavior_types":     ["mystery_new_orphan"],
    }
    d = diff_reports(prev, curr)
    assert "harden.lolbas_allowlist" in d["newly_dead_rules"]
    assert "mystery_new_orphan"      in d["new_orphan_behaviors"]
    assert d["coverage_delta"]["projection_to_recommendation"]["delta"] == -5.0


def test_diff_reports_flags_resolved_dead_rules():
    prev = {
        "coverage": {"evidence_to_behavior_pct": 80.0,
                      "behavior_to_projection_pct": 80.0,
                      "projection_to_recommendation_pct": 50.0},
        "dead_recommendation_rules": ["contain.kill_powershell",
                                            "erad.rotate_credentials"],
        "orphan_behavior_types":     [],
    }
    curr = {
        "coverage": {"evidence_to_behavior_pct": 90.0,
                      "behavior_to_projection_pct": 90.0,
                      "projection_to_recommendation_pct": 70.0},
        "dead_recommendation_rules": ["erad.rotate_credentials"],
        "orphan_behavior_types":     [],
    }
    d = diff_reports(prev, curr)
    assert "contain.kill_powershell" in d["resolved_dead_rules"]
    # Coverage improvements are surfaced.
    assert d["coverage_delta"]["evidence_to_behavior"]["delta"] == 10.0


def test_dead_behavior_types_are_a_subset_of_behavior_vocab():
    r = run_corpus(_manifest())
    from services.ida.behaviors import BEHAVIOR_TO_MITRE
    dead = set(r["dead_behavior_types"])
    vocab = set(BEHAVIOR_TO_MITRE.keys())
    assert dead <= vocab


# ══════════════════════════════════════════════════════════════════
# P0.10 · Traceability Completeness + Dead-rule classification
# ══════════════════════════════════════════════════════════════════
def test_report_includes_traceability_aggregate():
    r = run_corpus(_manifest())
    t = r["traceability_aggregate"]
    assert set(t.keys()) == {
        "total_behaviors", "complete_chains", "broken_chains",
        "complete_pct",
    }
    assert t["total_behaviors"]  == (t["complete_chains"]
                                          + t["broken_chains"])
    assert 0.0 <= t["complete_pct"] <= 100.0


def test_per_case_traceability_lists_broken_chains_with_reason():
    r = run_corpus(_manifest())
    for c in r["per_case"]:
        tc = c["traceability"]
        assert "complete_chains" in tc and "broken_chains" in tc
        for br in tc["broken_chains"]:
            assert "behavior_id"   in br
            assert "behavior_type" in br
            assert br["gap"] in ("missing_projection",
                                     "no_supporting_recommendation")


def test_dead_rules_are_classified_into_five_buckets():
    r = run_corpus(_manifest())
    cls = r["dead_rule_classification"]
    assert set(cls.keys()) == {
        "legitimately_dormant", "corpus_gap", "behavior_gap",
        "logic_gap", "mapping_gap",
    }
    all_ids = sorted(sum(cls.values(), []))
    assert all_ids == sorted(r["dead_recommendation_rules"]), (
        "every dead rule must be assigned to exactly one bucket")


def test_all_four_provenance_kinds_exercised_by_corpus():
    """Corpus expansion goal · exercise command_execution +
    malware_reference + lolbas_binary_reference + cve_reference."""
    r = run_corpus(_manifest())
    prov = r["provenance_distribution"]
    for kind in ("command_execution", "malware_reference",
                    "lolbas_binary_reference", "cve_reference"):
        assert prov.get(kind, 0) >= 1, (
            f"corpus does not exercise provenance kind {kind!r}")


def test_structured_case_produces_malware_reference_behaviors():
    r = run_corpus(_manifest())
    medusa = next(c for c in r["per_case"]
                       if c["id"] == "medusa_ransomware_family_reference")
    assert "data_encryption_for_impact" in medusa["behavior_types"]
    assert "malware_reference" in medusa["provenance_distribution"]


def test_cve_reference_case_surfaces_exploit_public_app_behavior():
    r = run_corpus(_manifest())
    cve = next(c for c in r["per_case"]
                    if c["id"] == "cve_2024_57727_simplehelp_traversal")
    assert "exploit_public_app" in cve["behavior_types"]
    assert "cve_reference"      in cve["provenance_distribution"]
