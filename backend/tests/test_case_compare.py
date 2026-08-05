"""Compare Cases — Phase A · item 2 unit tests.

Contract from owner (2026-02-16):
  1. Read-only — never modifies either case, CEM, verdict, evidence.
  2. Deterministic — same (a, b) → byte-identical output.
  3. Fingerprint-powered — consumes similarity_vector directly.
  4. Symmetric (up to provenance labels).
  5. Gracefully degrades on pre-convergence cases.
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from services.artifact_intelligence import dispatch
from services.attack_fingerprint import emit_fingerprint
from services.case_compare import COMPARE_VERSION, compare_cases
from services.cem import emit_cem
from services.recipe_planner import plan_and_execute
from services.recursive_child_pipeline import (
    process as rcp_process,
    flatten_for_correlation,
)

SAMPLES = Path(__file__).resolve().parent / "golden_corpus" / "samples"


# ────────────────────────────────────────────────────────────────────
# Fixtures — build cases the same way the golden harness does
# ────────────────────────────────────────────────────────────────────
def _workspace_case(case_id: str = "ws-case") -> dict:
    text = (SAMPLES / "workspace_ps_to_pe_chain.txt").read_text()
    plan = plan_and_execute(text)
    case = {
        "id": case_id,
        "input": text,
        "output": plan.canonical_output,
        "iedde": {"binary_artifact": {
            "routed_analysis": plan.binary_artifact.routed_analysis
        }},
        "iedde_terminal_state": plan.terminal_state,
        "canonical_confidence": 100,
        "iocs": {}, "mitre": [], "chain": list(plan.final_techniques or []),
    }
    case["cem"] = emit_cem(case)
    return case


def _docm_case(case_id: str = "docm-case") -> dict:
    data = (SAMPLES / "docm_ps_to_pe_chain.docm").read_bytes()
    routed = dispatch(data).to_dict()
    kids = rcp_process(routed)
    case = {
        "id": case_id,
        "input": data[:200].hex(),
        "output": "",
        "iedde": {
            "binary_artifact": {"routed_analysis": routed},
            "recursive_children": flatten_for_correlation(kids),
        },
        "iedde_terminal_state": "binary_artifact_recovered",
        "canonical_confidence": 100,
        "iocs": {}, "mitre": [], "chain": [],
    }
    case["cem"] = emit_cem(case)
    return case


# ────────────────────────────────────────────────────────────────────
# 1 · Read-only + determinism
# ────────────────────────────────────────────────────────────────────
class TestReadOnly:
    def test_does_not_mutate_inputs(self):
        a, b = _workspace_case("a"), _docm_case("b")
        a_before, b_before = copy.deepcopy(a), copy.deepcopy(b)
        compare_cases(a, b)
        assert a == a_before
        assert b == b_before


class TestDeterminism:
    def test_same_inputs_produce_identical_output(self):
        a, b = _workspace_case(), _docm_case()
        assert compare_cases(a, b) == compare_cases(a, b)

    def test_identity_pair_has_max_similarity(self):
        """A case compared to itself must be identical on every
        dimension and yield similarity_score == 1.0."""
        a = _workspace_case()
        r = compare_cases(a, a)
        assert r["fingerprint_match"] is True
        assert r["similarity_score"]["overall"] == 1.0
        for name, dim in r["dimensions"].items():
            if name == "confidence_provenance":
                continue
            # No "a_only" or "b_only" divergence anywhere.
            if "a_only" in dim:
                assert not dim["a_only"], f"{name}: a_only={dim['a_only']}"
            if "b_only" in dim:
                assert not dim["b_only"], f"{name}: b_only={dim['b_only']}"


# ────────────────────────────────────────────────────────────────────
# 2 · Symmetry
# ────────────────────────────────────────────────────────────────────
class TestSymmetry:
    def test_overall_score_symmetric(self):
        a, b = _workspace_case("a"), _docm_case("b")
        r_ab = compare_cases(a, b)
        r_ba = compare_cases(b, a)
        assert r_ab["similarity_score"]["overall"] == r_ba["similarity_score"]["overall"]

    def test_fingerprint_match_symmetric(self):
        a, b = _workspace_case("a"), _docm_case("b")
        assert (compare_cases(a, b)["fingerprint_match"]
                == compare_cases(b, a)["fingerprint_match"])

    def test_shared_sets_are_symmetric(self):
        a, b = _workspace_case("a"), _docm_case("b")
        r_ab = compare_cases(a, b)
        r_ba = compare_cases(b, a)
        # `shared` sets are invariant to argument order.
        for dim in ("mitre", "iocs", "canonical_hashes",
                    "behavior_codes", "artifact_graph"):
            assert r_ab["dimensions"][dim]["shared"] == \
                   r_ba["dimensions"][dim]["shared"], (
                f"dimension {dim} shared-set diverged under argument swap")
        # a_only / b_only flip.
        for dim in ("mitre", "canonical_hashes", "behavior_codes"):
            assert r_ab["dimensions"][dim]["a_only"] == r_ba["dimensions"][dim]["b_only"]
            assert r_ab["dimensions"][dim]["b_only"] == r_ba["dimensions"][dim]["a_only"]


# ────────────────────────────────────────────────────────────────────
# 3 · Fingerprint-powered — actually consumes similarity_vector
# ────────────────────────────────────────────────────────────────────
class TestFingerprintPowered:
    def test_shared_pe_across_docm_and_workspace(self):
        """The canonical PE recovered by both origins must appear in
        the shared `canonical_hashes` set — this is the exact analyst
        value proposition of Compare Cases."""
        a = _workspace_case()
        b = _docm_case()
        r = compare_cases(a, b)
        pe_sha = "aa5cca50fb3b54634533ed4c306f3b77343c4f9bd09d1b81ed2aa15d428ebb18"
        assert pe_sha in r["dimensions"]["canonical_hashes"]["shared"], (
            f"shared canonical PE missing from comparison\n"
            f"shared={r['dimensions']['canonical_hashes']['shared']}")

    def test_component_digest_matches_reported(self):
        a, b = _workspace_case(), _docm_case()
        r = compare_cases(a, b)
        cm = r["dimensions"]["attack_fingerprint"]["component_matches"]
        # At least one common digest must be reported (recipe or interpreter).
        assert cm, "component_matches unexpectedly empty"
        for k, v in cm.items():
            assert isinstance(v, bool), f"non-boolean match for {k}: {v!r}"


# ────────────────────────────────────────────────────────────────────
# 4 · Similarity score bounds + per-dimension weights
# ────────────────────────────────────────────────────────────────────
class TestSimilarityScore:
    def test_score_in_zero_to_one(self):
        a, b = _workspace_case(), _docm_case()
        r = compare_cases(a, b)
        s = r["similarity_score"]["overall"]
        assert 0.0 <= s <= 1.0, f"similarity score out of range: {s}"

    def test_per_dimension_jaccard_shape(self):
        a, b = _workspace_case(), _docm_case()
        r = compare_cases(a, b)
        for dim, val in r["similarity_score"]["per_dimension"].items():
            assert 0.0 <= val["jaccard"] <= 1.0, dim
            assert val["shared_count"] >= 0
            assert val["weight"] > 0


# ────────────────────────────────────────────────────────────────────
# 5 · Graceful degradation on pre-convergence cases
# ────────────────────────────────────────────────────────────────────
class TestGracefulDegradation:
    def test_pre_convergence_case_still_compares(self):
        pre = {
            "id": "pre",
            "iedde": {}, "iedde_terminal_state": "stability_gate",
            "canonical_confidence": 0, "iocs": {}, "mitre": [], "chain": [],
        }
        conv = _workspace_case("conv")
        r = compare_cases(pre, conv)
        assert r["compare_version"] == COMPARE_VERSION
        # Fingerprint match must be False (pre.hash is None).
        assert r["fingerprint_match"] is False
        # Overall score exists (typically 0.0 — nothing shared).
        assert isinstance(r["similarity_score"]["overall"], float)

    def test_stub_when_input_not_dict(self):
        r = compare_cases(None, {})
        assert r["compare_version"] == COMPARE_VERSION
        assert r["dimensions"] == {}

    def test_confidence_provenance_flagged_unavailable(self):
        a, b = _workspace_case(), _docm_case()
        r = compare_cases(a, b)
        cp = r["dimensions"]["confidence_provenance"]
        assert cp["available"] is False
        # When Confidence Provenance ledger ships (Phase A · item 3),
        # setting the field on both cases will flip this to True — the
        # placeholder wiring already handles it.
        a["confidence_provenance"] = {"score": 96, "rules": ["r1"]}
        b["confidence_provenance"] = {"score": 96, "rules": ["r1"]}
        r2 = compare_cases(a, b)
        assert r2["dimensions"]["confidence_provenance"]["available"] is True
        assert r2["dimensions"]["confidence_provenance"]["equal"] is True


# ────────────────────────────────────────────────────────────────────
# 6 · Output contract — every documented dimension present
# ────────────────────────────────────────────────────────────────────
class TestOutputContract:
    def test_all_documented_dimensions_present(self):
        a, b = _workspace_case(), _docm_case()
        r = compare_cases(a, b)
        expected = {
            "threat_summary", "attack_chain", "timeline", "mitre",
            "iocs", "recipe", "transformation_trace", "decision_trace",
            "interpreter_chain", "artifact_graph", "canonical_hashes",
            "behavior_codes", "attack_fingerprint", "confidence_provenance",
        }
        assert set(r["dimensions"].keys()) == expected

    def test_top_level_shape(self):
        a, b = _workspace_case(), _docm_case()
        r = compare_cases(a, b)
        for key in ("compare_version", "case_a_id", "case_b_id",
                    "fingerprint_match", "similarity_score",
                    "dimensions", "verdicts"):
            assert key in r, f"missing top-level key {key!r}"
