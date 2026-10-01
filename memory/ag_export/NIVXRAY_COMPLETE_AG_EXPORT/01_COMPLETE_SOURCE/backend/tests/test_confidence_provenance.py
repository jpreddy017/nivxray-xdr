"""Confidence Provenance Ledger — Phase A · item 3 unit tests.

Contract from owner (2026-02-16):
  1. Read-only — never modifies case, CEM, verdict, evidence.
  2. Deterministic — same case → byte-identical ledger.
  3. Explains, doesn't overwrite — `recorded` preserves upstream
     verdict; `derived` is a CEM-only reproduction.
  4. Versioned schema — `provenance_version = "1.0"`.
  5. Rule library declarative — each rule is a pure predicate.
  6. Every contribution auditable — evidence_refs point to exact
     analyzer.finding / MITRE id / artifact sha256.
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from services.artifact_intelligence import dispatch
from services.cem import emit_cem
from services.confidence_provenance import (
    PROVENANCE_VERSION,
    RULES,
    emit_provenance,
)
from services.recipe_planner import plan_and_execute
from services.recursive_child_pipeline import (
    process as rcp_process,
    flatten_for_correlation,
)

SAMPLES = Path(__file__).resolve().parent / "golden_corpus" / "samples"


def _workspace_case() -> dict:
    text = (SAMPLES / "workspace_ps_to_pe_chain.txt").read_text()
    plan = plan_and_execute(text)
    case = {
        "id": "ws-case",
        "input": text, "output": plan.canonical_output,
        "iedde": {"binary_artifact": {
            "routed_analysis": plan.binary_artifact.routed_analysis
        }},
        "iedde_terminal_state": plan.terminal_state,
        "canonical_confidence": 100,
        "iocs": {}, "mitre": [], "chain": list(plan.final_techniques or []),
    }
    case["cem"] = emit_cem(case)
    return case


def _docm_case() -> dict:
    data = (SAMPLES / "docm_ps_to_pe_chain.docm").read_bytes()
    routed = dispatch(data).to_dict()
    kids = rcp_process(routed)
    case = {
        "id": "docm-case",
        "input": data[:200].hex(), "output": "",
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
# 1 · Read-only
# ────────────────────────────────────────────────────────────────────
class TestReadOnly:
    def test_does_not_mutate_case(self):
        case = _workspace_case()
        before = copy.deepcopy(case)
        emit_provenance(case)
        assert case == before

    def test_does_not_mutate_cem(self):
        case = _workspace_case()
        cem_before = copy.deepcopy(case["cem"])
        emit_provenance(case)
        assert case["cem"] == cem_before


# ────────────────────────────────────────────────────────────────────
# 2 · Determinism
# ────────────────────────────────────────────────────────────────────
class TestDeterminism:
    def test_same_case_same_hash(self):
        case = _workspace_case()
        assert emit_provenance(case)["provenance_hash"] == \
               emit_provenance(case)["provenance_hash"]

    def test_full_ledger_stable(self):
        case = _workspace_case()
        assert emit_provenance(case) == emit_provenance(case)


# ────────────────────────────────────────────────────────────────────
# 3 · Explains, doesn't overwrite
# ────────────────────────────────────────────────────────────────────
class TestExplainsDoesNotOverwrite:
    def test_recorded_preserved(self):
        case = _workspace_case()
        case["verdict_card"] = {"verdict": "malicious", "risk_score": 92}
        p = emit_provenance(case)
        assert p["recorded"]["verdict"] == "malicious"
        assert p["recorded"]["risk_score"] == 92.0

    def test_recorded_none_when_absent(self):
        case = _workspace_case()
        case.pop("verdict_card", None)
        p = emit_provenance(case)
        assert p["recorded"]["verdict"] is None
        assert p["recorded"]["risk_score"] is None

    def test_derived_always_computed(self):
        case = _workspace_case()
        p = emit_provenance(case)
        assert p["derived"]["verdict"] in (
            "malicious", "suspicious", "low_risk", "benign")
        assert 0.0 <= p["derived"]["risk_score"] <= 100.0


# ────────────────────────────────────────────────────────────────────
# 4 · Rule library integrity
# ────────────────────────────────────────────────────────────────────
class TestRuleLibrary:
    def test_all_rule_ids_unique(self):
        ids = [r.id for r in RULES]
        assert len(ids) == len(set(ids)), f"duplicate rule ids: {ids}"

    def test_all_rule_weights_positive(self):
        assert all(r.weight > 0 for r in RULES)

    def test_no_rule_predicate_raises_on_empty_cem(self):
        empty = {"cem_version": "1.0", "convergence": {"reached": False},
                 "canonical_artifacts": [], "child_artifacts": [],
                 "mitre": [], "indicators": [], "events": [],
                 "traces": {}, "verdict": {}}
        for rule in RULES:
            try:
                out = rule.predicate(empty)
            except Exception as e:
                pytest.fail(f"rule {rule.id} raised on empty CEM: {e}")
            assert isinstance(out, list), (
                f"rule {rule.id} predicate returned non-list: {type(out)}")


# ────────────────────────────────────────────────────────────────────
# 5 · Auditable evidence
# ────────────────────────────────────────────────────────────────────
class TestAuditableEvidence:
    def test_every_fired_rule_has_evidence(self):
        case = _docm_case()
        p = emit_provenance(case)
        assert p["rules"], "no rules fired on the docm flagship"
        for r in p["rules"]:
            assert r["evidence_refs"], (
                f"rule {r['id']} fired but reported no evidence refs")
            assert r["hit_count"] == len(r["evidence_refs"])

    def test_docm_flagship_fires_office_macro_rule(self):
        p = emit_provenance(_docm_case())
        fired_ids = {r["id"] for r in p["rules"]}
        assert "office_macro_script_invocation" in fired_ids

    def test_workspace_flagship_fires_binary_recovered_rule(self):
        p = emit_provenance(_workspace_case())
        fired_ids = {r["id"] for r in p["rules"]}
        assert "binary_recovered_from_wrapper" in fired_ids


# ────────────────────────────────────────────────────────────────────
# 6 · Versioning + schema shape
# ────────────────────────────────────────────────────────────────────
class TestVersioning:
    def test_version_field_always_present(self):
        assert emit_provenance(_workspace_case())["provenance_version"] == \
               PROVENANCE_VERSION

    def test_version_present_even_on_stub(self):
        assert emit_provenance(None)["provenance_version"] == PROVENANCE_VERSION


class TestOutputShape:
    def test_all_documented_keys_present(self):
        p = emit_provenance(_workspace_case())
        for key in ("provenance_version", "provenance_hash",
                    "recorded", "derived", "rules", "rules_skipped",
                    "evidence_contributions", "mitre_contributions",
                    "analyzer_contributions"):
            assert key in p, f"missing key {key!r}"

    def test_rules_skipped_has_reason(self):
        p = emit_provenance(_workspace_case())
        for r in p["rules_skipped"]:
            assert "id" in r and "reason" in r


# ────────────────────────────────────────────────────────────────────
# 7 · Stub / degradation
# ────────────────────────────────────────────────────────────────────
class TestStubDegradation:
    def test_input_not_dict(self):
        p = emit_provenance(None)
        assert p["provenance_hash"] is None
        assert p["reason"] == "input_not_dict"

    def test_derived_verdict_bands(self):
        case = _workspace_case()
        p = emit_provenance(case)
        # Score 45 → low_risk per _VERDICT_BANDS.
        # But this depends on which rules fired; just sanity check.
        score = p["derived"]["risk_score"]
        v = p["derived"]["verdict"]
        if score >= 80:  assert v == "malicious"
        elif score >= 50: assert v == "suspicious"
        elif score >= 20: assert v == "low_risk"
        else:             assert v == "benign"
