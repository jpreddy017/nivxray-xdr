"""E3 · Detection Replay must be the SAME detection authority as live
ingest, and must never turn silence into a benign verdict.

The real Windows corpus proved a negative-explainability defect: 3,299
canonical rows existed with NOTHING in the finding/evaluation plane, so
every surface had to say "no detection engine claimed this observation"
— indistinguishable from "never evaluated".
"""
from __future__ import annotations

import inspect

import pytest

from edr_plane import detection_replay as dr
from edr_plane.trajectory_window import (
    ASSESSED,
    EVALUATED_NO_DETECTION,
    EVAL_FAILED,
    NOT_EVALUATED,
    SUPPRESSED,
    _assessment_state,
    _evaluations_from_rows,
    _EVAL_MEANING,
)
from services.edr.endpoint_query import (
    ENDPOINT_KEYED_STORES,
    TENANT_PARTITIONED_STORES,
    endpoint_predicate,
)

T_A = "ten_f1a5479243e901cf159e230fa0"
T_B = "ten_3f7f772b353a6bbbb0ac8bc564"


# ── A · ONE detection authority, no replay-specific logic ────────────
def test_replay_defines_no_rule_and_no_match_shape():
    src = inspect.getsource(dr)
    assert "evaluate_detection" in src
    for forbidden in ("def _pred", "command_line.lower()", "if \"powershell",
                      "rule_id ==", "severity ="):
        assert forbidden not in src, forbidden


def test_replay_calls_the_live_pipeline_evaluator():
    src = inspect.getsource(dr.replay_endpoint)
    assert "from detection_content.xdr_pipeline import evaluate_detection" \
        in src
    assert "evaluate_detection(canonical)" in src


def test_replay_persists_through_the_live_finding_plane():
    src = inspect.getsource(dr._record)
    assert "record_endpoint_detection" in src


def test_replay_never_writes_a_raw_event_or_canonical_row():
    # the CODE, not the prose that explains why it does not
    src = inspect.getsource(dr).replace(dr.__doc__ or "", "")
    assert "edr_raw_events" not in src
    assert "insert_one" not in src
    assert "update_one" not in src
    assert "delete_" not in src


# ── B · the two-instant retrospective time model ─────────────────────
def test_the_endpoint_instant_is_never_replaced_by_now():
    src = inspect.getsource(dr._record)
    assert 'observed_at=canonical.get("event_time")' in src
    assert '"derived_at": evaluated_at' in src


def test_replay_declares_that_it_is_not_reingestion():
    assert dr.REPLAY_BASIS == "CANONICAL_EVIDENCE_REPLAY_NOT_REINGESTION"


# ── C · E1 still owns the read: no tenant, no evidence ───────────────
def test_the_canonical_plane_is_a_declared_partitioned_store():
    assert "xdr_canonical_evidence" in ENDPOINT_KEYED_STORES
    assert TENANT_PARTITIONED_STORES["xdr_canonical_evidence"] == "tenant_id"


def test_replay_read_is_tenant_scoped():
    pred = endpoint_predicate(["DESKTOP-A9HGFJJ"], dr.CANONICAL_COLLECTION,
                              list(dr.CANONICAL_ENDPOINT_FIELDS),
                              tenant_id=T_A)
    assert pred["$and"][0] == {"tenant_id": T_A}
    assert pred["$and"][1]["$or"] == [
        {f: {"$in": ["DESKTOP-A9HGFJJ"]}}
        for f in dr.CANONICAL_ENDPOINT_FIELDS]


def test_the_same_hostname_in_two_tenants_replays_separately():
    a = endpoint_predicate(["DESKTOP-A9HGFJJ"], dr.CANONICAL_COLLECTION,
                           list(dr.CANONICAL_ENDPOINT_FIELDS), tenant_id=T_A)
    b = endpoint_predicate(["DESKTOP-A9HGFJJ"], dr.CANONICAL_COLLECTION,
                           list(dr.CANONICAL_ENDPOINT_FIELDS), tenant_id=T_B)
    assert a != b


@pytest.mark.asyncio
async def test_replay_without_a_tenant_evaluates_nothing():
    out = await dr.replay_endpoint(None, tenant_id=None,
                                   refs=["DESKTOP-A9HGFJJ"])
    assert out["state"] == "TENANT_NOT_RESOLVED_FOR_REPLAY"
    assert out["evaluated"] == 0
    assert out["applied"] is False


# ── D · dry run is the DEFAULT ───────────────────────────────────────
def test_apply_defaults_to_false():
    sig = inspect.signature(dr.replay_endpoint)
    assert sig.parameters["apply"].default is False


def test_a_dry_run_cannot_reach_the_writer():
    src = inspect.getsource(dr.replay_endpoint)
    # every _record call is guarded by `if apply:`
    assert src.count("await _record(") == src.count("if apply:")


# ── E · the rule set that produced a verdict is identified ───────────
def test_rule_set_fingerprint_is_stable_and_names_its_size():
    fp = dr.rule_set_fingerprint()
    assert fp["rule_count"] >= 37
    assert len(fp["rule_set_sha256"]) == 32
    assert dr.rule_set_fingerprint() == fp


# ── F · three DIFFERENT facts, never collapsed ───────────────────────
def test_a_matched_detection_is_assessed():
    assert _assessment_state({"rule_ids": ["DET-EX-001"]}, None) == ASSESSED
    assert _assessment_state(None, {"state": "FINDINGS_PRESENT"}) == ASSESSED


def test_evaluated_with_no_match_is_not_the_same_as_unexamined():
    assert _assessment_state(None, {"state": "EVALUATED_NO_FINDING"}) == \
        EVALUATED_NO_DETECTION
    assert _assessment_state(None, None) == NOT_EVALUATED
    assert EVALUATED_NO_DETECTION != NOT_EVALUATED


def test_suppression_and_failure_are_their_own_answers():
    assert _assessment_state(
        None, {"state": "EVALUATION_SUPPRESSED_BY_EXCLUSION"}) == SUPPRESSED
    assert _assessment_state(None, {"state": "EVALUATION_FAILED"}) == \
        EVAL_FAILED


def test_no_state_is_ever_described_as_benign_or_clean():
    for state, meaning in _EVAL_MEANING.items():
        low = meaning.lower()
        assert "benign" not in low or "not a statement that" in low, state
        assert not low.startswith("clean"), state
    assert "NOT a statement that the activity was benign" in \
        _EVAL_MEANING[EVALUATED_NO_DETECTION].replace("not", "NOT")


def test_every_assessment_state_has_a_stated_meaning():
    for s in (ASSESSED, EVALUATED_NO_DETECTION, NOT_EVALUATED, SUPPRESSED,
              EVAL_FAILED):
        assert _EVAL_MEANING[s]


# ── G · the evaluation join ──────────────────────────────────────────
def test_the_ledger_join_is_keyed_by_canonical_event_id():
    out = _evaluations_from_rows([
        {"evidence_ref": "sysmon-1-aaa", "state": "EVALUATED_NO_FINDING",
         "analyzer_id": "deterministic.rule", "analyzer_version": "1.0.0",
         "recorded_at": "2026-09-29T08:00:00+00:00",
         "evaluation_attempts": 1}])
    assert out["sysmon-1-aaa"]["state"] == "EVALUATED_NO_FINDING"
    assert out["sysmon-1-aaa"]["evaluated_at"] == "2026-09-29T08:00:00+00:00"


def test_a_finding_outranks_another_analyzers_no_finding():
    rows = [{"evidence_ref": "e1", "state": "FINDINGS_PRESENT",
             "analyzer_id": "a", "finding_ids": ["f1"]},
            {"evidence_ref": "e1", "state": "EVALUATED_NO_FINDING",
             "analyzer_id": "b"}]
    assert _evaluations_from_rows(rows)["e1"]["state"] == "FINDINGS_PRESENT"
    assert _evaluations_from_rows(list(reversed(rows)))["e1"]["state"] == \
        "FINDINGS_PRESENT"


def test_a_ledger_row_without_evidence_is_dropped():
    assert _evaluations_from_rows([{"state": "EVALUATED_NO_FINDING"}]) == {}


# ── H · an unevaluated observation is never painted as a detection ───
def test_evaluated_no_detection_is_not_a_malicious_claim():
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[3]
           / "apps/nivxray-xdr/src/nivxforge/trajectory/ampModel.js"
           ).read_text()
    assert 'e?.assessment_state === "ASSESSED_BY_DETECTION_FABRIC"' in src
    assert "EVALUATED_NO_DETECTION" not in src
