"""Evidence-backed detection invariant: len(evidence_refs) >= 1, enforced by the contract."""
import pytest

from edr_behavior.contracts import (OUTCOME_INSUFFICIENT, OUTCOME_MATCH, OUTCOME_NO_MATCH,
                                    Detection)
from edr_behavior.detection import detection_id
from factory import Harness, at, canon_process, rec, registry_of, simple_rule


def _matched():
    h = Harness(registry_of(simple_rule()))
    res = h.feed(rec(canon_process("winword.exe", guid="G1"), "r1"),
                 rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2"))
    return h, res


def _valid_kwargs():
    h, _ = _matched()
    [d] = h.detections()
    d.pop("revision", None)
    return d


@pytest.mark.parametrize("empty", [[], ()])
def test_a_detection_with_empty_evidence_refs_is_rejected(empty):
    kw = _valid_kwargs()
    kw["evidence_refs"] = empty
    with pytest.raises(ValueError, match="evidence_ref"):
        Detection(**kw)


def test_b_detection_with_none_evidence_refs_is_rejected():
    kw = _valid_kwargs()
    kw["evidence_refs"] = None
    with pytest.raises(ValueError, match="evidence_ref"):
        Detection(**kw)


def test_b_detection_with_missing_evidence_refs_is_rejected():
    kw = _valid_kwargs()
    del kw["evidence_refs"]
    with pytest.raises(TypeError, match="evidence_refs"):
        Detection(**kw)


def test_b_detection_with_ref_lacking_stable_key_is_rejected():
    kw = _valid_kwargs()
    kw["evidence_refs"] = [{"tenant_id": "t1", "raw_id": "r1"}]
    with pytest.raises(ValueError, match="stable_key"):
        Detection(**kw)


def test_b_detection_with_empty_evidence_keys_is_rejected():
    kw = _valid_kwargs()
    kw["evidence_keys"] = []
    with pytest.raises(ValueError, match="evidence_keys"):
        Detection(**kw)


def test_c_legitimate_match_with_evidence_refs_succeeds():
    h, res = _matched()
    assert res[1][0].outcome == OUTCOME_MATCH
    [d] = h.detections()
    assert len(d["evidence_refs"]) >= 1
    assert all(r["stable_key"] for r in d["evidence_refs"])
    assert sorted(r["stable_key"] for r in d["evidence_refs"]) == d["evidence_keys"]
    assert {r["raw_id"] for r in d["evidence_refs"]} == {"r1", "r2"}
    kw = dict(d)
    kw.pop("revision", None)
    assert Detection(**kw).to_dict()["evidence_refs"] == d["evidence_refs"]


def test_d_insufficient_evidence_creates_no_detection_and_is_not_no_match():
    h = Harness(registry_of(simple_rule()))
    res = h.feed(rec(canon_process("winword.exe", guid="G1"), "r1"),
                 rec(canon_process("powershell.exe", guid="G2", t=5), "r2"))
    outcome = res[1][0].outcome
    assert outcome == OUTCOME_INSUFFICIENT
    assert outcome != OUTCOME_NO_MATCH and outcome != OUTCOME_MATCH
    assert outcome not in ("NO_MATCH", "CLEAN")
    assert res[1][0].reasons
    assert h.detections() == []


def test_d_three_outcomes_are_distinct():
    assert len({OUTCOME_MATCH, OUTCOME_NO_MATCH, OUTCOME_INSUFFICIENT}) == 3


def test_e_retry_and_generation_change_are_idempotent():
    h, _ = _matched()
    [first] = h.detections()
    h.feed(rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2"))
    h.feed(rec(canon_process("winword.exe", guid="G1"), "r1", generation=3),
           rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2",
               generation=3))
    [after] = h.detections()
    assert after["detection_id"] == first["detection_id"]
    assert after["evidence_keys"] == first["evidence_keys"]
    assert after["raw_refs"] == first["raw_refs"]
    assert len(after["evidence_refs"]) == len(first["evidence_refs"])


def test_f_detection_id_is_deterministic():
    rule = simple_rule()
    a = detection_id("t1", "ep1", rule, "device:ep1", at(0))
    b = detection_id("t1", "ep1", rule, "device:ep1", at(1))
    assert a == b and a.startswith("e3det_")
    assert detection_id("t2", "ep1", rule, "device:ep1", at(0)) != a
    ids = []
    for _ in range(2):
        h, _ = _matched()
        [d] = h.detections()
        ids.append(d["detection_id"])
    assert ids[0] == ids[1]
