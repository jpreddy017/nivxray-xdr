from edr_behavior.contracts import (OUTCOME_INSUFFICIENT, OUTCOME_MATCH, OUTCOME_NO_MATCH,
                                    LINK_GUID, LINK_PID_SURROGATE)
from edr_behavior.detection import detection_id
from factory import Harness, canon_process, rec, registry_of, simple_rule, at


def _h(rule=None, **kw):
    return Harness(registry_of(rule or simple_rule()), **kw)


def test_single_event_does_not_match():
    h = _h()
    res = h.feed(rec(canon_process("WINWORD.EXE", guid="G1"), "r1"))
    assert res[0][0].outcome == OUTCOME_NO_MATCH
    assert h.detections() == []


def test_full_match_guid_linkage_and_contract_fields():
    h = _h()
    h.feed(rec(canon_process("winword.exe", guid="G1"), "r1"),
           rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2"))
    [d] = h.detections()
    assert d["rule_id"] == "T-PC" and d["rule_version"] == 1 and d["status"] == "OPEN"
    assert d["evidence_refs"] and d["raw_refs"] == ["r1", "r2"]
    assert d["canonical_event_ids"] == ["cev_r1_g0", "cev_r2_g0"]
    assert d["process_identities"] == ["proc_G1", "proc_G2"]
    assert d["matched_stages"][1]["linkage"] == {"p->c": LINK_GUID}
    assert d["confidence"] == 60
    assert "Rule T-PC v1" in d["explanation"] and "raw r2" in d["explanation"]
    assert d["provenance"]["chain"][0] == "RAW" and d["provenance"]["chain"][-1] == "DETECTION"
    assert d["provenance"]["rule"]["content_hash"].startswith("rc_")
    assert d["provenance"]["process_identity_authority"].endswith("bind_process_identity")


def test_explanation_and_id_are_deterministic_across_engines():
    out = []
    for order in ((0, 1), (1, 0)):
        h = _h()
        evs = [rec(canon_process("winword.exe", guid="G1"), "r1"),
               rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2")]
        h.feed(*[evs[i] for i in order])
        [d] = h.detections()
        out.append((d["detection_id"], d["explanation"], d["evidence_keys"]))
    assert out[0] == out[1]


def test_wrong_parent_is_no_match():
    h = _h()
    h.feed(rec(canon_process("winword.exe", guid="G1"), "r1"),
           rec(canon_process("powershell.exe", guid="G2", parent_guid="G9", t=5), "r2"))
    assert h.detections() == []


def test_missing_parent_linkage_is_insufficient_evidence_not_clean():
    h = _h()
    res = h.feed(rec(canon_process("winword.exe", guid="G1"), "r1"),
                 rec(canon_process("powershell.exe", guid="G2", t=5), "r2"))
    assert res[1][0].outcome == OUTCOME_INSUFFICIENT
    assert any("parent linkage" in r for r in res[1][0].reasons)
    assert h.detections() == []
    snap = h.engine.metrics.snapshot()
    assert snap["counters"]["insufficient_evidence"] >= 1
    assert snap["per_rule"]["T-PC@v1:INSUFFICIENT_EVIDENCE"] >= 1


def test_guid_required_linkage_with_pid_only_is_insufficient():
    rule = simple_rule(relationships=[{"type": "parent_child", "parent": "p", "child": "c",
                                       "min_linkage": "SOURCE_PROCESS_GUID"}])
    h = _h(rule)
    res = h.feed(rec(canon_process("winword.exe", pid="10"), "r1"),
                 rec(canon_process("powershell.exe", pid="11", ppid="10", t=5), "r2"))
    assert res[1][0].outcome == OUTCOME_INSUFFICIENT


def test_pid_surrogate_linkage_matches_with_penalty():
    h = _h()
    h.feed(rec(canon_process("winword.exe", pid="10"), "r1"),
           rec(canon_process("powershell.exe", pid="11", ppid="10", t=5), "r2"))
    [d] = h.detections()
    assert d["matched_stages"][1]["linkage"] == {"p->c": LINK_PID_SURROGATE}
    assert d["confidence"] == 45 and "PID surrogate" in d["explanation"]


def test_ordering_enforced():
    h = _h()
    h.feed(rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=0), "r2"),
           rec(canon_process("winword.exe", guid="G1", t=10), "r1"))
    assert h.detections() == []


def test_window_expiry():
    h = _h()
    h.feed(rec(canon_process("winword.exe", guid="G1"), "r1"),
           rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=121), "r2"))
    assert h.detections() == []


def test_late_arrival_still_matches_and_is_order_independent():
    h = _h()
    child = rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2")
    h.feed(child)
    assert h.detections() == []
    h.feed(rec(canon_process("winword.exe", guid="G1"), "r1"))
    assert len(h.detections()) == 1


def test_cross_device_rejected():
    h = _h()
    h.feed(rec(canon_process("winword.exe", guid="G1"), "r1", endpoint="ep1"),
           rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2", endpoint="ep2"))
    assert h.detections() == []


def test_retry_and_generation_change_do_not_duplicate():
    h = _h()
    a = rec(canon_process("winword.exe", guid="G1"), "r1")
    b0 = rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2", generation=0)
    b1 = rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2", generation=1)
    h.feed(a, b0)
    first = h.detections()[0]["detection_id"]
    h.feed(b0)
    import asyncio
    asyncio.run(h.engine.process(b1))
    ds = h.detections()
    assert len(ds) == 1 and ds[0]["detection_id"] == first
    assert h.counters()["duplicates_prevented"] >= 2
    assert b0.stable_key == b1.stable_key


def test_duplicate_evidence_is_ignored_by_provider():
    h = _h()
    a = rec(canon_process("winword.exe", guid="G1"), "r1")
    assert h.provider.add(a) is True
    assert h.provider.add(a) is False


def test_detection_id_algorithm_excludes_generation():
    r = simple_rule()
    i1 = detection_id("t1", "ep1", r, "device:ep1", at(5))
    assert i1 == detection_id("t1", "ep1", r, "device:ep1", at(30))  # same 120 s bucket
    assert i1 != detection_id("t2", "ep1", r, "device:ep1", at(5))
    assert i1 != detection_id("t1", "ep1", simple_rule(version=2), "device:ep1", at(5))
    assert i1.startswith("e3det_") and len(i1) == 38


def test_optional_negative_and_threshold_stages():
    neg = simple_rule(rule_id="T-NEG", stages=[
        {"id": "p", "type": "PROCESS", "predicate": {"field": "process.name", "op": "eq", "value": "winword.exe"}},
        {"id": "x", "type": "PROCESS", "negate": True,
         "predicate": {"field": "process.name", "op": "eq", "value": "approved_updater.exe"}},
        {"id": "c", "type": "PROCESS", "predicate": {"field": "process.name", "op": "eq", "value": "powershell.exe"}}],
        relationships=[{"type": "parent_child", "parent": "p", "child": "c"}])
    h = _h(neg)
    h.feed(rec(canon_process("winword.exe", guid="G1"), "r1"),
           rec(canon_process("approved_updater.exe", guid="G5", t=2), "r5"),
           rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2"))
    assert h.detections() == []
    thr = simple_rule(rule_id="T-THR", entity_scope="device", relationships=[], stages=[
        {"id": "c", "type": "PROCESS", "min_count": 3,
         "predicate": {"field": "process.name", "op": "eq", "value": "net.exe"}}])
    h2 = _h(thr)
    h2.feed(*[rec(canon_process("net.exe", guid=f"N{i}", t=i), f"n{i}") for i in range(2)])
    assert h2.detections() == []
    h2.feed(rec(canon_process("net.exe", guid="N2", t=3), "n2"))
    [d] = h2.detections()
    assert len(d["evidence_keys"]) == 3


def test_benign_interpreters_alone_do_not_detect():
    h = Harness()
    h.feed(rec(canon_process("powershell.exe", guid="A1", parent="explorer.exe", cmd="powershell Get-ChildItem"), "b1"),
           rec(canon_process("cmd.exe", guid="A2", parent="explorer.exe", cmd="cmd /c dir", t=3), "b2"),
           rec(canon_process("pwsh.exe", guid="A3", cmd="pwsh -NoProfile", t=6), "b3"))
    assert h.detections() == []
