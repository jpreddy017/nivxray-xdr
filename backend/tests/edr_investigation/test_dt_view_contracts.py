"""DT-I1B view-model contract tests (synthetic only)."""
import json

import pytest

from edr_investigation import ABSENCE_STATEMENT, NO_DETECTION_STATEMENT
from edr_investigation.builder import build_activity_detail
from edr_investigation.contracts import (SECTION_KEYS, AnalystDisposition, Relationship, RetroEntry, TIResult,
                                         validate_history)
from edr_investigation.ti import normalize_ioc_card, normalize_provider_result

FRAME = {"frame_iid": "tf_1", "ts": "2026-09-05T03:00:02Z", "lane": "process", "action": "process_create",
         "label": "winword.exe spawned powershell.exe", "canonical_evidence_id": "cev_a-p_g0",
         "evidence_ids": ["a-p"], "device": {"kind": "device", "iid": "dev_ep1", "label": "HOST-1"},
         "process": {"kind": "process", "iid": "proc_AP", "label": "powershell.exe",
                     "command_line": "powershell -enc AAAA"},
         "parent": {"kind": "process", "iid": "proc_AW", "label": "winword.exe"},
         "mitre": ["T1059.001", "T1027"], "provenance": {"source": "cem"}, "bridge_state": "BRIDGED",
         "remote_ip": "203.0.113.7", "sha256": "a" * 64}


def _det(**over):
    d = {"detection_id": "e3det_x", "tenant_id": "t1", "rule_id": "E3-SEQ-001", "rule_version": 1,
         "status": "OPEN", "severity": "HIGH", "confidence": 70, "mitre": [{"technique_id": "T1059.001"}],
         "evidence_refs": [{"canonical_event_id": "cev_a-p_g0", "raw_id": "a-p"}], "evidence_keys": ["k1"],
         "matched_stages": [{"stage_id": "parent"}, {"stage_id": "child"}], "explanation": "office -> shell"}
    d.update(over)
    return d


def test_sections_follow_section15_order_and_unwired_sources_are_not_wired():
    v = build_activity_detail({"frame_iid": "tf_0"}, tenant_id="t1")
    assert tuple(s.key for s in v.sections) == SECTION_KEYS and len(SECTION_KEYS) == 15
    for k in ("behavioral", "threat_intel", "ml", "retrospection", "response", "verification"):
        assert v.section(k).state == "NOT_WIRED", k
    assert v.machine_assessment == "NOT_ASSESSED"


def test_no_detection_is_never_clean():
    v = build_activity_detail(FRAME, tenant_id="t1", behavior_detections=[])
    det = v.section("detection_attribution")
    assert det.state == "EMPTY" and det.statements == (NO_DETECTION_STATEMENT, ABSENCE_STATEMENT)
    assert v.section("behavioral").state == "EMPTY"
    dump = json.dumps(v.to_dict()).lower()
    assert '"clean"' not in dump and '"benign"' not in dump and "contained" not in dump.replace("≠ contained", "")


def test_mitre_neutral_unless_attributed_by_an_engine():
    v = build_activity_detail(FRAME, tenant_id="t1", behavior_detections=[])
    assert {i["style"] for i in v.section("mitre").items} == {"neutral"}
    v2 = build_activity_detail(FRAME, tenant_id="t1", behavior_detections=[_det()])
    styles = {i["technique"]: i["style"] for i in v2.section("mitre").items}
    assert styles == {"T1059.001": "threat", "T1027": "neutral"}
    assert v2.section("detection_attribution").items[0]["engine"] == "edr_behavior"
    assert any(i["kind"] == "detection" for i in v2.section("supporting_evidence").items)


def test_unrelated_detection_is_not_attributed():
    other = _det(evidence_refs=[{"canonical_event_id": "cev_other", "raw_id": "zz"}])
    v = build_activity_detail(FRAME, tenant_id="t1", behavior_detections=[other])
    assert v.section("detection_attribution").state == "EMPTY"


def test_causal_edges_are_never_invented():
    v = build_activity_detail(FRAME, tenant_id="t1")
    [edge] = v.section("causal_context").items
    assert edge["state"] == "SUPPORTED_RELATIONSHIP" and edge["evidence_refs"]
    orphan = dict(FRAME, parent=None)
    [u] = build_activity_detail(orphan, tenant_id="t1").section("causal_context").items
    assert u["state"] == "UNKNOWN" and u["target"] is None
    assert any(m["source"] == "causal" for m in build_activity_detail(orphan, tenant_id="t1")
               .section("missing_evidence").items)
    with pytest.raises(ValueError):
        Relationship("process->child", "a", "b", "PROVEN_CAUSAL", ("k",), linkage=None)
    with pytest.raises(ValueError):
        Relationship("process->child", "a", "b", "CORRELATED", ())
    Relationship("process->child", "a", "b", "PROVEN_CAUSAL", ("k",), linkage="SOURCE_PROCESS_GUID")


def test_ti_states_no_data_is_not_benign_and_provider_required():
    assert normalize_provider_result("x", "ip", "abuseipdb", "clean").state == "BENIGN"
    assert normalize_provider_result("x", "ip", None, "clean").state == "UNKNOWN"
    assert normalize_provider_result("x", "ip", "vt", "pending").state == "UNAVAILABLE"
    assert normalize_provider_result("x", "ip", "vt", "rate_limited").state == "RATE_LIMITED"
    assert normalize_provider_result("x", "ip", "vt", "weird").state == "UNKNOWN"
    assert [r.state for r in normalize_ioc_card({"ioc": "x", "providers": []})] == ["NO_DATA"]
    card = {"ioc": "203.0.113.7", "ioc_type": "ip", "providers": [
        {"provider": "abuseipdb", "verdict": {"verdict": "malicious"}}, {"provider": "dshield", "verdict": "clean"}]}
    assert [r.state for r in normalize_ioc_card(card)] == ["MALICIOUS", "BENIGN"]
    with pytest.raises(ValueError):
        TIResult("x", "ip", "MALICIOUS", None)
    ti = [TIResult("203.0.113.7", "ip", "BENIGN", "dshield")]
    v = build_activity_detail(FRAME, tenant_id="t1", ti_results=ti)
    states = {i["type"]: i["state"] for i in v.section("threat_intel").items}
    assert states == {"sha256": "UNKNOWN", "ip": "BENIGN"}
    assert v.section("contradicting_evidence").items[0]["note"] == "context, not exoneration"
    assert any(m["detail"] == "UNKNOWN" for m in v.section("missing_evidence").items)


def test_response_accepted_or_executed_is_not_verified():
    cmds = [{"command_id": "c1", "action": "ISOLATE_ENDPOINT", "state": "EXECUTED", "tenant_id": "t1"},
            {"command_id": "c2", "action": "KILL_PROCESS", "state": "ACCEPTED"},
            {"command_id": "c3", "action": "KILL_PROCESS", "state": "VERIFIED"},
            {"command_id": "c4", "action": "KILL_PROCESS", "state": "WEIRD"}]
    v = build_activity_detail(FRAME, tenant_id="t1", response_commands=cmds)
    ver = {i["command_id"]: i for i in v.section("verification").items}
    assert [ver[c]["verified"] for c in ("c1", "c2", "c3", "c4")] == [False, False, True, False]
    assert ver["c1"]["proof"] == "SENSOR_CLAIM_ONLY_NOT_VERIFIED"
    assert {i["command_id"]: i["state"] for i in v.section("response").items}["c4"] == "UNKNOWN_STATE"


def test_retro_history_append_only_and_machine_vs_analyst_separate():
    h = [RetroEntry(1, "09:00", "INITIAL", "UNKNOWN", ("k",)),
         RetroEntry(2, "09:02", "NEW_EVIDENCE", "SUSPICIOUS", ("k", "k2"), supersedes=1),
         RetroEntry(3, "11:41", "REPUTATION_CHANGE", "MALICIOUS", ("k3",), supersedes=2)]
    a = AnalystDisposition("FALSE_POSITIVE", "analyst@x", "12:00")
    v = build_activity_detail(FRAME, tenant_id="t1", assessment_history=h, analyst_disposition=a)
    assert v.machine_assessment == "MALICIOUS" and v.to_dict()["analyst_disposition"]["value"] == "FALSE_POSITIVE"
    assert [i["version"] for i in v.section("retrospection").items] == [1, 2, 3]
    with pytest.raises(ValueError):
        validate_history([h[0], h[2]])
    with pytest.raises(ValueError):
        RetroEntry(2, "x", "INITIAL", "UNKNOWN", (), supersedes=None)
    with pytest.raises(ValueError):
        AnalystDisposition("CLEAN", "a", "t")
    with pytest.raises(ValueError):
        AnalystDisposition("FALSE_POSITIVE", "", "t")


def test_tenant_mandatory_and_cross_tenant_rejected():
    with pytest.raises(ValueError):
        build_activity_detail(FRAME, tenant_id="")
    with pytest.raises(ValueError):
        build_activity_detail(FRAME, tenant_id="t1", behavior_detections=[_det(tenant_id="t2")])
    with pytest.raises(ValueError):
        build_activity_detail(FRAME, tenant_id="t1", response_commands=[{"tenant_id": "t9", "state": "VERIFIED"}])


def test_deterministic_output_and_bounded_items():
    a = build_activity_detail(FRAME, tenant_id="t1", behavior_detections=[_det()]).to_dict()
    b = build_activity_detail(json.loads(json.dumps(FRAME)), tenant_id="t1", behavior_detections=[_det()]).to_dict()
    assert a == b
    many = [_det(detection_id=f"d{i}") for i in range(500)]
    v = build_activity_detail(FRAME, tenant_id="t1", behavior_detections=many)
    assert len(v.section("detection_attribution").items) == 50


def test_unbridged_frame_reports_missing_provenance():
    v = build_activity_detail(dict(FRAME, bridge_state="LEGACY_UNBRIDGED"), tenant_id="t1")
    assert {"source": "evidence_bridge", "detail": "LEGACY_UNBRIDGED"} in v.section("missing_evidence").items
    assert v.section("provenance").items[0]["bridge_state"] == "LEGACY_UNBRIDGED"
    assert {p["pivot"] for p in v.section("pivots").items} == {"process_ancestry", "file_trajectory", "network_hunt"}
