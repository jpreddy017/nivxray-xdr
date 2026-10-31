"""L4 cross-engine: real E3 behavior + ML outputs (synthetic evidence) -> Activity Details view."""
from edr_behavior.engine import SequenceEngine
from edr_behavior.provider import InMemoryEvidenceProvider
from edr_behavior.rules import RuleRegistry, parse_rule
from edr_behavior.store import InMemoryDetectionStore
from edr_investigation.builder import build_activity_detail
from mlsynth import MLH, NOW, attack_chain, benign_history, run


def test_engine_outputs_flow_into_view_with_lifecycle_and_evidence():
    h = MLH()
    h.warm(benign_history())
    w, ps, extra = attack_chain()
    for r in extra + [w]:
        h.provider.add(r)
    decisions = h.feed(ps)
    reg = RuleRegistry()
    reg.register(parse_rule({
        "rule_id": "E3-T-OFFICE-PS", "version": 1, "lifecycle": "ACTIVE", "name": "office->ps", "description": "t",
        "severity": "HIGH", "confidence": 60, "time_window_seconds": 60, "entity_scope": "device",
        "mitre": [{"technique_id": "T1059.001", "tactic": "execution"}],
        "stages": [{"id": "p", "type": "PROCESS", "predicate": {"field": "process.name", "op": "eq",
                                                                "value": "winword.exe"}},
                   {"id": "c", "type": "PROCESS", "predicate": {"field": "process.name", "op": "eq",
                                                                "value": "powershell.exe"}}],
        "relationships": [{"type": "parent_child", "parent": "p", "child": "c"}], "provenance": {"source": "NATIVE"}}))
    p, s = InMemoryEvidenceProvider(), InMemoryDetectionStore()
    for r in (w, ps):
        p.add(r)
    run(SequenceEngine(reg, p, s, clock=lambda: NOW).process(ps))
    dets = s.all("t1")
    assert len(dets) == 1
    frame = {"frame_iid": "tf_ps", "canonical_evidence_id": ps.ref.canonical_event_id, "evidence_ids": ["a-p"],
             "mitre": ["T1059.001", "T1105"], "parent": {"iid": "proc_AW"}, "process": {"iid": "proc_AP"}}
    v = build_activity_detail(frame, tenant_id="t1", behavior_detections=dets, ml_decisions=decisions)
    assert v.section("detection_attribution").items[0]["rule_id"] == "E3-T-OFFICE-PS"
    ml = v.section("ml").items
    assert ml and all(i["lifecycle"] == "TESTING" for i in ml)
    assert {i["technique"]: i["style"] for i in v.section("mitre").items} == {"T1059.001": "threat", "T1105": "neutral"}
    assert v.machine_assessment == "NOT_ASSESSED"
