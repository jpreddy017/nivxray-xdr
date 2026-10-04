"""Correlation boundary: ML signals feed sequence rules only alongside real evidence."""
from edr_behavior import ML_ONLY_REASON
from edr_behavior.contracts import OUTCOME_INSUFFICIENT
from edr_behavior.engine import SequenceEngine
from edr_behavior.normalize import from_detection_observation, is_ml_evidence
from edr_behavior.provider import InMemoryEvidenceProvider
from edr_behavior.rules import RuleRegistry, parse_rule
from edr_behavior.store import InMemoryDetectionStore
from edr_ml.pipeline import evidence_from_decision
from mlsynth import MLH, NOW, attack_chain, benign_history, run

ML_PRED = {"all": [{"field": "detection.source", "op": "eq", "value": "ML", "case": "sensitive"},
                   {"field": "detection.rule_id", "op": "eq", "value": "ml:ml.weighted.exec_behavior"},
                   {"field": "detection.score", "op": "gte", "value": 0.6}]}
PS_PRED = {"field": "process.name", "op": "eq", "value": "powershell.exe"}


def _rule(stages, rels=(), **over):
    doc = {"rule_id": over.pop("rule_id", "ML-SEQ"), "version": 1, "lifecycle": "ACTIVE", "name": "ml seq",
           "description": "test", "severity": "HIGH", "confidence": 50, "time_window_seconds": 120,
           "entity_scope": "process", "stages": stages, "relationships": list(rels),
           "provenance": {"source": "ML_SIGNAL"}}
    doc.update(over)
    reg = RuleRegistry()
    reg.register(parse_rule(doc))
    return reg


def _engine(reg):
    p, s = InMemoryEvidenceProvider(), InMemoryDetectionStore()
    return SequenceEngine(reg, p, s, clock=lambda: NOW), p, s


def _signal():
    h = MLH()
    # Shipped as TESTING; promote explicitly in-test (TESTING -> ACTIVE) to exercise the evidence path.
    h.models.set_lifecycle("ml.weighted.exec_behavior", "1.0.0", "ACTIVE")
    h.warm(benign_history())
    w, ps, extra = attack_chain()
    for r in extra + [w]:
        h.provider.add(r)
    d = h.by_model(h.feed(ps), "ml.weighted.exec_behavior")
    assert d["outcome"] == "EMITTED"
    ml = evidence_from_decision(d)
    assert is_ml_evidence(ml) and ml.process.process_iid == "proc_AP"
    return ps, ml, d


def test_ml_signal_alone_never_creates_detection():
    ps, ml, _ = _signal()
    eng, p, s = _engine(_rule([{"id": "ml", "type": "DETECTION", "predicate": ML_PRED}]))
    p.add(ml)
    res = run(eng.process(ml))
    assert res[0].outcome == OUTCOME_INSUFFICIENT and ML_ONLY_REASON in res[0].reasons
    assert s.all() == []
    assert eng.metrics.snapshot()["counters"]["ml_only_rejected"] == 1


def test_spoofed_ml_detection_observation_is_treated_as_ml():
    spoof = from_detection_observation({"event_time": NOW.isoformat(), "rule_id": "ml:x", "source": "ML"},
                                       tenant_id="t1", endpoint_id="ep1", raw_id="s-1")
    assert is_ml_evidence(spoof)
    eng, p, s = _engine(_rule([{"id": "ml", "type": "DETECTION",
                                "predicate": {"field": "detection.rule_id", "op": "eq", "value": "ml:x"}}]))
    p.add(spoof)
    run(eng.process(spoof))
    assert s.all() == []


def test_sequence_plus_ml_stage_matches_only_with_real_evidence():
    ps, ml, d = _signal()
    reg = _rule([{"id": "p", "type": "PROCESS", "predicate": PS_PRED},
                 {"id": "ml", "type": "DETECTION", "predicate": ML_PRED}],
                [{"type": "same_process", "stages": ["p", "ml"]}])
    eng, p, s = _engine(reg)
    p.add(ml)
    run(eng.process(ml))
    assert s.all() == []
    p.add(ps)
    run(eng.process(ps))
    [det] = s.all("t1")
    assert "a-p" in det["raw_refs"]
    assert ps.stable_key in det["evidence_keys"] and ml.stable_key in det["evidence_keys"]
    assert len(det["evidence_refs"]) >= 2
    eng2, p2, s2 = _engine(reg)
    p2.add(ps)
    run(eng2.process(ps))
    assert s2.all() == []


def test_ml_stage_as_bounded_confidence_bonus():
    ps, ml, _ = _signal()
    stages = [{"id": "p", "type": "PROCESS", "predicate": PS_PRED},
              {"id": "ml", "type": "DETECTION", "predicate": ML_PRED, "optional": True, "confidence_bonus": 20}]
    rels = [{"type": "same_process", "stages": ["p", "ml"]}]
    with_ml, p, s = _engine(_rule(stages, rels))
    p.add(ps)
    p.add(ml)
    run(with_ml.process(ml))
    without, p2, s2 = _engine(_rule(stages, rels))
    p2.add(ps)
    run(without.process(ps))
    assert s.all()[0]["confidence"] == 70 and s2.all()[0]["confidence"] == 50
    assert s.all()[0]["detection_id"] == s2.all()[0]["detection_id"]


def test_signal_evidence_is_deterministic_and_generation_independent():
    _, ml1, d1 = _signal()
    _, ml2, d2 = _signal()
    assert d1 == d2 and ml1.stable_key == ml2.stable_key
    assert all(r.generation is None or isinstance(r.generation, int) for r in [ml1.ref])


def test_detection_build_refuses_ml_only_evidence_and_engine_version_bumped():
    import pytest
    from edr_behavior import ENGINE_VERSION, ML_BOUNDARY_VERSION
    from edr_behavior.contracts import OUTCOME_MATCH, EvaluationResult, StageMatch
    from edr_behavior.detection import build
    _, ml, _ = _signal()
    rule = _rule([{"id": "ml", "type": "DETECTION", "predicate": ML_PRED}]).all()[0]
    res = EvaluationResult(rule.rule_id, rule.version, OUTCOME_MATCH, [], [StageMatch("ml", "DETECTION", [ml])])
    with pytest.raises(ValueError, match="ML signal evidence alone"):
        build(rule, res, tenant_id="t1", endpoint_id="ep1", suppression=None, notes=[], adjustments=[],
              mode="LIVE", trigger=None, now=NOW)
    assert ENGINE_VERSION == "e3-seq-1.1.0" and ML_BOUNDARY_VERSION == "e3.ml-boundary.v1"
