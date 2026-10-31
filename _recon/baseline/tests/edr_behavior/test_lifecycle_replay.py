import pytest

from edr_behavior import rules
from edr_behavior.contracts import Enrichment, OUTCOME_INSUFFICIENT
from edr_behavior.integration import BehaviorIntegration, BridgeContext, canonical_doc_mapper
from edr_behavior.provider import StaticEnrichmentProvider
from edr_behavior.replay import InMemoryCheckpointStore, ReplayRequest, run_replay
from factory import NOW, T0, Harness, actor, at, canon_process, rec, registry_of, run, simple_rule


def _pair(h, tenant="t1"):
    for r in (rec(canon_process("winword.exe", guid="G1"), "r1", tenant=tenant),
              rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2", tenant=tenant)):
        h.provider.add(r)


def test_versioning_attribution_and_immutability():
    reg = registry_of(simple_rule())
    h = Harness(reg)
    _pair(h)
    run(h.engine.process(h.provider._by_key[("t1", rec(canon_process("x"), "r2").stable_key)]))
    [v1] = h.detections()
    assert v1["rule_version"] == 1
    v2 = simple_rule(version=2, lifecycle="TESTING", confidence=70)
    reg.register(v2)
    reg.set_lifecycle("T-PC", 2, "ACTIVE")
    assert reg.get("T-PC", 1).lifecycle == "DEPRECATED"
    assert [(r.rule_id, r.version) for r in reg.live_rules()] == [("T-PC", 2)]
    run(h.engine.process(rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2")))
    ds = sorted(h.detections(), key=lambda d: d["rule_version"])
    assert [d["rule_version"] for d in ds] == [1, 2]
    assert ds[0]["detection_id"] == v1["detection_id"] and ds[0]["confidence"] == 60
    with pytest.raises(rules.RuleError):
        reg.register(simple_rule(version=1, confidence=99))
    with pytest.raises(rules.RuleError):
        reg.set_lifecycle("T-PC", 1, "ACTIVE")


def test_testing_rules_produce_testing_status_and_drafts_do_not_run():
    reg = registry_of(simple_rule(lifecycle="TESTING"), simple_rule(rule_id="T-DRAFT", lifecycle="DRAFT"))
    h = Harness(reg)
    h.feed(rec(canon_process("winword.exe", guid="G1"), "r1"),
           rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2"))
    assert [(d["rule_id"], d["status"]) for d in h.detections()] == [("T-PC", "TESTING")]


def test_retro_replay_when_rule_added_is_idempotent_and_resumable():
    reg = rules.RuleRegistry()
    h = Harness(reg)
    _pair(h)
    for i in range(5):
        h.provider.add(rec(canon_process("notepad.exe", guid=f"N{i}", t=10 + i), f"n{i}"))
    reg.register(simple_rule())
    req = ReplayRequest(replay_id="rp1", tenant_id="t1", endpoint_ids=("ep1",), start=T0, end=at(600),
                        reason="RULE_ADDED", rule_keys=(("T-PC", 1),), page_size=2)
    cps = InMemoryCheckpointStore()
    part = run(run_replay(h.engine, req, cps, max_pages=1))
    assert part["complete"] is False
    full = run(run_replay(h.engine, req, cps))
    assert full["complete"] is True
    [d] = h.detections()
    assert d["provenance"]["mode"] == "RETRO" and d["provenance"]["trigger"]["reason"] == "RULE_ADDED"
    run(run_replay(h.engine, ReplayRequest(replay_id="rp2", tenant_id="t1", endpoint_ids=("ep1",),
                                           start=T0, end=at(600), reason="MANUAL",
                                           rule_keys=(("T-PC", 1),)), InMemoryCheckpointStore()))
    assert len(h.detections()) == 1 and h.counters()["replay_runs"] == 3  # partial + resume + rp2


def _intel_rule():
    return rules.parse_rule({
        "rule_id": "T-INTEL", "version": 1, "lifecycle": "ACTIVE", "name": "ps to bad ip",
        "description": "x", "severity": "HIGH", "confidence": 60, "time_window_seconds": 300,
        "entity_scope": "process",
        "stages": [{"id": "ps", "type": "PROCESS",
                    "predicate": {"field": "process.name", "op": "eq", "value": "powershell.exe"}},
                   {"id": "bad", "type": "INTEL", "on_types": ["NETWORK"], "observable_field": "network.dest_ip",
                    "observable_type": "ip", "verdict_in": ["MALICIOUS"], "min_confidence": 70}],
        "relationships": [{"type": "same_process", "stages": ["ps", "bad"]}]})


def test_intel_unknown_then_retro_after_intel_change():
    intel = StaticEnrichmentProvider({})
    h = Harness(registry_of(_intel_rule()), enrichment=intel)
    res = h.feed(rec(canon_process("powershell.exe", guid="P1"), "p1"),
                 rec(actor("P1", "NETWORK", 3, dest_ip="203.0.113.7"), "n1"))
    assert res[1][0].outcome == OUTCOME_INSUFFICIENT and h.detections() == []
    intel.set("t1", "203.0.113.7", Enrichment("203.0.113.7", "ip", "MALICIOUS", 90, ("test-feed",),
                                              None, None, NOW.isoformat(), None))
    run(run_replay(h.engine, ReplayRequest(replay_id="intel-1", tenant_id="t1", endpoint_ids=("ep1",),
                                           start=T0, end=at(60), reason="INTEL_CHANGED"),
                   InMemoryCheckpointStore()))
    [d] = h.detections()
    assert d["provenance"]["trigger"]["reason"] == "INTEL_CHANGED"


def test_integration_adapter_is_disabled_by_default_and_never_raises():
    h = Harness(registry_of(simple_rule()))
    integ = BehaviorIntegration(h.engine)
    ctx = BridgeContext("t1", "ep1", "r1")
    assert run(integ.on_canonical(canon_process("winword.exe", guid="G1"), ctx))["reason"] == "DISABLED"
    integ = BehaviorIntegration(h.engine, enabled=True, sink=h.provider.add)
    bad = canon_process("winword.exe")
    bad["tenant_id"] = "other"
    assert run(integ.on_canonical(bad, ctx))["reason"] == "TENANT_MISMATCH"
    assert run(integ.on_canonical({"x": 1}, ctx))["reason"] == "UNSUPPORTED_KIND"
    run(integ.on_canonical(canon_process("winword.exe", guid="G1"), ctx))
    out = run(integ.on_canonical(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5),
                                 BridgeContext("t1", "ep1", "r2", "cev_r2_g0", 0)))
    assert out["evaluated"] and out["outcomes"][0]["outcome"] == "MATCH"

    class Boom:
        clock = staticmethod(lambda: NOW)
        metrics = h.engine.metrics
        async def process(self, rec):
            raise RuntimeError("x")
    assert run(BehaviorIntegration(Boom(), enabled=True).on_canonical(
        canon_process("a.exe", guid="Z"), ctx))["reason"] == "ENGINE_FAULT"


def test_canonical_doc_mapper():
    m = canonical_doc_mapper(tenant_field="tenant_id", endpoint_field="endpoint_id", raw_id_field="raw_id",
                             canonical_field="canonical", event_id_field="event_id")
    doc = {"tenant_id": "t1", "endpoint_id": "ep1", "raw_id": "r1", "event_id": "cev_r1_g0",
           "canonical": canon_process("winword.exe", guid="G1")}
    r = m(doc)
    assert r.ref.canonical_event_id == "cev_r1_g0" and r.tenant_id == "t1"
    assert m({"tenant_id": "t1"}) is None
