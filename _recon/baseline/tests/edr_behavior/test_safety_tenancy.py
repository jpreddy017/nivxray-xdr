import json

import pytest

from edr_behavior import predicates, rules
from edr_behavior.contracts import (OUTCOME_BUDGET, OUTCOME_INSUFFICIENT, EvidenceRef, MLSignal,
                                    STATUS_SUPPRESSED)
from edr_behavior.normalize import MAX_STR, NormalizationError, from_canonical, from_ml_signal
from edr_behavior.provider import InMemoryEvidenceProvider, MongoEvidenceProvider
from edr_behavior.suppression import SuppressionEntry, SuppressionPolicy
from factory import NOW, T0, Harness, at, canon_process, rec, registry_of, run, simple_rule


def test_cross_tenant_isolation():
    h = Harness(registry_of(simple_rule()))
    h.feed(rec(canon_process("winword.exe", guid="G1"), "r1", tenant="t1"),
           rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2", tenant="t2"))
    assert h.detections("t1") == [] and h.detections("t2") == []
    h.feed(rec(canon_process("winword.exe", guid="G1"), "r1", tenant="t2"))
    [d2] = h.detections("t2")
    assert d2["tenant_id"] == "t2" and all(r["tenant_id"] == "t2" for r in d2["evidence_refs"])


def test_provider_leaking_foreign_tenant_is_rejected():
    class Leaky(InMemoryEvidenceProvider):
        async def window(self, **kw):
            got = await super().window(**kw)
            return got + [rec(canon_process("winword.exe", guid="G1"), "evil", tenant="t-other")]
    leaky = Leaky()
    h = Harness(registry_of(simple_rule()), evidence_provider=leaky)
    child = rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2")
    leaky.add(child)
    run(h.engine.process(child))
    assert h.detections("t1") == []
    assert h.counters()["tenant_isolation_rejections"] >= 1


def test_tenant_spoofing_in_payload_is_rejected():
    c = canon_process("winword.exe", guid="G1")
    c["tenant_id"] = "t-attacker"
    with pytest.raises(NormalizationError) as e:
        from_canonical(c, tenant_id="t1", endpoint_id="ep1", raw_id="r1", now=NOW)
    assert e.value.code == "TENANT_MISMATCH"


@pytest.mark.parametrize("payload,code", [
    ("not-a-dict", "MALFORMED"),
    ({"activity": "PROCESS"}, "MISSING_EVENT_TIME"),
    ({"activity": "KERNEL_MAGIC", "activity_time": T0.isoformat()}, "UNSUPPORTED_KIND"),
    ({"activity": "PROCESS", "activity_time": "2099-01-01T00:00:00Z"}, "TIMESTAMP_UNTRUSTED"),
    ({"activity": "PROCESS", "activity_time": "x" * 5000}, "MISSING_EVENT_TIME"),
])
def test_malformed_payloads_rejected(payload, code):
    with pytest.raises(NormalizationError) as e:
        from_canonical(payload, tenant_id="t1", endpoint_id="ep1", raw_id="r1", now=NOW)
    assert e.value.code == code


def test_missing_context_rejected():
    with pytest.raises(NormalizationError):
        from_canonical(canon_process("a.exe"), tenant_id="", endpoint_id="ep1", raw_id="r1", now=NOW)


def test_huge_strings_are_bounded_and_flagged():
    r = rec(canon_process("powershell.exe", guid="G", cmd="A" * (MAX_STR * 4)), "r1")
    assert len(r.fields["process"]["command_line"]) == MAX_STR
    assert "process.command_line" in r.truncated_fields


@pytest.mark.parametrize("pred", [
    {"field": "process.name", "op": "regex", "value": "(a+)+$"},
    {"field": "__class__", "op": "eq", "value": "x"},
    {"field": "process.name", "op": "eq", "value": {"$where": "1"}},
    {"field": "process.name", "op": "eq", "value": "x", "eval": "os.system('id')"},
    {"field": "process.name", "op": "eq", "value": "x" * 600},
    {"not": {"not": {"not": {"not": {"not": {"not": {"not": {"field": "process.name", "op": "exists"}}}}}}}},
])
def test_rule_injection_and_unsafe_predicates_rejected(pred):
    with pytest.raises(rules.RuleError):
        simple_rule(stages=[{"id": "p", "type": "PROCESS", "predicate": pred}], relationships=[])


def test_unknown_rule_keys_rejected():
    with pytest.raises(rules.RuleError):
        simple_rule(code="import os")


def test_missing_command_line_is_insufficient_not_clean():
    rule = simple_rule(rule_id="T-CMD", relationships=[], stages=[
        {"id": "c", "type": "COMMAND", "predicate": {"field": "process.command_line", "op": "contains",
                                                     "value": "-enc"}}])
    h = Harness(registry_of(rule))
    res = h.feed(rec(canon_process("powershell.exe", guid="G1"), "r1"))
    assert res[0][0].outcome == OUTCOME_INSUFFICIENT
    assert h.counters()["insufficient_evidence"] == 1


def test_unknown_signer_never_suppresses():
    rule = simple_rule(exclusions=[{"stage": "c", "reason": "trusted signer",
                                    "predicate": {"field": "process.signer", "op": "eq", "value": "Microsoft"}}])
    h = Harness(registry_of(rule))
    h.feed(rec(canon_process("winword.exe", guid="G1"), "r1"),
           rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5), "r2"))
    [d] = h.detections()
    assert d["status"] == "OPEN" and "not evaluable" in d["explanation"]


def test_tenant_suppression_keeps_evidence():
    entry = SuppressionEntry(entry_id="s1", tenant_id="t1", reason="known admin tooling",
                             created_by="analyst@t1", rule_id="T-PC", stage="c",
                             predicate={"field": "process.command_line", "op": "contains", "value": "admin-script"})
    h = Harness(registry_of(simple_rule()), suppression=SuppressionPolicy((entry,)))
    h.feed(rec(canon_process("winword.exe", guid="G1"), "r1"),
           rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5, cmd="powershell admin-script"), "r2"))
    [d] = h.detections()
    assert d["status"] == STATUS_SUPPRESSED and d["suppression"]["entry_id"] == "s1"
    assert len(d["evidence_refs"]) == 2 and h.provider.add(rec(canon_process("winword.exe", guid="G1"), "r1")) is False
    assert h.counters()["suppressed_matches"] == 1
    h.feed(rec(canon_process("winword.exe", guid="G1"), "r1", tenant="t2"),
           rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5, cmd="powershell admin-script"), "r2", tenant="t2"))
    assert h.detections("t2")[0]["status"] == "OPEN"  # suppression is tenant-owned


def test_suppression_requires_tenant():
    with pytest.raises(ValueError):
        SuppressionEntry(entry_id="s", tenant_id="", reason="r", created_by="x",
                         predicate={"field": "process.name", "op": "exists"})


def test_window_and_evaluation_budgets():
    h = Harness(registry_of(simple_rule()), max_window_events=5)
    evs = [rec(canon_process("winword.exe", guid=f"W{i}", t=i), f"w{i}") for i in range(7)]
    res = h.feed(*evs)
    assert res[-1][0].outcome == OUTCOME_BUDGET and h.counters()["window_truncated"] >= 1
    h2 = Harness(registry_of(simple_rule()), budget=3)
    h2.feed(*[rec(canon_process("winword.exe", guid=f"W{i}", t=i), f"w{i}") for i in range(3)])
    res2 = h2.feed(rec(canon_process("powershell.exe", guid="C", parent_guid="W2", t=5), "c"))
    assert res2[0][0].outcome == OUTCOME_BUDGET and h2.counters()["budget_exceeded"] >= 1


def test_metrics_contain_no_telemetry_values():
    h = Harness(registry_of(simple_rule()))
    h.feed(rec(canon_process("winword.exe", guid="G1", cmd="SECRET-TOKEN-123"), "r1"),
           rec(canon_process("powershell.exe", guid="G2", parent_guid="G1", t=5, cmd="SECRET-TOKEN-123"), "r2"))
    dump = json.dumps(h.engine.metrics.snapshot())
    assert "SECRET" not in dump and "winword" not in dump and "G1" not in dump


def test_ml_signal_boundary_requires_evidence():
    ref = EvidenceRef("t1", "r1")
    with pytest.raises(ValueError):
        MLSignal("m", "1", "f1", 0.9, 80, {}, (), T0)
    sig = MLSignal("m", "1", "f1", 0.9, 80, {"top": ["x"]}, (ref,), T0)
    r = from_ml_signal(sig, endpoint_id="ep1")
    assert r.kind == "DETECTION" and r.fields["detection"]["source"] == "ML"


def test_mongo_provider_requires_tenant_and_builds_bounded_query():
    seen = {}

    class Cur:
        def __init__(self, docs): self.docs = docs
        def sort(self, s): seen["sort"] = s; return self
        def limit(self, n): seen["limit"] = n; return self
        def __aiter__(self):
            async def gen():
                for d in self.docs:
                    yield d
            return gen()

    class Coll:
        def find(self, flt): seen["filter"] = flt; return Cur([])

    p = MongoEvidenceProvider(Coll(), lambda d: None, tenant_field="tenant_id",
                              endpoint_field="endpoint_id", time_field="event_time")
    run(p.window(tenant_id="t1", endpoint_id="ep1", start=T0, end=at(60), kinds=["PROCESS"], limit=10))
    assert seen["filter"]["tenant_id"] == "t1" and "$gte" in seen["filter"]["event_time"]
    assert seen["limit"] == 10
    with pytest.raises(ValueError):
        run(p.window(tenant_id="", endpoint_id="ep1", start=T0, end=at(1), kinds=[], limit=1))


def test_predicate_three_valued_logic():
    r = rec(canon_process("powershell.exe", guid="G"), "r1")
    assert predicates.evaluate(r, {"field": "process.command_line", "op": "contains", "value": "x"}) == "UNKNOWN"
    assert predicates.evaluate(r, {"not": {"field": "process.command_line", "op": "contains", "value": "x"}}) == "UNKNOWN"
    assert predicates.evaluate(r, {"any": [{"field": "process.name", "op": "eq", "value": "POWERSHELL.EXE"},
                                           {"field": "process.command_line", "op": "contains", "value": "x"}]}) == "TRUE"
    assert predicates.evaluate(r, {"field": "process.command_line", "op": "not_exists"}) == "TRUE"
