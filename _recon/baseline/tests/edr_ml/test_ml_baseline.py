"""Baselines: tenant isolation, bounded state, poisoning guards, safe serialization, retry safety."""
import json
from dataclasses import replace
from datetime import timedelta

import pytest

from edr_behavior.contracts import EvidenceRecord
from edr_ml.baseline import (DUPLICATE, FROZEN, RATE_LIMITED, TIME_REJECTED, UPDATED, Baseline,
                             BaselineConfig, BaselineStore, fit_baselines)
from edr_ml.schema import COLD, KNOWN
from mlsynth import MLH, NOW, T0, attack_chain, benign_history, proc, run


def test_tenant_isolation_with_colliding_entity_names():
    h = MLH()
    h.warm(benign_history(tenant="t1"))
    w1, ps1, ex1 = attack_chain(tenant="t1")
    w2, ps2, ex2 = attack_chain(tenant="t2")
    for r in ex1 + ex2 + [w1, w2]:
        h.provider.add(r)
    v1, v2 = h.vector(ps1), h.vector(ps2)
    assert v1.get("parent_child_rarity").state == KNOWN
    assert v2.get("parent_child_rarity").state == COLD
    assert all(r.tenant_id == "t2" for fv in v2.values for r in fv.evidence_refs)
    d1, d2 = h.feed(ps1), h.feed(ps2)
    assert {d["signal_id"] for d in d1}.isdisjoint({d["signal_id"] for d in d2})
    assert all(d["tenant_id"] == "t2" for d in h.store.all("t2"))
    exp = h.baselines.export("t1")
    assert '"t2"' not in exp
    with pytest.raises(ValueError):
        h.baselines.load("t2", exp)


def test_no_default_tenant_anywhere():
    s = BaselineStore()
    for bad in ("", None):
        with pytest.raises(ValueError):
            s.get(bad, "tenant")
        with pytest.raises(ValueError):
            s.peek(bad, "tenant")
        with pytest.raises(ValueError):
            s.export(bad)
        with pytest.raises(ValueError):
            Baseline(bad, "tenant")


def test_provider_leaking_foreign_tenant_is_filtered():
    h = MLH()
    w, ps, extra = attack_chain(tenant="t1")
    foreign = [replace(r, endpoint_id="ep1") for r in attack_chain(tenant="t9")[2]]

    class Leaky:
        async def window(self, **kw):
            return extra + foreign

        async def page(self, **kw):
            return []

    h.pipeline.extractor.provider = Leaky()
    v = run(h.pipeline.extractor.extract(ps))
    assert all(r.tenant_id == "t1" for fv in v.values for r in fv.evidence_refs)
    assert v.get("outbound_fanout").value == 12.0


def test_bounded_state_caps_and_seen_keys():
    cfg = BaselineConfig(max_keys_per_family=16, max_seen_keys=32, max_updates_per_hour=10_000)
    s = BaselineStore(cfg)
    for i in range(300):
        s.observe(proc(f"p{i}.exe", f"G{i}", f"r{i}", t=i, parent=f"q{i}.exe", cmd="c"), NOW)
    for b in (s.peek("t1", "endpoint:ep1"), s.peek("t1", "tenant")):
        assert all(len(c) <= 16 for c in b.counters.values())
        assert len(b.to_dict()["seen"]) <= 32
    assert s.state_size() <= 2 * (16 * 6 + 32)


def test_rate_limit_freeze_and_time_guards():
    cfg = BaselineConfig(max_updates_per_hour=10)
    b = Baseline("t1", "endpoint:ep1")
    outs = [b.observe(proc("a.exe", f"R{i}", f"rl{i}", t=60 * i % 3000, cmd="c"), cfg, NOW) for i in range(11)]
    assert outs.count(UPDATED) == 10 and outs[-1] == RATE_LIMITED
    late = proc("a.exe", "RX", "rlx", t=10, cmd="c")
    assert b.observe(late, cfg, NOW) == RATE_LIMITED
    r = proc("a.exe", "Z", "z", t=5000, cmd="c")
    assert b.observe(replace(r, event_time=NOW + timedelta(hours=1)), cfg, NOW) == TIME_REJECTED
    assert b.observe(replace(r, event_time=NOW - timedelta(days=365)), cfg, NOW) == TIME_REJECTED
    assert b.observe(r, BaselineConfig(frozen=True), NOW) == FROZEN
    b.frozen = True
    assert b.observe(r, cfg, NOW) == FROZEN


def test_decay_halves_counts_after_half_life():
    cfg = BaselineConfig(half_life_days=2)
    b = Baseline("t1", "endpoint:ep1")
    for i in range(8):
        b.observe(proc("a.exe", f"D{i}", f"d{i}", t=i, cmd="c"), cfg, NOW)
    assert b.count("proc", "a.exe") == 8
    b.observe(proc("b.exe", "DX", "dx", t=4 * 86400, cmd="c"), cfg, NOW)
    assert b.count("proc", "a.exe") == 2 and b.count("proc", "b.exe") == 1


def test_retry_and_generation_change_do_not_double_count():
    h = MLH()
    h.warm(benign_history())
    w, ps, extra = attack_chain()
    for r in extra + [w]:
        h.provider.add(r)
    first = h.feed(ps)
    base = h.baselines.peek("t1", "endpoint:ep1")
    before = base.count("pc", "winword.exe>powershell.exe")
    again = h.feed(ps) + h.feed(proc("powershell.exe", "AP", "a-p", t=4 * 86400 + 3 * 3600 + 2,
                                     parent="winword.exe", parent_guid="AP", cmd="x", generation=4))
    assert [d["signal_id"] for d in again] == [d["signal_id"] for d in first] * 2
    assert again[:2] == first
    assert base.count("pc", "winword.exe>powershell.exe") == before == 1
    assert len(h.store.all("t1")) == len({d["signal_id"] for d in h.store.all("t1")})
    assert base.observe(ps, h.baselines.cfg, NOW) == DUPLICATE
    assert h.pipeline.metrics.snapshot()["counters"]["duplicates"] == 2


def test_serialization_roundtrip_is_json_and_validated():
    h = MLH()
    h.warm(benign_history(n=40))
    exp = h.baselines.export("t1")
    s2 = BaselineStore(h.baselines.cfg)
    assert s2.load("t1", exp) == 2
    assert s2.export("t1") == exp
    doc = json.loads(exp)
    doc["baselines"][0]["counters"]["proc"]["x"] = -1
    with pytest.raises(ValueError):
        s2.load("t1", json.dumps(doc))
    with pytest.raises(ValueError):
        s2.load("t1", exp.replace('"observations":', '"observations":NaN,"x":', 1))
    doc = json.loads(exp)
    doc["baselines"][0]["counters"]["proc"] = {f"k{i}": 1 for i in range(5000)}
    with pytest.raises(ValueError):
        s2.load("t1", json.dumps(doc))
    doc = json.loads(exp)
    doc["baselines"][0]["tenant_id"] = "t2"
    with pytest.raises(ValueError):
        s2.load("t1", json.dumps(doc))


def test_fit_baselines_synthetic_only():
    s = BaselineStore(BaselineConfig())
    recs = benign_history(n=20)
    assert fit_baselines(s, recs, now=NOW, data_label="SYNTHETIC")["UPDATED"] == 2 * len(recs)
    with pytest.raises(ValueError):
        fit_baselines(s, recs, now=NOW, data_label="PRODUCTION")
    assert isinstance(recs[0], EvidenceRecord) and recs[0].event_time >= T0
