"""Feature extraction: determinism, UNKNOWN semantics, cold start, hostile input."""
import time
from dataclasses import replace
from datetime import timedelta

import pytest

from edr_behavior.contracts import EvidenceRef
from edr_ml.features import MLInputError
from edr_ml.schema import COLD, KNOWN, UNKNOWN, FeatureValue
from mlsynth import BENIGN, MLH, NOW, attack_chain, benign_history, proc, run


def _attack_vector(h):
    w, ps, extra = attack_chain()
    for r in extra + [w]:
        h.provider.add(r)
    return h.vector(ps), ps


def test_determinism_same_input_same_features_scores_and_ids():
    outs = []
    for _ in range(2):
        h = MLH()
        h.warm(benign_history())
        v, ps = _attack_vector(h)
        outs.append((v.to_dict(), h.feed(ps)))
    assert outs[0] == outs[1]
    assert outs[0][1][0]["signal_id"].startswith("e3mls_")


def test_missing_values_are_unknown_never_zero():
    h = MLH()
    h.warm(benign_history())
    lone = proc("tool.exe", "L1", "l-1", t=4 * 86400 + 10 * 3600, parent=None, cmd=None)
    v = h.vector(lone)
    for name in ("cmdline_length", "cmdline_entropy", "cmdline_encoded_indicator", "parent_child_rarity",
                 "outbound_fanout", "registry_persistence_touches", "first_seen_domain", "first_seen_ip"):
        fv = v.get(name)
        assert fv.state == UNKNOWN and fv.value is None and fv.reason, name
    assert v.get("child_spawn_burst").state == KNOWN and v.get("child_spawn_burst").value == 0.0


def test_cold_start_is_insufficient_baseline_and_emits_nothing():
    h = MLH()
    w, ps, extra = attack_chain()
    for r in extra + [w]:
        h.provider.add(r)
    v = h.vector(ps)
    for name in ("parent_child_rarity", "process_rarity_endpoint", "process_rarity_tenant",
                 "first_seen_binary", "first_seen_domain", "first_seen_ip", "off_hours"):
        assert v.get(name).state == COLD and v.get(name).value is None, name
    d = h.by_model(h.feed(ps), "ml.rarity.process_tree")
    assert d["outcome"] == COLD and d["signal"] is None
    assert h.pipeline.metrics.snapshot()["counters"]["cold_start"] >= 1


def test_every_feature_value_carries_evidence_refs_including_anchor():
    h = MLH()
    h.warm(benign_history())
    v, ps = _attack_vector(h)
    for fv in v.values:
        assert fv.evidence_refs and fv.evidence_refs[0].stable_key() == ps.stable_key
    assert len(v.get("outbound_fanout").evidence_refs) <= 16
    with pytest.raises(ValueError):
        FeatureValue("x", UNKNOWN, None, ())
    with pytest.raises(ValueError):
        FeatureValue("x", KNOWN, float("nan"), (EvidenceRef("t1", "r"),))
    with pytest.raises(ValueError):
        FeatureValue("x", UNKNOWN, 0.0, (EvidenceRef("t1", "r"),))


def test_huge_command_line_is_bounded_and_flagged():
    h = MLH()
    big = proc("powershell.exe", "B1", "b-1", t=100, cmd="A" * 1_000_000)
    t0 = time.perf_counter()
    v = h.vector(big)
    assert time.perf_counter() - t0 < 2.0
    ln = v.get("cmdline_length")
    assert ln.value == 8192.0 and ln.baseline["truncated_lower_bound"] is True
    assert v.get("cmdline_entropy").baseline["chars_considered"] == 4096
    assert v.get("cmdline_entropy").value == 0.0


def test_nan_and_non_string_fields_become_unknown():
    h = MLH()
    r = proc("x.exe", "N1", "n-1", t=100, cmd="x")
    fields = dict(r.fields)
    fields["process"] = dict(fields["process"], command_line=float("nan"), name=float("inf"))
    v = h.vector(replace(r, fields=fields))
    assert v.get("cmdline_length").state == UNKNOWN
    assert v.get("process_rarity_endpoint").state == UNKNOWN


def test_future_or_naive_timestamps_rejected():
    h = MLH()
    r = proc("x.exe", "F1", "f-1", t=100, cmd="x")
    with pytest.raises(MLInputError):
        run(h.pipeline.extractor.extract(replace(r, event_time=NOW + timedelta(days=1))))
    with pytest.raises(MLInputError):
        run(h.pipeline.extractor.extract(replace(r, event_time=(NOW - timedelta(days=1)).replace(tzinfo=None))))
    assert h.feed(replace(r, event_time=NOW + timedelta(days=1))) == []
    assert h.pipeline.metrics.snapshot()["counters"]["events_rejected"] == 1


def test_window_truncation_makes_counts_unknown():
    h = MLH(max_events=5)
    recs = [proc("cmd.exe", f"K{i}", f"k-{i}", t=10 + i, parent="x.exe", parent_guid="P", cmd="c") for i in range(10)]
    for r in recs:
        h.provider.add(r)
    v = h.vector(proc("x.exe", "P", "p", t=5, cmd="x"))
    assert v.get("child_spawn_burst").state == UNKNOWN
    assert "truncated" in v.get("child_spawn_burst").reason


def test_benign_encoded_indicator_negative():
    h = MLH()
    v = h.vector(proc("chrome.exe", "C1", "c-1", t=100, cmd=BENIGN[0][2]))
    assert v.get("cmdline_encoded_indicator").value == 0.0
