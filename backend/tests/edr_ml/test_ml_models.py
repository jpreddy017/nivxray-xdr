"""Models: schema binding, lifecycle, validation, explanation, benign-vs-attack, fitting, metrics."""
import json
from dataclasses import replace

import pytest

from edr_behavior.contracts import EvidenceRef, MLSignal
from edr_ml.models import (SCHEMA_MISMATCH, ModelError, ModelRegistry, _norm_robust_z, fit_robust_z,
                           load_models, parse_model, register_scorer, score)
from edr_ml.schema import SchemaError, SchemaRegistry, load_schema, parse_schema
from edr_ml.signals import to_evidence, build_signal
from edr_ml.features import FeatureExtractor
from mlsynth import BENIGN, MLH, NOW, T0, attack_chain, benign_history, proc


def _doc(**over):
    d = {"model_id": "m.x", "model_version": "1", "feature_schema_version": "fs-1.0.0",
         "model_type": "RARITY", "lifecycle": "DRAFT", "threshold": 0.5,
         "parameters": {"features": ["parent_child_rarity"], "min_coverage": 0.5}}
    d.update(over)
    return d


def _reg():
    s = SchemaRegistry()
    s.register(load_schema())
    return s


def test_schema_version_mismatch_rejected():
    s = _reg()
    with pytest.raises(ModelError):
        parse_model(_doc(feature_schema_version="fs-9.9.9"), s)
    with pytest.raises(ModelError):
        parse_model(_doc(parameters={"features": ["nope"]}), s)
    with pytest.raises(ModelError):
        parse_model(_doc(model_type="ROBUST_Z", parameters={"features": {"first_seen_binary": {"median": 0, "mad": 1}}}), s)
    h = MLH()
    h.warm(benign_history(n=40))
    w, ps, extra = attack_chain()
    v = h.vector(ps)
    m = h.models.get("ml.rarity.process_tree", "1.0.0")
    assert score(m, replace(v, schema_version="fs-2.0.0")).outcome == SCHEMA_MISMATCH


def test_released_schema_is_immutable_and_strict():
    s = SchemaRegistry()
    base = json.loads(open(load_schema.__defaults__[0]).read())
    s.register(parse_schema(base))
    changed = dict(base, description="changed")
    with pytest.raises(SchemaError):
        s.register(parse_schema(changed))
    s.register(parse_schema(dict(base, feature_schema_version="fs-x", status="DRAFT")))
    s.register(parse_schema(dict(changed, feature_schema_version="fs-x", status="DRAFT")))
    bad = dict(base, features=[dict(base["features"][0], missing_policy="ZERO")])
    with pytest.raises(SchemaError):
        parse_schema(bad)
    odd = parse_schema(dict(base, feature_schema_version="fs-odd",
                            features=[dict(base["features"][0], name="unimplemented_feature")]))
    with pytest.raises(SchemaError):
        FeatureExtractor(odd, None, None)


def test_model_lifecycle_and_immutability():
    r = ModelRegistry(_reg())
    m = r.register(_doc())
    assert r.live() == []
    with pytest.raises(ModelError):
        r.set_lifecycle("m.x", "1", "ACTIVE")
    r.set_lifecycle("m.x", "1", "TESTING")
    assert [x.model_id for x in r.live()] == ["m.x"]
    r.set_lifecycle("m.x", "1", "ACTIVE")
    r.register(_doc(model_version="2", lifecycle="TESTING", threshold=0.6))
    r.set_lifecycle("m.x", "2", "ACTIVE")
    assert r.get("m.x", "1").lifecycle == "DEPRECATED"
    with pytest.raises(ModelError):
        r.set_lifecycle("m.x", "1", "ACTIVE")
    with pytest.raises(ModelError):
        r.register(_doc(threshold=0.9))
    assert m.content_hash == r.register(_doc(lifecycle="ACTIVE")).content_hash


def test_non_finite_and_out_of_range_parameters_rejected(tmp_path):
    s = _reg()
    for bad in (_doc(threshold=float("nan")), _doc(threshold=1.5),
                _doc(model_type="WEIGHTED", parameters={"features": {"cmdline_length": {"weight": float("inf")}}}),
                _doc(model_type="WEIGHTED", parameters={"features": {"cmdline_length": {"weight": 1, "range": [5, 5]}}}),
                _doc(model_type="EVAL"), _doc(extra_key=1), _doc(model_id="bad id!")):
        with pytest.raises(ModelError):
            parse_model(bad, s)
    p = tmp_path / "m.json"
    p.write_text('[{"model_id": "m", "threshold": NaN}]')
    with pytest.raises(ModelError):
        load_models(ModelRegistry(s), p)
    with pytest.raises(ValueError):
        MLSignal("m", "1", "fs", float("nan"), 50, {}, (EvidenceRef("t1", "r"),), T0)
    with pytest.raises(ModelError):
        register_scorer("RARITY", None, None)


def test_benign_scores_low_attack_scores_high_with_real_explanation():
    h = MLH()
    h.warm(benign_history())
    benign = h.feed(proc("chrome.exe", "BX", "b-x", t=3 * 86400 + 10 * 3600, cmd=BENIGN[0][2]))
    assert all(d["outcome"] == "BELOW_THRESHOLD" and d["score"] < 0.5 for d in benign)
    w, ps, extra = attack_chain()
    for r in extra + [w]:
        h.provider.add(r)
    v = h.vector(ps)
    out = h.feed(ps)
    assert all(d["outcome"] == "EMITTED" for d in out)
    for d in out:
        env = d["signal"]
        model = h.models.get(d["model_id"], d["model_version"])
        keys = {r["stable_key"] for r in env["evidence_refs"]}
        assert env["verdict"] is None and env["explanation"]["policy"] == "signal-not-verdict"
        assert env["evidence_refs"][0]["stable_key"] == ps.stable_key
        top = env["explanation"]["top_features"]
        assert top and len(top) <= 5
        for c in top:
            assert c["feature"] in model.features()
            assert c["value"] == v.get(c["feature"]).value
            assert set(c["evidence_keys"]) <= keys
        assert abs(sum(c["share"] for c in env["explanation"]["top_features"]) - d["score"]) < 0.05 \
            or len(top) == 5


def test_fit_robust_z_synthetic_deterministic_and_draft():
    h = MLH()
    hist = benign_history(n=60)
    h.warm(hist)
    vecs = [h.vector(r) for r in hist if r.kind == "PROCESS"]
    tpl = {"model_id": "ml.rz.cmdline", "feature_schema_version": "fs-1.0.0", "threshold": 0.6,
           "parameters": {"features": ["cmdline_length", "cmdline_entropy"], "z_cap": 6.0, "min_coverage": 0.5}}
    a = fit_robust_z(tpl, vecs, model_version="1.0.0", data_label="SYNTHETIC")
    assert a == fit_robust_z(tpl, list(reversed(vecs)), model_version="1.0.0", data_label="SYNTHETIC")
    assert a["lifecycle"] == "DRAFT" and a["provenance"]["data_label"] == "SYNTHETIC"
    with pytest.raises(ModelError):
        fit_robust_z(tpl, vecs, model_version="1.0.0", data_label="PRODUCTION")
    with pytest.raises(ModelError):
        fit_robust_z(tpl, vecs[:3], model_version="1.0.0", data_label="SYNTHETIC")
    m = h.models.register(a)
    w, ps, extra = attack_chain()
    hi = score(m, h.vector(ps))
    lo = score(m, h.vector(proc("svchost.exe", "S9", "s-9", t=86400, parent="services.exe", cmd=BENIGN[2][2])))
    assert hi.score > lo.score and lo.score < 0.5
    assert {c["feature"]: c["normalized"] for c in hi.contributions}["cmdline_length"] == 1.0
    assert _norm_robust_z(5.0, {"median": 5.0, "mad": 0.0, "z_cap": 6.0})[0] == 0.0
    assert _norm_robust_z(9.0, {"median": 5.0, "mad": 0.0, "z_cap": 6.0})[0] == 1.0


def test_testing_model_signal_cannot_become_behavioral_evidence():
    h = MLH()
    h.warm(benign_history())
    w, ps, extra = attack_chain()
    for r in extra + [w]:
        h.provider.add(r)
    v = h.vector(ps)
    m = replace(h.models.get("ml.rarity.process_tree", "1.0.0"), lifecycle="TESTING")
    sig, env = build_signal(m, v, score(m, v))
    with pytest.raises(ValueError):
        to_evidence(sig, env)


def test_metrics_carry_no_telemetry_values():
    h = MLH()
    h.warm(benign_history(n=40))
    w, ps, extra = attack_chain()
    h.feed(*(extra + [w, ps]))
    snap = h.pipeline.metrics.snapshot()
    dump = json.dumps(snap)
    for s in ("powershell", "evil", "203.0.113", "AP", "winword", "Run"):
        assert s not in dump
    c = snap["counters"]
    assert c["features_extracted"] > 0 and c["baseline_updates"] > 0
    assert snap["latency_ms"]["samples"] > 0 and snap["baseline_state_size"] > 0
    assert NOW > T0
