"""GATE 3 · contract tests for the detection & prevention fabric.

These assert the INVARIANTS, not the implementation:

  INV-1  an ML finding is not automatically malicious, and it cannot
         exist without a versioned model
  INV-2  no finding without cited evidence
  INV-3  the three outcomes stay three different facts
  INV-4  a score must declare its scale; features must be digestible
  INV-5  a finding is content-addressed, so re-evaluation is idempotent
  + the registry is a contract: an analyzer must declare itself
  + the fabric states its own blind spots instead of implying coverage
"""
from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from edr_plane import fabric
from edr_plane.fabric import registry, store
from edr_plane.fabric.analyzers.deterministic_rule import ANALYZER
from edr_plane.fabric.contracts import (AnalyzerClass, AnalyzerResult,
                                        EvidenceUnit, Finding,
                                        InferenceLocation, Outcome, Severity,
                                        feature_digest)


def _unit(**over):
    base = dict(tenant_id="t-fabric", evidence_ref="cev_x_0",
                endpoint_ref="ep_x",
                observed_at="2026-06-01T10:00:00+00:00",
                activity={"activity": "PROCESS"},
                derivations=[])
    base.update(over)
    return EvidenceUnit(**base)


def _finding(**over):
    base = dict(tenant_id="t-fabric", analyzer_id="deterministic.rule",
                analyzer_class=AnalyzerClass.DETERMINISTIC,
                analyzer_version="1.0.0", label="matched EDR-LNX-001",
                evidence_refs=["cev_x_0"],
                analysis_basis="test")
    base.update(over)
    return Finding(**base)


# ── INV-2 · no finding without evidence ─────────────────────────────────
def test_a_finding_cannot_exist_without_cited_evidence():
    with pytest.raises(ValidationError) as e:
        _finding(evidence_refs=[])
    assert "no verdict without evidence" in str(e.value)
    with pytest.raises(ValidationError):
        _finding(evidence_refs=[""])


# ── INV-4 · a number must mean something ────────────────────────────────
def test_a_score_must_declare_its_scale():
    with pytest.raises(ValidationError) as e:
        _finding(score=0.91)
    assert "scale" in str(e.value)
    ok = _finding(score=0.91, score_scale="probability")
    assert ok.score == 0.91


def test_features_are_always_digestible_so_a_score_can_be_re_audited():
    f = _finding(features={"rule_ids": ["EDR-LNX-001"], "n": 2})
    assert f.feature_digest == feature_digest({"rule_ids": ["EDR-LNX-001"],
                                               "n": 2})


# ── INV-1 · ML is a finding, not a verdict ──────────────────────────────
def test_an_ml_finding_requires_a_versioned_model():
    with pytest.raises(ValidationError) as e:
        _finding(analyzer_id="ml.command_line",
                 analyzer_class=AnalyzerClass.ML,
                 score=0.97, score_scale="probability")
    assert "model_id" in str(e.value)


def test_an_ml_finding_is_not_a_verdict_and_carries_no_malicious_flag():
    f = _finding(analyzer_id="ml.command_line",
                 analyzer_class=AnalyzerClass.ML,
                 model_id="nvf-cmdline", model_version="0.1.0",
                 score=0.97, score_scale="probability",
                 severity_hint=Severity.HIGH,
                 features={"tokens": 14})
    d = f.to_mongo()
    # There is no verdict/malicious/disposition field to set — by design.
    assert "verdict" not in d and "disposition" not in d
    assert d["severity_hint"] == "HIGH"      # a HINT, named as one
    assert d["score_scale"] == "probability"
    assert d["model_version"] == "0.1.0"


# ── INV-5 · content-addressed identity ──────────────────────────────────
def test_the_same_evaluation_yields_the_same_identity():
    a = _finding(features={"rule_ids": ["EDR-LNX-001"]})
    b = _finding(features={"rule_ids": ["EDR-LNX-001"]})
    c = _finding(features={"rule_ids": ["EDR-LNX-002"]})
    assert a.finding_id == b.finding_id
    assert a.finding_id != c.finding_id
    assert a.finding_id.startswith("fnd_")


def test_the_store_recognises_a_repeated_evaluation_instead_of_duplicating():
    tenant = f"t-fabric-{uuid.uuid4().hex[:8]}"
    f = _finding(tenant_id=tenant, features={"rule_ids": ["EDR-LNX-001"]})
    try:
        first = store.persist([f])
        second = store.persist([f])
        assert first["inserted"] == 1 and first["already_present"] == 0
        assert second["inserted"] == 0 and second["already_present"] == 1
        rows = store.read(tenant)
        assert len(rows) == 1 and rows[0]["finding_id"] == f.finding_id
        # tenant partitioned: another tenant sees nothing
        assert store.read(f"{tenant}-other") == []
    finally:
        from deps import sync_collection
        sync_collection(store.COLLECTION).delete_many({"tenant_id": tenant})


# ── INV-3 · three outcomes stay three facts ─────────────────────────────
def test_an_outcome_must_match_what_it_carries():
    with pytest.raises(ValidationError):
        AnalyzerResult(analyzer_id="x", outcome=Outcome.FINDINGS)
    with pytest.raises(ValidationError):
        AnalyzerResult(analyzer_id="x", outcome=Outcome.EVALUATED_NO_FINDING,
                       findings=[_finding()])
    with pytest.raises(ValidationError) as e:
        AnalyzerResult(analyzer_id="x", outcome=Outcome.NOT_EVALUATED)
    assert "reason" in str(e.value)


def test_not_evaluated_is_never_reported_as_no_finding():
    res = ANALYZER.evaluate(_unit(derivations=[]))
    assert res.outcome == Outcome.NOT_EVALUATED.value
    assert "not a statement that the activity was benign" in res.reason

    res = ANALYZER.evaluate(_unit(derivations=[
        {"outcome": "DETECTION_NOT_EVALUATED",
         "reason": "no detection content version was deployed"}]))
    assert res.outcome == Outcome.NOT_EVALUATED.value
    assert res.reason == "no detection content version was deployed"

    res = ANALYZER.evaluate(_unit(derivations=[
        {"outcome": "DETECTION_EVALUATED_NO_MATCH"}]))
    assert res.outcome == Outcome.EVALUATED_NO_FINDING.value
    assert res.findings == []


# ── the deterministic producer projects, it does not invent ─────────────
def test_the_deterministic_analyzer_projects_the_recorded_detection():
    res = ANALYZER.evaluate(_unit(derivations=[
        {"outcome": "CANONICAL_EVIDENCE_CREATED",
         "event_id": "cev_x_0"},
        {"outcome": "DETECTION_MATCHED",
         "event_id": "cev_x_0",
         "reason": "rules: EDR-LNX-001",
         "detection_content_version":
             "nivxray::detection_content::nivxray_native_sigma",
         "verdict_version": "LIKELY_BENIGN",
         "derived_at": "2026-06-01T10:00:05+00:00"}]))
    assert res.outcome == Outcome.FINDINGS.value
    f = res.findings[0]
    assert f.evidence_refs == ["cev_x_0"]
    assert f.features["rule_ids"] == ["EDR-LNX-001"]
    assert f.analyzer_version == (
        "nivxray::detection_content::nivxray_native_sigma")
    # the ingest label is a hint, and it is NOT promoted to a verdict
    assert f.severity_hint == Severity.LOW.value
    assert f.features["ingest_verdict_label"] == "LIKELY_BENIGN"
    # analysis time and activity time stay separate facts
    assert f.evaluation_time == "2026-06-01T10:00:05+00:00"
    assert f.observed_at == "2026-06-01T10:00:00+00:00"
    assert "does not invent a rule" in f.analysis_basis


def test_a_matched_rule_with_no_rule_id_is_named_not_invented():
    res = ANALYZER.evaluate(_unit(derivations=[
        {"outcome": "DETECTION_MATCHED", "event_id": "cev_x_0",
         "reason": None, "detection_content_version": "v1"}]))
    assert "unnamed rule" in res.findings[0].label
    assert res.findings[0].features["rule_ids"] == []


# ── the registry is a contract ──────────────────────────────────────────
def test_every_registered_analyzer_declares_itself():
    assert registry.analyzers(), "the fabric has no producer"
    for a in registry.analyzers():
        assert a.id and a.version
        assert isinstance(a.analyzer_class, AnalyzerClass)
        assert isinstance(a.inference_location, InferenceLocation)
        cap = a.capability()
        assert cap.evaluates, f"{a.id} claims no capability"
        assert cap.cannot, (f"{a.id} declares no blind spot — the fabric may "
                            f"not imply total coverage")


def test_an_undeclared_analyzer_cannot_be_registered():
    class Nameless:
        id = ""
        analyzer_class = AnalyzerClass.ML
        version = "0"
        inference_location = InferenceLocation.BACKEND

    with pytest.raises(ValueError):
        registry.register(Nameless())


def test_the_fabric_states_what_it_cannot_do_today():
    caps = registry.declared_capabilities()
    assert len(caps) == 1, ("the fabric has exactly one analyzer today; if "
                            "that changed, this gate's evidence must change "
                            "with it")
    only = caps[0]
    assert only["analyzer_id"] == "deterministic.rule"
    assert only["analyzer_class"] == "DETERMINISTIC"
    blind = " ".join(only["cannot"]).lower()
    for absent in ("reputation", "static", "machine-learned", "behavioural",
                   "anomaly"):
        assert absent in blind
    # and no ML analyzer is pretending to exist
    assert not [c for c in caps if c["analyzer_class"] == "ML"]


def test_the_fabric_never_writes_to_the_evidence_stores():
    """Structural: the fabric package may not ACCESS the raw or canonical
    evidence collections. Prose may name them (the deterministic analyzer
    documents where its input comes from); code may not open them."""
    import io
    import pathlib
    import tokenize
    root = pathlib.Path(fabric.__file__).parent
    for py in root.rglob("*.py"):
        code = []
        with io.open(py, "rb") as fh:
            for tok in tokenize.tokenize(fh.readline):
                if tok.type == tokenize.STRING or tok.type == tokenize.COMMENT:
                    # a string LITERAL naming a collection is an access
                    if tok.type == tokenize.STRING and tok.line.strip().startswith(
                            ('"""', "'''")):
                        continue        # docstring: prose, not access
                code.append(tok.string)
        text = " ".join(code)
        for forbidden in ("edr_raw_events", "xdr_canonical_evidence",
                          "v2_shadow_observations"):
            assert forbidden not in text, (
                f"{py.name} accesses {forbidden} — the fabric must not "
                f"write to or re-read the evidence stores directly")
