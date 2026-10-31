"""T1.3 · Contract test against ADR-005 §3.2.

The composer's IUEDecision must expose every field ADR-005 §3.2 requires.
"""
from canonical.iue import (
    Capability,
    ConfidenceMatrix,
    DispatchPolicy,
    IUEDecision,
    InputProfile,
    Provenance,
    classify,
)
from canonical.iue.models import InputHealthResult, Intent, IUEEvidence, PlanStep


REQUIRED_TOP_LEVEL = {
    "input_health", "input_profile", "intent", "capabilities", "plan",
    "confidence_matrix", "dispatch_policy", "provenance", "next_engine_hint",
    "evidence", "determinism_hash",
}


REQUIRED_MATRIX_AXES = {
    "input_classification", "decode_path", "language_detection",
    "estimated_recovery", "artifact_completeness", "telemetry_richness",
}


REQUIRED_PROFILE_FIELDS = {
    "primary_type", "embedded", "input_kind", "encoding",
    "size_bytes", "byte_signature", "filename", "mime_hint",
}


REQUIRED_PLANSTEP_FIELDS = {
    "engine", "action", "reason", "required", "expected_output_kind", "capability",
}


REQUIRED_HEALTH_FIELDS = {"ok", "blocking", "size_bytes", "control_char_ratio",
                          "encoding", "issues"}


def _all_fields(cls) -> set:
    return set(cls.__dataclass_fields__.keys())


def test_iue_decision_has_all_required_top_level_fields():
    assert REQUIRED_TOP_LEVEL.issubset(_all_fields(IUEDecision))


def test_confidence_matrix_has_six_named_axes():
    assert REQUIRED_MATRIX_AXES == _all_fields(ConfidenceMatrix)


def test_input_profile_has_all_required_fields():
    assert REQUIRED_PROFILE_FIELDS.issubset(_all_fields(InputProfile))


def test_planstep_has_all_required_fields():
    assert REQUIRED_PLANSTEP_FIELDS.issubset(_all_fields(PlanStep))


def test_input_health_has_all_required_fields():
    assert REQUIRED_HEALTH_FIELDS.issubset(_all_fields(InputHealthResult))


def test_dispatch_policy_is_declared_enum():
    values = {p.value for p in DispatchPolicy}
    assert {"strict_ordered", "parallel_where_safe", "dag"}.issubset(values)


def test_capability_enum_covers_adr_005_capabilities():
    required = {"INPUT_HEALTH", "DECODER", "ARCHIVE_EXTRACT", "ARTIFACT_SPLIT",
                "IDA_ACQUIRE", "IOC_EXTRACTOR", "COMMAND_DETECT",
                "VENDOR_NORMALISER", "SEMANTIC_AST", "DKP_MATCH", "MITRE_MAP",
                "ATTACK_CHAIN", "THREAT_INTEL_ENRICH", "RECURSIVE_DISCOVERY",
                "LOLBAS_MATCH", "QUALITY_SCORE"}
    have = {c.value for c in Capability}
    missing = required - have
    assert not missing, f"missing capabilities: {missing}"


def test_provenance_has_all_required_fields():
    assert {"engine", "version", "at", "upstream_evidence_ids"}.issubset(_all_fields(Provenance))


def test_iue_evidence_has_all_required_fields():
    assert {"id", "source", "observation", "confidence", "rationale",
            "meta", "provenance"}.issubset(_all_fields(IUEEvidence))


def test_composer_produces_declared_types_at_runtime():
    d = classify("cmd /c whoami")
    assert isinstance(d, IUEDecision)
    assert isinstance(d.input_health, InputHealthResult)
    assert isinstance(d.input_profile, InputProfile)
    assert isinstance(d.intent, Intent)
    assert all(isinstance(c, Capability) for c in d.capabilities)
    assert all(isinstance(p, PlanStep) for p in d.plan)
    assert isinstance(d.confidence_matrix, ConfidenceMatrix)
    assert isinstance(d.dispatch_policy, DispatchPolicy)
    assert isinstance(d.provenance, Provenance)
    assert all(isinstance(e, IUEEvidence) for e in d.evidence)
