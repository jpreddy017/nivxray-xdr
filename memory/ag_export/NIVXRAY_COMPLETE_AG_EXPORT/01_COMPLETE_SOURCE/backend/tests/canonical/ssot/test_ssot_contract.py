"""T2.1 · Contract vs ADR-005 §4.1 minimum information."""
from dataclasses import fields
from canonical.ssot import (
    AuthoritativeSSOT, SCHEMA_VERSION,
    ActivityProjection, IOCProjection, ThreatIntelProjection,
    AttckProjection, VerdictProjection, ReportsProjection,
    Provenance, Source,
)
from canonical.ssot.models import (
    EvidenceGraph, GraphNode, GraphEdge, ReasoningStep, Artifact,
    ExecutionStep, ContextBucket, HistoricalItem,
)


REQUIRED_AUTHORITATIVE = {
    "id", "schema_version", "created_at", "updated_at", "source",
    "input_raw", "input_profile", "input_health", "iue_decision",
    "plan", "execution_trace", "artifacts",
    "evidence_graph", "reasoning_steps",
    "context", "provenance", "metadata",
}


REQUIRED_PROJECTIONS = {
    "activity", "iocs", "threat_intel", "attck",
    "attack_chain", "attack_story", "verdict", "recommendations",
    "analyst_summary", "executive_summary", "reports", "timeline",
}


def _field_names(cls):
    return {f.name for f in fields(cls) if not f.name.startswith("_")}


def test_authoritative_ssot_has_all_required_top_level_fields():
    have = _field_names(AuthoritativeSSOT)
    missing_auth = REQUIRED_AUTHORITATIVE - have
    missing_proj = REQUIRED_PROJECTIONS - have
    assert not missing_auth, f"missing authoritative fields: {missing_auth}"
    assert not missing_proj, f"missing projection fields: {missing_proj}"


def test_schema_version_is_declared():
    assert SCHEMA_VERSION.startswith("2.")
    s = AuthoritativeSSOT()
    assert s.schema_version == SCHEMA_VERSION


def test_evidence_graph_contract():
    assert _field_names(GraphNode) == {"id", "kind", "label", "attrs", "provenance"}
    assert _field_names(GraphEdge) == {"id", "from_node_id", "to_node_id", "kind", "attrs", "provenance"}
    assert _field_names(EvidenceGraph) == {"nodes", "edges"}


def test_reasoning_step_contract():
    assert _field_names(ReasoningStep) == {"id", "rule", "rationale",
                                            "input_evidence_ids",
                                            "output_evidence_ids",
                                            "provenance"}


def test_artifact_contract_supports_recursion():
    fs = _field_names(Artifact)
    assert "investigation_ref" in fs, "Artifact must carry investigation_ref (D6-r)"
    assert "parent_evidence_id" in fs


def test_execution_step_contract():
    assert {"step_id", "capability", "engine", "status",
            "started_at", "finished_at",
            "output_evidence_ids", "notes",
            "provenance"} == _field_names(ExecutionStep)


def test_provenance_envelope_contract():
    assert _field_names(Provenance) == {"engine", "version", "at", "upstream_evidence_ids"}


def test_source_contract():
    assert _field_names(Source) == {"surface", "endpoint", "correlation_id",
                                     "session_id", "channel"}


def test_context_bucket_has_historical():
    assert "historical" in _field_names(ContextBucket)


def test_projection_scaffolds_are_declared():
    # Presence check — Phase 4 will populate; Phase 2 just requires shape.
    for proj_cls in (ActivityProjection, IOCProjection, ThreatIntelProjection,
                     AttckProjection, VerdictProjection, ReportsProjection):
        assert len(fields(proj_cls)) >= 1
