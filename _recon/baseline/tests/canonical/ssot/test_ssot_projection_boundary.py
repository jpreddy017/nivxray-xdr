"""T2.6 · Projection tier boundary — projections empty; authoritative populated."""
import pytest
from canonical.ssot import (
    AuthoritativeSSOT, Provenance, GraphNode, ReasoningStep, Artifact,
    ExecutionStep, HistoricalItem,
)


PROV = Provenance(engine="test", version="1.0.0", at="phase2")


def _populate_authoritative(s: AuthoritativeSSOT) -> None:
    s.append("evidence_graph.nodes",
             GraphNode(id="n1", kind="input", label="root"), PROV)
    s.append("evidence_graph.nodes",
             GraphNode(id="n2", kind="artifact", label="child"), PROV)
    s.append("reasoning_steps",
             ReasoningStep(id="r1", rule="deterministic", rationale="test"), PROV)
    s.append("artifacts",
             Artifact(id="a1", kind="blob", label="artefact-1"), PROV)
    s.append("execution_trace",
             ExecutionStep(step_id="s1", capability="DECODER",
                           engine="test", status="executed"), PROV)
    s.append("context.historical",
             HistoricalItem(kind="prior_case", ref="c-001"), PROV)


def test_authoritative_populated_projections_empty_passes_guard():
    s = AuthoritativeSSOT()
    _populate_authoritative(s)
    # Authoritative populated:
    assert len(s.evidence_graph.nodes) == 2
    assert len(s.evidence_graph.edges) == 0
    assert len(s.reasoning_steps) == 1
    assert len(s.artifacts) == 1
    assert len(s.execution_trace) == 1
    assert len(s.context.historical) == 1
    # Projections empty:
    s.assert_projections_empty()  # must not raise


def test_projection_bucket_violation_is_detected():
    s = AuthoritativeSSOT()
    # Directly poke into a projection bucket to simulate a violation.
    s.iocs.urls.append("https://example.com")
    with pytest.raises(AssertionError, match="projection buckets non-empty"):
        s.assert_projections_empty()


@pytest.mark.parametrize("projection_bucket,mutation", [
    ("activity", lambda s: s.activity.processes.append({"pid": 1})),
    ("iocs", lambda s: s.iocs.ips.append("1.2.3.4")),
    ("attck", lambda s: s.attck.techniques.append({"id": "T1059"})),
    ("attack_chain", lambda s: s.attack_chain.append({"stage": "exec"})),
    ("recommendations", lambda s: s.recommendations.append({"text": "x"})),
    ("timeline", lambda s: s.timeline.append({"ts": "2026-01-01"})),
])
def test_every_projection_bucket_is_guarded(projection_bucket, mutation):
    s = AuthoritativeSSOT()
    mutation(s)
    with pytest.raises(AssertionError):
        s.assert_projections_empty()


def test_fingerprint_stable_when_projections_stay_empty():
    """Projection-tier definitions must not accidentally change the
    fingerprint from replay to replay when they remain empty."""
    a = AuthoritativeSSOT(id="fx", created_at="t", updated_at="t")
    b = AuthoritativeSSOT(id="fx", created_at="t", updated_at="t")
    _populate_authoritative(a)
    _populate_authoritative(b)
    assert a.fingerprint() == b.fingerprint()
