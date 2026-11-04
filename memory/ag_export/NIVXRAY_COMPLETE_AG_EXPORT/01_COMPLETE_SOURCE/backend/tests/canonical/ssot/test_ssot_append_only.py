"""T2.3 · Append-only invariant."""
import pytest
from canonical.ssot import (
    AuthoritativeSSOT, Provenance, GraphNode, Artifact,
    ReasoningStep,
)


PROV = Provenance(engine="test", version="1.0.0", at="phase2")


def test_append_grows_bucket_monotonically():
    s = AuthoritativeSSOT()
    for i in range(5):
        s.append("evidence_graph.nodes",
                 GraphNode(id=f"n{i}", kind="input", label=str(i)), PROV)
        assert len(s.evidence_graph.nodes) == i + 1


def test_freeze_locks_future_appends():
    s = AuthoritativeSSOT()
    s.append("evidence_graph.nodes",
             GraphNode(id="n1", kind="input", label="x"), PROV)
    s.freeze()
    assert s.is_frozen()
    with pytest.raises(ValueError, match="frozen"):
        s.append("evidence_graph.nodes",
                 GraphNode(id="n2", kind="input", label="y"), PROV)


def test_existing_entry_can_carry_stamped_provenance_only_once():
    """Appending the same entry object twice would create a duplicate
    reference — allowed if the caller genuinely means it, but the
    provenance stays on the entry, not on the list slot. This test
    documents the semantics."""
    s = AuthoritativeSSOT()
    entry = ReasoningStep(id="r1", rule="deterministic", rationale="test",
                          provenance=PROV)
    s.append("reasoning_steps", entry)
    s.append("reasoning_steps", entry)  # allowed (same-object twice)
    assert len(s.reasoning_steps) == 2
    assert s.reasoning_steps[0] is s.reasoning_steps[1]


def test_freeze_is_idempotent():
    s = AuthoritativeSSOT()
    s.freeze()
    s.freeze()  # second call is a no-op
    assert s.is_frozen()


def test_frozen_flag_is_not_serialised():
    s = AuthoritativeSSOT()
    s.freeze()
    d = s.to_dict()
    assert "_frozen" not in d


def test_fingerprint_unchanged_by_freeze_state():
    """freeze() must not affect the fingerprint — otherwise storing a
    frozen SSOT would change its content hash."""
    s = AuthoritativeSSOT()
    s.append("evidence_graph.nodes",
             GraphNode(id="n1", kind="input", label="x"), PROV)
    fp_before = s.fingerprint()
    s.freeze()
    fp_after = s.fingerprint()
    assert fp_before == fp_after
