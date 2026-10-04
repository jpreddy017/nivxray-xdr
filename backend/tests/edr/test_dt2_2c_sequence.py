"""DT2-2C · focused tests for the temporal/causal sequence primitive.

Hermetic: pure Python, no Mongo, no network, no environment.
"""
from __future__ import annotations

import json

import pytest

from edr_plane.trajectory import models as m
from edr_plane.trajectory import relationships as r
from edr_plane.trajectory import sequence as s

EP = "ep_test"
T = "2026-06-01T01:00:0"


def _row(iid, ts, **kw):
    row = {"event_iid": iid, "timestamp": ts,
           "provenance": {"raw_event_id": f"raw-{iid}",
                          "canonical_event_id": f"can-{iid}"}}
    prov = kw.pop("provenance", {})
    row["provenance"].update(prov)
    row.update(kw)
    return row


def _spawn(iid, ts, parent, child, *, guid=True):
    prov = {"parent_process_guid": f"{{p-{parent}}}",
            "process_guid": f"{{c-{child}}}"} if guid else {}
    return _row(iid, ts, event_type="process_create",
                process_iid=child, parent_process_iid=parent,
                image=f"{child}.exe", parent_image=f"{parent}.exe",
                pid=100, ppid=10, provenance=prov)


def _act(iid, ts, actor, kind, **kw):
    return _row(iid, ts, event_type=kind, process_iid=actor,
                image=f"{actor}.exe", pid=100,
                provenance={"process_guid": f"{{c-{actor}}}"}, **kw)


# The DT2-2C target shape, built ONLY from evidence-backed rows.
ROWS = [
    _spawn("s1", T + "0.000+00:00", "winword", "powershell"),
    _act("a1", T + "1.000+00:00", "powershell", "dns_query",
         entity="evil.example.test"),
    _act("a2", T + "2.000+00:00", "powershell", "network_connect",
         network="203.0.113.10:443"),
    _act("a3", T + "3.000+00:00", "powershell", "file_create",
         file="C:/tmp/payload.dll"),
    _spawn("s2", T + "4.000+00:00", "powershell", "rundll32"),
]


def _build(rows=None, **kw):
    rows = ROWS if rows is None else rows
    return s.temporal_sequences(r.process_edges(rows, EP),
                                r.activity_edges(rows, EP), EP, **kw)


# ══════════════════════════════════════════════════════════════════════
# POSITIVE
# ══════════════════════════════════════════════════════════════════════

def test_c01_the_connected_lineage_forms_one_ordered_sequence():
    seqs = _build()
    assert len(seqs) == 1
    seq = seqs[0]
    assert len(seq.steps) == 5
    assert [st.times.source_time for st in seq.steps] == \
        sorted(st.times.source_time for st in seq.steps)
    assert seq.root_process_iid == "winword"
    assert seq.ordering_basis == s.SEQUENCE_ORDERING_BASIS


def test_c02_a_step_only_ever_references_an_existing_edge():
    for st in _build()[0].steps:
        assert isinstance(st.edge, (r.ProcessEdge, r.ActivityEdge))
        assert st.edge.evidence_ref
        assert st.edge.derivation_basis in m.ACCEPTED_BASES


def test_c03_a_step_cannot_reference_anything_but_a_proven_edge():
    for fake in ({"parent": "winword", "child": "powershell"},
                 "winword->powershell", None, 42):
        with pytest.raises(ValueError, match="EXISTING ProcessEdge"):
            s.SequenceStep(step_id="x", edge=fake, times=s.StepTimes())


def test_c04_spawn_into_the_child_actor_is_causal_evidence():
    seq = _build()
    dns = seq[0].steps[1]
    assert dns.link_to_previous == s.CAUSAL_EVIDENCE
    assert dns.link_basis == m.BASIS_PARENT_GUID
    assert dns.link_evidence_ref
    assert dns.previous_step_id == seq[0].steps[0].step_id
    assert "lineage" in dns.link_reason


def test_c05_same_actor_activity_is_ordered_observation_not_causal():
    steps = _build()[0].steps
    for st in steps[2:]:
        assert st.link_to_previous == s.ORDERED_OBSERVATION
        assert st.link_basis is None
        assert st.link_evidence_ref == ()
        assert "nothing shows one caused the other" in st.link_reason


def test_c06_the_first_step_never_claims_causality():
    first = _build()[0].steps[0]
    assert first.link_to_previous == s.CAUSALITY_UNKNOWN
    assert first.previous_step_id is None
    assert "no preceding relationship" in first.link_reason


def test_c07_the_four_times_are_preserved_separately():
    seqs = _build(times={"a1": {"ingest_time": T + "1.500+00:00",
                                "canonicalized_time": T + "1.900+00:00",
                                "detection_time": T + "9.000+00:00"}})
    t = seqs[0].steps[1].times
    assert t.source_time == T + "1.000+00:00"
    assert t.ingest_time == T + "1.500+00:00"
    assert t.canonicalized_time == T + "1.900+00:00"
    assert t.detection_time == T + "9.000+00:00"
    assert len({t.source_time, t.ingest_time, t.canonicalized_time,
                t.detection_time}) == 4
    assert t.ordering_basis == s.TIME_SOURCE
    assert t.ordering_time == t.source_time


def test_c08_missing_times_are_never_backfilled_from_each_other():
    t = s.StepTimes(ingest_time=T + "1.500+00:00")
    assert t.source_time is None
    assert t.ordering_time is None
    assert t.ordering_basis == s.ORDERING_TIME_ABSENT
    assert t.orderable is False


def test_c09_ordering_uses_source_time_only_not_ingest_time():
    """Ingest order is deliberately the reverse of source order."""
    seqs = _build(times={"a1": {"ingest_time": T + "8.000+00:00"},
                         "a3": {"ingest_time": T + "1.000+00:00"}})
    order = [st.edge.edge_id for st in seqs[0].steps]
    assert order.index("aedge:powershell:act:dns:evil.example.test") \
        < order.index("aedge:powershell:act:file:C:/tmp/payload.dll")


def test_c10_identity_downgrade_state_is_carried_through():
    rows = [_spawn("d1", T + "0.000+00:00", "winword", "powershell",
                   guid=False),
            _act("d2", T + "1.000+00:00", "powershell", "dns_query",
                 entity="x.example.test")]
    rows[1]["provenance"].pop("process_guid")
    seq = _build(rows)[0]
    assert seq.steps[0].downgraded is True
    assert seq.steps[0].identity_authority == m.AUTHORITY_DERIVED
    assert seq.steps[0].edge.derivation_basis == m.BASIS_PARENT_IDENTITY
    assert seq.steps[1].downgraded is True
    assert seq.steps[1].link_to_previous == s.CAUSAL_EVIDENCE
    assert seq.steps[1].link_basis == m.BASIS_PARENT_IDENTITY


def test_c11_every_step_answers_why_and_keeps_its_provenance():
    for st in _build()[0].steps:
        assert st.link_reason
        assert st.evidence_ref
        assert st.edge.reason
        assert st.edge.provenance
        assert st.actor_process_iid
        assert st.edge_kind in (s.EDGE_PROCESS, s.EDGE_ACTIVITY)


def test_c12_the_summary_counts_claims_without_inventing_any():
    seq = _build()[0]
    assert seq.causality_summary == {s.CAUSAL_EVIDENCE: 1,
                                     s.ORDERED_OBSERVATION: 3,
                                     s.CAUSALITY_UNKNOWN: 0}
    assert seq.has_causal_evidence is True


def test_c13_the_sequence_serializes_for_transport():
    d = _build()[0].to_dict()
    assert d["step_count"] == 5
    assert d["steps"][1]["link_to_previous"] == s.CAUSAL_EVIDENCE
    assert d["steps"][1]["times"]["ordering_basis"] == s.TIME_SOURCE
    assert d["steps"][0]["edge"]["evidence_ref"]
    json.dumps(d)


def test_c14_a_lone_activity_edge_is_a_valid_one_step_sequence():
    rows = [_act("l1", T + "1.000+00:00", "powershell", "dns_query",
                 entity="only.example.test")]
    seqs = _build(rows)
    assert len(seqs) == 1 and len(seqs[0].steps) == 1
    assert seqs[0].causality_summary[s.CAUSAL_EVIDENCE] == 0


def test_c15_sequences_are_endpoint_scoped():
    other = s.temporal_sequences(r.process_edges(ROWS, "ep_a"),
                                 r.activity_edges(ROWS, "ep_a"), EP)
    assert other == []


# ══════════════════════════════════════════════════════════════════════
# NEGATIVE — nothing may become causal by accident
# ══════════════════════════════════════════════════════════════════════

def test_c16_unrelated_events_milliseconds_apart_stay_separate():
    """The core anti-proximity proof for DT2-2C."""
    rows = [_act("u1", T + "0.000+00:00", "alpha", "dns_query",
                 entity="a.example.test"),
            _act("u2", T + "0.001+00:00", "beta", "network_connect",
                 network="203.0.113.9:443")]
    seqs = _build(rows)
    assert len(seqs) == 2
    for seq in seqs:
        assert len(seq.steps) == 1
        assert seq.has_causal_evidence is False


def test_c17_proximity_never_promotes_a_link_inside_a_sequence():
    """Two lineage branches that share a root but not an actor."""
    rows = [_spawn("b0", T + "0.000+00:00", "root", "alpha"),
            _spawn("b1", T + "0.001+00:00", "root", "beta"),
            _act("b2", T + "0.002+00:00", "beta", "dns_query",
                 entity="b.example.test")]
    steps = _build(rows)[0].steps
    by_edge = {st.edge.edge_id: st for st in steps}
    beta_spawn = by_edge["pedge:root:beta"]
    assert beta_spawn.link_to_previous == s.ORDERED_OBSERVATION
    dns = by_edge["aedge:beta:act:dns:b.example.test"]
    assert dns.link_to_previous == s.CAUSAL_EVIDENCE
    assert dns.previous_step_id == beta_spawn.step_id


def test_c18_an_unorderable_step_is_never_causal():
    rows = [_spawn("n1", T + "0.000+00:00", "winword", "powershell"),
            _act("n2", None, "powershell", "dns_query",
                 entity="c.example.test")]
    steps = _build(rows)[0].steps
    assert steps[-1].times.orderable is False
    assert steps[-1].link_to_previous == s.CAUSALITY_UNKNOWN
    assert "cannot even be ordered" in steps[-1].link_reason


def test_c19_causal_evidence_cannot_be_claimed_without_a_basis():
    edge = r.process_edges(ROWS, EP)[0]
    with pytest.raises(ValueError, match="CAUSAL_EVIDENCE requires"):
        s.SequenceStep(step_id="x", edge=edge, times=s.StepTimes(),
                       link_to_previous=s.CAUSAL_EVIDENCE,
                       link_reason="because", previous_step_id="p",
                       link_evidence_ref=edge.evidence_ref)


def test_c20_causal_evidence_cannot_be_claimed_without_evidence():
    edge = r.process_edges(ROWS, EP)[0]
    with pytest.raises(ValueError, match="WHY IT EXISTS"):
        s.SequenceStep(step_id="x", edge=edge, times=s.StepTimes(),
                       link_to_previous=s.CAUSAL_EVIDENCE,
                       link_reason="because", previous_step_id="p",
                       link_basis=m.BASIS_PARENT_GUID)


def test_c21_causal_evidence_must_name_its_predecessor():
    edge = r.process_edges(ROWS, EP)[0]
    with pytest.raises(ValueError, match="descends from"):
        s.SequenceStep(step_id="x", edge=edge, times=s.StepTimes(),
                       link_to_previous=s.CAUSAL_EVIDENCE,
                       link_reason="because",
                       link_basis=m.BASIS_PARENT_GUID,
                       link_evidence_ref=edge.evidence_ref)


def test_c22_temporal_proximity_is_rejected_as_a_link_basis():
    edge = r.process_edges(ROWS, EP)[0]
    for bad in ("TEMPORAL_PROXIMITY", "TIMESTAMP_PROXIMITY",
                "DISPLAY_ADJACENCY", "SAME_USERNAME", "GUESS"):
        with pytest.raises(ValueError, match="forbidden link basis"):
            s.SequenceStep(step_id="x", edge=edge, times=s.StepTimes(),
                           link_to_previous=s.ORDERED_OBSERVATION,
                           link_reason="because", link_basis=bad)


def test_c23_an_unknown_causality_level_is_rejected():
    edge = r.process_edges(ROWS, EP)[0]
    for bad in ("MALICIOUS", "LIKELY_CAUSAL", "CAUSAL", ""):
        with pytest.raises(ValueError, match="causality level"):
            s.SequenceStep(step_id="x", edge=edge, times=s.StepTimes(),
                           link_to_previous=bad, link_reason="because")


def test_c24_a_level_without_a_reason_is_rejected():
    edge = r.process_edges(ROWS, EP)[0]
    with pytest.raises(ValueError, match="WHY"):
        s.SequenceStep(step_id="x", edge=edge, times=s.StepTimes(),
                       link_reason="")


def test_c25_an_empty_sequence_and_a_causal_first_step_are_rejected():
    edge = r.process_edges(ROWS, EP)[0]
    with pytest.raises(ValueError, match="empty sequence"):
        s.TemporalSequence(sequence_id="x", endpoint_id=EP, steps=())
    bad_first = s.SequenceStep(
        step_id="f", edge=edge, times=s.StepTimes(),
        link_to_previous=s.ORDERED_OBSERVATION, link_reason="because")
    with pytest.raises(ValueError, match="no predecessor"):
        s.TemporalSequence(sequence_id="x", endpoint_id=EP,
                           steps=(bad_first,))


def test_c26_a_sequence_never_spans_endpoints():
    step = s.SequenceStep(step_id="f", edge=r.process_edges(ROWS, "ep_a")[0],
                          times=s.StepTimes())
    with pytest.raises(ValueError, match="never spans endpoints"):
        s.TemporalSequence(sequence_id="x", endpoint_id="ep_b",
                           steps=(step,))


def test_c27_no_behavioral_or_attack_classification_is_emitted():
    d = _build()[0].to_dict()
    blob = json.dumps(d).lower()
    for banned in ("malicious", "mitre", "att&ck", "attack", "technique",
                   "severity", "score", "risk", "verdict", "threat"):
        assert banned not in blob, banned


def test_c28_unattributed_evidence_cannot_enter_a_sequence():
    orphan = _row("o1", T + "1.000+00:00", event_type="network_connect",
                  network="203.0.113.7:443")
    rows = [_spawn("s1", T + "0.000+00:00", "winword", "powershell"), orphan]
    steps = _build(rows)[0].steps
    assert len(steps) == 1
    assert steps[0].edge_kind == s.EDGE_PROCESS


def test_c29_the_dt2_2_relationship_primitives_are_unchanged():
    assert len(r.process_edges(ROWS, EP)) == 2
    assert len(r.activity_edges(ROWS, EP)) == 3
    assert r.process_edges(ROWS, EP)[0].guid_proven is True
