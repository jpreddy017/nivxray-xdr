"""DT2-2D · focused tests for the behavioral relationship primitive.

Hermetic: pure Python, no Mongo, no network, no environment.
"""
from __future__ import annotations

import json

import pytest

from edr_plane.trajectory import behavior as b
from edr_plane.trajectory import models as m
from edr_plane.trajectory import relationships as r
from edr_plane.trajectory import sequence as sq

EP = "ep_test"
T = "2026-06-01T01:00:0"


def _row(iid, ts, **kw):
    row = {"event_iid": iid, "timestamp": ts,
           "provenance": {"raw_event_id": f"raw-{iid}",
                          "canonical_event_id": f"can-{iid}"}}
    row["provenance"].update(kw.pop("provenance", {}))
    row.update(kw)
    return row


def _spawn(iid, ts, parent, child, *, guid=True):
    prov = {"parent_process_guid": f"{{p-{parent}}}",
            "process_guid": f"{{c-{child}}}"} if guid else {}
    return _row(iid, ts, event_type="process_create", process_iid=child,
                parent_process_iid=parent, image=f"{child}.exe",
                parent_image=f"{parent}.exe", pid=100, ppid=10,
                provenance=prov)


def _act(iid, ts, actor, kind, *, guid=True, **kw):
    prov = {"process_guid": f"{{c-{actor}}}"} if guid else {}
    return _row(iid, ts, event_type=kind, process_iid=actor,
                image=f"{actor}.exe", pid=100, provenance=prov, **kw)


ROWS = [
    _spawn("s1", T + "0.000+00:00", "winword", "powershell"),
    _act("a1", T + "1.000+00:00", "powershell", "dns_query",
         entity="evil.example.test"),
    _act("a2", T + "2.000+00:00", "powershell", "network_connect",
         network="203.0.113.10:443"),
    _act("a3", T + "3.000+00:00", "powershell", "file_create",
         file="C:/tmp/payload.dll"),
    _act("a4", T + "3.500+00:00", "powershell", "registry_value_set",
         entity="HKLM/Software/Run/X"),
    _spawn("s2", T + "4.000+00:00", "powershell", "rundll32"),
]


def _seqs(rows=None):
    rows = ROWS if rows is None else rows
    return sq.temporal_sequences(r.process_edges(rows, EP),
                                 r.activity_edges(rows, EP), EP)


def _build(rows=None):
    return b.behaviors(_seqs(rows))


def _by_type(rows=None):
    out = {}
    for beh in _build(rows):
        out.setdefault(beh.behavior_type, []).append(beh)
    return out


# ══════════════════════════════════════════════════════════════════════
# POSITIVE
# ══════════════════════════════════════════════════════════════════════

def test_d01_the_five_initial_behavior_types_are_the_only_ones():
    assert b.BEHAVIOR_TYPES == (
        "PROCESS_CHAIN", "EXECUTION_TO_DNS", "EXECUTION_TO_NETWORK",
        "EXECUTION_TO_FILE", "EXECUTION_TO_REGISTRY")
    assert b.TRUTH_LEVELS == ("OBSERVED", "DERIVED", "CORRELATED",
                              "INFERRED")


def test_d02_the_proven_graph_produces_all_five_behaviors():
    kinds = _by_type()
    assert set(kinds) == set(b.BEHAVIOR_TYPES)
    assert len(kinds["PROCESS_CHAIN"]) == 1
    for t in ("EXECUTION_TO_DNS", "EXECUTION_TO_NETWORK",
              "EXECUTION_TO_FILE", "EXECUTION_TO_REGISTRY"):
        assert len(kinds[t]) == 1


def test_d03_a_direct_evidence_backed_activity_is_observed():
    dns = _by_type()["EXECUTION_TO_DNS"][0]
    assert dns.truth_level == b.TRUTH_OBSERVED
    assert dns.asserts_direct_observation is True
    assert dns.downgraded is False
    assert dns.identity_authority == m.AUTHORITY_AUTHORITATIVE
    assert dns.process_iids == ("powershell",)
    assert dns.derivation_bases == (m.BASIS_ACTOR_BINDING,)
    assert "directly evidence-backed" in dns.reason


def test_d04_a_proven_lineage_chain_is_derived():
    chain = _by_type()["PROCESS_CHAIN"][0]
    assert chain.truth_level == b.TRUTH_DERIVED
    assert chain.process_iids == ("winword", "powershell", "rundll32")
    assert chain.link_levels == (sq.CAUSAL_EVIDENCE,)
    assert chain.asserts_direct_observation is False
    assert chain.evidence_backed is True
    assert "proven lineage" in chain.reason


def test_d05_a_behavior_only_ever_references_existing_step_ids():
    seq = _seqs()[0]
    known = {s.step_id for s in seq.steps}
    for beh in b.behaviors_of(seq):
        assert beh.step_ids
        assert set(beh.step_ids) <= known


def test_d06_evidence_is_reused_from_the_steps_never_manufactured():
    seq = _seqs()[0]
    step_refs = {(x.kind, x.id) for s in seq.steps
                 for x in s.evidence_ref}
    for beh in b.behaviors_of(seq):
        assert beh.evidence_ref
        assert {(x.kind, x.id) for x in beh.evidence_ref} <= step_refs


def test_d07_every_required_field_is_preserved():
    for beh in _build():
        assert beh.behavior_id and beh.endpoint_id == EP
        assert beh.behavior_type in b.BEHAVIOR_TYPES
        assert beh.truth_level in b.TRUTH_LEVELS
        assert beh.process_iids and beh.step_ids and beh.evidence_ref
        assert beh.reason and beh.provenance
        assert beh.start_time and beh.end_time
        assert beh.time_basis == sq.TIME_SOURCE
        assert beh.identity_authority in m.AUTHORITIES
        assert isinstance(beh.downgraded, bool)
        assert beh.sequence_id == _seqs()[0].sequence_id


def test_d08_the_time_span_comes_from_the_steps_source_times():
    chain = _by_type()["PROCESS_CHAIN"][0]
    assert chain.start_time == T + "0.000+00:00"
    assert chain.end_time == T + "4.000+00:00"
    dns = _by_type()["EXECUTION_TO_DNS"][0]
    assert dns.start_time == dns.end_time == T + "1.000+00:00"


def test_d09_a_pid_surrogate_activity_actor_is_correlated_not_observed():
    rows = [_act("p1", T + "1.000+00:00", "pid:actor", "network_connect",
                 guid=False, network="198.51.100.5:80")]
    beh = _build(rows)[0]
    assert beh.truth_level == b.TRUTH_CORRELATED
    assert beh.asserts_direct_observation is False
    assert beh.evidence_backed is False
    assert beh.downgraded is True
    assert beh.identity_authority == m.AUTHORITY_DERIVED
    assert "not" in beh.reason and "direct observation" in beh.reason
    assert "says nothing about intent" in beh.reason


def test_d10_a_chain_with_a_surrogate_hop_is_correlated_not_derived():
    rows = [_spawn("c1", T + "0.000+00:00", "winword", "powershell"),
            _spawn("c2", T + "1.000+00:00", "powershell", "rundll32",
                   guid=False)]
    chain = _by_type(rows)["PROCESS_CHAIN"][0]
    assert chain.truth_level == b.TRUTH_CORRELATED
    assert chain.downgraded is True
    assert chain.asserts_direct_observation is False
    assert chain.identity_authority == m.AUTHORITY_DERIVED
    assert m.BASIS_PARENT_IDENTITY in chain.derivation_bases


def test_d11_the_underlying_causal_ordering_status_is_preserved():
    beh = _by_type()["EXECUTION_TO_NETWORK"][0]
    assert beh.provenance["step_link_to_previous"] in sq.CAUSALITY_LEVELS
    chain = _by_type()["PROCESS_CHAIN"][0]
    assert chain.provenance["step_link_levels"] == [
        sq.CAUSALITY_UNKNOWN, sq.ORDERED_OBSERVATION]
    assert chain.link_levels == (sq.CAUSAL_EVIDENCE,)


def test_d12_derived_intelligence_never_overwrites_the_evidence():
    seq = _seqs()[0]
    before = [s.to_dict() for s in seq.steps]
    b.behaviors_of(seq)
    assert [s.to_dict() for s in seq.steps] == before
    assert r.process_edges(ROWS, EP)[0].guid_proven is True


def test_d13_behaviors_serialize_with_their_truth_level_attached():
    d = _by_type()["EXECUTION_TO_FILE"][0].to_dict()
    assert d["truth_level"] == b.TRUTH_OBSERVED
    assert d["asserts_direct_observation"] is True
    assert d["step_ids"] and d["evidence_ref"]
    json.dumps(d)


def test_d14_a_four_deep_lineage_yields_one_maximal_chain():
    rows = [_spawn("x1", T + "0.000+00:00", "a", "bb"),
            _spawn("x2", T + "1.000+00:00", "bb", "cc"),
            _spawn("x3", T + "2.000+00:00", "cc", "dd")]
    chains = _by_type(rows)["PROCESS_CHAIN"]
    assert len(chains) == 1
    assert chains[0].process_iids == ("a", "bb", "cc", "dd")
    assert chains[0].link_levels == (sq.CAUSAL_EVIDENCE,) * 2
    assert chains[0].truth_level == b.TRUTH_DERIVED


def test_d15_behaviors_are_endpoint_scoped():
    for beh in _build():
        assert beh.endpoint_id == EP
        assert beh.behavior_id.startswith(f"beh:{EP}:")


# ══════════════════════════════════════════════════════════════════════
# NEGATIVE
# ══════════════════════════════════════════════════════════════════════

def test_d16_temporal_proximity_alone_creates_no_behavior():
    """Two unrelated actors 1 ms apart: two separate OBSERVED activities,
    no chain, no fused behavior."""
    rows = [_act("u1", T + "0.000+00:00", "alpha", "dns_query",
                 entity="a.example.test"),
            _act("u2", T + "0.001+00:00", "beta", "network_connect",
                 network="203.0.113.9:443")]
    out = _build(rows)
    assert len(out) == 2
    assert all(len(x.step_ids) == 1 for x in out)
    assert all(x.behavior_type != "PROCESS_CHAIN" for x in out)
    assert {x.process_iids for x in out} == {("alpha",), ("beta",)}


def test_d17_a_lone_spawn_is_not_a_process_chain():
    rows = [_spawn("o1", T + "0.000+00:00", "winword", "powershell")]
    assert _build(rows) == []


def test_d18_unattributed_evidence_never_becomes_behavior():
    orphan = _row("n1", T + "1.000+00:00", event_type="network_connect",
                  network="203.0.113.7:443")
    bare = _row("n2", T + "2.000+00:00", event_type="file_create",
                file="C:/tmp/y", process_iid="pid:only", pid=7)
    assert _build([orphan, bare]) == []


def test_d19_an_unsupported_activity_family_never_becomes_behavior():
    rows = [_act("w1", T + "1.000+00:00", "powershell", "wmi_event_filter",
                 entity="x"),
            _act("w2", T + "2.000+00:00", "powershell", "4648",
                 entity="CORP/admin")]
    assert _build(rows) == []


def test_d20_no_behavior_type_outside_the_allow_list_can_be_built():
    for bad in ("PERSISTENCE", "BEACONING", "CREDENTIAL_ACCESS",
                "LATERAL_MOVEMENT", "MALICIOUS_CHAIN", "SUSPICIOUS", ""):
        with pytest.raises(ValueError, match="unsupported behavior_type"):
            b.BehavioralRelationship(
                behavior_id="x", endpoint_id=EP, behavior_type=bad,
                truth_level=b.TRUTH_OBSERVED, process_iids=("p",),
                step_ids=("s",),
                evidence_ref=(m.EvidenceReference(kind="RAW_EVENT", id="r"),),
                reason="because",
                identity_authority=m.AUTHORITY_AUTHORITATIVE,
                downgraded=False)


def _kwargs(**kw):
    base = dict(behavior_id="x", endpoint_id=EP,
                behavior_type=b.BEHAVIOR_EXECUTION_TO_DNS,
                truth_level=b.TRUTH_OBSERVED, process_iids=("p",),
                step_ids=("s",),
                evidence_ref=(m.EvidenceReference(kind="RAW_EVENT", id="r"),),
                reason="because",
                identity_authority=m.AUTHORITY_AUTHORITATIVE,
                downgraded=False)
    base.update(kw)
    return base


def test_d21_a_behavior_without_steps_evidence_or_why_is_rejected():
    with pytest.raises(ValueError, match="existing sequence step ids"):
        b.BehavioralRelationship(**_kwargs(step_ids=()))
    with pytest.raises(ValueError, match="WHY IT EXISTS"):
        b.BehavioralRelationship(**_kwargs(evidence_ref=()))
    with pytest.raises(ValueError, match="stated WHY"):
        b.BehavioralRelationship(**_kwargs(reason=""))
    with pytest.raises(ValueError, match="participating process"):
        b.BehavioralRelationship(**_kwargs(process_iids=()))


def test_d22_observed_cannot_be_claimed_across_steps_or_when_downgraded():
    with pytest.raises(ValueError, match="OBSERVED may only describe ONE"):
        b.BehavioralRelationship(**_kwargs(
            step_ids=("s1", "s2"), link_levels=(sq.CAUSAL_EVIDENCE,)))
    with pytest.raises(ValueError, match="cannot be presented as OBSERVED"):
        b.BehavioralRelationship(**_kwargs(
            downgraded=True, identity_authority=m.AUTHORITY_DERIVED))


def test_d23_derived_requires_proven_causality_on_every_join():
    for level in (sq.ORDERED_OBSERVATION, sq.CAUSALITY_UNKNOWN):
        with pytest.raises(ValueError, match="every join to be CAUSAL"):
            b.BehavioralRelationship(**_kwargs(
                truth_level=b.TRUTH_DERIVED, step_ids=("s1", "s2"),
                link_levels=(level,)))
    with pytest.raises(ValueError, match="at least two steps"):
        b.BehavioralRelationship(**_kwargs(truth_level=b.TRUTH_DERIVED))


def test_d24_correlated_must_state_what_weakens_it():
    with pytest.raises(ValueError, match="CORRELATED must state"):
        b.BehavioralRelationship(**_kwargs(
            truth_level=b.TRUTH_CORRELATED, step_ids=("s1", "s2"),
            link_levels=(sq.CAUSAL_EVIDENCE,)))


def test_d25_inferred_is_defined_but_has_no_producer_yet():
    with pytest.raises(ValueError, match="named inference producer"):
        b.BehavioralRelationship(**_kwargs(truth_level=b.TRUTH_INFERRED))
    assert all(x.truth_level != b.TRUTH_INFERRED for x in _build())


def test_d26_correlated_and_inferred_are_never_serialized_as_observed():
    rows = [_act("p1", T + "1.000+00:00", "pid:actor", "dns_query",
                 guid=False, entity="c.example.test")]
    d = _build(rows)[0].to_dict()
    assert d["truth_level"] == b.TRUTH_CORRELATED
    assert d["asserts_direct_observation"] is False
    assert d["evidence_backed"] is False
    assert b.TRUTH_OBSERVED not in json.dumps(d)


def test_d27_temporal_proximity_is_rejected_as_a_derivation_basis():
    for bad in ("TEMPORAL_PROXIMITY", "DISPLAY_ADJACENCY", "GUESS"):
        with pytest.raises(ValueError, match="forbidden derivation basis"):
            b.BehavioralRelationship(**_kwargs(derivation_bases=(bad,)))


def test_d28_no_judgement_can_be_smuggled_through_provenance():
    for key in ("severity", "score", "verdict", "mitre", "malicious",
                "beaconing", "persistence", "lateral_movement"):
        with pytest.raises(ValueError, match="is a judgement"):
            b.BehavioralRelationship(**_kwargs(provenance={key: "x"}))


def test_d29_no_verdict_vocabulary_is_emitted_anywhere():
    blob = json.dumps([x.to_dict() for x in _build()]).lower()
    for banned in ("malicious", "suspicious", "mitre", "att&ck", "attack",
                   "technique", "severity", "score", "verdict", "threat",
                   "risk", "beaconing", "persistence", "lateral",
                   "credential", "ueba"):
        assert banned not in blob, banned


def test_d30_a_process_chain_needs_two_spawns_and_three_processes():
    with pytest.raises(ValueError, match="PROCESS_CHAIN needs"):
        b.BehavioralRelationship(**_kwargs(
            behavior_type=b.BEHAVIOR_PROCESS_CHAIN,
            truth_level=b.TRUTH_DERIVED, process_iids=("a", "bb"),
            step_ids=("s1", "s2"), link_levels=(sq.CAUSAL_EVIDENCE,)))


def test_d31_the_dt2_2abc_layers_are_unchanged():
    assert len(r.process_edges(ROWS, EP)) == 2
    assert len(r.activity_edges(ROWS, EP)) == 4
    seq = _seqs()[0]
    assert len(seq.steps) == 6
    assert seq.causality_summary[sq.CAUSAL_EVIDENCE] == 1
