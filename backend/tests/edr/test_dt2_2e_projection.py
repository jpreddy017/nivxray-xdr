"""DT2-2E · focused CONTRACT tests for the trajectory graph projection.

Hermetic: pure Python, no Mongo, no network, no environment. These tests
assert the SHAPE the UI will render and the truths the projection must
carry forward — they do not re-test 2A/2B/2C/2D logic.
"""
from __future__ import annotations

import json

import pytest

from edr_plane.trajectory import behavior as bh
from edr_plane.trajectory import contract as c
from edr_plane.trajectory import models as m
from edr_plane.trajectory import projection as p
from edr_plane.trajectory import relationships as rel
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


def _spawn(iid, ts, parent, child, *, guid=True, **kw):
    prov = {"parent_process_guid": f"{{p-{parent}}}",
            "process_guid": f"{{c-{child}}}"} if guid else {}
    return _row(iid, ts, event_type="process_create", process_iid=child,
                parent_process_iid=parent, image=f"{child}.exe",
                process=child, parent_image=f"{parent}.exe", pid=100,
                ppid=10, lane_group="PROCESS", provenance=prov, **kw)


def _act(iid, ts, actor, kind, *, guid=True, **kw):
    prov = {"process_guid": f"{{c-{actor}}}"} if guid else {}
    return _row(iid, ts, event_type=kind, process_iid=actor,
                image=f"{actor}.exe", process=actor, pid=100,
                provenance=prov, **kw)


# The AMP-shaped target graph, from evidence only.
ROWS = [
    _spawn("s1", T + "0.000+00:00", "winword", "powershell"),
    _act("a1", T + "1.000+00:00", "powershell", "dns_query",
         entity="evil.example.test"),
    _act("a2", T + "2.000+00:00", "powershell", "network_connect",
         network="203.0.113.10:443"),
    _act("a3", T + "3.000+00:00", "powershell", "file_create",
         file="C:/tmp/payload.dll", event_content_digest="abc123"),
    _act("a4", T + "3.500+00:00", "powershell", "registry_value_set",
         entity="HKLM/Software/Run/X"),
    _spawn("s2", T + "4.000+00:00", "powershell", "rundll32"),
]

V1 = {"events": ROWS,
      "time_range": {"start": T + "0.000+00:00", "end": T + "4.000+00:00"},
      "lane_axis": {"total_lanes": 3, "lanes": [{"lane_id": "l1"}]},
      "cursor": {"timestamp": T + "0.000+00:00", "event_iid": "s1"},
      "next_cursor": {"timestamp": T + "4.000+00:00", "event_iid": "s2"},
      "has_more": True}


def _graph(v1=None, **kw):
    return p.build_graph(dict(v1 or V1), endpoint_id=EP,
                         requested_start=T + "0.000+00:00",
                         requested_end=T + "5.000+00:00", **kw)


def _pnode(graph, iid):
    return next(n for n in graph.process_nodes if n.process_iid == iid)


# ══════════════════════════════════════════════════════════════════════
# PROJECTION SHAPE
# ══════════════════════════════════════════════════════════════════════

def test_e01_the_target_amp_graph_is_rendered():
    g = _graph()
    assert {n.process_iid for n in g.process_nodes} == {
        "winword", "powershell", "rundll32"}
    assert {n.family for n in g.activity_nodes} == {
        "DNS", "NETWORK", "FILE", "REGISTRY"}
    assert g.root_node_ids == (p.process_node_id("winword"),)
    word, shell = _pnode(g, "winword"), _pnode(g, "powershell")
    assert word.child_node_ids == (p.process_node_id("powershell"),)
    assert shell.child_node_ids == (p.process_node_id("rundll32"),)
    assert len(shell.activity_node_ids) == 4
    assert (word.depth, shell.depth, _pnode(g, "rundll32").depth) == (0, 1, 2)


def test_e02_the_projection_composes_and_derives_nothing_itself():
    g = _graph()
    assert g.provenance["composes"] == ["dt2.0", "dt2-2a", "dt2-2b",
                                        "dt2-2c", "dt2-2d"]
    assert g.provenance["derives_relationships"] is False
    assert g.provenance["client_may_derive_edges"] is False
    assert g.provenance["creates_no_store"] is True
    assert g.contract_version == p.GRAPH_CONTRACT_VERSION
    # every rendered edge IS a DT2-2A/2B edge id
    produced = {e.edge_id for e in rel.process_edges(ROWS, EP)} | {
        e.edge_id for e in rel.activity_edges(ROWS, EP)}
    assert {e.edge_id for e in g.edges} == produced


def test_e03_the_whole_graph_serializes_for_transport():
    d = _graph().to_dict()
    for key in ("process_nodes", "activity_nodes", "edges", "order",
                "sequences", "behaviors", "detection_pivots",
                "navigation", "coverage", "availability", "ranges"):
        assert key in d, key
    json.dumps(d)


# ══════════════════════════════════════════════════════════════════════
# PROCESS NODE CONTRACT
# ══════════════════════════════════════════════════════════════════════

def test_e04_a_process_node_carries_identity_authority_and_downgrade():
    shell = _pnode(_graph(), "powershell")
    assert shell.identity_authority == m.AUTHORITY_AUTHORITATIVE
    assert shell.identity_basis == rel.IDENTITY_BASIS_GUID
    assert shell.downgraded is False
    assert shell.process_guid and shell.pid == 100
    assert shell.presence == p.PRESENCE_OBSERVED
    assert shell.expandable is True


def test_e05_a_pid_surrogate_node_stays_visibly_downgraded():
    rows = [_spawn("d1", T + "0.000+00:00", "winword", "powershell",
                   guid=False)]
    g = _graph({"events": rows})
    assert _pnode(g, "powershell").downgraded is True
    assert _pnode(g, "winword").downgraded is True
    assert _pnode(g, "winword").identity_authority == m.AUTHORITY_DERIVED


def test_e06_a_parent_known_only_from_a_child_row_is_marked_referenced():
    word = _pnode(_graph(), "winword")
    assert word.presence == p.PRESENCE_REFERENCED
    assert word.provenance["has_own_observation"] is False
    assert word.evidence_ref            # still evidence-backed


def test_e07_a_lifeline_is_an_evidence_span_never_a_process_lifetime():
    shell = _pnode(_graph(), "powershell")
    assert shell.lifeline["first_evidence_at"] == T + "0.000+00:00"
    assert shell.lifeline["last_evidence_at"] == T + "4.000+00:00"
    assert shell.lifeline["end_time"] is None
    assert shell.lifeline["exit_observed"] is False
    assert shell.lifeline["end_state"] == p.END_STATE_UNAVAILABLE
    assert shell.lifeline["basis"] == p.LIFELINE_BASIS
    assert shell.lifeline["end_evidence_availability"] == m.AVAIL_UNAVAILABLE


def test_e08_a_fabricated_process_end_is_rejected_at_construction():
    with pytest.raises(ValueError, match="termination"):
        p.ProcessNode(node_id="x", process_iid="i", endpoint_id=EP,
                      lifeline={"end_time": T + "9.000+00:00"})


def test_e09_node_ids_are_stable_and_derived_from_identity():
    a, b = _graph(), _graph()
    assert [n.node_id for n in a.process_nodes] == \
        [n.node_id for n in b.process_nodes]
    assert [n.node_id for n in a.activity_nodes] == \
        [n.node_id for n in b.activity_nodes]
    assert _pnode(a, "powershell").node_id == p.process_node_id("powershell")


# ══════════════════════════════════════════════════════════════════════
# RELATIONSHIP CONTRACT
# ══════════════════════════════════════════════════════════════════════

def test_e10_every_edge_answers_why_with_evidence_and_a_basis():
    g = _graph()
    assert g.edges
    known = g.node_ids()
    for e in g.edges:
        assert e.source_node_id in known and e.target_node_id in known
        assert e.evidence_ref and e.reason
        assert e.derivation_basis in m.ACCEPTED_BASES
        assert e.authority in m.AUTHORITIES
        assert isinstance(e.downgraded, bool)
        assert e.step_id and e.sequence_id
        assert e.focus_targets["evidence"]


def test_e11_an_edge_without_evidence_or_why_cannot_be_rendered():
    ref = (m.EvidenceReference(kind="RAW_EVENT", id="r"),)
    base = dict(edge_id="x", endpoint_id=EP,
                relationship_type=m.REL_PROCESS_PROCESS,
                source_node_id="a", target_node_id="b",
                derivation_basis=m.BASIS_PARENT_GUID, reason="because",
                authority=m.AUTHORITY_AUTHORITATIVE, downgraded=False)
    with pytest.raises(ValueError, match="without evidence_ref"):
        p.GraphEdge(**{**base, "evidence_ref": ()})
    with pytest.raises(ValueError, match="carry its WHY"):
        p.GraphEdge(**{**base, "evidence_ref": ref, "reason": ""})
    for bad in ("TEMPORAL_PROXIMITY", "DISPLAY_ADJACENCY", "GUESS"):
        with pytest.raises(ValueError, match="derivation_basis"):
            p.GraphEdge(**{**base, "evidence_ref": ref,
                           "derivation_basis": bad})


def test_e12_parent_child_edges_keep_their_dt2_2a_grading():
    edge = next(e for e in _graph().edges
                if e.relationship_type == m.REL_PROCESS_PROCESS
                and e.target_node_id == p.process_node_id("powershell"))
    assert edge.derivation_basis == m.BASIS_PARENT_GUID
    assert edge.provenance["guid_proven"] is True
    assert edge.focus_targets["parent"]["value"] == "winword"
    assert edge.focus_targets["child"]["value"] == "powershell"


def test_e13_each_edge_keeps_the_four_times_separate():
    g = _graph(times={"a1": {"ingest_time": T + "1.500+00:00",
                             "canonicalized_time": T + "1.900+00:00",
                             "detection_time": T + "9.000+00:00"}})
    edge = next(e for e in g.edges
                if e.relationship_type == m.REL_PROCESS_DNS)
    t = edge.times
    assert t["source_time"] == T + "1.000+00:00"
    assert t["ingest_time"] == T + "1.500+00:00"
    assert t["canonicalized_time"] == T + "1.900+00:00"
    assert t["detection_time"] == T + "9.000+00:00"
    assert t["ordering_basis"] == sq.TIME_SOURCE


def test_e14_the_causal_ordering_status_travels_with_the_edge():
    for e in _graph().edges:
        assert e.link_to_previous in sq.CAUSALITY_LEVELS
        assert e.provenance["link_reason"]


# ══════════════════════════════════════════════════════════════════════
# ACTIVITY CONTRACT
# ══════════════════════════════════════════════════════════════════════

def test_e15_activity_nodes_attach_to_their_proven_process():
    g = _graph()
    for node in g.activity_nodes:
        assert node.process_iid == "powershell"
        assert node.process_node_id == p.process_node_id("powershell")
        assert node.node_id in _pnode(g, "powershell").activity_node_ids
        assert node.label and node.kind and node.evidence_ref
        assert node.times["ordering_basis"] == sq.TIME_SOURCE
        assert node.focus_targets["evidence"]


def test_e16_each_family_keeps_its_canonical_attributes():
    by_family = {n.family: n for n in _graph().activity_nodes}
    assert by_family["DNS"].attributes["query"] == "evil.example.test"
    assert by_family["NETWORK"].attributes["destination"] \
        == "203.0.113.10:443"
    assert by_family["FILE"].attributes["path"] == "C:/tmp/payload.dll"
    assert by_family["FILE"].attributes["sha256"] == "abc123"
    assert by_family["REGISTRY"].attributes["key"] == "HKLM/Software/Run/X"


def test_e17_an_unsupported_family_cannot_be_rendered():
    with pytest.raises(ValueError, match="unsupported activity family"):
        p.ActivityNode(node_id="x", endpoint_id=EP, family="AUTH",
                       label="CORP/a", process_iid="i",
                       process_node_id="pnode:i", edge_id="e")


def test_e18_unattributed_activity_never_enters_the_graph():
    orphan = _row("n1", T + "1.000+00:00", event_type="network_connect",
                  network="203.0.113.7:443")
    g = _graph({"events": [ROWS[0], orphan]})
    assert g.activity_nodes == ()
    assert all(e.relationship_type == m.REL_PROCESS_PROCESS
               for e in g.edges)


# ══════════════════════════════════════════════════════════════════════
# BEHAVIOR CONTRACT
# ══════════════════════════════════════════════════════════════════════

def test_e19_behaviors_are_reused_from_dt2_2d_not_reclassified():
    g = _graph()
    assert {b.behavior_type for b in g.behaviors} == set(bh.BEHAVIOR_TYPES)
    known_steps = {o["step_id"] for o in g.order}
    for b in g.behaviors:
        assert b.truth_level in bh.TRUTH_LEVELS
        assert set(b.step_ids) <= known_steps
        assert b.evidence_ref and b.reason
    chain = next(b for b in g.behaviors
                 if b.behavior_type == bh.BEHAVIOR_PROCESS_CHAIN)
    assert chain.truth_level == bh.TRUTH_DERIVED
    assert chain.process_iids == ("winword", "powershell", "rundll32")


def test_e20_no_verdict_vocabulary_is_introduced_by_the_projection():
    blob = json.dumps([b.to_dict() for b in _graph().behaviors]).lower()
    for banned in ("malicious", "suspicious", "mitre", "attack",
                   "technique", "severity", "score", "verdict", "threat"):
        assert banned not in blob, banned


# ══════════════════════════════════════════════════════════════════════
# FOCUS / NAVIGATION CONTRACT
# ══════════════════════════════════════════════════════════════════════

def test_e21_every_focus_target_uses_the_dt2_0_focus_vocabulary():
    g = _graph()
    seen = []
    for node in g.process_nodes:
        seen.append(node.focus_targets["process"])
        seen += node.focus_targets["evidence"]
        seen += node.focus_targets["children"]
        if node.focus_targets["parent"]:
            seen.append(node.focus_targets["parent"])
    for node in g.activity_nodes:
        seen.append(node.focus_targets["process"])
        seen += node.focus_targets["evidence"]
    assert seen
    for target in seen:
        m.FocusTarget(kind=target["kind"], value=target["value"])


def test_e22_process_and_activity_pivot_to_exact_evidence():
    g = _graph()
    shell_evidence = {t["kind"] for t in
                      _pnode(g, "powershell").focus_targets["evidence"]}
    assert {"raw_event_id", "canonical_event_id",
            "observation_id"} <= shell_evidence
    dns = next(n for n in g.activity_nodes if n.family == "DNS")
    assert {"raw_event_id", "canonical_event_id"} <= {
        t["kind"] for t in dns.focus_targets["evidence"]}


def test_e23_parent_and_child_pivots_are_exposed_on_both_sides():
    g = _graph()
    shell = _pnode(g, "powershell")
    assert shell.focus_targets["parent"]["value"] == "winword"
    assert shell.focus_targets["children"] == [
        {"kind": "process_iid", "value": "rundll32"}]
    assert _pnode(g, "winword").focus_targets["parent"] is None


def test_e24_event_to_trajectory_resolves_through_dt2_0_focus():
    g = _graph(focus=m.FocusTarget(kind="observation_id", value="a2"))
    assert g.focus.state == m.FOCUS_RESOLVED
    d = g.to_dict()["focus"]
    assert d["observation_id"] == "a2"
    assert d["process_node_id"] == p.process_node_id("powershell")
    assert d["basis"] == "EXACT_EVIDENCE_ID"


def test_e25_a_focus_target_outside_the_window_is_not_faked():
    g = _graph(focus=m.FocusTarget(kind="raw_event_id", value="raw-nope"))
    assert g.focus.state == m.FOCUS_EVIDENCE_MISSING
    assert g.to_dict()["focus"]["process_node_id"] is None


def test_e26_detection_to_trajectory_pivots_are_exposed():
    det = _act("det1", T + "2.500+00:00", "powershell", "file_create",
               file="C:/tmp/bad.dll", is_detection=True,
               detection={"finding_id": "f-1", "engine": "sigma"},
               rule_id="r-1")
    g = _graph({"events": ROWS + [det]})
    pivot = next(x for x in g.detection_pivots
                 if x["detection_id"] == "f-1")
    assert pivot["focus"] == {"kind": "detection_id", "value": "f-1"}
    assert pivot["process_node_id"] == p.process_node_id("powershell")
    assert pivot["observation_focus"] == [
        {"kind": "observation_id", "value": "det1"}]
    assert pivot["evidence_ref"]


def test_e27_before_after_navigation_is_exposed_without_claiming_absence():
    nav = _graph().navigation
    assert nav["ordered_step_ids"]
    assert nav["cursor"]["event_iid"] == "s1"
    assert nav["next_cursor"]["event_iid"] == "s2"
    assert nav["has_more"] is True
    assert nav["before"]["state"] == m.AVAIL_UNKNOWN
    assert nav["after"]["state"] == m.AVAIL_UNKNOWN
    assert "NOT_PROVABLE" in nav["before"]["basis"]
    assert "NOT_PROVABLE" in nav["after"]["basis"]
    assert nav["ordering_basis"] == sq.SEQUENCE_ORDERING_BASIS


def test_e28_step_order_exposes_neighbours_for_step_navigation():
    order = _graph().order
    assert [o["index"] for o in order] == list(range(len(order)))
    assert order[0]["previous_step_id"] is None
    assert order[-1]["next_step_id"] is None
    for previous, following in zip(order, order[1:]):
        assert following["previous_step_id"] == previous["step_id"]
        assert previous["next_step_id"] == following["step_id"]
    known = _graph().node_ids()
    assert all(o["node_id"] in known for o in order)
    assert all(o["actor_node_id"] in known for o in order)


# ══════════════════════════════════════════════════════════════════════
# COVERAGE TRUTH
# ══════════════════════════════════════════════════════════════════════

def test_e29_coverage_is_re_exported_from_dt2_0_not_recomputed():
    v1 = dict(V1)
    expected = c.coverage(v1, ROWS, T + "0.000+00:00", T + "5.000+00:00")
    got = _graph().coverage
    assert [(x.state, x.start, x.end, x.authority,
             x.boundary_certainty, x.absence_inferable) for x in got] == \
        [(x.state, x.start, x.end, x.authority,
          x.boundary_certainty, x.absence_inferable) for x in expected]
    assert _graph().provenance["coverage_source"] == \
        "dt2.0.contract.coverage"


def test_e30_an_empty_window_stays_unknown_and_never_becomes_absence():
    g = _graph({"events": []})
    assert g.process_nodes == () and g.edges == () and g.behaviors == ()
    states = {iv.state for iv in g.coverage}
    assert states == {m.COV_UNKNOWN}
    for iv in g.coverage:
        assert iv.absence_inferable is False
        assert iv.boundary_certainty == "UNKNOWN"
        assert "not proof of absence" in (iv.reason or "")
    assert g.availability["observations"] == m.AVAIL_EMPTY


def test_e31_unprovable_process_end_stays_unavailable_everywhere():
    g = _graph()
    assert g.availability["process_end_evidence"] == m.AVAIL_UNAVAILABLE
    assert all(n.lifeline["end_time"] is None for n in g.process_nodes)
    assert g.ranges["retention_boundary"]["state"] == m.AVAIL_UNKNOWN


def test_e32_the_underlying_layers_are_not_mutated_by_projection():
    before = c.build(dict(V1), endpoint_id=EP).to_dict()
    _graph()
    assert c.build(dict(V1), endpoint_id=EP).to_dict() == before
    assert len(rel.process_edges(ROWS, EP)) == 2
    assert len(rel.activity_edges(ROWS, EP)) == 4
    assert len(sq.temporal_sequences(rel.process_edges(ROWS, EP),
                                     rel.activity_edges(ROWS, EP),
                                     EP)[0].steps) == 6
