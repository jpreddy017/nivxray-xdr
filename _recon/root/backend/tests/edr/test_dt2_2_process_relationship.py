"""DT2-2 · focused tests for the process-relationship primitive only.

Hermetic: pure Python, no Mongo, no network, no environment. Nothing here
touches DT2-0 or DT2-1 behaviour.
"""
from __future__ import annotations

import pytest

from edr_plane.trajectory import models as m
from edr_plane.trajectory import relationships as r

EP = "ep_test"


def _row(**kw):
    row = {"event_iid": "e1", "timestamp": "2026-06-01T01:00:00+00:00",
           "provenance": {"raw_event_id": "raw-1",
                          "canonical_event_id": "can-1"}}
    row.update(kw)
    return row


GUID_ROW = _row(
    process_iid="guid:child", pid=4242, image="C:/W/powershell.exe",
    parent_process_iid="guid:parent", parent_image="C:/W/explorer.exe",
    provenance={"raw_event_id": "raw-1", "canonical_event_id": "can-1",
                "process_guid": "{c-guid}",
                "parent_process_guid": "{p-guid}"})

PID_ROW = _row(
    event_iid="e2", process_iid="pid:child", pid=99, image="cmd.exe",
    parent_process_iid="pid:parent", ppid=77, parent_image="wscript.exe")


# ── identity grading ──────────────────────────────────────────────────

def test_d01_process_guid_is_authoritative_identity():
    ident = r.identity_of(GUID_ROW, role="child")
    assert ident.authority == m.AUTHORITY_AUTHORITATIVE
    assert ident.basis == r.IDENTITY_BASIS_GUID
    assert ident.downgraded is False
    assert ident.presentable is True


def test_d02_parent_guid_is_read_from_the_parent_fields():
    ident = r.identity_of(GUID_ROW, role="parent")
    assert ident.process_guid == "{p-guid}"
    assert ident.authority == m.AUTHORITY_AUTHORITATIVE


def test_d03_pid_plus_image_is_derived_and_explicitly_downgraded():
    ident = r.identity_of(PID_ROW, role="child")
    assert ident.authority == m.AUTHORITY_DERIVED
    assert ident.basis == r.IDENTITY_BASIS_PID_IMAGE
    assert ident.downgraded is True
    assert ident.presentable is True


def test_d04_a_bare_pid_is_unstable_and_never_presentable():
    ident = r.identity_of(_row(process_iid="x", pid=5), role="child")
    assert ident.authority == m.AUTHORITY_UNSTABLE
    assert ident.basis == r.IDENTITY_BASIS_PID_ONLY
    assert ident.presentable is False


def test_d05_absent_identity_is_unknown_not_assumed():
    ident = r.identity_of(_row(), role="parent")
    assert ident.authority == m.AUTHORITY_UNKNOWN
    assert ident.basis == r.IDENTITY_BASIS_ABSENT
    assert ident.process_iid is None


def test_d06_role_must_be_child_or_parent():
    with pytest.raises(ValueError):
        r.identity_of(GUID_ROW, role="grandparent")


# ── edge construction and its invariants ──────────────────────────────

def test_d07_a_guid_bound_edge_is_authoritative_and_guid_proven():
    edges = r.process_edges([GUID_ROW], EP)
    assert len(edges) == 1
    edge = edges[0]
    assert edge.parent.process_iid == "guid:parent"
    assert edge.child.process_iid == "guid:child"
    assert edge.authority == m.AUTHORITY_AUTHORITATIVE
    assert edge.guid_proven is True
    assert edge.derivation_basis == m.BASIS_PARENT_GUID


def test_d08_a_pid_derived_edge_reports_reduced_authority():
    edge = r.process_edges([PID_ROW], EP)[0]
    assert edge.authority == m.AUTHORITY_DERIVED
    assert edge.guid_proven is False
    assert edge.derivation_basis == m.BASIS_PARENT_IDENTITY
    assert "PID reuse" in edge.reason


def test_d09_an_edge_is_never_stronger_than_its_weakest_endpoint():
    mixed = _row(event_iid="e3", process_iid="c", pid=1, image="a.exe",
                 parent_process_iid="p",
                 provenance={"raw_event_id": "raw-3",
                             "parent_process_guid": "{p}"})
    edge = r.process_edges([mixed], EP)[0]
    assert edge.parent.authority == m.AUTHORITY_AUTHORITATIVE
    assert edge.child.authority == m.AUTHORITY_DERIVED
    assert edge.authority == m.AUTHORITY_DERIVED


def test_d10_every_edge_states_why_it_exists():
    for row in (GUID_ROW, PID_ROW):
        edge = r.process_edges([row], EP)[0]
        assert edge.reason
        assert edge.evidence_ref
        assert any(ref.kind == "RAW_EVENT" and ref.byte_preserved
                   for ref in edge.evidence_ref)


def test_d11_an_edge_without_evidence_cannot_be_constructed():
    ident = r.identity_of(GUID_ROW, role="child")
    parent = r.identity_of(GUID_ROW, role="parent")
    with pytest.raises(ValueError, match="WHY IT EXISTS"):
        r.ProcessEdge(edge_id="x", endpoint_id=EP, parent=parent,
                      child=ident, derivation_basis=m.BASIS_PARENT_GUID,
                      evidence_ref=(), reason="because")


def test_d12_an_edge_without_a_reason_cannot_be_constructed():
    with pytest.raises(ValueError, match="reason"):
        r.ProcessEdge(
            edge_id="x", endpoint_id=EP,
            parent=r.identity_of(GUID_ROW, role="parent"),
            child=r.identity_of(GUID_ROW, role="child"),
            derivation_basis=m.BASIS_PARENT_GUID,
            evidence_ref=(m.EvidenceReference(kind="RAW_EVENT", id="r"),),
            reason="")


def test_d13_temporal_proximity_is_rejected_as_a_derivation_basis():
    for bad in ("TEMPORAL_PROXIMITY", "TIMESTAMP_PROXIMITY",
                "derived_from_temporal_proximity"):
        with pytest.raises(ValueError):
            r.ProcessEdge(
                edge_id="x", endpoint_id=EP,
                parent=r.identity_of(GUID_ROW, role="parent"),
                child=r.identity_of(GUID_ROW, role="child"),
                derivation_basis=bad,
                evidence_ref=(m.EvidenceReference(kind="RAW_EVENT",
                                                  id="r"),),
                reason="because")


def test_d14_an_unrecognised_basis_is_rejected():
    with pytest.raises(ValueError, match="unrecognised"):
        r.ProcessEdge(
            edge_id="x", endpoint_id=EP,
            parent=r.identity_of(GUID_ROW, role="parent"),
            child=r.identity_of(GUID_ROW, role="child"),
            derivation_basis="I_JUST_DECIDED_THIS",
            evidence_ref=(m.EvidenceReference(kind="RAW_EVENT", id="r"),),
            reason="because")


def test_d15_a_half_known_edge_is_not_a_relationship():
    with pytest.raises(ValueError, match="BOTH endpoints"):
        r.ProcessEdge(
            edge_id="x", endpoint_id=EP,
            parent=r.identity_of(_row(), role="parent"),
            child=r.identity_of(GUID_ROW, role="child"),
            derivation_basis=m.BASIS_PARENT_GUID,
            evidence_ref=(m.EvidenceReference(kind="RAW_EVENT", id="r"),),
            reason="because")


def test_d16_a_process_cannot_be_its_own_parent():
    with pytest.raises(ValueError, match="own parent"):
        ident = r.identity_of(GUID_ROW, role="child")
        r.ProcessEdge(
            edge_id="x", endpoint_id=EP, parent=ident, child=ident,
            derivation_basis=m.BASIS_PARENT_GUID,
            evidence_ref=(m.EvidenceReference(kind="RAW_EVENT", id="r"),),
            reason="because")


# ── no fabrication, ever ──────────────────────────────────────────────

def test_d17_two_close_observations_never_produce_an_edge():
    """The core anti-guessing proof: neither row names a parent, and they
    are 40 ms apart. A proximity-based deriver would join them."""
    a = _row(event_iid="a", process_iid="A", pid=1, image="a.exe",
             timestamp="2026-06-01T01:00:00.000+00:00")
    b = _row(event_iid="b", process_iid="B", pid=2, image="b.exe",
             timestamp="2026-06-01T01:00:00.040+00:00")
    assert r.process_edges([a, b], EP) == []


def test_d18_an_unattributed_observation_yields_no_edge():
    assert r.process_edges([_row(process_iid="only-child")], EP) == []
    assert r.process_edges([_row(parent_process_iid="only-parent")],
                           EP) == []


def test_d19_an_observation_without_provenance_yields_no_edge():
    naked = {"event_iid": None, "process_iid": "c",
             "parent_process_iid": "p", "provenance": {}}
    assert r.process_edges([naked], EP) == []


def test_d20_a_self_parented_row_is_dropped_not_raised():
    same = _row(process_iid="same", parent_process_iid="same")
    assert r.process_edges([same], EP) == []


def test_d21_repeated_observations_of_one_edge_are_deduplicated():
    again = dict(GUID_ROW)
    again["event_iid"] = "e-again"
    assert len(r.process_edges([GUID_ROW, again], EP)) == 1


def test_d22_pid_reuse_does_not_merge_two_distinct_children():
    first = _row(event_iid="r1", process_iid="guid:A", pid=4242,
                 image="a.exe", parent_process_iid="guid:P",
                 provenance={"raw_event_id": "raw-r1",
                             "process_guid": "{A}",
                             "parent_process_guid": "{P}"})
    second = _row(event_iid="r2", process_iid="guid:B", pid=4242,
                  image="b.exe", parent_process_iid="guid:P",
                  provenance={"raw_event_id": "raw-r2",
                              "process_guid": "{B}",
                              "parent_process_guid": "{P}"})
    edges = r.process_edges([first, second], EP)
    assert len(edges) == 2
    assert {e.child.process_iid for e in edges} == {"guid:A", "guid:B"}


# ── serialization and isolation ───────────────────────────────────────

def test_d23_the_edge_serializes_for_transport_without_loss():
    d = r.process_edges([PID_ROW], EP)[0].to_dict()
    assert d["relationship_type"] == m.REL_PROCESS_PROCESS
    assert d["parent"]["downgraded"] is True
    assert d["authority"] == m.AUTHORITY_DERIVED
    assert d["guid_proven"] is False
    assert d["evidence_ref"][0]["kind"] == "RAW_EVENT"
    assert d["reason"]
    import json
    json.dumps(d)


def test_d24_the_edge_is_endpoint_scoped():
    assert r.process_edges([GUID_ROW], "ep_a")[0].endpoint_id == "ep_a"
    assert r.process_edges([GUID_ROW], "ep_b")[0].endpoint_id == "ep_b"


def test_d25_the_primitive_performs_no_io_and_no_writes():
    src = (__import__("pathlib").Path(r.__file__)).read_text()
    for banned in ("motor", "pymongo", "insert_one", "update_one",
                   "delete_one", "find_one", "requests", "httpx",
                   "os.environ", "open("):
        assert banned not in src, banned


def test_d26_dt2_0_relationship_semantics_are_untouched():
    """DT2-2 is additive: the DT2-0 edge model still rejects what it
    always rejected."""
    with pytest.raises(ValueError):
        m.Relationship(
            relationship_id="x", relationship_type=m.REL_PROCESS_PROCESS,
            source_id="a", target_id="b", endpoint_id=EP,
            derivation_basis="TEMPORAL_PROXIMITY",
            authority=m.AUTHORITY_AUTHORITATIVE,
            evidence_ref=(m.EvidenceReference(kind="RAW_EVENT", id="r"),))
