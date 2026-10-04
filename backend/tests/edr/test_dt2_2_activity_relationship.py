"""DT2-2 · focused tests for PROCESS → ACTIVITY attachment only.

Hermetic: pure Python, no Mongo, no network, no environment.
"""
from __future__ import annotations

import json

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


def _guid(**kw):
    """A row whose acting process is ProcessGuid-identified."""
    prov = {"raw_event_id": "raw-1", "canonical_event_id": "can-1",
            "process_guid": "{c-guid}"}
    prov.update(kw.pop("provenance", {}))
    base = {"process_iid": "guid:actor", "pid": 10,
            "image": "powershell.exe"}
    base.update(kw)
    return _row(provenance=prov, **base)


FILE_ROW = _guid(event_type="file_create", file="C:/tmp/payload.exe",
                 event_content_digest="abc123")
REG_ROW = _guid(event_iid="e2", event_type="registry_value_set",
                entity="HKLM/Software/Run/X")
DNS_ROW = _guid(event_iid="e3", event_type="dns_query",
                entity="evil.example.test")
NET_ROW = _guid(event_iid="e4", event_type="network_connect",
                network="203.0.113.10:443")


# ── family resolution from canonical evidence only ────────────────────

def test_e01_the_four_supported_families_resolve():
    assert r.family_of(FILE_ROW) == "FILE"
    assert r.family_of(REG_ROW) == "REGISTRY"
    assert r.family_of(DNS_ROW) == "DNS"
    assert r.family_of(NET_ROW) == "NETWORK"
    assert r.ACTIVITY_FAMILIES == ("NETWORK", "FILE", "REGISTRY", "DNS")


def test_e02_lane_group_from_the_canonicaliser_is_authoritative():
    assert r.family_of(_guid(lane_group="NETWORK")) == "NETWORK"


def test_e03_an_unsupported_event_type_resolves_to_no_family():
    for kind in ("wmi_event_filter", "pipe_created", "clipboard_change",
                 "process_tampering", "", None, "4798", "5379"):
        assert r.family_of(_guid(event_type=kind)) is None


def test_e04_auth_is_deliberately_not_a_supported_family_yet():
    assert r.family_of(_guid(event_type="logon", user="ADMIN")) is None
    assert "AUTH" not in r.ACTIVITY_FAMILIES
    assert r.activity_edges([_guid(event_type="logon", user="A")], EP) == []


# ── the activity endpoint ─────────────────────────────────────────────

def test_e05_each_family_carries_its_own_canonical_attributes():
    assert r.activity_of(FILE_ROW).attributes["path"] \
        == "C:/tmp/payload.exe"
    assert r.activity_of(FILE_ROW).attributes["sha256"] == "abc123"
    assert r.activity_of(REG_ROW).attributes["key"] \
        == "HKLM/Software/Run/X"
    assert r.activity_of(DNS_ROW).attributes["query"] \
        == "evil.example.test"
    assert r.activity_of(NET_ROW).attributes["destination"] \
        == "203.0.113.10:443"


def test_e06_an_unlabelled_artifact_is_not_an_activity():
    assert r.activity_of(_guid(event_type="file_create")) is None
    assert r.activity_of(_guid(event_type="dns_query")) is None


def test_e07_an_unsupported_family_cannot_be_constructed():
    with pytest.raises(ValueError, match="unsupported activity family"):
        r.ActivityRef(activity_id="x", family="AUTH", label="ADMIN")


# ── attachment with graded identity ───────────────────────────────────

def test_e08_a_guid_identified_actor_yields_an_authoritative_edge():
    edge = r.activity_edges([FILE_ROW], EP)[0]
    assert edge.process.process_iid == "guid:actor"
    assert edge.activity.family == "FILE"
    assert edge.authority == m.AUTHORITY_AUTHORITATIVE
    assert edge.downgraded is False
    assert edge.relationship_type == m.REL_PROCESS_FILE
    assert "ProcessGuid" in edge.reason


def test_e09_a_pid_derived_actor_stays_visibly_downgraded():
    row = _row(event_iid="p1", event_type="network_connect",
               network="198.51.100.5:80", process_iid="pid:actor",
               pid=4242, image="cmd.exe")
    edge = r.activity_edges([row], EP)[0]
    assert edge.authority == m.AUTHORITY_DERIVED
    assert edge.downgraded is True
    assert edge.process.basis == r.IDENTITY_BASIS_PID_IMAGE
    assert "PID reuse" in edge.reason
    assert edge.authority != m.AUTHORITY_AUTHORITATIVE


def test_e10_process_guid_takes_precedence_over_pid():
    """Both present: the GUID wins and the edge is not downgraded."""
    row = _guid(event_iid="both", event_type="dns_query",
                entity="a.example.test", pid=9999, image="x.exe")
    edge = r.activity_edges([row], EP)[0]
    assert edge.process.process_guid == "{c-guid}"
    assert edge.process.basis == r.IDENTITY_BASIS_GUID
    assert edge.downgraded is False


def test_e11_all_four_relationship_types_map_correctly():
    edges = r.activity_edges([FILE_ROW, REG_ROW, DNS_ROW, NET_ROW], EP)
    assert {e.relationship_type for e in edges} == {
        m.REL_PROCESS_FILE, m.REL_PROCESS_REGISTRY,
        m.REL_PROCESS_DNS, m.REL_PROCESS_NETWORK}


def test_e12_every_association_carries_the_full_required_payload():
    for row in (FILE_ROW, REG_ROW, DNS_ROW, NET_ROW):
        edge = r.activity_edges([row], EP)[0]
        assert edge.process.process_iid
        assert edge.activity.family and edge.activity.label
        assert edge.evidence_ref
        assert edge.derivation_basis == m.BASIS_ACTOR_BINDING
        assert edge.reason
        assert edge.provenance["source_event_iid"]
        assert edge.observed_at and edge.time_basis == "SOURCE_TIME"
        assert edge.authority and isinstance(edge.downgraded, bool)


def test_e13_repeated_observations_of_one_association_deduplicate():
    again = dict(FILE_ROW)
    again["event_iid"] = "again"
    assert len(r.activity_edges([FILE_ROW, again], EP)) == 1


def test_e14_the_edge_serializes_for_transport():
    d = r.activity_edges([NET_ROW], EP)[0].to_dict()
    assert d["relationship_type"] == m.REL_PROCESS_NETWORK
    assert d["activity"]["attributes"]["destination"] \
        == "203.0.113.10:443"
    assert d["process"]["downgraded"] is False
    assert d["evidence_ref"][0]["kind"] == "RAW_EVENT"
    json.dumps(d)


# ── NEGATIVE: nothing may be invented ─────────────────────────────────

def test_e15_close_timestamps_without_an_identity_pointer_create_nothing():
    """The core anti-guessing proof. A process starts, and 30 ms later a
    network connection is observed with NO acting-process pointer. A
    proximity-based deriver would attach them. We must not."""
    proc = _row(event_iid="p", process_iid="guid:actor",
                event_type="process_create", image="powershell.exe",
                timestamp="2026-06-01T01:00:00.000+00:00")
    orphan = _row(event_iid="n", event_type="network_connect",
                  network="203.0.113.10:443",
                  timestamp="2026-06-01T01:00:00.030+00:00")
    assert r.activity_edges([proc, orphan], EP) == []
    assert r.activity_edges([orphan, proc], EP) == []


def test_e16_row_adjacency_creates_nothing():
    orphan = _row(event_iid="n1", event_type="file_write",
                  file="C:/tmp/a.txt")
    actor = _guid(event_iid="a1", event_type="dns_query",
                  entity="b.example.test")
    edges = r.activity_edges([actor, orphan, actor, orphan], EP)
    assert all(e.activity.family == "DNS" for e in edges)
    assert len(edges) == 1


def test_e17_a_shared_image_name_alone_creates_nothing():
    actor = _guid(event_iid="i1", event_type="process_create",
                  image="powershell.exe")
    orphan = _row(event_iid="i2", event_type="file_create",
                  file="C:/tmp/x", image="powershell.exe")
    assert r.activity_edges([actor, orphan], EP) == []


def test_e18_a_shared_user_alone_creates_nothing():
    actor = _guid(event_iid="u1", event_type="process_create", user="CORP/a")
    orphan = _row(event_iid="u2", event_type="registry_value_set",
                  entity="HKLM/X", user="CORP/a")
    assert r.activity_edges([actor, orphan], EP) == []


def test_e19_the_same_endpoint_alone_creates_nothing():
    orphans = [_row(event_iid=f"o{i}", event_type="network_connect",
                    network=f"10.0.0.{i}:443") for i in range(5)]
    assert r.activity_edges(orphans, EP) == []


def test_e20_a_bare_pid_actor_cannot_anchor_an_association():
    row = _row(event_iid="bare", event_type="file_create",
               file="C:/tmp/y", process_iid="pid:only", pid=7)
    assert r.identity_of(row).authority == m.AUTHORITY_UNSTABLE
    assert r.activity_edges([row], EP) == []


def test_e21_an_unsupported_windows_event_creates_no_association():
    for kind in ("wmi_event_consumer", "pipe_created", "4798", "5379",
                 "4648", "4672"):
        row = _guid(event_iid=f"u-{kind}", event_type=kind,
                    entity="something", file="C:/x", network="1.2.3.4:1")
        assert r.activity_edges([row], EP) == [], kind


def test_e22_an_observation_without_provenance_creates_nothing():
    naked = {"event_iid": None, "event_type": "file_create",
             "file": "C:/tmp/z", "process_iid": "guid:actor",
             "provenance": {"process_guid": "{g}"}}
    assert r.activity_edges([naked], EP) == []


def test_e23_temporal_proximity_is_rejected_as_a_basis():
    actor = r.identity_of(FILE_ROW)
    activity = r.activity_of(FILE_ROW)
    ref = (m.EvidenceReference(kind="RAW_EVENT", id="raw-1"),)
    for bad in ("TEMPORAL_PROXIMITY", "TIMESTAMP_PROXIMITY",
                "SAME_SECOND_HEURISTIC"):
        with pytest.raises(ValueError):
            r.ActivityEdge(edge_id="x", endpoint_id=EP, process=actor,
                           activity=activity, derivation_basis=bad,
                           evidence_ref=ref, reason="because")


def test_e24_an_edge_without_evidence_or_reason_cannot_be_constructed():
    actor = r.identity_of(FILE_ROW)
    activity = r.activity_of(FILE_ROW)
    ref = (m.EvidenceReference(kind="RAW_EVENT", id="raw-1"),)
    with pytest.raises(ValueError, match="WHY IT EXISTS"):
        r.ActivityEdge(edge_id="x", endpoint_id=EP, process=actor,
                       activity=activity,
                       derivation_basis=m.BASIS_ACTOR_BINDING,
                       evidence_ref=(), reason="because")
    with pytest.raises(ValueError, match="reason"):
        r.ActivityEdge(edge_id="x", endpoint_id=EP, process=actor,
                       activity=activity,
                       derivation_basis=m.BASIS_ACTOR_BINDING,
                       evidence_ref=ref, reason="")


def test_e25_an_unattributed_actor_cannot_anchor_an_edge():
    with pytest.raises(ValueError, match="acting process identity"):
        r.ActivityEdge(
            edge_id="x", endpoint_id=EP,
            process=r.identity_of(_row(event_type="file_create")),
            activity=r.activity_of(FILE_ROW),
            derivation_basis=m.BASIS_ACTOR_BINDING,
            evidence_ref=(m.EvidenceReference(kind="RAW_EVENT", id="r"),),
            reason="because")


# ── isolation ─────────────────────────────────────────────────────────

def test_e26_activity_edges_are_endpoint_scoped():
    assert r.activity_edges([FILE_ROW], "ep_a")[0].endpoint_id == "ep_a"
    assert r.activity_edges([FILE_ROW], "ep_b")[0].endpoint_id == "ep_b"


def test_e27_process_edges_from_dt2_2_step_one_still_behave():
    row = _guid(event_iid="lin", event_type="process_create",
                parent_process_iid="guid:parent",
                provenance={"parent_process_guid": "{p-guid}"})
    edges = r.process_edges([row], EP)
    assert len(edges) == 1 and edges[0].guid_proven is True


def test_e28_dt2_0_contract_relationships_are_not_modified():
    from edr_plane.trajectory import contract as c
    rels = c.relationships([FILE_ROW], EP)
    assert any(x.relationship_type == m.REL_PROCESS_FILE for x in rels)
