"""DT2-0 · Device Trajectory V2 contract tests.

These are the invariants the owner gate names: an edge must carry evidence,
temporal proximity is never authority, absence has seven distinct truths,
density is not severity, a process with no termination evidence has no end,
4624 without a process binding gets no process edge, unattributed evidence
is preserved rather than dropped, retention truth is not manufactured, and
the V1 response surface is untouched.
"""
from __future__ import annotations

import pytest

from edr_plane import trajectory as dt2
from edr_plane.trajectory import contract as c
from edr_plane.trajectory import models as m

EP = "ep_1989031c8c1d0085812f"


def _row(**over):
    row = {
        "event_iid": "obs_1", "timestamp": "2026-09-27T10:00:00+00:00",
        "event_type": "process_create", "lane_group": "PROCESS",
        "process": "powershell.exe", "process_iid": "p_child",
        "parent_process_iid": "p_parent", "parent_state": "OBSERVED",
        "pid": 4242, "ppid": 900, "image": r"C:\Windows\powershell.exe",
        "command_line": "powershell -enc AAA", "user": "LAB\\svc",
        "disposition": "UNKNOWN_NOT_ASSESSED", "is_detection": False,
        "mitre": [], "assessment_state": "NO_DETECTION_CLAIMED",
        "provenance": {"raw_event_id": "raw_1",
                       "canonical_event_id": "can_1",
                       "evidence_id": "obs_1", "source": "sysmon",
                       "parser_state": "OK"},
    }
    row.update(over)
    return row


def _v1(rows):
    return {"events": rows,
            "lane_axis": {"total_lanes": len(rows),
                          "lanes": [{"lane_id": f"l{i}"}
                                    for i, _ in enumerate(rows)]},
            "time_range": {"start": "2026-09-27T00:00:00+00:00",
                           "end": "2026-09-27T23:59:59+00:00"},
            "projection": {"state": "PROJECTION_COMPLETE"},
            "observations_all_time": len(rows), "matched_in_window": len(rows)}


# ── A/B · serialization and validation ────────────────────────────────
def test_the_window_serializes_every_first_class_object():
    out = c.build(_v1([_row()]), endpoint_id=EP).to_dict()
    for key in ("observations", "relationships", "detections", "density",
                "coverage", "process_instances", "artifacts", "axis",
                "requested_range", "effective_range", "available_range",
                "retention_boundary", "availability", "provenance",
                "contract_version"):
        assert key in out, key
    assert out["contract_version"] == m.DT2_CONTRACT_VERSION


def test_an_unrecognised_relationship_type_is_rejected():
    with pytest.raises(ValueError):
        m.Relationship(relationship_id="r", relationship_type="GUESSWORK",
                       source_id="a", target_id="b", endpoint_id=EP,
                       derivation_basis=m.BASIS_ACTOR_BINDING,
                       authority=m.AUTHORITY_AUTHORITATIVE,
                       evidence_ref=(m.EvidenceReference(kind="RAW_EVENT",
                                                         id="raw_1"),))


# ── C · V1 backward compatibility ─────────────────────────────────────
def test_v1_keys_are_untouched_and_dt2_is_purely_additive():
    v1 = _v1([_row()])
    before = {k: v for k, v in v1.items() if k != "dt2"}
    after = dt2.augment(v1, endpoint_id=EP)
    assert after["events"] is before["events"]
    for key, value in before.items():
        assert after[key] == value, f"V1 key {key} mutated"
    assert set(after) - set(before) == {"dt2"}


# ── D/E/F/G · process identity authority ──────────────────────────────
def test_processguid_is_authoritative_identity():
    row = _row(provenance={**_row()["provenance"], "process_guid": "{GUID}"})
    proc = c.process_instances([row], EP)[0]
    assert proc.identity_authority == m.AUTHORITY_AUTHORITATIVE
    assert proc.identity_basis == "SYSMON_PROCESS_GUID"


def test_pid_and_image_without_guid_is_downgraded_to_derived():
    proc = c.process_instances([_row()], EP)[0]
    assert proc.identity_authority == m.AUTHORITY_DERIVED
    assert "NO_GUID" in proc.identity_basis


def test_a_bare_pid_is_never_presented_as_stable_identity():
    row = _row(image=None, process=None)
    proc = c.process_instances([row], EP)[0]
    assert proc.identity_authority == m.AUTHORITY_UNSTABLE


def test_authoritative_identity_cannot_be_claimed_without_a_guid():
    with pytest.raises(ValueError):
        m.ProcessInstance(process_iid="p", endpoint_id=EP,
                          identity_authority=m.AUTHORITY_AUTHORITATIVE,
                          identity_basis="made_up")


def test_a_process_without_termination_evidence_has_no_end():
    proc = c.process_instances([_row()], EP)[0]
    assert proc.exit_observed is False and proc.end_time is None
    with pytest.raises(ValueError):
        m.ProcessInstance(process_iid="p", endpoint_id=EP,
                          identity_authority=m.AUTHORITY_DERIVED,
                          identity_basis="b", exit_observed=False,
                          end_time="2026-09-27T10:05:00+00:00")


# ── H/I · attribution ─────────────────────────────────────────────────
def test_an_artifact_acted_on_by_a_process_is_attributed():
    row = _row(event_type="file_write", lane_group="FILE",
               file=r"C:\Temp\script.ps1")
    art = c._artifact_of(row, EP)
    assert art.attribution_state == "ATTRIBUTED"
    assert art.attributed_process_iid == "p_child"


def test_an_artifact_without_a_process_binding_is_kept_as_unattributed():
    row = _row(event_type="file_write", lane_group="FILE",
               file=r"C:\Temp\orphan.bin", process_iid=None,
               parent_process_iid=None)
    art = c._artifact_of(row, EP)
    assert art is not None, "evidence without a relationship is still evidence"
    assert art.attribution_state == m.UNATTRIBUTED
    assert art.attributed_process_iid is None
    window = c.build(_v1([row]), endpoint_id=EP)
    assert len(window.artifacts) == 1 and len(window.observations) == 1


# ── J-N · evidence-backed edges ───────────────────────────────────────
@pytest.mark.parametrize("kind,group,payload,expect", [
    ("file_write", "FILE", {"file": r"C:\Temp\a.ps1"}, m.REL_PROCESS_FILE),
    ("registry_value_set", "REGISTRY", {"entity": r"HKLM\Run\x"},
     m.REL_PROCESS_REGISTRY),
    ("dns_query", "DNS", {"entity": "example.com"}, m.REL_PROCESS_DNS),
    ("network_connect", "NETWORK", {"network": "203.0.113.7:443"},
     m.REL_PROCESS_NETWORK),
])
def test_process_to_object_edges_are_derived_from_actor_binding(
        kind, group, payload, expect):
    rels = c.relationships([_row(event_type=kind, lane_group=group,
                                 **payload)], EP)
    edge = next(r for r in rels if r.relationship_type == expect)
    assert edge.derivation_basis == m.BASIS_ACTOR_BINDING
    assert edge.evidence_ref and edge.source_id == "p_child"


def test_process_to_process_edge_uses_reported_parent_identity():
    edge = next(r for r in c.relationships([_row()], EP)
                if r.relationship_type == m.REL_PROCESS_PROCESS)
    assert edge.source_id == "p_parent" and edge.target_id == "p_child"
    assert edge.derivation_basis == m.BASIS_PARENT_IDENTITY
    assert any(ref.kind == "RAW_EVENT" for ref in edge.evidence_ref)


# ── O · owner decision: 4624 with no process binding ──────────────────
def test_auth_without_a_process_binding_gets_no_process_edge():
    row = _row(event_type="logon_success", lane_group="AUTHENTICATION",
               process=None, process_iid=None, parent_process_iid=None,
               user="LAB\\alice")
    rels = c.relationships([row], EP)
    assert not any(r.relationship_type == m.REL_PROCESS_AUTH for r in rels)
    assert rels == [], "no binding means no edge"
    window = c.build(_v1([row]), endpoint_id=EP)
    assert window.observations[0].activity_class == "AUTHENTICATION"
    assert window.observations[0].attribution_state == m.UNATTRIBUTED


# ── P/Q · detection edges ─────────────────────────────────────────────
def test_detection_to_observation_edge_is_emitted_with_evidence():
    row = _row(is_detection=True, rule_id="RULE-1",
               detection={"finding_id": "find_1", "engine": "deterministic"})
    rels = c.relationships([row], EP)
    obs_edge = next(r for r in rels
                    if r.relationship_type == m.REL_DETECTION_OBSERVATION)
    assert obs_edge.derivation_basis == m.BASIS_DETECTION_EVIDENCE
    proc_edge = next(r for r in rels
                     if r.relationship_type == m.REL_DETECTION_PROCESS)
    assert proc_edge.target_id == "p_child"


def test_detection_process_edge_is_absent_without_a_process_instance():
    row = _row(is_detection=True, rule_id="RULE-1", process_iid=None,
               parent_process_iid=None,
               detection={"finding_id": "find_1"})
    rels = c.relationships([row], EP)
    assert any(r.relationship_type == m.REL_DETECTION_OBSERVATION
               for r in rels)
    assert not any(r.relationship_type == m.REL_DETECTION_PROCESS
                   for r in rels)


def test_a_detection_marker_is_separate_from_the_observation():
    row = _row(is_detection=True, rule_id="RULE-1", mitre=["T1059.001"],
               detection={"finding_id": "find_1", "engine": "deterministic"})
    marker = c.detections([row], EP)[0]
    assert marker.detection_id == "find_1"
    assert marker.observation_ids == ("obs_1",)
    assert marker.mitre_authority == m.AUTHORITY_DERIVED, \
        "NivXForge-derived ATT&CK must not masquerade as Windows telemetry"
    window = c.build(_v1([row]), endpoint_id=EP)
    assert window.observations[0].disposition == row["disposition"]


def test_a_detection_process_binding_needs_a_stated_authority():
    with pytest.raises(ValueError):
        m.DetectionMarker(detection_id="d", endpoint_id=EP,
                          detected_at=None, evaluation_state="MATCHED",
                          process_iid="p_child",
                          process_binding_authority=m.AUTHORITY_UNKNOWN)


# ── R/S · the forbidden edge ──────────────────────────────────────────
def test_a_relationship_without_evidence_is_rejected():
    with pytest.raises(ValueError, match="evidence_ref"):
        m.Relationship(relationship_id="r",
                       relationship_type=m.REL_PROCESS_FILE,
                       source_id="p", target_id="f", endpoint_id=EP,
                       derivation_basis=m.BASIS_ACTOR_BINDING,
                       authority=m.AUTHORITY_AUTHORITATIVE,
                       evidence_ref=())


@pytest.mark.parametrize("basis", ["TEMPORAL_PROXIMITY",
                                   "TIMESTAMP_PROXIMITY_WITHIN_2S",
                                   "SAME_USERNAME", "SAME_FILENAME",
                                   "LOOSE_PID_MATCH", "VISUAL_ADJACENCY"])
def test_a_proximity_derived_edge_is_rejected(basis):
    with pytest.raises(ValueError, match="forbidden derivation_basis"):
        m.Relationship(relationship_id="r",
                       relationship_type=m.REL_PROCESS_NETWORK,
                       source_id="p", target_id="n", endpoint_id=EP,
                       derivation_basis=basis,
                       authority=m.AUTHORITY_AUTHORITATIVE,
                       evidence_ref=(m.EvidenceReference(kind="RAW_EVENT",
                                                         id="raw_1"),))


# ── T · density is navigation, not a verdict ──────────────────────────
def test_density_carries_no_severity():
    buckets = c.density([_row()], "2026-09-27T00:00:00+00:00",
                        "2026-09-27T23:59:59+00:00")
    assert buckets, "density should be produced for observed activity"
    fields = set(vars(buckets[0]))
    assert not fields & {"severity", "disposition", "risk", "score"}
    assert buckets[0].semantics == "NAVIGATION_ONLY_NOT_SEVERITY"
    assert {b.stream for b in buckets} >= {"events", "process"}


# ── U/V/W/X/Y · coverage and retention truth ──────────────────────────
def test_retention_is_never_manufactured_as_not_collected():
    w = c.build(_v1([_row()]), endpoint_id=EP,
                requested_start="2026-08-28T00:00:00+00:00",
                requested_end="2026-09-27T23:59:59+00:00")
    assert w.retention_boundary["state"] == m.AVAIL_UNKNOWN
    states = {i.state for i in w.coverage}
    assert m.COV_NOT_COLLECTED not in states, \
        "a short retention must not be reported as 23 days of NOT_COLLECTED"
    assert m.COV_UNKNOWN in states and m.COV_OBSERVED in states
    assert w.available_range["from"] == "2026-09-27T10:00:00+00:00"


def test_an_empty_window_is_unknown_not_proof_of_absence():
    w = c.build(_v1([]), endpoint_id=EP, requested_start="a", requested_end="b")
    interval = w.coverage[0]
    assert interval.state == m.COV_UNKNOWN
    assert interval.absence_inferable is False
    assert "not proof of absence" in (interval.reason or "")


def test_not_collected_requires_proof():
    with pytest.raises(ValueError, match="requires proof"):
        m.CoverageInterval(state=m.COV_NOT_COLLECTED, start=None, end=None,
                           authority="guess", boundary_certainty="UNKNOWN",
                           absence_inferable=False)
    ok = m.CoverageInterval(
        state=m.COV_NOT_COLLECTED, start=None, end=None,
        authority="COLLECTION_POLICY", boundary_certainty="PROVEN",
        absence_inferable=False,
        proof_ref=(m.EvidenceReference(kind="POLICY", id="pol_1"),))
    assert ok.state == m.COV_NOT_COLLECTED


def test_absence_may_only_be_inferred_from_not_observed():
    with pytest.raises(ValueError, match="absence"):
        m.CoverageInterval(state=m.COV_UNKNOWN, start=None, end=None,
                           authority="a", boundary_certainty="UNKNOWN",
                           absence_inferable=True)


def test_an_unsupported_windows_event_stays_unsupported():
    row = _row(event_type="detection", lane_group="OTHER",
               process=None, process_iid=None, parent_process_iid=None,
               provenance={"raw_event_id": "raw_5379",
                           "canonical_event_id": None,
                           "parser_state": "WINDOWS_EVENT_ID_NOT_SUPPORTED",
                           "source": "security"})
    w = c.build(_v1([row]), endpoint_id=EP)
    obs = w.observations[0]
    assert obs.support_state == m.COV_NOT_CANONICALIZED
    assert obs.activity_class is None, "never stamped with a made-up class"
    assert obs.raw_evidence_ref.id == "raw_5379"
    assert any(i.state == m.COV_NOT_CANONICALIZED for i in w.coverage)
    assert w.relationships == []


# ── Z/AA/AB/AC · focus contract ───────────────────────────────────────
def test_focus_resolves_an_exact_evidence_id():
    res = c.resolve_focus(m.FocusTarget(kind="raw_event_id", value="raw_1"),
                          [_row()])
    assert res.state == m.FOCUS_RESOLVED
    assert res.observation_id == "obs_1" and res.basis == "EXACT_EVIDENCE_ID"


def test_focus_reports_ambiguity_instead_of_guessing():
    rows = [_row(), _row(event_iid="obs_2")]
    res = c.resolve_focus(m.FocusTarget(kind="raw_event_id", value="raw_1"),
                          rows)
    assert res.state == m.FOCUS_AMBIGUOUS


def test_focus_reports_missing_evidence_instead_of_a_generic_fallback():
    res = c.resolve_focus(m.FocusTarget(kind="canonical_event_id",
                                        value="nope"), [_row()])
    assert res.state == m.FOCUS_EVIDENCE_MISSING
    assert res.observation_id is None


def test_timestamp_only_focus_is_labelled_as_such():
    res = c.resolve_focus(m.FocusTarget(kind="timestamp",
                                        value="2026-09-27T10:00:00+00:00"),
                          [_row()])
    assert res.state == m.FOCUS_RESOLVED and res.timestamp_only is True


def test_a_resolved_focus_must_name_what_it_resolved():
    with pytest.raises(ValueError, match="no silent generic fallback"):
        m.FocusResolution(state=m.FOCUS_RESOLVED)


def test_focus_rejects_an_unknown_target_kind():
    with pytest.raises(ValueError):
        m.FocusTarget(kind="vibes", value="x")


# ── AD · provenance chain ─────────────────────────────────────────────
def test_the_provenance_chain_is_traversable_backwards():
    row = _row(is_detection=True, rule_id="RULE-1",
               detection={"finding_id": "find_1"})
    w = c.build(_v1([row]), endpoint_id=EP)
    det = w.detections[0]
    obs_id = det.observation_ids[0]
    obs = next(o for o in w.observations if o.observation_id == obs_id)
    assert obs.canonical_evidence_ref.id == "can_1"
    assert obs.raw_evidence_ref.id == "raw_1"
    assert obs.raw_evidence_ref.byte_preserved is True
    edge = next(r for r in w.relationships
                if r.relationship_type == m.REL_DETECTION_OBSERVATION)
    assert any(ref.kind == "CANONICAL_EVENT" for ref in edge.evidence_ref)


# ── AG · no write side effect / axis / cursor ─────────────────────────
def test_the_contract_layer_touches_no_datastore():
    import inspect
    for mod in (c, m):
        src = inspect.getsource(mod)
        for forbidden in ("insert_one", "update_one", "delete_one",
                          "insert_many", "update_many", "delete_many",
                          "find_one", "aggregate(", "sync_collection"):
            assert forbidden not in src, f"{mod.__name__} touches {forbidden}"
    assert c.build(_v1([_row()]),
                   endpoint_id=EP).provenance["creates_no_store"] is True


def test_the_axis_declares_its_mode():
    v1 = _v1([_row()])
    assert c.build(v1, endpoint_id=EP).axis.mode == "ENDPOINT_INVARIANT"
    v1["projection"]["axis_scope"] = "FILTER_SCOPED_ROWS_WITH_MATCHING_ACTIVITY"
    assert c.build(v1, endpoint_id=EP).axis.mode == "FILTER_SCOPED"


def test_a_malformed_cursor_is_rejected():
    with pytest.raises(ValueError):
        m.TrajectoryCursor.parse({"timestamp": "2026-09-27T10:00:00+00:00"})
    cur = m.TrajectoryCursor.parse({"timestamp": "t", "event_iid": "obs_1"})
    assert cur.event_iid == "obs_1"


def test_unavailable_is_not_reported_as_empty():
    w = c.build(_v1([_row()]), endpoint_id=EP)
    assert w.availability["process_end_evidence"] == m.AVAIL_UNAVAILABLE
    assert w.availability["signer_evidence"] == m.AVAIL_UNAVAILABLE
    assert w.availability["observations"] == m.AVAIL_AVAILABLE
    assert c.build(_v1([]), endpoint_id=EP).availability["observations"] \
        == m.AVAIL_EMPTY


# ── AI · the route stays additive even if the contract fails ──────────
def test_the_route_wires_the_contract_additively():
    import routers.edr as edr_router
    src = __import__("inspect").getsource(
        edr_router.endpoint_trajectory_window)
    assert "dt2.augment(out" in src
    assert "DT2_CONTRACT_UNAVAILABLE" in src, \
        "a V2 contract failure must never take the V1 surface down"
