"""COMPROMISE / IOC CONTRIBUTOR CONTRACT — refusal is the feature.

Pins the architectural distinction: `event.kind` is what was OBSERVED, a
detection is what a detection engine CONCLUDED, and a compromise is what
an authoritative correlation / IOC mechanism concluded. Contributor
membership comes from that authority and from nowhere else.
"""
from __future__ import annotations

import pytest

from edr_plane import compromise_contract as cc


def _detection_derivation(**over):
    doc = {
        "outcome": "DETECTION_MATCHED",
        "derived_at": "2026-09-22T16:20:09.742000+00:00",
        "detection_content_version": "nivxray_native_sigma@1.4.0",
        "event_id": "cev_abc_0",
        "evidence_ids": ["evt_child_1", "evt_child_2"],
        "reason": "rules: win_susp_registry_run_key",
    }
    doc.update(over)
    return doc


# ── A · only an authority may raise a compromise ────────────────────
@pytest.mark.parametrize("authority", sorted(cc.AUTHORITIES))
def test_each_declared_authority_is_accepted(authority):
    ev = cc.CompromiseEvent(
        compromise_event_id="cmp_1", indicator_id="ind_1",
        authority=authority, derivation_basis="ENGINE_STATED_MEMBERSHIP",
        description="d",
        contributing_event_refs=(cc.ContributingEventRef(
            event_iid="evt_1", contribution_basis="ENGINE_NAMED_MEMBER",
            stated_by=authority),))
    assert ev.authority == authority


@pytest.mark.parametrize("bogus", [
    "detection", "kind=detection", "registry_value_set", "frontend",
    "trajectory_ui", "", "   ", "ANALYST", None,
])
def test_a_telemetry_kind_or_a_client_is_never_an_authority(bogus):
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.CompromiseEvent(
            compromise_event_id="cmp_1", indicator_id="ind_1",
            authority=bogus, derivation_basis="X", description="d")
    assert e.value.code == "COMPROMISE_AUTHORITY_INVALID"


# ── B · contributors may never be inferred ──────────────────────────
@pytest.mark.parametrize("basis", sorted(cc.FORBIDDEN_BASES))
def test_no_inferred_contributor_basis_is_accepted(basis):
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.ContributingEventRef(
            event_iid="evt_1", contribution_basis=basis,
            stated_by=cc.AUTHORITY_DETECTION_FABRIC)
    assert e.value.code == "CONTRIBUTOR_BASIS_FORBIDDEN"


@pytest.mark.parametrize("basis", ["temporal_proximity", "Same_Pid",
                                   "ui_proximity", "GUESS"])
def test_forbidden_basis_rejection_is_case_insensitive(basis):
    with pytest.raises(cc.CompromiseContractError):
        cc.ContributingEventRef(
            event_iid="evt_1", contribution_basis=basis,
            stated_by=cc.AUTHORITY_DETECTION_FABRIC)


def test_a_contributor_needs_a_basis_at_all():
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.ContributingEventRef(
            event_iid="evt_1", contribution_basis="",
            stated_by=cc.AUTHORITY_DETECTION_FABRIC)
    assert e.value.code == "CONTRIBUTOR_BASIS_FORBIDDEN"


def test_a_contributor_must_reference_a_real_observation():
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.ContributingEventRef(
            event_iid="", contribution_basis="ENGINE_NAMED_MEMBER",
            stated_by=cc.AUTHORITY_DETECTION_FABRIC)
    assert e.value.code == "CONTRIBUTOR_EVENT_IID_REQUIRED"


def test_forbidden_derivation_basis_is_refused_on_the_compromise_too():
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.CompromiseEvent(
            compromise_event_id="cmp_1", indicator_id="ind_1",
            authority=cc.AUTHORITY_IOC_CORRELATION,
            derivation_basis="TEMPORAL_PROXIMITY", description="d")
    assert e.value.code == "COMPROMISE_BASIS_FORBIDDEN"


def test_a_contributor_named_by_another_mechanism_is_refused():
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.CompromiseEvent(
            compromise_event_id="cmp_1", indicator_id="ind_1",
            authority=cc.AUTHORITY_IOC_CORRELATION,
            derivation_basis="ENGINE_STATED_MEMBERSHIP", description="d",
            contributing_event_refs=(cc.ContributingEventRef(
                event_iid="evt_1", contribution_basis="X",
                stated_by=cc.AUTHORITY_MITRE_EVIDENCE),))
    assert e.value.code == "CONTRIBUTOR_AUTHORITY_MISMATCH"


def test_a_duplicate_contributor_is_refused():
    ref = lambda: cc.ContributingEventRef(
        event_iid="evt_1", contribution_basis="ENGINE_NAMED_MEMBER",
        stated_by=cc.AUTHORITY_IOC_CORRELATION)
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.CompromiseEvent(
            compromise_event_id="cmp_1", indicator_id="ind_1",
            authority=cc.AUTHORITY_IOC_CORRELATION,
            derivation_basis="ENGINE_STATED_MEMBERSHIP", description="d",
            contributing_event_refs=(ref(), ref()))
    assert e.value.code == "CONTRIBUTOR_DUPLICATE"


def test_a_raw_dict_cannot_smuggle_in_an_unvalidated_contributor():
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.CompromiseEvent(
            compromise_event_id="cmp_1", indicator_id="ind_1",
            authority=cc.AUTHORITY_IOC_CORRELATION,
            derivation_basis="ENGINE_STATED_MEMBERSHIP", description="d",
            contributing_event_refs=({"event_iid": "evt_1",
                                      "contribution_basis": "SAME_PID"},))
    assert e.value.code == "CONTRIBUTOR_TYPE_INVALID"


# ── C · missing provenance stays missing ────────────────────────────
def test_proven_and_empty_is_a_contradiction():
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.CompromiseEvent(
            compromise_event_id="cmp_1", indicator_id="ind_1",
            authority=cc.AUTHORITY_IOC_CORRELATION,
            derivation_basis="ENGINE_STATED_MEMBERSHIP", description="d")
    assert e.value.code == "CONTRIBUTORS_CLAIMED_BUT_ABSENT"


def test_an_authority_that_named_no_contributors_is_reported_honestly():
    ev = cc.unproven_contributors(
        compromise_event_id="cmp_1", indicator_id="ind_1",
        authority=cc.AUTHORITY_IOC_CORRELATION,
        derivation_basis="ENGINE_STATED_MEMBERSHIP",
        description="the correlation engine raised this but named no members")
    assert ev.contributors_state == cc.CONTRIBUTORS_NOT_PROVEN
    assert ev.contributing_event_refs == ()
    assert ev.to_dict()["contributing_event_refs"] == []


def test_contributors_cannot_be_listed_and_disclaimed_at_once():
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.CompromiseEvent(
            compromise_event_id="cmp_1", indicator_id="ind_1",
            authority=cc.AUTHORITY_IOC_CORRELATION,
            derivation_basis="ENGINE_STATED_MEMBERSHIP", description="d",
            contributing_event_refs=(cc.ContributingEventRef(
                event_iid="evt_1", contribution_basis="ENGINE_NAMED_MEMBER",
                stated_by=cc.AUTHORITY_IOC_CORRELATION),),
            contributors_state=cc.CONTRIBUTORS_NOT_PROVEN)
    assert e.value.code == "CONTRIBUTORS_PRESENT_BUT_DISCLAIMED"


# ── D · from a real detection derivation ────────────────────────────
def test_detection_derivation_yields_only_the_events_it_named():
    ev = cc.from_detection_derivation(_detection_derivation(),
                                      observation_iid="evt_subject")
    assert ev.authority == cc.AUTHORITY_DETECTION_FABRIC
    assert ev.indicator_id == "nivxray_native_sigma@1.4.0"
    assert [r.event_iid for r in ev.contributing_event_refs] == [
        "evt_subject", "evt_child_1", "evt_child_2"]
    assert ev.contributing_event_refs[0].contribution_basis == \
        "DETECTION_DERIVATION_SUBJECT_OBSERVATION"
    assert ev.contributing_event_refs[1].contribution_basis == \
        "DETECTION_DERIVATION_NAMED_EVIDENCE_ID"
    assert ev.contributors_state == cc.CONTRIBUTORS_PROVEN


def test_a_derivation_naming_nothing_extra_proves_exactly_one_contributor():
    ev = cc.from_detection_derivation(
        _detection_derivation(evidence_ids=[]), observation_iid="evt_subject")
    assert [r.event_iid for r in ev.contributing_event_refs] == ["evt_subject"]


@pytest.mark.parametrize("outcome", [
    "DETECTION_EVALUATED_NO_MATCH", "DETECTION_NOT_EVALUATED",
    "CANONICAL_EVIDENCE_CREATED", "DUPLICATE_OBSERVATION_OF_KNOWN_ACTIVITY",
    "", None,
])
def test_only_a_matched_detection_is_an_authority(outcome):
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.from_detection_derivation(
            _detection_derivation(outcome=outcome),
            observation_iid="evt_subject")
    assert e.value.code == "NOT_A_DETECTION_ATTRIBUTION"


def test_not_evaluated_is_not_clean_and_raises_no_compromise():
    """A detection gap must not become either a compromise or a clean
    claim: the contract simply refuses to produce anything."""
    with pytest.raises(cc.CompromiseContractError):
        cc.from_detection_derivation(
            {"outcome": "DETECTION_NOT_EVALUATED",
             "reason": "the detection fabric could not be reached"},
            observation_iid="evt_subject")


def test_a_derivation_that_names_no_indicator_is_refused():
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.from_detection_derivation(
            _detection_derivation(detection_content_version=None,
                                  event_id=None),
            observation_iid="evt_subject")
    assert e.value.code == "INDICATOR_ID_REQUIRED"


# ── E · from the observation's own MITRE attribution ────────────────
def test_mitre_authority_proves_exactly_one_contributor():
    ev = cc.from_mitre_attributed_evidence(
        observation_iid="evt_subject", techniques=("T1547.001",))
    assert ev.authority == cc.AUTHORITY_MITRE_EVIDENCE
    assert [r.event_iid for r in ev.contributing_event_refs] == ["evt_subject"]
    assert ev.techniques == ("T1547.001",)


def test_mitre_authority_without_a_technique_raises_nothing():
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.from_mitre_attributed_evidence(observation_iid="evt_1",
                                          techniques=())
    assert e.value.code == "MITRE_ATTRIBUTION_ABSENT"


# ── F · MITRE ids are validated, never accepted as prose ────────────
@pytest.mark.parametrize("bad", ["T154", "1547", "T1547.1", "persistence",
                                 "TA0003.001", "T1547.0011"])
def test_a_technique_must_look_like_a_technique(bad):
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.CompromiseEvent(
            compromise_event_id="cmp_1", indicator_id="ind_1",
            authority=cc.AUTHORITY_MITRE_EVIDENCE,
            derivation_basis="OBSERVATION_OWN_MITRE_TECHNIQUE_ATTRIBUTION",
            description="d", techniques=(bad,),
            contributing_event_refs=(cc.ContributingEventRef(
                event_iid="evt_1", contribution_basis="X",
                stated_by=cc.AUTHORITY_MITRE_EVIDENCE),))
    assert e.value.code == "TECHNIQUE_INVALID"


@pytest.mark.parametrize("bad", ["T1547", "persistence", "TA003"])
def test_a_tactic_must_look_like_a_tactic(bad):
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.CompromiseEvent(
            compromise_event_id="cmp_1", indicator_id="ind_1",
            authority=cc.AUTHORITY_MITRE_EVIDENCE,
            derivation_basis="OBSERVATION_OWN_MITRE_TECHNIQUE_ATTRIBUTION",
            description="d", tactics=(bad,),
            contributing_event_refs=(cc.ContributingEventRef(
                event_iid="evt_1", contribution_basis="X",
                stated_by=cc.AUTHORITY_MITRE_EVIDENCE),))
    assert e.value.code == "TACTIC_INVALID"


def test_valid_mitre_ids_are_accepted():
    ev = cc.CompromiseEvent(
        compromise_event_id="cmp_1", indicator_id="ind_1",
        authority=cc.AUTHORITY_MITRE_EVIDENCE,
        derivation_basis="OBSERVATION_OWN_MITRE_TECHNIQUE_ATTRIBUTION",
        description="d", tactics=("TA0003",),
        techniques=("T1547", "T1547.001"),
        contributing_event_refs=(cc.ContributingEventRef(
            event_iid="evt_1", contribution_basis="X",
            stated_by=cc.AUTHORITY_MITRE_EVIDENCE),))
    assert ev.tactics == ("TA0003",)


# ── G · the wire shape a consumer receives ──────────────────────────
def test_the_serialised_contract_carries_every_required_field():
    ev = cc.from_detection_derivation(_detection_derivation(),
                                      observation_iid="evt_subject",
                                      techniques=("T1547.001",))
    doc = ev.to_dict()
    assert set(doc) == {
        "compromise_event_id", "indicator_id", "authority",
        "derivation_basis", "description", "contributors_state",
        "contributing_event_refs", "evidence_refs", "tactics",
        "techniques", "observed_at"}
    assert doc["contributing_event_refs"][0]["stated_by"] == \
        cc.AUTHORITY_DETECTION_FABRIC
    assert doc["techniques"] == ["T1547.001"]


def test_description_is_required_so_a_compromise_always_says_what_it_means():
    with pytest.raises(cc.CompromiseContractError) as e:
        cc.CompromiseEvent(
            compromise_event_id="cmp_1", indicator_id="ind_1",
            authority=cc.AUTHORITY_IOC_CORRELATION,
            derivation_basis="ENGINE_STATED_MEMBERSHIP", description="  ",
            contributing_event_refs=(cc.ContributingEventRef(
                event_iid="evt_1", contribution_basis="X",
                stated_by=cc.AUTHORITY_IOC_CORRELATION),))
    assert e.value.code == "COMPROMISE_DESCRIPTION_REQUIRED"
