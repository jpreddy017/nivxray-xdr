"""Workspace State model · determinism + persistence-contract tests."""
from __future__ import annotations

import pytest

from l2_investigation.state import InvestigationState
from l2_investigation.workspace_state import (
    WorkspaceLens,
    WorkspaceMode,
    WorkspaceState,
    default_lens_for,
)


def test_initial_state_defaults():
    s = WorkspaceState.initial("c1")
    assert s.case_id == "c1"
    assert s.mode is WorkspaceMode.INVESTIGATION
    assert s.active_lens is WorkspaceLens.SUMMARY
    assert s.investigation_state is InvestigationState.NEW


@pytest.mark.parametrize(
    "mode,expected_lens",
    [
        (WorkspaceMode.QUICK_TRIAGE, WorkspaceLens.SUMMARY),
        (WorkspaceMode.INVESTIGATION, WorkspaceLens.SUMMARY),
        (WorkspaceMode.DEEP_ANALYSIS, WorkspaceLens.EVIDENCE),
    ],
)
def test_default_lens_matches_blueprint_table(mode, expected_lens):
    assert default_lens_for(mode) is expected_lens
    assert WorkspaceState.initial("c", mode=mode).active_lens is expected_lens


def test_roundtrip_dict_is_fixed_point():
    a = WorkspaceState(
        case_id="c",
        mode=WorkspaceMode.DEEP_ANALYSIS,
        active_lens=WorkspaceLens.EVIDENCE,
        scroll_positions={"evidence": 420, "story": 12},
        selected_evidence_id="ioc-001",
        filters={"mitre": ["T1059.001"], "hide_noise": True},
        timeline_position=7,
        investigation_state=InvestigationState.REVIEWING,
    )
    b = WorkspaceState.from_dict(a.to_dict())
    assert a.to_dict() == b.to_dict()
    assert a.fingerprint == b.fingerprint


def test_fingerprint_stable_across_instances():
    a = WorkspaceState.initial("c1")
    b = WorkspaceState.initial("c1")
    assert a.fingerprint == b.fingerprint


def test_fingerprint_changes_on_mode_switch():
    a = WorkspaceState.initial("c1", mode=WorkspaceMode.QUICK_TRIAGE)
    b = WorkspaceState.initial("c1", mode=WorkspaceMode.DEEP_ANALYSIS)
    assert a.fingerprint != b.fingerprint


def test_filters_canonicalization_is_order_independent():
    a = WorkspaceState(case_id="c", filters={"b": 1, "a": 2, "c": {"z": 1, "a": 0}})
    b = WorkspaceState(case_id="c", filters={"a": 2, "c": {"a": 0, "z": 1}, "b": 1})
    assert a.to_json() == b.to_json()
    assert a.fingerprint == b.fingerprint


def test_all_persistence_fields_present_per_blueprint_8_3():
    required = {
        "case_id", "mode", "active_lens", "scroll_positions",
        "selected_evidence_id", "filters", "timeline_position",
        "investigation_state",
    }
    assert set(WorkspaceState.initial("c").to_dict()) == required
