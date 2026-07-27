"""NivXRay v1.0 · Investigation Brain baseline lock.

Freezes the component set and version identity that constitutes the
v1.0 baseline. Adding a new component or bumping the major version
requires deliberate change to this file — the CI gate prevents
accidental architectural drift.

Per Product Owner directive (2026-07-29):
    "Freeze the core architecture. From now on, evolve the platform
     primarily through real-world corpus expansion, regression-driven
     improvements, analyst workflow enhancements, and report quality."
"""
from __future__ import annotations

from v2.investigation import version


BASELINE_COMPONENTS = frozenset({
    "input_understanding",
    "command_reconstruction_engine",
    "recursive_transformation_engine",
    "semantic_intent_layer",
    "verdict_uplift",
    "evidence_graph",
    "analyst_report",
    "trust_metrics_harness",
})


def test_version_is_v1():
    """The Investigation Brain baseline is v1.x — any move to v2 must
    be an intentional edit to this test."""
    assert version.VERSION.startswith("1."), (
        f"Investigation Brain is locked at v1.x — got {version.VERSION}. "
        "A major-version bump requires deliberate change of this test."
    )


def test_component_set_matches_baseline():
    """The component set is frozen. Adding a component without
    updating this test is a silent architectural drift — blocked."""
    assert set(version.COMPONENTS) == BASELINE_COMPONENTS, (
        f"Investigation Brain component set drifted from baseline.\n"
        f"  expected: {sorted(BASELINE_COMPONENTS)}\n"
        f"  actual:   {sorted(version.COMPONENTS)}\n"
        "New engines are only added when repeated real-world evidence "
        "demonstrates the current architecture cannot model a class of "
        "investigations."
    )


def test_architecture_frozen_flag_is_true():
    assert version.ARCHITECTURE_FROZEN is True


def test_version_string_is_analyst_readable():
    s = version.version_string()
    assert "v1." in s
    assert "Investigation Brain" in s
