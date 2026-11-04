"""
P0.16 · Behavior Knowledge Base (BKB) · regression tests

Locks the invariants of the new static knowledge base that will
become the single source of truth for behavior → MITRE mapping
(per user directive 2026-02-09).
"""
from __future__ import annotations

import pytest

from services.knowledge import behavior_registry as bkb
from services.ice.correlate import tactic_for


def test_registry_has_a_pinned_lower_bound_count():
    # Prevent silent shrinkage.
    assert len(bkb.labels()) >= 80


def test_every_spec_has_at_least_one_technique():
    for label in bkb.labels():
        spec = bkb.lookup(label)
        assert spec.canonical_techniques, f"{label!r} has no canonical techniques"
        for t in spec.canonical_techniques:
            assert t.get("id") and t.get("name")


def test_every_spec_resolves_at_least_one_tactic():
    for label in bkb.labels():
        spec = bkb.lookup(label)
        assert spec.canonical_tactics, f"{label!r} has no canonical tactics"
        # Every technique resolves to a canonical tactic via the ICE
        # tactic_for helper — a spec that references an unknown
        # technique would fail this invariant.
        for t in spec.canonical_techniques:
            assert tactic_for(t["id"]), \
                f"{label!r} references {t['id']} with no tactic resolver"


def test_severity_domain_is_locked():
    for label in bkb.labels():
        assert bkb.lookup(label).severity in ("low", "medium", "high", "critical")


def test_lookup_returns_none_for_unknown_label():
    assert bkb.lookup("this-does-not-exist-123") is None
    assert bkb.lookup("") is None
    assert bkb.lookup(None) is None      # type: ignore[arg-type]


def test_has_matches_lookup():
    for label in bkb.labels():
        assert bkb.has(label)
    assert not bkb.has("nope")


def test_snapshot_is_deterministic_and_json_safe():
    import json
    a = bkb.snapshot()
    b = bkb.snapshot()
    assert a == b
    # Round-trips through JSON without loss.
    assert json.loads(json.dumps(a)) == a


def test_as_purpose_to_mitre_matches_registry_shape():
    view = bkb.as_purpose_to_mitre()
    for label, techs in view.items():
        spec = bkb.lookup(label)
        assert techs == list(spec.canonical_techniques)


# ══════════════════════════════════════════════════════════════════
# Canonical mappings the user has repeatedly flagged as broken
# — these MUST be pinned by this suite.
# ══════════════════════════════════════════════════════════════════
def test_registry_modification_maps_to_defense_evasion_T1112():
    spec = bkb.lookup("Registry modification")
    assert [t["id"] for t in spec.canonical_techniques] == ["T1112"]
    assert list(spec.canonical_tactics) == ["defense_evasion"]


def test_scheduled_task_create_maps_to_execution_T1053_005():
    spec = bkb.lookup("Scheduled Task create")
    assert [t["id"] for t in spec.canonical_techniques] == ["T1053.005"]
    assert list(spec.canonical_tactics) == ["execution"]


def test_hidden_window_ps_carries_execution_and_defense_evasion():
    spec = bkb.lookup("PowerShell hidden window")
    tids = [t["id"] for t in spec.canonical_techniques]
    assert "T1059.001" in tids
    assert "T1564.003" in tids
    tt = list(spec.canonical_tactics)
    assert "execution" in tt
    assert "defense_evasion" in tt


def test_current_user_discovery_maps_to_discovery_T1033():
    spec = bkb.lookup("Current-user discovery")
    assert [t["id"] for t in spec.canonical_techniques] == ["T1033"]
    assert list(spec.canonical_tactics) == ["discovery"]
