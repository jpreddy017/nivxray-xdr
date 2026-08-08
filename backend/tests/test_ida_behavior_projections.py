"""P0.5 · Behavior/Projection separation regression tests.

Locks the framework-independence contract:
    · Behavior schema carries NO framework-specific fields
      (no mitre, no kill_chain_tags, no impact_tags on the object)
    · Every framework mapping lives in ``services.ida.projections.*``
    · Adding a new framework does NOT require editing Behavior
"""
from __future__ import annotations

from dataclasses import fields

from services.ida.behaviors import (
    Behavior, generate_behaviors, collect_outcome_inputs_from_behaviors,
)
from services.ida.projections.mitre       import (
    BEHAVIOR_TO_MITRE, project_to_mitre,
)
from services.ida.projections.kill_chain  import (
    BEHAVIOR_TO_KILL_CHAIN, project_to_kill_chain,
)
from services.ida.projections.impact      import (
    BEHAVIOR_TO_IMPACTS, project_to_impacts,
)


# ══════════════════════════════════════════════════════════════════
# Framework-independence contract
# ══════════════════════════════════════════════════════════════════
def test_behavior_has_no_framework_specific_fields():
    """Behavior must NOT carry mitre / kill_chain / impact tags.
    Framework projections are external."""
    field_names = {f.name for f in fields(Behavior)}
    for banned in ("mitre", "kill_chain_tags", "impact_tags",
                     "attck_id", "attck_ids", "d3fend", "nist"):
        assert banned not in field_names, (
            f"Behavior schema leaks framework field {banned!r}")


def test_behavior_minimal_field_set():
    """Behavior fields are the framework-neutral semantic set only."""
    field_names = {f.name for f in fields(Behavior)}
    expected = {
        "behavior_type", "label", "source", "source_ref",
        "provenance", "confidence", "evidence",
    }
    assert field_names == expected, (
        f"Behavior schema drift · fields={sorted(field_names)}")


def test_projections_are_independent_modules():
    """Every projection lives in its own module and is a pure
    lookup — adding a new framework requires no Behavior edit."""
    import services.ida.projections.mitre       as pm
    import services.ida.projections.kill_chain  as pk
    import services.ida.projections.impact      as pi
    # Every projection exports its map + a project_to_* function.
    assert callable(pm.project_to_mitre)
    assert callable(pk.project_to_kill_chain)
    assert callable(pi.project_to_impacts)
    assert isinstance(pm.BEHAVIOR_TO_MITRE,      dict)
    assert isinstance(pk.BEHAVIOR_TO_KILL_CHAIN, dict)
    assert isinstance(pi.BEHAVIOR_TO_IMPACTS,    dict)


# ══════════════════════════════════════════════════════════════════
# Composition · projections aggregate correctly for the Talos case
# ══════════════════════════════════════════════════════════════════
def _extraction_for_talos_style() -> dict:
    return {
        "commands": [
            {"executable": r"C:\Windows\System32\vssadmin.exe",
             "command":    r"C:\Windows\System32\vssadmin.exe delete shadows /all",
             "line": 37},
            {"executable": r"C:\Windows\System32\OpenSSH\ssh.exe",
             "command":    r"C:\Windows\System32\OpenSSH\ssh.exe -R :12840 -N ... -p 443",
             "line": 13},
        ],
        "malware_families": [{"name": "Medusa"}, {"name": "AnyDesk"}],
        "body_artifacts":   [{"type": "file_path", "value": r"C:\Windows\System32\vssadmin.exe"}],
        "cves":             [{"id": "CVE-2024-57727"}],
    }


def test_project_to_mitre_dedup_and_provenance():
    behaviors = generate_behaviors(_extraction_for_talos_style())
    mitre     = project_to_mitre(behaviors)
    ids = [m["id"] for m in mitre]
    assert len(ids) == len(set(ids)), "MITRE ids not deduped"
    for m in mitre:
        assert m["source"].startswith("ida.behaviors:"), (
            f"missing provenance source on {m}")


def test_project_to_kill_chain_covers_expected_tactics_for_talos():
    behaviors = generate_behaviors(_extraction_for_talos_style())
    kc = set(project_to_kill_chain(behaviors))
    assert "impact"           in kc
    assert "c2"               in kc
    assert "lateral_movement" in kc


def test_project_to_impacts_covers_expected_impact_tags_for_talos():
    behaviors = generate_behaviors(_extraction_for_talos_style())
    imp = set(project_to_impacts(behaviors))
    assert "recovery_inhibited" in imp
    assert "data_encrypted"     in imp


def test_full_outcome_input_composition_matches_individual_projections():
    """The composed aggregator must equal the sum of the individual
    projections — proving it's built by composition, not by
    re-implementing the maps inline."""
    behaviors = generate_behaviors(_extraction_for_talos_style())
    outcome   = collect_outcome_inputs_from_behaviors(behaviors)
    assert outcome["behaviors"]        == project_to_kill_chain(behaviors)
    assert outcome["impacts"]          == project_to_impacts(behaviors)
    assert outcome["mitre_techniques"] == sorted(
        m["id"] for m in project_to_mitre(behaviors))


def test_empty_behaviors_yields_empty_projections():
    assert project_to_mitre([])      == []
    assert project_to_kill_chain([]) == []
    assert project_to_impacts([])    == []
