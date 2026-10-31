"""Attack-Posture Normalizer · regression tests.

Locks the contract:
    · derives posture ONLY from ``mitre_techniques`` (never raw evidence)
    · empty / no-MITRE outcome → no confirmed posture
    · T1486 present → impact confirmed
    · unknown techniques → no false posture
    · deterministic + idempotent
    · never invents MITRE techniques
"""
from __future__ import annotations

import copy

from services.mitigation.evidence_driven.investigation_outcome import (
    empty_outcome,
)
from services.mitigation.evidence_driven.attack_posture_normalizer import (
    TECHNIQUE_TO_TACTIC,
    derive_posture_from_mitre,
    normalize_attack_posture,
)


# ── Basic derivation ────────────────────────────────────────────────
def test_empty_outcome_yields_no_confirmed_posture():
    o = normalize_attack_posture(empty_outcome())
    for tactic, status in o["attack_posture"].items():
        assert status == "not_observed", (
            f"normalizer invented posture for {tactic}={status}")


def test_no_mitre_field_yields_no_confirmed_posture():
    outcome = empty_outcome()
    outcome["output_text"] = ("vssadmin delete shadows /all /quiet\n"
                                "Invoke-Mimikatz -DumpCreds")
    outcome["behaviors"]   = ["execution", "impact", "credential_access"]
    outcome["impacts"]     = ["data_encrypted", "credential_exposed"]
    outcome["mitre_techniques"] = []          # explicitly none
    o = normalize_attack_posture(outcome)
    for tactic, status in o["attack_posture"].items():
        assert status == "not_observed", (
            f"normalizer read a non-MITRE field to fill posture: "
            f"{tactic}={status}")


def test_t1486_confirms_impact():
    outcome = empty_outcome()
    outcome["mitre_techniques"] = ["T1486"]
    o = normalize_attack_posture(outcome)
    assert o["attack_posture"]["impact"] == "confirmed"
    # Nothing else changes.
    for tactic, status in o["attack_posture"].items():
        if tactic != "impact":
            assert status == "not_observed"


def test_unknown_technique_does_not_confirm_any_tactic():
    outcome = empty_outcome()
    outcome["mitre_techniques"] = ["T9999", "TXXX.001", "not-a-technique"]
    o = normalize_attack_posture(outcome)
    for tactic, status in o["attack_posture"].items():
        assert status == "not_observed", (
            f"unknown technique confirmed tactic {tactic}={status}")


def test_normalizer_never_reads_output_text():
    """Even a rich ``output_text`` that clearly demonstrates
    ransomware behaviour must NOT influence posture — the normalizer
    only reads ``mitre_techniques``."""
    outcome = empty_outcome()
    outcome["output_text"] = (
        "vssadmin delete shadows /all /quiet\n"
        "cipher /w:C:\\\n"
        "wbadmin delete catalog -quiet\n"
        "bcdedit /set {default} bootstatuspolicy ignoreallfailures"
    )
    outcome["mitre_techniques"] = []
    o = normalize_attack_posture(outcome)
    assert o["attack_posture"]["impact"] == "not_observed"


def test_normalizer_never_invents_mitre_techniques():
    """The normalizer's job is to READ ``mitre_techniques`` — it may
    NEVER add, remove, or mutate the list."""
    outcome = empty_outcome()
    outcome["mitre_techniques"] = ["T1486", "T1490"]
    original = list(outcome["mitre_techniques"])
    o = normalize_attack_posture(outcome)
    assert o["mitre_techniques"] == original
    # Input dict is not mutated either
    assert outcome["mitre_techniques"] == original


def test_normalizer_is_deterministic():
    outcome = empty_outcome()
    outcome["mitre_techniques"] = ["T1486", "T1003", "T1059.001",
                                       "T1021.002", "T1071.001"]
    a = normalize_attack_posture(outcome)
    b = normalize_attack_posture(outcome)
    assert a == b


def test_normalizer_is_idempotent():
    """Running the normalizer twice yields the same result."""
    outcome = empty_outcome()
    outcome["mitre_techniques"] = ["T1486", "T1003", "T1059.001"]
    once  = normalize_attack_posture(outcome)
    twice = normalize_attack_posture(once)
    assert once == twice


def test_normalizer_preserves_existing_meaningful_posture():
    """If Workspace already asserted ``confirmed``/``strong`` for a
    tactic, the normalizer must NOT downgrade it — it only upgrades
    ``not_observed`` / missing values."""
    outcome = empty_outcome()
    outcome["mitre_techniques"] = []          # no MITRE to derive from
    outcome["attack_posture"]["impact"]           = "strong"
    outcome["attack_posture"]["credential_access"] = "confirmed"
    o = normalize_attack_posture(outcome)
    assert o["attack_posture"]["impact"]            == "strong"
    assert o["attack_posture"]["credential_access"] == "confirmed"


def test_derive_helper_is_pure_lookup():
    """``derive_posture_from_mitre`` only knows the static
    technique→tactic map — nothing else."""
    d = derive_posture_from_mitre(["T1486", "T1003", "TXXX"])
    assert d == {"impact": "confirmed", "credential_access": "confirmed"}


def test_derive_helper_handles_empty():
    assert derive_posture_from_mitre([]) == {}
    assert derive_posture_from_mitre(None) == {}


def test_talos_ransomware_technique_set_yields_full_kill_chain():
    """The 19 techniques Talos enumerated for the ransomware case
    map to the expected tactic surface — this is the acceptance
    fixture from the P0 review."""
    outcome = empty_outcome()
    outcome["mitre_techniques"] = [
        "T1656", "T1219.002", "T1053.005",
        "T1016", "T1018", "T1033",
        "T1090.002", "T1021.001", "T1531",
        "T1562.001", "T1039", "T1486",
        "T1082", "T1112", "T1047",
        "T1569.002", "T1021.002",
        "T1059.001", "T1218.007",
    ]
    o = normalize_attack_posture(outcome)
    p = o["attack_posture"]
    for tactic in ("initial_access", "execution", "discovery",
                     "defense_evasion", "lateral_movement",
                     "collection", "command_and_control", "impact"):
        assert p[tactic] == "confirmed", (
            f"talos technique set failed to confirm {tactic}")
    # Credential-access absent because no T1003 in the set.
    assert p["credential_access"] == "not_observed"
    # No exfiltration technique in the set either.
    assert p["exfiltration"] == "not_observed"


def test_normalizer_does_not_mutate_input():
    outcome = empty_outcome()
    outcome["mitre_techniques"] = ["T1486"]
    original = copy.deepcopy(outcome)
    normalize_attack_posture(outcome)
    assert outcome == original, "normalizer mutated its input dict"


def test_map_contains_only_valid_atttck_ids():
    """Sanity: every key looks like a MITRE ID (T####[.###])."""
    import re
    pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
    for tid in TECHNIQUE_TO_TACTIC:
        assert pattern.match(tid), f"non-MITRE id in map: {tid}"


def test_map_values_are_canonical_tactic_slugs():
    """Every value is a recognized ATT&CK tactic slug."""
    valid = {
        "initial_access", "execution", "persistence",
        "privilege_escalation", "defense_evasion", "credential_access",
        "discovery", "lateral_movement", "collection",
        "command_and_control", "exfiltration", "impact",
    }
    for tid, tactic in TECHNIQUE_TO_TACTIC.items():
        assert tactic in valid, (
            f"{tid} maps to unknown tactic {tactic!r}")


def test_t1027_013_maps_to_defense_evasion():
    """P0.2 · Track C · T1027.013 (Encrypted/Encoded File) is a
    2024-added ATT&CK sub-technique the UAIE crypto_shape_detector
    emits.  It must map to defense_evasion so posture is complete."""
    outcome = empty_outcome()
    outcome["mitre_techniques"] = ["T1027.013"]
    o = normalize_attack_posture(outcome)
    assert o["attack_posture"]["defense_evasion"] == "confirmed"


def test_t1027_009_maps_to_defense_evasion():
    """P0.2 · Track C · T1027.009 (Embedded Payloads) is the sub-
    technique the UAIE pe_extractor emits."""
    outcome = empty_outcome()
    outcome["mitre_techniques"] = ["T1027.009"]
    o = normalize_attack_posture(outcome)
    assert o["attack_posture"]["defense_evasion"] == "confirmed"
