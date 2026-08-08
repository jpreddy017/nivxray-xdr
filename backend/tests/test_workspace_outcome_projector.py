"""Workspace → InvestigationOutcome projector acceptance tests.

Locks the projection-only contract:
    · no new detection
    · no re-analysis
    · no field invention
    · no tactic derivation (that lives in the posture normalizer)
"""
from __future__ import annotations

from services.mitigation.evidence_driven.workspace_projector import (
    project_workspace_ssot,
)
from services.mitigation.evidence_driven.attack_posture_normalizer import (
    normalize_attack_posture,
)
from services.mitigation.evidence_driven.investigation_outcome import (
    empty_outcome, INVESTIGATION_OUTCOME_SCHEMA_VERSION,
)
from services.mitigation.evidence_driven.engine import (
    evidence_driven_recommendations,
)


def test_projector_empty_ssot_returns_default_outcome():
    o = project_workspace_ssot({})
    assert o["schema_version"] == INVESTIGATION_OUTCOME_SCHEMA_VERSION
    assert o["mitre_techniques"] == []
    # Every tactic starts at not_observed
    for t, v in o["attack_posture"].items():
        assert v == "not_observed", f"{t} != not_observed"


def test_projector_does_not_derive_posture_from_mitre():
    """POST P0.1 — the projector is now pure field-copy.  Even when
    the SSOT supplies MITRE techniques, the projector must NOT
    derive tactic posture — that belongs to the downstream
    ``attack_posture_normalizer``."""
    ssot = {
        "mitre": ["T1486", "T1490", "T1003", "T1059.001", "T1021.002"],
    }
    o = project_workspace_ssot(ssot)
    # MITRE techniques passed through verbatim.
    assert o["mitre_techniques"] == sorted(ssot["mitre"])
    # Posture is DELIBERATELY all not_observed at the projector
    # boundary — normalizer will fill it later.
    for tactic, status in o["attack_posture"].items():
        assert status == "not_observed", (
            f"projector derived posture — {tactic}={status} — "
            "posture derivation must live in the normalizer")


def test_projector_passes_through_workspace_asserted_posture():
    """If the SSOT itself already asserts a posture (e.g. Workspace
    wants to force ``confirmed``), the projector preserves it
    verbatim.  This is field-copy, not derivation."""
    ssot = {
        "attack_posture": {
            "impact":            "confirmed",
            "credential_access": "strong",
        },
    }
    o = project_workspace_ssot(ssot)
    assert o["attack_posture"]["impact"]            == "confirmed"
    assert o["attack_posture"]["credential_access"] == "strong"
    # Unrelated tactics stay at not_observed
    assert o["attack_posture"]["exfiltration"]      == "not_observed"


def test_projector_is_projection_only_never_derives_mitre():
    """The projector MUST NOT invent MITRE techniques from
    ``output_text`` — that is the investigation engine's job."""
    ssot = {
        "output_text": "vssadmin delete shadows /all /quiet\n"
                        "Invoke-Mimikatz -DumpCreds",
        # No ``mitre`` field, no ``behaviors`` field
    }
    o = project_workspace_ssot(ssot)
    assert o["mitre_techniques"] == [], (
        "projector invented MITRE from output text — "
        f"got {o['mitre_techniques']}")
    for t, v in o["attack_posture"].items():
        assert v == "not_observed"


def test_projector_plus_normalizer_produces_talos_posture():
    """End-to-end · SSOT → projector → normalizer.  The Talos
    ransomware engagement (19 confirmed techniques) surfaces the
    correct kill-chain posture ONLY after the normalizer runs.
    The projector alone leaves posture empty."""
    ssot = {
        "verdict": {"severity": "critical", "one_liner": "Ransomware"},
        "mitre": ["T1656", "T1219.002", "T1053.005",
                    "T1016", "T1018", "T1033",
                    "T1090.002", "T1021.001", "T1531",
                    "T1562.001", "T1039", "T1486",
                    "T1082", "T1112", "T1047",
                    "T1569.002", "T1021.002",
                    "T1059.001", "T1218.007"],
        "behaviors": ["execution", "impact", "credential_access",
                        "c2", "lateral_movement", "discovery",
                        "defense_evasion", "collection"],
        "impacts": ["data_encrypted", "recovery_inhibited"],
        "iocs": {"ip": ["185.220.101.5"]},
        "detection_confidence": "high",
    }
    projected = project_workspace_ssot(ssot)
    # Projector output has posture ALL not_observed
    for t, v in projected["attack_posture"].items():
        assert v == "not_observed"

    # Only after normalization does posture reflect the kill chain.
    o = normalize_attack_posture(projected)
    p = o["attack_posture"]
    for tactic in ("initial_access", "execution", "discovery",
                     "defense_evasion",
                     "lateral_movement", "collection",
                     "command_and_control", "impact"):
        assert p[tactic] == "confirmed", (
            f"expected {tactic} == confirmed, got {p[tactic]}")
    # Credential-access is NOT confirmed for Talos — the article
    # doesn't establish LSASS/Mimikatz activity, so no T1003
    # technique was surfaced.  The normalizer must therefore leave
    # the tactic at ``not_observed`` — no invention.
    assert p["credential_access"] == "not_observed"


def test_projector_output_feeds_engine_and_produces_disjoint_recs():
    """Full end-to-end: SSOT → projector → normalizer → engine.
    The eSentire vs Talos SSOTs must still produce disjoint rules."""
    esentire_ssot = {
        "behaviors": ["c2"],
        "lolbas_hits": ["certutil.exe"],
        "iocs": {"urls": ["http://attacker.example.com/edge.zip"]},
        "mitre": ["T1219.002"],
        "detection_confidence": "medium",
    }
    talos_ssot = {
        "behaviors": ["execution", "impact", "credential_access", "c2"],
        "mitre": ["T1486", "T1490", "T1003"],
        "impacts": ["data_encrypted", "recovery_inhibited",
                     "credential_exposed"],
        "iocs": {"ips": ["185.220.101.5"]},
        "detection_confidence": "high",
    }
    a = normalize_attack_posture(project_workspace_ssot(esentire_ssot))
    b = normalize_attack_posture(project_workspace_ssot(talos_ssot))
    a_ids = {r["id"] for r in evidence_driven_recommendations(
                                    investigation_outcome=a
                                )["recommendations"]}
    b_ids = {r["id"] for r in evidence_driven_recommendations(
                                    investigation_outcome=b
                                )["recommendations"]}
    assert a_ids, "eSentire projection produced zero recs"
    assert b_ids, "Talos projection produced zero recs"
    assert not (a_ids & b_ids), (
        f"projector-fed engine produced shared rules: {sorted(a_ids & b_ids)}")
    # Talos gets impact-family recommendations
    assert "erad.reimage_ransomware" in b_ids
    assert "erad.protect_shadow_copies" in b_ids
    # eSentire gets LOLBAS + URL block
    assert any(i.startswith("contain.block_url:") for i in a_ids)
    assert "harden.lolbas_allowlist" in a_ids


def test_technique_to_tactic_map_is_dense_enough():
    """Regression guard — the normalizer's technique→tactic map
    covers every technique currently referenced in the rule library
    so no fired rule is orphaned from the posture view."""
    from services.mitigation.evidence_driven import rule_library
    from services.mitigation.evidence_driven.attack_posture_normalizer import (
        TECHNIQUE_TO_TACTIC,
    )
    rule_techniques = set()
    for group in ("INVESTIGATE_RULES", "HUNT_RULES", "CONTAIN_RULES",
                    "ERADICATE_RULES", "RECOVER_RULES", "HARDEN_RULES"):
        for r in getattr(rule_library, group, []):
            rule_techniques.update(r.mitre or ())
    missing = rule_techniques - set(TECHNIQUE_TO_TACTIC.keys())
    assert not missing, (
        "rule_library references techniques not in the posture map: "
        f"{sorted(missing)}")
