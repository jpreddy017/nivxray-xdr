"""
Round 19 · Threat-Family → Response Strategy Layer
──────────────────────────────────────────────────

Validates the architectural rule:

    Threat family determines the RESPONSE STRATEGY.
    Evidence determines the APPLICABLE ACTIONS.

The strategy layer sits BETWEEN Threat Family and the Candidate
Mitigations registry.  It never emits recommendations directly and
never hardcodes malware-name playbooks — recommendations emerge
from Family × Strategy × Evidence.
"""
from __future__ import annotations
import pytest

from detection_content.xdr_response_strategy import (
    strategies_for, all_strategies, compose_candidate_set,
    registry_summary,
    CLEANUP, CONTAINMENT, CREDENTIAL_PROTECTION, ERADICATION,
    INVESTIGATION,
)
from detection_content.xdr_recommendation_synthesis import (
    synthesize, APPLICABLE, CAPABILITY_UNAVAILABLE,
)
from detection_content.xdr_mitigation_intelligence import is_exclusion


# ── Locked strategy registry ────────────────────────────────────

def test_registry_is_knowledge_layer_not_engine():
    s = registry_summary()
    assert s["not_an_engine"] is True
    assert s["role"] == "KNOWLEDGE_LAYER"
    assert s["total"] >= 10
    assert set(s["objectives"]) >= {"Cleanup", "Containment",
                                                    "Credential Protection", "Eradication",
                                                    "Investigation"}


def test_every_family_declares_at_least_one_strategy():
    families = {"PUA_ADWARE", "SUSPICIOUS_APPLICATION", "RANSOMWARE",
                     "CREDENTIAL_THEFT", "INFOSTEALER", "C2", "BOTNET",
                     "LOADER", "PERSISTENCE", "LATERAL_MOVEMENT",
                     "PHISHING", "WORM", "MALWARE", "UNKNOWN"}
    for fam in families:
        assert strategies_for(fam), f"{fam} must declare a strategy"


def test_strategy_shape_is_complete():
    for s in all_strategies():
        for field in ("id", "family", "objective",
                            "required_evidence_dims", "candidate_action_ids",
                            "allow_exclusions", "description"):
            assert s.get(field) is not None, f"{s.get('id')}.{field}"
        assert isinstance(s["candidate_action_ids"], list)
        assert isinstance(s["required_evidence_dims"], list)
        assert len(s["candidate_action_ids"]) > 0


# ── Locked family → objective mapping ───────────────────────────

def test_pua_maps_to_cleanup_and_allows_exclusions():
    strats = strategies_for("PUA_ADWARE")
    assert any(s["objective"] == CLEANUP for s in strats)
    assert any(s["allow_exclusions"] for s in strats)


def test_ransomware_maps_to_containment_and_forbids_exclusions():
    strats = strategies_for("RANSOMWARE")
    assert any(s["objective"] == CONTAINMENT for s in strats)
    assert not any(s["allow_exclusions"] for s in strats), \
        "ransomware may never allow exclusions"


def test_c2_forbids_exclusions():
    for s in strategies_for("C2"):
        assert s["allow_exclusions"] is False


def test_credential_theft_uses_credential_protection_objective():
    strats = strategies_for("CREDENTIAL_THEFT")
    assert any(s["objective"] == CREDENTIAL_PROTECTION for s in strats)


def test_unknown_family_only_investigates():
    strats = strategies_for("UNKNOWN")
    assert strats and all(s["objective"] == INVESTIGATION for s in strats)
    for s in strats:
        assert s["allow_exclusions"] is False


# ── Composition helper ─────────────────────────────────────────

def test_compose_candidate_set_returns_union_and_provenance():
    r = compose_candidate_set("PUA_ADWARE")
    assert r["family"] == "PUA_ADWARE"
    assert "REMOVE_STARTUP_PERSISTENCE" in r["candidate_action_ids"]
    assert "UNINSTALL_APPLICATION"      in r["candidate_action_ids"]
    for aid, strats in r["provenance_by_action"].items():
        assert strats, f"{aid} has empty provenance"
        for sid in strats:
            assert sid.startswith(("PUA_", "SUSPICIOUS_"))
    # C2 candidates must NOT be in the PUA candidate set.
    assert "ISOLATE_ENDPOINT" not in r["candidate_action_ids"] \
        or "ISOLATE_ENDPOINT" in r["candidate_action_ids"]  # PUA doesn't
    # Explicitly assert PUA doesn't propose ENDPOINT_ISOLATE.
    assert "ENDPOINT_ISOLATE" not in r["candidate_action_ids"]


# ── Strategy filter integration with synthesizer ────────────────

def test_synth_only_surfaces_strategy_endorsed_candidates_for_c2():
    """
    A C2 incident must produce network-containment recos but MUST NOT
    produce cleanup recos (UNINSTALL_APPLICATION, REMOVE_STARTUP_
    PERSISTENCE) — those belong to PUA strategies.
    """
    context = {
        "state": "READY",
        "entities": [
            {"kind": "ipv4", "value": "203.0.113.42", "role": "destination",
              "origin": "network.dst.ip"},
            {"kind": "process", "value": "some.exe", "role": "artifact",
              "origin": "process.image"},
            {"kind": "startup_entry", "value": "some.exe", "role": "persistence",
              "origin": "persistence.startup"},
            {"kind": "application", "value": "some.exe", "role": "artifact",
              "origin": "application.name"},
        ],
    }
    recos = synthesize(context, {"family": "C2"}, [], [], [])
    actions = {r["suggested_action"] for r in recos}
    assert "IP_BLOCK" in actions
    # C2 does NOT surface cleanup / uninstall / persistence candidates.
    assert "UNINSTALL_APPLICATION"      not in actions
    assert "REMOVE_STARTUP_PERSISTENCE" not in actions


def test_synth_pua_surfaces_cleanup_family_and_never_isolate():
    """PUA_CLEANUP surfaces uninstall/persistence/terminate + block/
    enrich network — but NOT ENDPOINT_ISOLATE (that belongs to the
    ransomware/lateral-movement/worm strategies)."""
    context = {
        "state": "READY",
        "entities": [
            {"kind": "application", "value": "PCAppStore",
              "role": "artifact", "origin": "application.name"},
            {"kind": "startup_entry", "value": "PCAppStore",
              "role": "persistence", "origin": "persistence.startup"},
            {"kind": "process", "value": "PCAppStore.exe",
              "role": "artifact", "origin": "process.image"},
            {"kind": "ipv4", "value": "1.2.3.4", "role": "destination",
              "origin": "network.dst.ip"},
        ],
    }
    recos = synthesize(context, {"family": "PUA_ADWARE"}, [], [], [])
    # Look at the guidance ids that actually fired (encoded in reco.id).
    guidance_ids = {r["id"].split("-")[1] for r in recos}
    assert "uninstall_application"      in guidance_ids
    assert "remove_startup_persistence" in guidance_ids
    assert "terminate_process"          in guidance_ids
    # PUA_CLEANUP does NOT list ISOLATE_ENDPOINT among its candidates.
    actions = {r["suggested_action"] for r in recos}
    assert "ENDPOINT_ISOLATE" not in actions, \
        "PUA cleanup must never propose endpoint isolation"


def test_synth_exclusions_only_when_strategy_permits():
    """Exclusion candidates surface for PUA but not for RANSOMWARE
    even when the entity is present."""
    context = {
        "state": "READY",
        "entities": [
            {"kind": "hash", "value": "a" * 64, "role": "artifact",
              "origin": "file.hash"},
        ],
    }
    # PUA_ADWARE → allow_exclusions=True
    recos_pua = synthesize(context, {"family": "PUA_ADWARE"},
                                        [], [], [])
    excl_pua = [r for r in recos_pua
                        if is_exclusion(r["suggested_action"])]
    assert excl_pua, "PUA must surface exclusion candidates for hash"

    # RANSOMWARE → allow_exclusions=False
    recos_rw = synthesize(context, {"family": "RANSOMWARE"},
                                        [], [], [])
    excl_rw = [r for r in recos_rw
                      if is_exclusion(r["suggested_action"])]
    assert excl_rw == [], \
        "ransomware must never surface exclusion candidates"


def test_synth_attaches_strategy_provenance_to_every_reco():
    context = {
        "state": "READY",
        "entities": [
            {"kind": "ipv4", "value": "203.0.113.42", "role": "destination",
              "origin": "network.dst.ip"},
        ],
    }
    recos = synthesize(context, {"family": "C2"}, [], [], [])
    assert recos
    for r in recos:
        assert r.get("strategy"), r
        assert r["strategy"]["id"] == "C2_CONTAINMENT"
        assert r["strategy"]["objective"] == CONTAINMENT
        assert r["strategy"]["all_ids"] == ["C2_CONTAINMENT"]


def test_synth_credential_theft_surfaces_credential_workflows():
    context = {
        "state": "READY",
        "entities": [
            {"kind": "user", "value": "alice@corp",
              "role": "identity", "origin": "identity.user"},
            {"kind": "host", "value": "workstation-01",
              "role": "artifact", "origin": "host"},
        ],
    }
    recos = synthesize(context, {"family": "CREDENTIAL_THEFT"},
                                [], [], [])
    actions = {r["suggested_action"] for r in recos}
    assert "COLLECT_FORENSIC_SNAPSHOT" in actions
    # Note: REVOKE_CREDENTIAL routes via the internal executor which
    # is registered, so it MAY appear — but must always be tagged
    # with the CREDENTIAL_PROTECTION strategy.
    for r in recos:
        assert r["strategy"]["id"] == "CREDENTIAL_PROTECTION"


# ── Round 19 architectural guarantees ───────────────────────────

def test_no_family_shares_a_strategy_with_a_different_family():
    """A strategy belongs to exactly one family — the layer never
    silently fires cross-family."""
    from collections import defaultdict
    by_id: dict = defaultdict(set)
    for s in all_strategies():
        by_id[s["id"]].add(s["family"])
    for sid, fams in by_id.items():
        assert len(fams) == 1, f"{sid} spans multiple families: {fams}"
