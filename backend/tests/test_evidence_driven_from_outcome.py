"""Investigation-Outcome path · acceptance tests.

Locks the user-mandated architecture (2026-02-04):

    Workspace discovers → Recommendation Engine reasons over what
    Workspace discovered → only applicable recommendations produced.

The engine MUST NOT re-analyze the original payload when the caller
passes an ``investigation_outcome``.  It sees ONLY the structured
findings — string-matching on ``output_text`` is legal only because
the Workspace put that text into the outcome deliberately.
"""
from __future__ import annotations

import pytest

from services.mitigation.evidence_driven.engine import (
    evidence_driven_recommendations,
)
from services.mitigation.evidence_driven.investigation_outcome import (
    empty_outcome, INVESTIGATION_OUTCOME_SCHEMA_VERSION,
)


# ══════════════════════════════════════════════════════════════════
# Direct outcome construction — the canonical Workspace → Engine path
# ══════════════════════════════════════════════════════════════════
def test_outcome_empty_produces_no_recommendations():
    o = empty_outcome()
    r = evidence_driven_recommendations(investigation_outcome=o)
    assert r["disabled"] is False
    assert r["recommendations"] == []
    assert r["verdict"]["severity"] == "informational"


def test_outcome_cobalt_strike_case_produces_expected_rules():
    """Workspace hands the engine a CS-stager finding set.
    The engine reasons ONLY over these structured facts — no
    payload, no decode."""
    o = empty_outcome()
    o["behaviors"]        = ["execution", "defense_evasion", "c2"]
    o["mitre_techniques"] = ["T1027", "T1055", "T1059.001",
                                 "T1140", "T1620"]
    o["malware"]          = {"family": "cobalt_strike",
                                "capabilities": ["beacon"]}
    o["iocs"]             = {"ips": ["149.28.81.19"]}
    o["reached_shellcode"] = True
    o["attack_pattern"]   = {"obfuscation_layers": 4,
                                "kill_chain_phases": ["delivery",
                                                        "exploitation",
                                                        "installation",
                                                        "command_and_control"]}
    o["processes"]        = ["powershell.exe"]
    o["detection_confidence"] = "confirmed"
    r = evidence_driven_recommendations(investigation_outcome=o)
    ids = {rec["id"] for rec in r["recommendations"]}
    for expected in ("contain.isolate_host",
                       "contain.kill_powershell",
                       "contain.preserve_memory",
                       "contain.block_ip:149.28.81.19",
                       "hunt.encoded_powershell",
                       "harden.ps_script_block_logging"):
        assert expected in ids, (
            f"CS-stager outcome missed {expected!r} — got {sorted(ids)}")
    # Not-fired discipline — no credential/ransomware evidence.
    for forbidden in ("erad.rotate_credentials",
                        "erad.reimage_ransomware",
                        "erad.stop_encryption",
                        "rec.restore_backups"):
        assert forbidden not in ids


def test_outcome_esentire_email_bombing_case_produces_narrow_rules():
    """Case A · social-engineering + LOLBAS abuse (Quick Assist,
    certutil), no shellcode, no encryption."""
    o = empty_outcome()
    o["behaviors"]     = ["c2"]
    o["lolbas_hits"]   = ["certutil.exe"]
    o["iocs"]          = {"urls": ["http://attacker.example.com/edge.zip"]}
    o["detection_confidence"] = "medium"
    r = evidence_driven_recommendations(investigation_outcome=o)
    ids = {rec["id"] for rec in r["recommendations"]}
    # Concrete evidence-linked actions
    assert ("contain.block_url:http://attacker.example.com/edge.zip"
              in ids)
    assert "harden.lolbas_allowlist" in ids
    # MUST NOT fire — no supporting evidence
    for forbidden in ("contain.isolate_host",
                        "erad.rotate_credentials",
                        "erad.reimage_ransomware",
                        "erad.stop_encryption",
                        "rec.restore_backups"):
        assert forbidden not in ids


def test_outcome_talos_ransomware_case_produces_impact_rules():
    """Case B · encryption + recovery-inhibition + credential theft."""
    o = empty_outcome()
    o["behaviors"]     = ["execution", "impact", "credential_access", "c2"]
    o["mitre_techniques"] = ["T1486", "T1490", "T1003"]
    o["impacts"]       = ["data_encrypted", "recovery_inhibited",
                             "credential_exposed"]
    o["iocs"]          = {"ips": ["185.220.101.5"]}
    o["detection_confidence"] = "high"
    r = evidence_driven_recommendations(investigation_outcome=o)
    ids = {rec["id"] for rec in r["recommendations"]}
    for expected in ("erad.stop_encryption",
                       "erad.protect_shadow_copies",
                       "erad.reimage_ransomware",
                       "erad.rotate_credentials",
                       "rec.restore_backups",
                       "inv.ransomware_scope",
                       "inv.check_credential_theft",
                       "contain.block_ip:185.220.101.5"):
        assert expected in ids, (
            f"ransomware outcome missed {expected!r} — got {sorted(ids)}")


# ══════════════════════════════════════════════════════════════════
# Zero-overlap invariant — the two cases produce disjoint rule sets
# (except for anything each independently justifies).
# ══════════════════════════════════════════════════════════════════
def test_esentire_and_talos_outcomes_have_zero_shared_rules():
    o_a = empty_outcome()
    o_a["behaviors"]   = ["c2"]
    o_a["lolbas_hits"] = ["certutil.exe"]
    o_a["iocs"]        = {"urls": ["http://a.example.com/x"]}

    o_b = empty_outcome()
    o_b["behaviors"]   = ["execution", "impact", "credential_access", "c2"]
    o_b["impacts"]     = ["data_encrypted", "recovery_inhibited",
                            "credential_exposed"]
    o_b["mitre_techniques"] = ["T1486", "T1490", "T1003"]
    o_b["iocs"]        = {"ips": ["185.220.101.5"]}

    a_ids = {r["id"] for r in evidence_driven_recommendations(
                                    investigation_outcome=o_a
                                )["recommendations"]}
    b_ids = {r["id"] for r in evidence_driven_recommendations(
                                    investigation_outcome=o_b
                                )["recommendations"]}
    assert not (a_ids & b_ids), (
        f"outcomes shared rules {sorted(a_ids & b_ids)} — engine "
        "over-recommending on disjoint case shapes")


# ══════════════════════════════════════════════════════════════════
# Engine API discipline — mutual exclusion between the two inputs
# ══════════════════════════════════════════════════════════════════
def test_engine_rejects_both_inputs_at_once():
    with pytest.raises(ValueError):
        evidence_driven_recommendations(
            decode_result={"iocs": {}},
            investigation_outcome=empty_outcome())


def test_engine_rejects_no_input():
    with pytest.raises(ValueError):
        evidence_driven_recommendations()


# ══════════════════════════════════════════════════════════════════
# Endpoint · direct-handler invocation (see other test files)
# ══════════════════════════════════════════════════════════════════
def test_from_outcome_endpoint_returns_expected_envelope():
    from routers.mitigations_evidence_driven import (
        post_from_outcome, _OutcomeRequest,
    )
    o = empty_outcome()
    o["behaviors"] = ["execution", "c2"]
    o["mitre_techniques"] = ["T1059.001", "T1027"]
    o["iocs"] = {"ips": ["1.1.1.1"]}
    o["detection_confidence"] = "high"
    body = post_from_outcome(_OutcomeRequest(outcome=o))
    assert body["ok"] is True
    edr = body["evidence_recommendations"]
    assert edr["schema_version"] == 2
    ids = {r["id"] for r in edr["recommendations"]}
    assert "contain.block_ip:1.1.1.1" in ids
    assert "hunt.encoded_powershell" in ids


def test_from_outcome_endpoint_rejects_empty_outcome():
    from fastapi import HTTPException
    from routers.mitigations_evidence_driven import (
        post_from_outcome, _OutcomeRequest,
    )
    with pytest.raises(HTTPException) as ei:
        post_from_outcome(_OutcomeRequest(outcome={}))
    assert ei.value.status_code == 400


# ══════════════════════════════════════════════════════════════════
# Legacy path still works — the compare workflow keeps a raw-paste
# input.  Not the canonical path, but the contract survives.
# ══════════════════════════════════════════════════════════════════
def test_engine_still_accepts_decode_result_positional():
    r = evidence_driven_recommendations({"iocs": {}, "reached_shellcode": False})
    assert r["disabled"] is False
    assert isinstance(r["recommendations"], list)
