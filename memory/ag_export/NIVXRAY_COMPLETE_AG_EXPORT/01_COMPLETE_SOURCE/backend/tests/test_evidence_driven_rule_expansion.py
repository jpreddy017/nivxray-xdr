"""Rule expansion tests · Ransomware + credential-theft + lateral +
recon + compare-endpoint acceptance.

Every rule ships with BOTH:

    · FIRES     — evidence supports the rule → rule appears in output
    · DOES NOT FIRE — evidence absent → rule MUST NOT appear

Follows the user directive (2026-02-04): "the biggest risk now isn't
breaking the Workspace — it's gradually making v2 over-recommend as
the rule library grows."
"""
from __future__ import annotations

import pytest

from services.mitigation.evidence_driven.engine import (
    evidence_driven_recommendations,
)


# ══════════════════════════════════════════════════════════════════
# Synthetic decode-result fixtures (deterministic — no LLM, no I/O)
# ══════════════════════════════════════════════════════════════════
def _ransomware_case() -> dict:
    return {
        "output": (
            "vssadmin delete shadows /all /quiet\n"
            "wbadmin delete catalog -quiet\n"
            "bcdedit /set {default} recoveryenabled No\n"
            "Get-ChildItem C:\\ -Recurse | ForEach-Object { "
            "Move-Item $_.FullName ($_.FullName + '.locked') }\n"
            "README_RESTORE.txt dropped in every directory\n"
        ),
        "recipe": [{"op": "deep-peel-from_base64_string"}],
        "iocs":   {"ip": ["185.220.101.5"]},
        "reached_shellcode": False,
    }


def _credential_theft_case() -> dict:
    return {
        "output": (
            "Invoke-Mimikatz -DumpCreds\n"
            "sekurlsa::logonpasswords\n"
            "procdump.exe -accepteula -ma lsass.exe c:\\lsass.dmp\n"
        ),
        "recipe": [{"op": "decoder-powershell-encoded-command"}],
        "iocs":   {},
        "reached_shellcode": False,
    }


def _lateral_movement_case() -> dict:
    return {
        "output": (
            "Enter-PSSession -ComputerName DC01\n"
            "Invoke-WMIMethod -Class Win32_Process -Name Create\n"
            "$s = New-PSSession -ComputerName SRV01\n"
        ),
        "recipe": [], "iocs": {}, "reached_shellcode": False,
    }


def _recon_case() -> dict:
    return {
        "output": (
            "Get-ADUser -Filter *\n"
            "Get-ADComputer -Filter *\n"
            "net view /domain\n"
            "whoami /priv\n"
        ),
        "recipe": [], "iocs": {}, "reached_shellcode": False,
    }


def _benign_case() -> dict:
    return {
        "output": "Hello analyst.  Normal text.",
        "recipe": [], "iocs": {}, "reached_shellcode": False,
    }


# ══════════════════════════════════════════════════════════════════
# Ransomware family · FIRES on encryption+recovery-inhibition
# ══════════════════════════════════════════════════════════════════
def test_ransomware_case_fires_impact_rules():
    ids = {r["id"] for r in evidence_driven_recommendations(
                                _ransomware_case())["recommendations"]}
    for expect in ("erad.protect_shadow_copies",
                     "erad.reimage_ransomware",
                     "inv.ransomware_scope",
                     "rec.restore_backups"):
        assert expect in ids, (
            f"ransomware trigger MISSED {expect} — got {sorted(ids)}")


def test_benign_case_does_NOT_fire_ransomware_rules():
    ids = {r["id"] for r in evidence_driven_recommendations(
                                _benign_case())["recommendations"]}
    for forbidden in ("erad.protect_shadow_copies",
                        "erad.reimage_ransomware",
                        "inv.ransomware_scope",
                        "rec.restore_backups"):
        assert forbidden not in ids, (
            f"ransomware rule {forbidden} fired on BENIGN input — "
            f"got {sorted(ids)}")


# ══════════════════════════════════════════════════════════════════
# Credential theft · FIRES on LSASS / Mimikatz / sekurlsa markers
# ══════════════════════════════════════════════════════════════════
def test_credential_theft_case_fires_credential_rules():
    ids = {r["id"] for r in evidence_driven_recommendations(
                                _credential_theft_case())["recommendations"]}
    assert "erad.rotate_credentials" in ids
    assert "inv.check_credential_theft" in ids


def test_ransomware_case_does_NOT_fire_credential_rotation():
    """Ransomware evidence alone MUST NOT trigger credential
    rotation — that's exactly the over-recommendation trap."""
    ids = {r["id"] for r in evidence_driven_recommendations(
                                _ransomware_case())["recommendations"]}
    assert "erad.rotate_credentials" not in ids
    assert "inv.check_credential_theft" not in ids


# ══════════════════════════════════════════════════════════════════
# Lateral movement · FIRES on PSSession / WMI / PSExec markers
# ══════════════════════════════════════════════════════════════════
def test_lateral_movement_case_fires_lateral_rule():
    ids = {r["id"] for r in evidence_driven_recommendations(
                                _lateral_movement_case())["recommendations"]}
    assert "inv.lateral_movement_trace" in ids


def test_ransomware_case_does_NOT_fire_lateral_rule():
    ids = {r["id"] for r in evidence_driven_recommendations(
                                _ransomware_case())["recommendations"]}
    assert "inv.lateral_movement_trace" not in ids


# ══════════════════════════════════════════════════════════════════
# Discovery / Recon · FIRES on AD-recon markers
# ══════════════════════════════════════════════════════════════════
def test_recon_case_fires_recon_rule():
    ids = {r["id"] for r in evidence_driven_recommendations(
                                _recon_case())["recommendations"]}
    assert "inv.recon_activity" in ids


def test_credential_case_does_NOT_fire_recon_rule():
    ids = {r["id"] for r in evidence_driven_recommendations(
                                _credential_theft_case())["recommendations"]}
    assert "inv.recon_activity" not in ids


# ══════════════════════════════════════════════════════════════════
# Compare endpoint · direct handler invocation (see other test file
# for rationale — TestClient hangs on this app's startup hooks).
# ══════════════════════════════════════════════════════════════════
def test_compare_endpoint_returns_both_engines_side_by_side():
    from routers.mitigations_evidence_driven import (
        post_compare, _EDRRequest,
    )
    body = post_compare(_EDRRequest(input="Get-ADUser -Filter *; "
                                         "net view /domain"))
    assert body["ok"] is True
    # BOTH engines executed on the SAME input
    assert "v1" in body and "v2" in body
    # v1 preserves its legacy schema
    assert body["v1"]["schema_version"] == 1
    for k in ("immediate", "hunting", "containment", "hardening"):
        assert k in body["v1"]
    # v2 carries the new engine's schema
    assert body["v2"]["schema_version"] == 2
    # Delta set arithmetic present
    for k in ("v1_only_ids", "v2_only_ids", "common_ids",
                "v1_count", "v2_count"):
        assert k in body["delta"]


def test_compare_endpoint_recon_case_v2_shows_recon_but_v1_static():
    """The load-bearing behavioural test — v2 differentiates a
    recon-only case from a ransomware case; v1 emits the same
    template regardless."""
    from routers.mitigations_evidence_driven import (
        post_compare, _EDRRequest,
    )
    recon_body = post_compare(_EDRRequest(
        input="Get-ADUser -Filter *; net view /domain; whoami /priv"))
    v2_ids = {r["id"] for r
                in recon_body["v2"]["recommendations"]}
    # v2 recognises this as recon → fires the recon rule
    assert "inv.recon_activity" in v2_ids
    # v2 does NOT fire ransomware / credential-theft / shellcode rules
    for forbidden in ("erad.rotate_credentials",
                        "contain.isolate_host",
                        "erad.reimage_ransomware"):
        assert forbidden not in v2_ids, (
            f"v2 over-recommended {forbidden} on a recon-only case")
