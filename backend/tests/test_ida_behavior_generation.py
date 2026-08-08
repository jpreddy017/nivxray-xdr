"""P0.3 · Stage 5 · Behavior Generation regression tests.

Locks the deterministic-lookup contract:
    · No prose inference — Behaviors come only from already-
      extracted entities (commands, malware_families, LOLBAS
      binaries in body_artifacts, CVEs).
    · No invention — techniques absent from the static maps produce
      no Behavior and no MITRE ID.
    · Deterministic + idempotent — same input → same list.
"""
from __future__ import annotations

from services.ida.behaviors import (
    Behavior, BEHAVIOR_TO_MITRE, MALWARE_FAMILY_TO_BEHAVIORS,
    LOLBAS_BINARY_TO_BEHAVIORS, CVE_TO_BEHAVIORS,
    classify_command, generate_behaviors, collect_mitre_from_behaviors,
)


# ══════════════════════════════════════════════════════════════════
# Vocabulary integrity
# ══════════════════════════════════════════════════════════════════
def test_every_behavior_type_maps_to_at_least_one_mitre_id():
    for btype, mitre in BEHAVIOR_TO_MITRE.items():
        assert mitre, f"behavior {btype!r} has empty MITRE tuple"
        for tid in mitre:
            assert tid.startswith("T") and tid[1:].split(".")[0].isdigit(), (
                f"invalid MITRE id {tid!r} for behavior {btype!r}")


def test_malware_family_map_only_references_known_behavior_types():
    for fam, btypes in MALWARE_FAMILY_TO_BEHAVIORS.items():
        for b in btypes:
            assert b in BEHAVIOR_TO_MITRE, (
                f"malware {fam!r} maps to unknown behavior {b!r}")


def test_lolbas_map_only_references_known_behavior_types():
    for bin_, btypes in LOLBAS_BINARY_TO_BEHAVIORS.items():
        for b in btypes:
            assert b in BEHAVIOR_TO_MITRE, (
                f"lolbas {bin_!r} maps to unknown behavior {b!r}")


def test_cve_map_only_references_known_behavior_types():
    for cid, btypes in CVE_TO_BEHAVIORS.items():
        for b in btypes:
            assert b in BEHAVIOR_TO_MITRE, (
                f"cve {cid!r} maps to unknown behavior {b!r}")


# ══════════════════════════════════════════════════════════════════
# classify_command — deterministic (label, behavior_type)
# ══════════════════════════════════════════════════════════════════
def test_vssadmin_delete_shadows_produces_shadow_copy_deletion():
    label, b = classify_command(
        r"C:\Windows\System32\vssadmin.exe 'delete' 'shadows' '/all'",
        "vssadmin.exe",
    )
    assert b == "shadow_copy_deletion"
    assert "Shadow copy deletion" in label


def test_msiexec_produces_signed_binary_proxy_msi():
    label, b = classify_command(
        r"C:\Windows\system32\msiexec.exe /V", "msiexec.exe")
    assert b == "signed_binary_proxy_msi"


def test_wmic_product_uninstall_produces_defense_evasion():
    label, b = classify_command(
        r"C:\WINDOWS\system32\cmd.EXE /c wmic product where name=Duo Authentication for Windows call uninstall",
        "cmd.exe",
    )
    assert b == "defense_evasion_disable_tool"


def test_reverse_ssh_produces_protocol_tunneling():
    label, b = classify_command(
        r"C:\Windows\System32\OpenSSH\ssh.exe -R :12840 -N REDACTED -p 443",
        "ssh.exe",
    )
    assert b == "protocol_tunneling_ssh"


def test_rclone_style_produces_data_staging_exfil():
    label, b = classify_command(
        "wininit.exe copy --max-age 1y --exclude *{psd,7z,mox,pst,iso,exe} source target",
        "wininit.exe",
    )
    assert b == "data_staging_exfil_rclone"


def test_unrecognized_command_produces_no_behavior():
    label, b = classify_command("some_random.exe --flag", "some_random.exe")
    # Falls through to the generic label with no behavior_type.
    assert b is None
    assert label == "Command execution"


# ══════════════════════════════════════════════════════════════════
# Behavior generation — end-to-end from a synthetic extraction
# ══════════════════════════════════════════════════════════════════
def _extraction_for_talos_style() -> dict:
    """A synthetic ``extract_all()``-shaped dict that mirrors what the
    Talos IR ransomware article actually produces at Stage 4."""
    return {
        "commands": [
            {"executable": r"C:\Windows\System32\vssadmin.exe",
             "command":    r"C:\Windows\System32\vssadmin.exe delete shadows /all",
             "line": 37},
            {"executable": r"C:\Windows\system32\msiexec.exe",
             "command":    r"C:\Windows\system32\msiexec.exe /V",
             "line": 39},
            {"executable": r"C:\WINDOWS\system32\cmd.EXE",
             "command":    r"C:\WINDOWS\system32\cmd.EXE /c wmic product where name=Duo call uninstall",
             "line": 21},
            {"executable": r"C:\Windows\System32\OpenSSH\ssh.exe",
             "command":    r"C:\Windows\System32\OpenSSH\ssh.exe -R :12840 -N REDACTED -p 443",
             "line": 13},
            {"executable": "wininit.exe",
             "command":    "wininit.exe copy --max-age 1y --exclude *{psd,7z} src dst",
             "line": 23},
        ],
        "malware_families": [
            {"name": "Medusa"},
            {"name": "Chaos"},
            {"name": "AnyDesk"},
            {"name": "ScreenConnect"},
            {"name": "SimpleHelp"},
            {"name": "Quick Assist"},
        ],
        "body_artifacts": [
            {"type": "file_path", "value": r"C:\Windows\System32\vssadmin.exe"},
            {"type": "file_path", "value": r"C:\Windows\System32\OpenSSH\ssh.exe"},
        ],
        "cves": [
            {"id": "CVE-2024-57727"},
        ],
    }


def test_generate_behaviors_from_talos_style_extraction():
    ex = _extraction_for_talos_style()
    behaviors = generate_behaviors(ex)
    btypes = {b.behavior_type for b in behaviors}

    # From commands ↓
    assert "shadow_copy_deletion"          in btypes
    assert "signed_binary_proxy_msi"       in btypes
    assert "defense_evasion_disable_tool"  in btypes
    assert "protocol_tunneling_ssh"        in btypes
    assert "data_staging_exfil_rclone"     in btypes
    # From malware lookup ↓
    assert "data_encryption_for_impact"    in btypes    # Medusa / Chaos
    assert "remote_access_software"        in btypes    # AnyDesk etc
    assert "quickassist_it_impersonation"  in btypes    # Quick Assist
    # From CVE lookup ↓
    assert "exploit_public_app"            in btypes    # CVE-2024-57727


def test_derived_mitre_ids_cover_talos_kill_chain():
    behaviors = generate_behaviors(_extraction_for_talos_style())
    mitre = {m["id"] for m in collect_mitre_from_behaviors(behaviors)}

    # A representative slice — every one should be present.
    assert "T1490"     in mitre    # shadow copy deletion / recovery inhibition
    assert "T1218.007" in mitre    # msiexec proxy
    assert "T1572"     in mitre    # protocol tunneling
    assert "T1021.004" in mitre    # SSH lateral movement
    assert "T1567.002" in mitre    # exfil to cloud
    assert "T1219"     in mitre    # remote access software
    assert "T1562.001" in mitre    # disable/modify tools
    assert "T1486"     in mitre    # data encryption for impact
    assert "T1190"     in mitre    # exploit public-facing app
    # T1566.004 (Spearphishing via Service — Quick Assist arm)
    assert "T1566.004" in mitre


def test_deterministic_output_across_runs():
    ex = _extraction_for_talos_style()
    a = [b.to_dict() for b in generate_behaviors(ex)]
    b = [b.to_dict() for b in generate_behaviors(ex)]
    assert a == b


def test_no_behavior_emitted_when_input_is_empty():
    assert generate_behaviors({}) == []
    assert generate_behaviors({"commands": [], "malware_families": []}) == []


def test_no_behavior_emitted_for_unknown_malware_family():
    ex = {"malware_families": [{"name": "TotallyMadeUpMalware9000"}]}
    assert generate_behaviors(ex) == []


def test_no_behavior_emitted_for_unknown_lolbas_binary():
    ex = {"body_artifacts": [{"type": "file_path", "value": r"C:\foo\notlolbas.exe"}]}
    assert generate_behaviors(ex) == []


def test_generator_does_not_invent_techniques_from_narrative():
    """Regression: the generator only reads structured extraction
    output.  A rich ``output_text`` narrative alone must not
    influence the Behavior list."""
    ex = {
        "commands": [],
        "malware_families": [],
        "body_artifacts": [],
        "cves": [],
        # A narrative string is deliberately absent from the API.
    }
    assert generate_behaviors(ex) == []


# ══════════════════════════════════════════════════════════════════
# Backward compatibility · legacy _classify_command_purpose still
# returns a label so existing callers don't break.
# ══════════════════════════════════════════════════════════════════
def test_legacy_classify_command_purpose_still_exists_and_returns_label():
    from services.ida.report_extractors import _classify_command_purpose
    label = _classify_command_purpose(
        r"C:\Windows\System32\vssadmin.exe delete shadows /all",
        "vssadmin.exe",
    )
    assert isinstance(label, str) and "Shadow" in label
