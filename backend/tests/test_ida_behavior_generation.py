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


# ══════════════════════════════════════════════════════════════════
# Schema refinement · provenance, kill-chain tags, impact tags, id
# ══════════════════════════════════════════════════════════════════
def test_behavior_id_is_stable_content_hash():
    ex = _extraction_for_talos_style()
    a = generate_behaviors(ex)
    b = generate_behaviors(ex)
    assert [x.id for x in a] == [x.id for x in b]
    # Different source_ref → different id
    ids = {x.id for x in a}
    assert len(ids) == len(a), "ids collided across distinct behaviors"


def test_command_behaviors_have_command_execution_provenance():
    ex = _extraction_for_talos_style()
    for b in generate_behaviors(ex):
        if b.source == "command_classifier":
            assert b.provenance == "command_execution"


def test_malware_lookup_behaviors_have_malware_reference_provenance():
    ex = _extraction_for_talos_style()
    for b in generate_behaviors(ex):
        if b.source == "malware_lookup":
            assert b.provenance == "malware_reference"


def test_lolbas_lookup_behaviors_have_lolbas_binary_reference_provenance():
    ex = _extraction_for_talos_style()
    for b in generate_behaviors(ex):
        if b.source == "lolbas_lookup":
            assert b.provenance == "lolbas_binary_reference"


def test_cve_lookup_behaviors_have_cve_reference_provenance():
    ex = _extraction_for_talos_style()
    for b in generate_behaviors(ex):
        if b.source == "cve_lookup":
            assert b.provenance == "cve_reference"


def test_every_behavior_carries_kill_chain_and_impact_tags_when_mapped():
    """A Behavior's projections must match the static maps.  With
    the P0.5 refactor the tags no longer live ON the Behavior — we
    project them on demand."""
    from services.ida.behaviors import (
        BEHAVIOR_TO_KILL_CHAIN, BEHAVIOR_TO_IMPACTS,
    )
    from services.ida.projections.kill_chain import project_to_kill_chain
    from services.ida.projections.impact     import project_to_impacts
    behaviors = generate_behaviors(_extraction_for_talos_style())
    for b in behaviors:
        expected_kc  = BEHAVIOR_TO_KILL_CHAIN.get(b.behavior_type, ())
        expected_imp = BEHAVIOR_TO_IMPACTS.get(b.behavior_type, ())
        actual_kc    = set(project_to_kill_chain([b]))
        actual_imp   = set(project_to_impacts([b]))
        assert actual_kc  == set(expected_kc)
        assert actual_imp == set(expected_imp)


# ══════════════════════════════════════════════════════════════════
# Wiring · behaviors → engine-facing InvestigationOutcome fields
# ══════════════════════════════════════════════════════════════════
def test_collect_outcome_inputs_from_talos_behaviors():
    from services.ida.behaviors import collect_outcome_inputs_from_behaviors
    behaviors = generate_behaviors(_extraction_for_talos_style())
    outcome_inputs = collect_outcome_inputs_from_behaviors(behaviors)

    # ── behaviors (kill-chain tactic tags) ─────────────────────
    assert "impact"            in outcome_inputs["behaviors"]   # shadow copy, ransomware
    assert "defense_evasion"   in outcome_inputs["behaviors"]   # msi proxy, disable duo
    assert "c2"                in outcome_inputs["behaviors"]   # SSH tunnel, remote access
    assert "lateral_movement"  in outcome_inputs["behaviors"]   # SSH tunnel
    assert "exfiltration"      in outcome_inputs["behaviors"]   # rclone
    # ── impacts ─────────────────────────────────────────────────
    assert "recovery_inhibited" in outcome_inputs["impacts"]
    assert "data_encrypted"     in outcome_inputs["impacts"]
    assert "data_theft"         in outcome_inputs["impacts"]
    # ── MITRE ids aggregated ────────────────────────────────────
    for tid in ("T1490", "T1218.007", "T1572", "T1567.002",
                  "T1562.001", "T1486", "T1219", "T1566.004",
                  "T1190"):
        assert tid in outcome_inputs["mitre_techniques"], (
            f"missing {tid}")
    # ── provenance audit trail ──────────────────────────────────
    assert len(outcome_inputs["provenance"]) == len(behaviors)


def test_collect_outcome_inputs_provenance_whitelist_filters_correctly():
    """A stricter whitelist (e.g. command_execution only) must
    reject malware-reference / cve-reference / lolbas-reference
    behaviors."""
    from services.ida.behaviors import collect_outcome_inputs_from_behaviors
    behaviors = generate_behaviors(_extraction_for_talos_style())

    # Command-execution only
    only_cmd = collect_outcome_inputs_from_behaviors(
        behaviors, provenance_whitelist=("command_execution",))
    # ransomware family provenance is malware_reference → excluded
    assert "data_encrypted" not in only_cmd["impacts"]
    assert "T1486" not in only_cmd["mitre_techniques"]
    # certutil/msiexec via LOLBAS provenance → excluded
    # But msiexec command was ALSO extracted as a command → still present
    assert "T1218.007" in only_cmd["mitre_techniques"]
    # Every provenance entry must be command_execution
    for meta in only_cmd["provenance"].values():
        assert meta["provenance"] == "command_execution"


def test_outcome_inputs_flow_end_to_end_into_v2_engine():
    """Full wiring — behaviors → outcome fields → engine → recommendations."""
    from services.mitigation.evidence_driven.investigation_outcome import (
        empty_outcome,
    )
    from services.mitigation.evidence_driven.engine import (
        evidence_driven_recommendations,
    )
    from services.ida.behaviors import (
        collect_outcome_inputs_from_behaviors,
    )
    behaviors = generate_behaviors(_extraction_for_talos_style())
    inputs    = collect_outcome_inputs_from_behaviors(behaviors)

    outcome = empty_outcome()
    outcome["behaviors"]        = inputs["behaviors"]
    outcome["impacts"]          = inputs["impacts"]
    outcome["mitre_techniques"] = inputs["mitre_techniques"]

    result = evidence_driven_recommendations(investigation_outcome=outcome)
    rec_ids = {r["id"] for r in result["recommendations"]}

    # With behaviors=[impact] + impacts=[recovery_inhibited, data_encrypted],
    # the ransomware-family rules should fire.
    assert "erad.reimage_ransomware"     in rec_ids
    assert "erad.protect_shadow_copies"  in rec_ids
    # SSH tunnel + remote access → c2 behavior tagged
    # (No specific C2 rule guaranteed to fire without domain IOCs — but the
    # engine must at least return SOMETHING more than the baseline.)
    assert len(rec_ids) >= 2, (
        f"expected multiple recommendations from full behavior graph, "
        f"got {sorted(rec_ids)}")


def test_no_provenance_leakage_between_sources():
    """command_execution behaviors must not carry
    malware/lolbas/cve provenance, and vice-versa."""
    ex = _extraction_for_talos_style()
    for b in generate_behaviors(ex):
        if b.provenance == "command_execution":
            assert b.source == "command_classifier"
        elif b.provenance == "malware_reference":
            assert b.source == "malware_lookup"
        elif b.provenance == "lolbas_binary_reference":
            assert b.source == "lolbas_lookup"
        elif b.provenance == "cve_reference":
            assert b.source == "cve_lookup"
        else:
            assert False, f"unexpected provenance {b.provenance!r}"
