"""Phase 5 · MITRE v2 — 1:N mapping / multi-technique behaviors."""
from __future__ import annotations

import pytest
from engine.exec_graph import Behavior, TacticKind
from engine.detectors.mitre_mapper import map_behaviors_to_mitre


def _b(tactic, sub, params, conf=100, nid="n_x", recon=""):
    return Behavior(tactic=tactic, sub_kind=sub, evidence_nodes=(nid,),
                    reconstructed=recon or f"{tactic.value}:{sub}",
                    confidence=conf, parameters=params or {})


# ── 1:N mapping — same behavior fires multiple rules simultaneously ───
def test_bitsadmin_download_emits_T1105_AND_T1197():
    b = _b(TacticKind.command_and_control, "download",
           {"image": "bitsadmin.exe"}, nid="n_1")
    mm = map_behaviors_to_mitre([b])
    ids = {(m.technique_id, m.sub_technique_id) for m in mm}
    assert ("T1105", None) in ids
    assert ("T1197", None) in ids


def test_certutil_download_emits_T1105_AND_T1140():
    b = _b(TacticKind.command_and_control, "download",
           {"image": "certutil.exe"}, nid="n_2")
    mm = map_behaviors_to_mitre([b])
    ids = {m.technique_id for m in mm}
    assert "T1105" in ids and "T1140" in ids


def test_powershell_with_two_behaviors_emits_T1059_and_T1027_010():
    # Same node — two behaviors: process_spawn(powershell) + obfuscation(encoded)
    b1 = _b(TacticKind.execution, "process_spawn",
            {"image": "powershell.exe"}, nid="n_p")
    b2 = _b(TacticKind.defense_evasion, "obfuscation",
            {"kind": "encoded_command"}, nid="n_p")
    mm = map_behaviors_to_mitre([b1, b2])
    ids = {(m.technique_id, m.sub_technique_id) for m in mm}
    assert ("T1059", "T1059.001") in ids
    assert ("T1027", "T1027.010") in ids


def test_amsi_and_reflection_both_map_independently():
    b1 = _b(TacticKind.defense_evasion, "bypass_amsi", {}, nid="n_a")
    b2 = _b(TacticKind.defense_evasion, "reflection", {}, nid="n_r")
    mm = map_behaviors_to_mitre([b1, b2])
    subs = {m.sub_technique_id for m in mm}
    assert "T1562.001" in subs
    assert "T1055.001" in subs


def test_mshta_with_download_emits_T1218_005_AND_T1105():
    b1 = _b(TacticKind.execution, "process_spawn",
            {"image": "mshta.exe"}, nid="n_m1")
    b2 = _b(TacticKind.command_and_control, "download",
            {"image": "mshta.exe"}, nid="n_m1")
    mm = map_behaviors_to_mitre([b1, b2])
    ids = {(m.technique_id, m.sub_technique_id) for m in mm}
    assert ("T1218", "T1218.005") in ids
    assert ("T1105", None) in ids


def test_rundll32_execution_maps_to_T1218_011_only():
    b = _b(TacticKind.execution, "process_spawn",
           {"image": "rundll32.exe"}, nid="n_rd")
    mm = map_behaviors_to_mitre([b])
    ids = {(m.technique_id, m.sub_technique_id) for m in mm}
    assert ("T1218", "T1218.011") in ids
    # No T1059 or T1105 firing off a pure rundll32 process spawn
    assert not any(m.technique_id in ("T1059", "T1105") for m in mm)


def test_persistence_autorun_also_fires_write_registry_when_supplied():
    # The extractor emits both write_registry AND autorun_registration; mapper
    # therefore emits both T1112 and T1547.001.
    b1 = _b(TacticKind.persistence, "write_registry",
            {"image": "reg.exe"}, nid="n_rp")
    b2 = _b(TacticKind.persistence, "autorun_registration",
            {"key_hint": r"hkcu\software\microsoft\windows\currentversion\run"},
            nid="n_rp")
    mm = map_behaviors_to_mitre([b1, b2])
    subs = {(m.technique_id, m.sub_technique_id) for m in mm}
    assert ("T1112", None) in subs
    assert ("T1547", "T1547.001") in subs


def test_lsass_dump_maps_only_T1003_001_for_mimikatz():
    b = _b(TacticKind.credential_access, "dump_credentials",
           {"image": "mimikatz.exe"}, nid="n_mi")
    mm = map_behaviors_to_mitre([b])
    subs = {m.sub_technique_id for m in mm if m.technique_id == "T1003"}
    assert subs == {"T1003.001"}


def test_upload_with_ftp_only_emits_T1041():
    b = _b(TacticKind.exfiltration, "upload",
           {"image": "ftp.exe"}, nid="n_up")
    mm = map_behaviors_to_mitre([b])
    ids = {m.technique_id for m in mm}
    assert ids == {"T1041"}


@pytest.mark.parametrize("image", ["mimikatz", "MIMIKATZ.EXE", "MiMiKaTz.exe"])
def test_image_matching_is_case_insensitive(image):
    b = _b(TacticKind.credential_access, "dump_credentials",
           {"image": image}, nid="n_ci")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == "T1003.001" for m in mm)


@pytest.mark.parametrize("image", ["POWERSHELL.EXE", "PowerShell", "pwsh"])
def test_ps_image_matches_multiple_variants(image):
    b = _b(TacticKind.execution, "process_spawn",
           {"image": image}, nid="n_pv")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == "T1059.001" for m in mm)


def test_process_with_no_image_does_not_crash():
    b = _b(TacticKind.execution, "process_spawn", {}, nid="n_ni")
    # process_spawn without image should not match image-predicated rules.
    mm = map_behaviors_to_mitre([b])
    assert not any(m.sub_technique_id in ("T1059.001", "T1059.003",
                                          "T1218.005", "T1218.011") for m in mm)


def test_missing_parameters_ignored_by_predicated_rules():
    # sub_kind matches but the image predicate fails.
    b = _b(TacticKind.execution, "process_spawn",
           {"image": "unknown.exe"}, nid="n_uk")
    mm = map_behaviors_to_mitre([b])
    assert not any(m.rule_id == "R-EXE-PS" for m in mm)


def test_mapping_confidence_is_max_across_grouped_behaviors():
    # Two behaviors, different confidences → grouping keeps the max.
    b_low = _b(TacticKind.execution, "process_spawn",
               {"image": "powershell.exe"}, conf=30, nid="n_lo")
    b_hi  = _b(TacticKind.execution, "process_spawn",
               {"image": "powershell.exe"}, conf=90, nid="n_hi")
    mm = map_behaviors_to_mitre([b_low, b_hi])
    ps = [m for m in mm if m.rule_id == "R-EXE-PS"][0]
    assert ps.confidence == min(95, 90)  # rule base 95, behavior high 90


def test_reconstructed_list_is_ordered_stable():
    b1 = _b(TacticKind.execution, "process_spawn",
            {"image": "powershell.exe"}, nid="n_1", recon="A")
    b2 = _b(TacticKind.execution, "process_spawn",
            {"image": "powershell.exe"}, nid="n_2", recon="B")
    mm = map_behaviors_to_mitre([b1, b2])
    ps = [m for m in mm if m.rule_id == "R-EXE-PS"][0]
    assert list(ps.reconstructed) == ["A", "B"]


def test_evidence_node_ids_do_not_duplicate():
    b1 = _b(TacticKind.execution, "process_spawn",
            {"image": "powershell.exe"}, nid="n_dup")
    b2 = _b(TacticKind.execution, "process_spawn",
            {"image": "powershell.exe"}, nid="n_dup")
    mm = map_behaviors_to_mitre([b1, b2])
    ps = [m for m in mm if m.rule_id == "R-EXE-PS"][0]
    assert list(ps.evidence_node_ids) == ["n_dup"]
