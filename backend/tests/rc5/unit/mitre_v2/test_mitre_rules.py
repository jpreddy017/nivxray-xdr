"""Phase 5 · MITRE v2 mapper tests — rule matching (positive + negative).

Every entry in `MITRE_RULES` MUST have at least one positive AND one
negative test (§ 16). Structured behaviors are hand-crafted (no parser
required) so these tests isolate the mapper.
"""
from __future__ import annotations

import pytest

from engine.exec_graph import (
    Behavior, ExecGraph, ExecNode, NodeKind, TacticKind,
)
from engine.detectors.mitre_mapper import (
    MITRE_RULES, MITRE_TACTIC_IDS, MitreMapping, MitreMapper,
    map_behaviors_to_mitre,
)


# ── helpers ────────────────────────────────────────────────────────────
def _node(kind=NodeKind.process, image="cmd.exe", args=None, conf=100):
    a = {"image": image, **(args or {})}
    return ExecNode(kind=kind, args=a, confidence=conf, reconstructed=f"{image}")


def _behavior(tactic: TacticKind, sub=None, params=None, conf=100,
              node_id="n_xxx", recon=""):
    return Behavior(
        tactic=tactic, sub_kind=sub,
        evidence_nodes=(node_id,),
        reconstructed=recon or f"{tactic.value}:{sub}",
        confidence=conf,
        parameters=params or {},
    )


# ── (1-5) empty / minimal ──────────────────────────────────────────────
def test_empty_behaviors_returns_empty():
    assert map_behaviors_to_mitre([]) == []


def test_single_ps_execution_maps_to_T1059_001():
    b = _behavior(TacticKind.execution, "process_spawn",
                  {"image": "powershell.exe"}, node_id="n_ps")
    mm = map_behaviors_to_mitre([b])
    assert any(m.technique_id == "T1059" and m.sub_technique_id == "T1059.001" for m in mm)


def test_cmd_shell_execution_maps_to_T1059_003():
    b = _behavior(TacticKind.execution, "process_spawn",
                  {"image": "cmd.exe"}, node_id="n_cmd")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == "T1059.003" for m in mm)


def test_wscript_maps_to_T1059_005():
    b = _behavior(TacticKind.execution, "process_spawn",
                  {"image": "wscript.exe"}, node_id="n_ws")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == "T1059.005" for m in mm)


def test_wmic_maps_to_T1047():
    b = _behavior(TacticKind.execution, "process_spawn",
                  {"image": "wmic.exe"}, node_id="n_wm")
    mm = map_behaviors_to_mitre([b])
    assert any(m.technique_id == "T1047" for m in mm)


# ── (6-14) LOLBIN execution → defense evasion sub-techniques ───────────
@pytest.mark.parametrize("image,sub", [
    ("mshta.exe",    "T1218.005"),
    ("MSHTA.EXE",    "T1218.005"),
    ("rundll32.exe", "T1218.011"),
    ("regsvr32.exe", "T1218.010"),
])
def test_lolbin_binary_proxy_execution(image, sub):
    b = _behavior(TacticKind.execution, "process_spawn",
                  {"image": image}, node_id="n_l")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == sub for m in mm)


def test_shellcode_exec_maps_to_T1055_002():
    b = _behavior(TacticKind.execution, "shellcode_exec", {}, node_id="n_sh")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == "T1055.002" for m in mm)


def test_dll_load_maps_to_T1129():
    b = _behavior(TacticKind.execution, "dll_load", {}, node_id="n_dl")
    mm = map_behaviors_to_mitre([b])
    assert any(m.technique_id == "T1129" for m in mm)


def test_process_spawn_notepad_does_not_map_to_ps_or_cmd():
    b = _behavior(TacticKind.execution, "process_spawn",
                  {"image": "notepad.exe"}, node_id="n_np")
    mm = map_behaviors_to_mitre([b])
    assert not any(m.sub_technique_id in ("T1059.001", "T1059.003") for m in mm)


# ── (15-24) command_and_control ────────────────────────────────────────
def test_download_maps_to_T1105():
    b = _behavior(TacticKind.command_and_control, "download",
                  {"image": "curl.exe"}, node_id="n_cu")
    mm = map_behaviors_to_mitre([b])
    assert any(m.technique_id == "T1105" for m in mm)


def test_bitsadmin_download_also_maps_T1197():
    b = _behavior(TacticKind.command_and_control, "download",
                  {"image": "bitsadmin.exe"}, node_id="n_bi")
    mm = map_behaviors_to_mitre([b])
    tids = {m.technique_id for m in mm}
    assert "T1105" in tids and "T1197" in tids


def test_certutil_download_maps_T1140():
    b = _behavior(TacticKind.command_and_control, "download",
                  {"image": "certutil.exe"}, node_id="n_ce")
    mm = map_behaviors_to_mitre([b])
    assert any(m.technique_id == "T1140" for m in mm)


def test_http_beacon_maps_T1071_001():
    b = _behavior(TacticKind.command_and_control, "http", {}, node_id="n_ht")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == "T1071.001" for m in mm)


def test_dns_beacon_maps_T1071_004():
    b = _behavior(TacticKind.dns_query, None, {}, node_id="n_dn")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == "T1071.004" for m in mm)


def test_named_pipe_maps_T1573():
    b = _behavior(TacticKind.named_pipe, None, {}, node_id="n_pipe")
    mm = map_behaviors_to_mitre([b])
    assert any(m.technique_id == "T1573" for m in mm)


def test_download_no_bitsadmin_hint_does_not_emit_T1197():
    b = _behavior(TacticKind.command_and_control, "download",
                  {"image": "curl.exe"}, node_id="n_c2")
    mm = map_behaviors_to_mitre([b])
    assert not any(m.technique_id == "T1197" for m in mm)


# ── (25-33) persistence ────────────────────────────────────────────────
def test_autorun_registry_maps_T1547_001():
    b = _behavior(TacticKind.persistence, "autorun_registration",
                  {"key_hint": r"hkcu\software\microsoft\windows\currentversion\run"},
                  node_id="n_ar")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == "T1547.001" for m in mm)


def test_schtasks_maps_T1053_005():
    b = _behavior(TacticKind.persistence, "create_task",
                  {"image": "schtasks.exe"}, node_id="n_sc")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == "T1053.005" for m in mm)


def test_service_install_maps_T1543_003():
    b = _behavior(TacticKind.persistence, "install_service",
                  {"image": "sc.exe"}, node_id="n_svc")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == "T1543.003" for m in mm)


def test_registry_write_no_autorun_still_maps_T1112():
    b = _behavior(TacticKind.persistence, "write_registry",
                  {"image": "reg.exe"}, node_id="n_rw")
    mm = map_behaviors_to_mitre([b])
    assert any(m.technique_id == "T1112" for m in mm)


def test_wmi_subscription_maps_T1546_003():
    b = _behavior(TacticKind.wmi_subscription, None, {}, node_id="n_wmi")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == "T1546.003" for m in mm)


# ── (34-40) credential access ──────────────────────────────────────────
@pytest.mark.parametrize("image,sub", [
    ("mimikatz.exe", "T1003.001"),
    ("procdump.exe", "T1003.001"),
    ("ntdsutil.exe", "T1003.003"),
])
def test_credential_access_family(image, sub):
    b = _behavior(TacticKind.credential_access, "dump_credentials",
                  {"image": image}, node_id="n_ca")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == sub for m in mm)


def test_credential_access_unknown_tool_yields_no_mapping():
    b = _behavior(TacticKind.credential_access, "dump_credentials",
                  {"image": "whoami.exe"}, node_id="n_x")
    mm = map_behaviors_to_mitre([b])
    # Only techniques whose image predicate matches will fire — 0 here.
    assert not any(m.technique_id == "T1003" for m in mm)


# ── (41-50) defense evasion ────────────────────────────────────────────
def test_encoded_command_maps_T1027_010():
    b = _behavior(TacticKind.defense_evasion, "obfuscation",
                  {"kind": "encoded_command"}, node_id="n_ec")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == "T1027.010" for m in mm)


def test_obfuscation_wrong_kind_does_not_map():
    b = _behavior(TacticKind.defense_evasion, "obfuscation",
                  {"kind": "some_other_kind"}, node_id="n_ec")
    mm = map_behaviors_to_mitre([b])
    assert not any(m.sub_technique_id == "T1027.010" for m in mm)


def test_amsi_bypass_maps_T1562_001():
    b = _behavior(TacticKind.defense_evasion, "bypass_amsi", {}, node_id="n_a")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == "T1562.001" for m in mm)


def test_etw_bypass_maps_T1562_006():
    b = _behavior(TacticKind.defense_evasion, "bypass_etw", {}, node_id="n_e")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == "T1562.006" for m in mm)


def test_reflection_maps_T1055_001():
    b = _behavior(TacticKind.defense_evasion, "reflection", {}, node_id="n_r")
    mm = map_behaviors_to_mitre([b])
    assert any(m.sub_technique_id == "T1055.001" for m in mm)


def test_memory_alloc_maps_T1055():
    b = _behavior(TacticKind.defense_evasion, "memory_alloc",
                  {"size": 4096}, node_id="n_m")
    mm = map_behaviors_to_mitre([b])
    assert any(m.technique_id == "T1055" and m.sub_technique_id is None
               for m in mm)


# ── (51-56) exfil / impact / collection ────────────────────────────────
def test_exfil_upload_maps_T1041():
    b = _behavior(TacticKind.exfiltration, "upload",
                  {"image": "ftp.exe"}, node_id="n_ex")
    mm = map_behaviors_to_mitre([b])
    assert any(m.technique_id == "T1041" for m in mm)


def test_file_delete_maps_T1485():
    b = _behavior(TacticKind.impact, "file_delete",
                  {"path": "C:/temp/x.txt"}, node_id="n_fd")
    mm = map_behaviors_to_mitre([b])
    assert any(m.technique_id == "T1485" for m in mm)


def test_file_create_maps_T1005():
    b = _behavior(TacticKind.collection, "file_create",
                  {"path": "C:/x.bin"}, node_id="n_fc")
    mm = map_behaviors_to_mitre([b])
    assert any(m.technique_id == "T1005" for m in mm)


def test_clipboard_maps_T1115():
    b = _behavior(TacticKind.clipboard, None, {}, node_id="n_cb")
    mm = map_behaviors_to_mitre([b])
    assert any(m.technique_id == "T1115" for m in mm)


# ── (57-70) evidence linkage / confidence rules ────────────────────────
def test_every_mapping_has_at_least_one_behavior_id():
    b = _behavior(TacticKind.execution, "process_spawn",
                  {"image": "powershell.exe"}, node_id="n_p")
    mm = map_behaviors_to_mitre([b])
    assert mm
    for m in mm:
        assert len(m.evidence_behavior_ids) >= 1


def test_every_mapping_has_at_least_one_node_id():
    b = _behavior(TacticKind.execution, "process_spawn",
                  {"image": "powershell.exe"}, node_id="n_p1")
    mm = map_behaviors_to_mitre([b])
    for m in mm:
        assert len(m.evidence_node_ids) >= 1


def test_mapping_confidence_capped_by_behavior_confidence():
    b = _behavior(TacticKind.execution, "process_spawn",
                  {"image": "powershell.exe"}, conf=40, node_id="n_p2")
    mm = map_behaviors_to_mitre([b])
    # base_confidence for R-EXE-PS is 95; behavior conf is 40 → final=40
    ps_maps = [m for m in mm if m.rule_id == "R-EXE-PS"]
    assert ps_maps and all(m.confidence == 40 for m in ps_maps)


def test_mapping_confidence_capped_by_rule_base():
    # Behavior confidence is high, rule base is lower → final=base.
    b = _behavior(TacticKind.collection, "file_create",
                  {"path": "C:/x.bin"}, conf=100, node_id="n_fc")
    mm = map_behaviors_to_mitre([b])
    m = [x for x in mm if x.rule_id == "R-COL-FILE-CREATE"][0]
    assert m.confidence == 45  # rule base_confidence


def test_multiple_behaviors_merge_into_one_mapping():
    b1 = _behavior(TacticKind.execution, "process_spawn",
                   {"image": "powershell.exe"}, node_id="n_a")
    b2 = _behavior(TacticKind.execution, "process_spawn",
                   {"image": "powershell.exe"}, node_id="n_b")
    mm = map_behaviors_to_mitre([b1, b2])
    ps = [m for m in mm if m.rule_id == "R-EXE-PS"]
    assert len(ps) == 1
    assert set(ps[0].evidence_node_ids) == {"n_a", "n_b"}


def test_deterministic_ordering():
    # Two runs on identical input must produce identical ordered results
    # (comparing rule_ids + evidence lists).
    b = _behavior(TacticKind.execution, "process_spawn",
                  {"image": "powershell.exe"}, node_id="n_x")
    m1 = map_behaviors_to_mitre([b])
    m2 = map_behaviors_to_mitre([b])
    assert [(m.technique_id, m.sub_technique_id, m.rule_id) for m in m1] == \
           [(m.technique_id, m.sub_technique_id, m.rule_id) for m in m2]


def test_tactic_id_matches_MITRE_TACTIC_IDS():
    b = _behavior(TacticKind.execution, "process_spawn",
                  {"image": "powershell.exe"}, node_id="n_tt")
    mm = map_behaviors_to_mitre([b])
    for m in mm:
        expected = MITRE_TACTIC_IDS[m.tactic]
        assert m.tactic_id == expected[0]
        assert m.tactic_name == expected[1]


def test_reconstructed_strings_deduplicated_in_mapping():
    b1 = _behavior(TacticKind.command_and_control, "download",
                   {"image": "curl.exe"}, node_id="n_r1", recon="curl h://a")
    b2 = _behavior(TacticKind.command_and_control, "download",
                   {"image": "curl.exe"}, node_id="n_r2", recon="curl h://a")
    mm = map_behaviors_to_mitre([b1, b2])
    dl = [m for m in mm if m.rule_id == "R-C2-DOWNLOAD"][0]
    assert list(dl.reconstructed).count("curl h://a") == 1


def test_data_sources_populated_for_every_mapping():
    for rule in MITRE_RULES:
        assert rule.data_sources, f"{rule.rule_id} lacks data_sources"


def test_detections_are_strings_only():
    for rule in MITRE_RULES:
        for k, v in rule.detections.items():
            assert isinstance(k, str) and isinstance(v, str)


def test_mitre_mapping_immutable():
    b = _behavior(TacticKind.execution, "process_spawn",
                  {"image": "powershell.exe"}, node_id="n_im")
    m = map_behaviors_to_mitre([b])[0]
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        m.technique_id = "T9999"  # frozen model
