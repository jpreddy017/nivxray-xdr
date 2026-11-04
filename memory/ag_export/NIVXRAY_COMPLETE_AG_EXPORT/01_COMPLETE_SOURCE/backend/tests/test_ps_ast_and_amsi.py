"""Tests for PowerShell AST-lite deobfuscation + AMSI-bypass detection."""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import operations, ops_extended  # noqa: F401
from powershell_ast import deobfuscate_ps
from amsi_detector import detect_amsi_bypass
from command_analyzer import analyze_command


# --------------------------- PowerShell AST --------------------------- #

def test_variable_assignment_and_concat():
    r = deobfuscate_ps('$a="I";$b="EX";$c=$a+$b')
    assert r["bindings"] == {"$a": "I", "$b": "EX", "$c": "IEX"}
    assert "'IEX'" in r["output"]
    kinds = [t["kind"] for t in r["transformations"]]
    assert "variable-substitution" in kinds
    assert "string-concat" in kinds


def test_format_string_obfuscation():
    r = deobfuscate_ps('"{0}{1}{2}" -f \'I\',\'E\',\'X\'')
    assert "'IEX'" in r["output"]
    assert any(t["kind"] == "format-string" for t in r["transformations"])


def test_format_string_reordered():
    r = deobfuscate_ps('"{2}{0}{1}" -f \'B\',\'C\',\'A\'')
    assert "'ABC'" in r["output"]


def test_replace_char_substitution():
    r = deobfuscate_ps("('IZEZX').Replace('Z','')")
    assert "'IEX'" in r["output"]


def test_replace_multiple_passes():
    r = deobfuscate_ps("('IQZQEQZQX').Replace('Q','').Replace('Z','')")
    assert "'IEX'" in r["output"]


def test_char_code_substitution():
    r = deobfuscate_ps("[char]73+[char]69+[char]88")
    assert "'IEX'" in r["output"]
    assert any(t["kind"] == "char-code" for t in r["transformations"])


def test_backtick_escape_removal():
    r = deobfuscate_ps("i`e`x whoami")
    # after backtick strip + case-normalize → IEX
    assert "IEX" in r["output"] or "iex" in r["output"]
    assert any(t["kind"] == "backtick-escape" for t in r["transformations"])


def test_case_normalization():
    r = deobfuscate_ps("InVOkE-eXpReSsION 'ls'")
    assert "Invoke-Expression" in r["output"]


def test_multi_pass_composition():
    r = deobfuscate_ps("$a='I';$b='E';$c='X'; & ($a+$b+$c) 'whoami'")
    assert "IEX" in r["output"]


def test_no_change_when_clean():
    r = deobfuscate_ps("Get-ChildItem C:\\Users")
    assert r["transformations"] == [] or all(t["kind"] == "case-normalization" for t in r["transformations"])


# --------------------------- AMSI detection --------------------------- #

def test_amsi_classic_reflection_bypass():
    payload = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
    r = detect_amsi_bypass(payload)
    assert r["detected"] is True
    assert r["severity"] in ("critical", "high")
    ids = [t["pattern_id"] for t in r["techniques"]]
    assert "reflection-amsi-setvalue-true" in ids
    assert "amsi-initfailed-field" in ids
    assert "reflection-amsi-getfield" in ids


def test_amsi_byte_patch_metsysbench():
    r = detect_amsi_bypass("$patch = [byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)")
    assert r["detected"] is True
    assert any(t["pattern_id"] == "amsi-bytepatch-metsysbench" for t in r["techniques"])


def test_amsi_scanbuffer_reference():
    r = detect_amsi_bypass("Marshal.WriteByte($AmsiScanBuffer_ptr, 0, 0x31)")
    assert r["detected"] is True
    assert any(t["pattern_id"] == "amsi-scanbuffer" for t in r["techniques"])


def test_etw_bypass():
    r = detect_amsi_bypass("[System.Diagnostics.Eventing.EventProvider].GetField('EtwEventWrite', 'NonPublic,Static')")
    assert r["detected"] is True
    assert r["etw_related_count"] >= 1


def test_amsi_clean_command_no_false_positive():
    r = detect_amsi_bypass("Get-ChildItem C:\\Users\\public")
    assert r["detected"] is False
    assert r["severity"] == "none"


# --------------------------- End-to-end via analyze_command --------------------------- #

def test_e2e_ps_obfuscated_with_amsi_bypass():
    cmd = "$a='I';$b='E';$c='X'; & ($a+$b+$c) ([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true))"
    r = analyze_command(cmd)
    # AST deob fired
    assert r["ast_deobfuscation"]["applied"] is True
    assert r["ast_deobfuscation"]["bindings"] == {"$a": "I", "$b": "E", "$c": "X"}
    # AMSI detected
    assert r["amsi_bypass"]["detected"] is True
    assert r["amsi_bypass"]["severity"] == "critical"
    # Behaviors tagged
    assert any(b["tag"] == "amsi-bypass" for b in r["behaviors"])
    # MITRE mapped
    assert any(m["id"] == "T1562.001" for m in r["mitre"])


def test_e2e_amsi_hidden_inside_base64_ps_enc():
    """AMSI bypass wrapped in base64 -Enc should still be detected after decode."""
    import base64
    inner = ("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
             ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")
    utf16 = inner.encode("utf-16-le")
    b64 = base64.b64encode(utf16).decode()
    r = analyze_command(f"powershell -Enc {b64}")
    assert r["amsi_bypass"]["detected"] is True, \
        "AMSI bypass hidden in -Enc payload should be detected after decode"
    assert r["amsi_bypass"]["severity"] == "critical"
    assert any(m["id"] == "T1562.001" for m in r["mitre"])


def test_e2e_no_amsi_no_false_alarm():
    r = analyze_command("powershell.exe -Command Get-ChildItem C:\\Users")
    assert r["amsi_bypass"]["detected"] is False
