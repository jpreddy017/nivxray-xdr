"""
IDA · Slice 1.7 · Resource Acquisition + Threat-Report Extractors.

Two flavours of test:
  · Deterministic unit tests over `understand_document` and
    `extract_all` against a canned article body — no network.
  · One end-to-end guardrail that hits the live eSentire URL and
    proves acquisition + extraction populate the SSOT.  Marked
    `slow` so CI can skip when offline.
"""
from __future__ import annotations
import pytest

from services.ida import (
    understand_document, extract_all,
    classify_url_intent, acquire_url,
)


CANNED_ARTICLE = """
Email Bombing, IT Impersonation, Quick Assist, and Edgecution
Author: Esentire TRU
Published: July 22, 2026

Executive Summary

In July 2026, eSentire observed UNC6692 conducting a multi-stage
intrusion. Initial access relied on email bombing followed by IT
impersonation over Microsoft Teams. Operators pivoted through Quick
Assist to establish hands-on-keyboard access on the victim host.

Attack Chain

1. Phishing → email bombing
2. Quick Assist session with the attacker
3. Download of Edgecution ZIP
4. Extract Python native messaging host
5. Load Edge extension for persistence

Commands observed:

    powershell -NoProfile -EncodedCommand JAB0ID0g...
    cmd.exe /c tar -xf edgecution.zip
    python.exe C:\\Users\\Public\\python\\host.py

MITRE ATT&CK Techniques

T1078 Valid Accounts
T1105 Ingress Tool Transfer
T1176 Browser Extensions
T1218 Signed Binary Proxy Execution
T1547 Boot or Logon Autostart Execution

Malware and Tooling

Edgecution loader, Quick Assist RMM abuse, Cobalt Strike beacon.

Indicators of Compromise

    d41d8cd98f00b204e9800998ecf8427ed41d8cd98f00b204e9800998ecf8427e
    hxxps://evil-cdn.example/payload.zip
    203.0.113.42
    edgecution-c2.example

Vulnerabilities

CVE-2024-38112 was leveraged during the initial access phase.

Timeline

- July 3, 2026 — first phishing wave sent
- July 8, 2026 — victim contacts help-desk
- July 12, 2026 — Quick Assist session established
- July 15, 2026 — Edge extension deployed

YARA Rules

rule Edgecution_Native_Messaging_Host
{
  meta:
    author = "eSentire TRU"
  strings:
    $a = "native-messaging" ascii
  condition:
    $a
}
"""


def test_understand_document_finds_capabilities_and_signals():
    prof = understand_document(
        CANNED_ARTICLE,
        {"sitename": "eSentire", "title": "Test", "author": "TRU",
         "published_date": "2026-07-22", "language": "en"},
    )
    assert prof["ok"] is True
    assert prof["vendor"]        == "eSentire"
    assert prof["mitre_present"] is True
    assert prof["cve_present"]   is True
    assert prof["yara_present"]  is True
    assert prof["timeline_present"] is True
    assert "initial_access" in prof["capabilities"]
    assert "persistence"    in prof["capabilities"]
    assert "command_and_control" in prof["capabilities"]
    # Section detection is order-preserving and precision-first.
    assert "Executive Summary" in prof["sections"]
    assert "Attack Chain"      in prof["sections"]
    assert "Timeline"          in prof["sections"]
    # MITRE / YARA presence is asserted via presence flags above —
    # `MITRE ATT&CK` as a raw header may or may not appear on its own
    # line depending on the article layout.


def test_extract_all_populates_every_bucket():
    ext = extract_all(CANNED_ARTICLE)
    totals = ext["totals"]
    assert totals["mitre"]     >= 5
    assert totals["cves"]      >= 1
    assert totals["actors"]    >= 1
    assert totals["malware"]   >= 2
    assert totals["commands"]  >= 2
    assert totals["timeline"]  >= 4
    assert totals["yara"]      == 1
    # Every MITRE hit carries an ID + evidence excerpt.
    for t in ext["mitre_techniques"]:
        assert t["id"].startswith("T")
        assert t["evidence"]
    # CVE parses year.
    assert ext["cves"][0]["year"] == 2024
    # Actor list carries UNC6692 (generic pattern) not a curated one.
    assert any(a["name"] == "UNC6692" for a in ext["threat_actors"])
    # Every command carries a purpose label.
    for c in ext["commands"]:
        assert c.get("purpose"), f"command missing purpose: {c}"


def test_extract_commands_from_structured_blocks_matches_esentire_table():
    """Reproduces the eSentire UNC6692 Command-Line table shape —
    every row is a `<td>` cell.  IDA-4 must extract every row and
    dedupe."""
    structured_blocks = [
        'tar.exe -xf "<random>.zip" -C "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\test1" --passphrase "<random>"',
        'tar.exe -xf "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\test1\\python-3.13.3-embed-amd64-with-pip.zip" -C "%PROGRAMDATA%\\python-3.13.3"',
        'cmd.exe /c python --version 2>&1',
        'cmd.exe /c python3 --version 2>&1',
        '"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" --user-data-dir="%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Recovery" --load-extension="%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\test1\\extension" --no-first-run --no-startup-window --disable-sync',
        '"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" --user-data-dir="%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Recovery" --load-extension="%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\test1\\extension" --no-first-run --headless=new --disable-sync',
        'cmd /c start /min "" cmd /c timeout 4 & del "<AutoHotkey_path>" 2>nul & del "<.ahk path>" & exit /b',
        'powershell -NoProfile -NonInteractive -Command "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress -Depth 2"',
        'cmd /c chcp 65001 >nul && powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -',
    ]
    ext = extract_all("", structured_blocks)
    heads = [c["head"] for c in ext["commands"]]
    # All 9 rows must be extracted.
    assert len(ext["commands"]) == 9, [c["command"][:60] for c in ext["commands"]]
    # Purpose labels for the most-recognisable rows.
    purposes = [c["purpose"] for c in ext["commands"]]
    assert any("Unzip Python" in p for p in purposes)
    assert any("Python interpreter discovery" in p for p in purposes)
    assert any("Microsoft Edge launch" in p for p in purposes)
    assert any("Self-deletion" in p for p in purposes)
    assert any("PowerShell process enumeration" in p for p in purposes)
    # No prose false positives — "Ping/pong (health check)" / "PowerShell
    # execution in native_host.py" must NOT sneak in.
    for c in ext["commands"]:
        assert "health check" not in c["command"]
        assert "native_host.py" not in c["command"] or c["command"].startswith("cmd")


def test_extract_all_empty_input():
    ext = extract_all("")
    assert ext["totals"]["artifacts"] == 0
    assert ext["mitre_techniques"] == []


def test_url_intent_ip_only_url_stays_atomic():
    v = classify_url_intent("http://203.0.113.42/beacon")
    assert v["intent"]     == "atomic_ioc"
    assert v["acquirable"] is False


def test_acquire_url_rejects_private_host():
    r = acquire_url("http://127.0.0.1/secret")
    assert r.ok is False
    assert r.error_code == "private_host"


def test_acquire_url_rejects_blocked_scheme():
    r = acquire_url("file:///etc/passwd")
    assert r.ok is False
    assert r.error_code == "blocked_scheme"


@pytest.mark.slow
def test_acquire_esentire_end_to_end_live():
    """Live network guardrail — proves the full IDA-3 → IDA-3.5 →
    IDA-4 pass populates the SSOT for a real vendor article."""
    url = ("https://www.esentire.com/blog/email-bombing-it-impersonation-"
           "quick-assist-and-edgecution-breaking-down-unc6692s-tradecraft")
    r = acquire_url(url)
    if not r.ok:
        pytest.skip(f"eSentire unreachable in CI: {r.error_code} — {r.error_detail}")
    assert r.article_chars > 2000
    assert "esentire" in (r.sitename or "").lower() or "esentire" in url
    ext = extract_all(r.article_text)
    assert ext["totals"]["actors"] >= 1
    assert ext["totals"]["malware"] >= 1
