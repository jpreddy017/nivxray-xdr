"""P0.15A · Octlurk regression fixture · Securelist 2026-02-08.

Locks the end-to-end contract:
    OCR-derived Octlurk commands
        → Canonicalizer (cmd /S /C unwrap)
        → _classify_command_purpose
        → _mitre_from_purpose bridge
        → MITRE tids + tactics land

This is the case that motivated ADR-002 · the Securelist Octlurk
article rendered every command as an image with empty alt-text
AND every command wrapped as ``cmd.exe /S /C "..."``.  When VEEE
lands in P0.15B it will simply feed OCR text through this same
path — this fixture proves the downstream contract holds today.
"""
from __future__ import annotations

from services.ida.report_extractors      import _classify_command_purpose
from services.ice.correlate              import _mitre_from_purpose, tactic_for


# Post-OCR reproduction of every command from the 5 Octlurk images.
# `head` reflects the RAW head — canonicalizer must unwrap cmd.exe.
_OCTLURK_COMMANDS = [
    ("cmd.exe",
     'cmd.exe /S /C "SCHTASKS /Create /S 10.0.0.1 /U corp\\alice /P pwd '
     '/SC ONCE /TN GoogleUpDate /TR C:\\Users\\v\\Videos\\1.bat '
     '/ST 23:00 /ru system /F"',
     "Scheduled Task remote create"),
    ("cmd.exe",
     'cmd.exe /S /C "schtasks /query /S 10.0.0.1 /TN GoogleUpDate /V"',
     "Scheduled Task query"),
    ("cmd.exe",
     'cmd.exe /S /C "SCHTASKS /run /S 10.0.0.1 /TN GoogleUpDate"',
     "Scheduled Task remote create"),   # /run is a remote-exec pattern
    ("reg.exe",
     'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" '
     '/v NgcCIntSvc /t REG_MULTI_SZ /d NgcCIntSvc /f',
     "Registry modification"),
    ("sc.exe",
     'sc create "NgcCIntSvc" binPath= "system32\\svchost.exe -k NgcCIntSvc" '
     'type= share start= auto DisplayName= "Microsoft Passport Interface"',
     "Windows Service create (persistence)"),
    ("reg.exe",
     'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NgcCIntSvc\\Parameters" '
     '/v ServiceDll /t REG_EXPAND_SZ /d c:\\Windows\\System32\\oleasapi.dll /f',
     "Registry modification"),
    ("net.exe",
     'net start "NgcCIntSvc"',
     "Windows Service start"),
    ("sc.exe",
     'sc failure "NgcCIntSvc" reset= 0 actions= restart/10000',
     "Windows Service failure-action configure"),
    ("cmd.exe",
     'cmd.exe /S /C "ping dns.essentialserv.xyz -n 1"',
     "Ping (C2 beacon / DNS resolution)"),
    ("cmd.exe",
     'cmd.exe /S /C "%TEMP%\\adobe.exe user@10.0.0.1 -no-pass '
     '-just-dc-user Administrator"',
     "Credential dumping (secretsdump-family)"),
    ("cmd.exe",
     'cmd.exe /S /C "tasklist /v"',
     "Process discovery (tasklist)"),
    ("cmd.exe",
     'cmd.exe /S /C "taskkill /f /im Adobe.exe"',
     "Process termination"),
    ("cmd.exe",
     'cmd.exe /S /C "net group Domain Controllers /domain"',
     "Domain-controllers enumeration"),
    ("cmd.exe",
     'cmd.exe /S /C "C:\\Users\\Public\\Pictures\\AnyDesk.exe"',
     "AnyDesk RMM execution"),
    ("cmd.exe",
     'cmd.exe /S /C "schtasks /create /tn AnyDesk /tr AnyDesk.exe /sc onlogon '
     '/ru NT_AUTHORITY_INTERACTIVE"',
     "Scheduled Task create"),
]


# ══════════════════════════════════════════════════════════════════
# Every command lands on the expected purpose label
# ══════════════════════════════════════════════════════════════════
def test_every_octlurk_command_classifies_to_expected_purpose():
    misses = []
    for head, cmd, expected in _OCTLURK_COMMANDS:
        got = _classify_command_purpose(cmd, head)
        if got != expected:
            misses.append(f"  · [{head}] {cmd[:50]}… → got {got!r}, expected {expected!r}")
    assert not misses, (
        "Canonicalizer + classifier drift on Octlurk fixture:\n"
        + "\n".join(misses))


# ══════════════════════════════════════════════════════════════════
# Every purpose has a MITRE bridge entry
# ══════════════════════════════════════════════════════════════════
def test_every_octlurk_purpose_bridges_to_mitre():
    unbridged = []
    for _, _, expected in _OCTLURK_COMMANDS:
        if not _mitre_from_purpose(expected):
            unbridged.append(expected)
    assert not unbridged, (
        f"Missing bridge for Octlurk purposes: {sorted(set(unbridged))}")


# ══════════════════════════════════════════════════════════════════
# ATT&CK tactic coverage — must span ≥ 5 tactics
# ══════════════════════════════════════════════════════════════════
def test_octlurk_fixture_spans_at_least_5_attack_tactics():
    tactics = set()
    for _, _, expected in _OCTLURK_COMMANDS:
        for m in _mitre_from_purpose(expected):
            t = tactic_for(m["id"])
            if t:
                tactics.add(t)
    # Discovery, Persistence, Credential Access, Impact, C2 all
    # legitimately observed on the Octlurk campaign.
    assert len(tactics) >= 5, (
        f"Octlurk fixture should cover ≥ 5 tactics, got {sorted(tactics)}")
    for required in ("persistence", "credential_access",
                       "discovery", "command_and_control"):
        assert required in tactics, (
            f"Octlurk fixture must cover {required} — got {sorted(tactics)}")


# ══════════════════════════════════════════════════════════════════
# Baseline check — before P0.15A the same fixture collapses to
# a single generic label.  This test ensures we can't silently
# regress back to the pre-canonicalizer behaviour.
# ══════════════════════════════════════════════════════════════════
def test_octlurk_fixture_does_not_collapse_to_generic_command_execution():
    labels = {_classify_command_purpose(cmd, head)
                  for head, cmd, _ in _OCTLURK_COMMANDS}
    assert "Command execution" not in labels, (
        "The Canonicalizer must peel cmd.exe /S /C wrappers — if this "
        "test fails we've silently regressed to the pre-P0.15A behaviour.")
    assert len(labels) >= 10, (
        f"Expected ≥ 10 distinct labels, got {len(labels)}: {sorted(labels)}")
