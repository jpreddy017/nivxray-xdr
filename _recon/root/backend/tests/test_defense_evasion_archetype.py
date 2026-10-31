"""Plaintext defense-evasion behavior detector regression — Feb 2026.

Real-world SOC gap: a WorkBuddy/CodeBuddy incident triaged by Cisco XDR + MDE
was a **plaintext** PowerShell script — no obfuscation, so none of NivXRay's
unwrap-first archetypes matched. This archetype hunts for concurrent
defense-evasion + credential-access + security-software-discovery TTPs and
produces a HIGH-severity annotation.

These tests lock the behaviour so no future change can silently degrade it.
"""
from __future__ import annotations
import os, sys, pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from wrapper_archetypes import try_archetypes


def test_ttp_pattern_disable_defender_and_cmdkey():
    """sc.exe stop Sense + cmdkey /list + Get-Process → must fire."""
    sample = (
        "sc.exe config Sense start= disabled\n"
        "reg.exe delete HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender /f\n"
        "cmdkey.exe /list\n"
        "Get-Process | Format-Table\n"
        "http://49.75.27.62/c2\n"
    )
    r = try_archetypes(sample)
    assert r is not None, "archetype should have matched"
    out = r["output"]
    assert "Defense-Evasion Behavior Pattern Detected" in out
    assert "T1562.001" in out
    assert "T1071" in out
    assert "49.75.27.62" in out


def test_edr_product_enumeration_alone_is_not_enough():
    """Listing EDR product names WITHOUT any TTP action should NOT fire."""
    sample = (
        "product_list = ['CrowdStrike', 'SentinelOne', 'Carbon Black', "
        "'Cortex', 'Cylance', 'ESET', 'Kaspersky', 'Sophos']\n"
        "print(product_list)\n"
    )
    r = try_archetypes(sample)
    # Only one family (T1518.001) hits → below the ≥ 2 threshold
    if r is not None:
        assert "Defense-Evasion Behavior Pattern Detected" not in r.get("output", "")


def test_workbuddy_launcher_signal_annotated():
    """Presence of WorkBuddy / CodeBuddy tokens must be called out."""
    sample = (
        "$launcher = 'C:\\Users\\x\\AppData\\Local\\CodeBuddy\\launcher.exe'\n"
        "Get-Process ; Get-Service\n"
        "sc.exe config WinDefend start= disabled\n"
    )
    r = try_archetypes(sample)
    assert r is not None
    assert "WorkBuddy/CodeBuddy weaponisation profile matched" in r["output"]


def test_terminal_and_idempotent():
    """Archetype must not re-fire on its own output (cascade guard)."""
    sample = (
        "sc.exe config Sense start= disabled\n"
        "reg.exe delete HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender /f\n"
        "cmdkey /list\n"
        "http://8.8.8.8/x\n"
    )
    r = try_archetypes(sample)
    # engine label must not contain the archetype ID twice
    parts = (r["engine"] or "").split("+")
    parts = [p.replace("archetype:", "") for p in parts]
    assert parts.count("WINDOWS_DEFENSE_EVASION_BEHAVIOR_PATTERN") == 1


def test_json_escaped_content_still_detected():
    """A JSON-escaped script (with \\\\ and \\\" everywhere) must still
    trigger detection — the handler normalises escapes before scoring."""
    inner = 'sc.exe config Sense start= disabled\nreg.exe delete "Windows Defender" /f\nhttp://49.75.27.62/'
    escaped = inner.replace("\\", "\\\\").replace('"', '\\"')
    sample = f'$config = "{escaped}"; Invoke-Expression $config'
    r = try_archetypes(sample)
    assert r is not None
    assert "T1562.001" in r["output"]
