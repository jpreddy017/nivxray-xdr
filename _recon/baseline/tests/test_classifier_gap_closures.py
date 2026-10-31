"""
Classifier gap-closure regression tests (2026-02-09)

Locks the three classifier fixes surfaced by the Quality
Dashboard on the vendor corpus.  If any of these labels ever
regress to "Command execution" (the deliberate catch-all), CI
fails immediately.
"""
from __future__ import annotations
import pytest
from services.ida.report_extractors import _classify_command_purpose
from services.knowledge.behavior_registry import lookup


# ── The three gaps that were closed in the sprint close ──────────
_CASES = [
    # (name, command, head_token, expected_label, expected_technique_id)
    ("SMB admin-share access · T1021.002",
        "net use \\\\target\\c$ /user:admin pwd123",
        "net",
        "SMB admin share access",
        "T1021.002"),
    ("WMI process discovery · call getowner",
        "cmd.exe /c wmic process where name='lsass.exe' call getowner",
        "cmd.exe",
        "WMI process discovery",
        "T1057"),
    ("PowerShell encoded command via cmd /c",
        "cmd.exe /c powershell.exe -EncodedCommand SQBFAFgAKAA==",
        "cmd.exe",
        "PowerShell encoded command",
        "T1059.001"),
]


@pytest.mark.parametrize("name, command, head, expected_label, expected_tech",
                              _CASES,
                              ids=[c[0] for c in _CASES])
def test_gap_closure_label_stable(name, command, head, expected_label, expected_tech):
    got = _classify_command_purpose(command, head)
    assert got == expected_label, (
        f"[{name}] classifier regressed · got {got!r}, expected {expected_label!r}. "
        f"This means the sprint-close gap-closure has been reverted.")


@pytest.mark.parametrize("name, command, head, expected_label, expected_tech",
                              _CASES,
                              ids=[c[0] for c in _CASES])
def test_gap_closure_bkb_mapping_stable(name, command, head, expected_label, expected_tech):
    """Every closed-gap label must remain in the BKB and map to
    its canonical technique."""
    spec = lookup(expected_label)
    assert spec is not None, f"BKB entry missing for {expected_label!r}"
    tech_ids = [t["id"] for t in spec.canonical_techniques]
    assert expected_tech in tech_ids, (
        f"BKB canonical techniques for {expected_label!r} = {tech_ids}, "
        f"expected {expected_tech!r} present")


def test_generic_fallback_still_reserved_for_true_unknowns():
    """The 'Command execution' catch-all must still return for
    truly-unknown commands — closing gaps must not overreach."""
    for cmd in ("bogus-xyz-abc-executable --do-nothing",
                    "totally-made-up-command foo bar"):
        got = _classify_command_purpose(cmd, cmd.split()[0])
        assert got == "Command execution", (
            f"unknown command {cmd!r} classified as {got!r} · "
            f"pattern-matching too greedy")
