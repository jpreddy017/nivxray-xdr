"""Broken Payload Diagnostics — Phase 2 · 2026-02.

Every non-canonical PlanResult must carry structured, analyst-facing
`diagnostics` that cite:
    • layer          — which decoder / cipher / structural step halted
    • reason         — human-readable explanation
    • recommendation — what the analyst should do next
    • severity       — critical | high | medium | info
    • code           — machine-parseable label
    • hex_snippet    — optional 32-byte peek of the offending bytes

Rule 23 anchor: the engine must never fail silently. These tests lock
that contract in place.
"""
import pytest

from services.recipe_planner import plan_and_execute


def _all_have_required_fields(diags):
    for d in diags:
        for key in ("layer", "reason", "recommendation", "severity", "code"):
            assert key in d, f"diagnostic missing key: {key} · diag={d}"
            assert isinstance(d[key], str)
            assert d[key], f"empty value on key {key}"


def test_canonical_recovery_carries_no_diagnostics():
    """Successful recovery → diagnostics list must be empty."""
    r = plan_and_execute("whoami")
    assert r.terminal_state == "canonical"
    assert r.diagnostics == []


def test_stability_gate_carries_reasoned_diagnostics():
    """Any non-canonical terminal state must produce ≥1 diagnostic."""
    r = plan_and_execute(
        'powershell.exe -Command "$aes = [System.Security.Cryptography.Aes]::Create()"'
    )
    assert r.terminal_state == "stability_gate"
    assert len(r.diagnostics) >= 1
    _all_have_required_fields(r.diagnostics)


def test_diagnostics_are_deterministic():
    """Identical input → byte-identical diagnostics (Rule 21)."""
    payload = 'powershell.exe -Command "$aes = [System.Security.Cryptography.Aes]::Create()"'
    r1 = plan_and_execute(payload)
    r2 = plan_and_execute(payload)
    assert r1.diagnostics == r2.diagnostics


def test_binary_artifact_recovered_produces_no_diagnostics():
    """Binary handoff is not a failure — no diagnostics."""
    import base64
    pe = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"\x64\x86" + b"\x00" * 120
    b64 = base64.b64encode(pe).decode()
    payload = f'powershell.exe -c "[Convert]::FromBase64String(\'{b64}\')"'
    r = plan_and_execute(payload)
    assert r.terminal_state == "binary_artifact_recovered"
    assert r.diagnostics == []


def test_diagnostics_serialize_into_planresult_dict():
    r = plan_and_execute(
        'powershell.exe -Command "$aes = [System.Security.Cryptography.Aes]::Create()"'
    )
    d = r.to_dict()
    assert "diagnostics" in d
    assert isinstance(d["diagnostics"], list)
    assert len(d["diagnostics"]) >= 1


def test_diagnostics_include_hex_snippet_or_none():
    r = plan_and_execute(
        'powershell.exe -Command "$aes = [System.Security.Cryptography.Aes]::Create()"'
    )
    for d in r.diagnostics:
        assert "hex_snippet" in d
        # hex_snippet is either None or a whitespace-separated hex string.
        if d["hex_snippet"]:
            parts = d["hex_snippet"].split()
            assert all(len(p) == 2 and int(p, 16) >= 0 for p in parts)
