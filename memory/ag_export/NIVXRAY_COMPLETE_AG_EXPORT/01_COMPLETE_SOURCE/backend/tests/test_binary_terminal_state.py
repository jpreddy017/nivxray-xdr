"""Tests for the canonical-binary terminal state (IEDDE §5.1)."""
from __future__ import annotations

import base64

from services.recipe_planner import plan_and_execute


def _wrap_pe_in_ps(pe_bytes: bytes) -> str:
    """A PS payload that base64-decodes a PE binary — the classic
    'reflective-load' shape: fromBase64 → PE bytes in memory."""
    b64 = base64.b64encode(pe_bytes).decode()
    return f"powershell.exe -c \"[Convert]::FromBase64String('{b64}')\""


def test_pe_binary_recovered_after_base64_decode():
    # Minimal PE-like header: MZ...
    pe = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"\x64\x86" + b"\x00" * 120
    r = plan_and_execute(_wrap_pe_in_ps(pe))
    assert r.terminal_state == "binary_artifact_recovered", r.terminal_state
    assert r.binary_artifact is not None
    assert r.binary_artifact.kind == "PE"
    assert "Parse PE Header" in r.binary_artifact.to_dict()["next_actions"]
    assert "canonical_binary_recovered" in r.stop_reason


def test_elf_binary_recovered():
    elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 80
    r = plan_and_execute(_wrap_pe_in_ps(elf))
    assert r.terminal_state == "binary_artifact_recovered"
    assert r.binary_artifact.kind == "ELF"


def test_plain_text_starting_with_mz_not_labelled_binary():
    """`MZ` at the start of a plain-text sentence must NOT trigger
    the binary terminal state."""
    r = plan_and_execute("MZ is the CEO of Meta Platforms. Just a plain sentence.")
    assert r.terminal_state != "binary_artifact_recovered"


def test_text_canonical_still_canonical():
    r = plan_and_execute("Get-Process")
    assert r.terminal_state == "canonical"
    assert r.binary_artifact is None
