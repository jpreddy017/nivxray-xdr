"""Regression suite for the recursive deterministic deobfuscator
(NivXRay-Workspace 2026-07-25).

Locked with SOC user 2026-07-25. The reference sample uses:
    • dynamic type name via `-f` format
    • dynamic method name via `-f` format
    • backtick escape inside `v`ALUe`
    • Get-Variable indirection to fetch the type
    • [String]::Join over a %{ [char]([Convert]::ToInt16(...,8)) } octal
      character reconstruction

The final payload MUST recover to:
    Write-Host 'Hello, from PowerShell!'
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v2.semantic.ps_deobfuscate import deobfuscate                    # noqa: E402


_USER_SAMPLE = (
    "$cmDwhy =[TyPe](\"{0}{1}\" -f 'S','TrING');\n"
    "$pz2Sb0 =[TYpE](\"{1}{0}{2}\"-f'nv','cO','ert');\n"
    "\n"
    "&(\"{0}{2}{3}{1}{4}\" -f'In','SiO','vOKe-EXp','ReS','n')(\n"
    "    (&(\"{1}{2}{0}\"-f'blE','gET-','vaRIA')('CMdwhy'))"
    "\"v`ALUe\"::(\"{1}{0}\" -f'iN','jO').Invoke(\n"
    "        '',\n"
    "        (\n"
    "            (127,162,151,164,145,55,110,157,163,164,40,47,110,145,154,154,157,54,40,146,162,157,155,40,120,157,167,145,162,123,150,145,154,154,41,47)\n"
    "            | %{[char]([Convert]::ToInt16(([string]$_),8))}\n"
    "        )\n"
    "    )\n"
    ")"
)


def test_recovers_final_payload() -> None:
    r = deobfuscate(_USER_SAMPLE)
    # The octal-decoded literal MUST appear in the final text.
    assert "Write-Host 'Hello, from PowerShell!'" in r.final, (
        f"expected the fully deobfuscated payload; got\n{r.final[:400]}")


def test_stage_chain_contains_all_techniques() -> None:
    r = deobfuscate(_USER_SAMPLE)
    techs = [s.technique for s in r.stages]
    assert any("backtick" in t.lower() for t in techs), techs
    assert any("format" in t.lower() for t in techs), techs
    assert any("octal" in t.lower() for t in techs), techs


def test_stops_at_execution_boundary() -> None:
    r = deobfuscate(_USER_SAMPLE)
    assert r.boundary_op, "expected an execution boundary to be reported"
    assert "invoke" in r.boundary_op.lower(), (
        f"expected Invoke-Expression as the halt boundary; got {r.boundary_op!r}")


def test_never_executes_iex() -> None:
    """The deobfuscator must NEVER interpret Invoke-Expression — it
    stops safely instead of trying to run the payload."""
    r = deobfuscate(_USER_SAMPLE)
    # The final still contains the invoke call (not executed)
    assert "invoke" in r.final.lower()


def test_octal_recovery_correct_bytes() -> None:
    """Direct verification: 127 (octal) = 87 = 'W', etc."""
    r = deobfuscate(_USER_SAMPLE)
    assert "Write" in r.final
    assert "Hello, from PowerShell!" in r.final


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
