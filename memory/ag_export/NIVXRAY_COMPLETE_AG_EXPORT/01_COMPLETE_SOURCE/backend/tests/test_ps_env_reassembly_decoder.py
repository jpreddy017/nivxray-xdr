"""PowerShell env-var reassembly decoder regression
=====================================================

The classic dynamic-assembly obfuscation:

    powershell.exe -NoP -c "set-item env:x 'Write-';
                             set-item env:y 'Output \"hi\"';
                             iex (gci env:x).value(gci env:y).value"

Splits a command across environment variables and reassembles it via
``iex (gci env:X).value + (gci env:Y).value``. Deterministic reversal
matches every assignment, substitutes the values, and concatenates the
single-quoted literals appearing after ``iex``.

Interpreter Ownership (Governance Rule 19): fires only when
`powershell.exe` / `pwsh` is present in the raw input.
"""
from __future__ import annotations
import pytest

from services.canonical_evidence_recovery import recover_canonical_evidence


def test_ps_env_reassembly_two_var_reported_by_analyst():
    """Exact analyst-reported payload — must produce Write-Output "Test"."""
    payload = (
        'powershell.exe -NoP -c "set-item env:x \'Write-\'; '
        'set-item env:y \'Output "Test"\'; '
        "iex (gci env:x).value(gci env:y).value\""
    )
    art = recover_canonical_evidence(payload)
    assert art.terminal_state == "recovered"
    assert art.decoded_output == 'Write-Output "Test"'
    assert art.chain_ids == ["decoder-ps-env-reassembly"]
    assert art.engine == "ps-env-reassembly"


def test_ps_env_reassembly_dollar_env_form():
    """`$env:X = 'value'` short-form also decodes."""
    payload = (
        "powershell.exe -NoP -c \"$env:a = 'Get-'; "
        "$env:b = 'Process'; "
        "iex (gci env:a).value(gci env:b).value\""
    )
    art = recover_canonical_evidence(payload)
    assert art.terminal_state == "recovered"
    assert art.decoded_output == "Get-Process"


def test_ps_env_reassembly_requires_powershell_host():
    """Governance Rule 19: without positive PS host identification
    (`powershell.exe` / `pwsh`), the reassembly must NOT fire —
    otherwise it would misfire on unrelated env-var references."""
    payload = (
        "set-item env:x 'foo'; iex (gci env:x).value"
    )
    art = recover_canonical_evidence(payload)
    # Must not chain the env-reassembly decoder on bare input without
    # `powershell.exe` or `pwsh` host identification.
    assert art.chain_ids != ["decoder-ps-env-reassembly"]


def test_ps_env_reassembly_falls_through_when_no_env_assignments():
    """Bare PowerShell with no env assignments must not trigger."""
    payload = 'powershell.exe -c "Write-Host \\"hi\\""'
    art = recover_canonical_evidence(payload)
    assert art.chain_ids != ["decoder-ps-env-reassembly"]
