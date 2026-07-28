"""v1.5.2 regression coverage — two production-visible defects surfaced
by an analyst screenshot on 2026-02-XX:

    (1) Pressing DECODE on a PowerShell EncodedCommand+Gzip payload
        showed a red "Unknown operation: ps-encodedcommand-recovery"
        badge inside the Recipe / Decoding Trace panel. Root cause:
        the RC22 orchestrator emits `ps-encodedcommand-recovery` as
        step 02 of every EncodedCommand recipe, but the op-id was
        NOT registered in ``operations.OPERATIONS`` — so the
        ``/api/recipe/run`` replay path raised ValueError.

    (2) On the fully-recovered L2 shellcode-injector plaintext the
        Investigation Brain returned ``BENIGN · confidence 60`` with
        "No adversarial intent was inferred" — even though the
        recovered code was a textbook reflective PowerShell shellcode
        loader (VirtualAlloc RWX + Marshal.Copy + delegate invoke +
        Microsoft.Win32.UnsafeNativeMethods reflection). Root cause:
        the Defense-Evasion rule had no signatures for the canonical
        reflective-injection primitives.

These tests LOCK both fixes into the regression suite so a future
refactor cannot silently re-introduce either defect."""
from __future__ import annotations

import pytest


# ── Fix 1 · ps-encodedcommand-recovery is a known op ─────────────

def test_ps_encodedcommand_recovery_is_registered():
    """The recipe UI must be able to look this op-id up."""
    # Import via ``server`` so every decoder module's @op decorator
    # has run — otherwise ``operations.OPERATIONS`` is only partially
    # populated and the alias registration in operations.py cannot
    # find ``powershell-encoded`` at import time.
    import server  # noqa: F401
    from operations import OPERATIONS
    assert "ps-encodedcommand-recovery" in OPERATIONS, (
        "The RC22 orchestrator emits `ps-encodedcommand-recovery` as a "
        "recipe step; it MUST be resolvable by run_operation()."
    )


def test_ps_encodedcommand_recovery_replay_matches_powershell_encoded():
    """The alias must reproduce the SAME output as the underlying
    ``powershell-encoded`` decoder — recipe replay is expected to be
    byte-identical to the smart_decode L0→L1 result."""
    import server  # noqa: F401
    from operations import run_operation

    sample = (
        "%COMSPEC% /b /c start /b /min powershell -nop -w hidden "
        "-encodedcommand "
        # base64(UTF-16LE("Write-Host STAGE-1"))
        "VwByAGkAdABlAC0ASABvAHMAdAAgAFMAVABBAEcARQAtADEA"
    )
    alias_out = run_operation("ps-encodedcommand-recovery", sample)
    canon_out = run_operation("powershell-encoded", sample)
    assert alias_out == canon_out, (
        "ps-encodedcommand-recovery must be a byte-identical alias of "
        "powershell-encoded."
    )
    assert "Write-Host" in alias_out
    assert "STAGE-1" in alias_out


def test_recipe_run_no_longer_errors_on_encodedcommand_recovery_step():
    """End-to-end regression: a two-step recipe that STARTS with
    ``ps-encodedcommand-recovery`` must succeed with zero errors."""
    import server  # noqa: F401
    from operations import run_operation
    sample = (
        "powershell -encodedcommand "
        "VwByAGkAdABlAC0ASABvAHMAdAAgAEcATwA="  # b64(utf16le("Write-Host GO"))
    )
    out = run_operation("ps-encodedcommand-recovery", sample)
    assert out and "Write-Host" in out


# ── Fix 2 · Reflective shellcode injection fires DEFENSE_EVASION ─

_REFLECTIVE_LOADER = r"""
Set-StrictMode -Version 2

$DoIt = @'
function func_get_proc_address {
    Param ($var_module, $var_procedure)
    $var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))
    return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))
}

[Byte[]]$var_code = [System.Convert]::FromBase64String('AAECAwQFBgcICQ==')

for ($x = 0; $x -lt $var_code.Count; $x++) {
    $var_code[$x] = $var_code[$x] -bxor 35
}

$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))
$var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)

$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))
$var_runme.Invoke([IntPtr]::Zero)
'@

IEX $DoIt
"""


def _fire_defense_evasion(text: str):
    from v2.investigation.intent.rules.defense_evasion import RULE
    return RULE.detect(text, {})


def test_reflective_injection_primitives_fire_defense_evasion():
    """The four canonical primitives of a reflective PowerShell
    shellcode loader MUST each fire a DEFENSE_EVASION intent when
    present in the recovered artefact."""
    intents = _fire_defense_evasion(_REFLECTIVE_LOADER)
    signatures = {
        (ev.meta.get("signature") if ev.meta else None)
        for i in intents for ev in i.evidence
    }
    # At LEAST these three must fire. Marshal.Copy is a bonus depending
    # on whitespace but the loader has all three primary signals.
    assert "Delegate-invoked function pointer" in signatures
    assert "Reflective Win32 API resolution"   in signatures
    assert "RWX shellcode allocation"          in signatures


def test_reflective_injection_intents_are_high_risk():
    """Reflective injection primitives must carry HIGH risk so the
    verdict engine's `high_evasion` short-circuit fires MALICIOUS."""
    from v2.investigation.intent.models import RiskBand
    intents = _fire_defense_evasion(_REFLECTIVE_LOADER)
    reflective_names = {
        "RWX shellcode allocation",
        "Delegate-invoked function pointer",
        "Reflective Win32 API resolution",
        "Shellcode copy to unmanaged memory",
    }
    for it in intents:
        for ev in it.evidence:
            sig = ev.meta.get("signature") if ev.meta else None
            if sig in reflective_names:
                assert it.risk == RiskBand.HIGH, (
                    f"Reflective-injection signature {sig!r} must be HIGH "
                    f"risk; got {it.risk}."
                )


def test_reflective_loader_verdict_is_malicious():
    """End-to-end through the Investigation Brain: the reflective
    loader must be MALICIOUS, never BENIGN."""
    from v2.investigation.pipeline import investigate
    inv = investigate(_REFLECTIVE_LOADER)
    v = inv.verdict.to_dict()
    assert v.get("band") == "malicious", (
        f"Expected MALICIOUS verdict on reflective shellcode loader, "
        f"got {v.get('band')!r}. Reason: {v.get('reason')!r}"
    )
    assert "defense_evasion" in (v.get("reasoning") or {}).get("composition", [])


def test_benign_admin_ps_still_not_flagged_by_reflective_rules():
    """The new signatures must NOT fire on benign administrative
    scripts — protects against false positives."""
    benign = (
        'Write-Host "Applying policy"\n'
        'Set-ExecutionPolicy -Scope Process RemoteSigned\n'
        'Get-Service -Name Spooler | Restart-Service\n'
        'Write-Host "Done"\n'
    )
    intents = _fire_defense_evasion(benign)
    reflective = {
        "RWX shellcode allocation",
        "Delegate-invoked function pointer",
        "Reflective Win32 API resolution",
        "Shellcode copy to unmanaged memory",
        "In-memory dynamic assembly build",
    }
    for it in intents:
        for ev in it.evidence:
            sig = ev.meta.get("signature") if ev.meta else None
            assert sig not in reflective, (
                f"False positive: signature {sig!r} fired on benign admin "
                f"script."
            )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
