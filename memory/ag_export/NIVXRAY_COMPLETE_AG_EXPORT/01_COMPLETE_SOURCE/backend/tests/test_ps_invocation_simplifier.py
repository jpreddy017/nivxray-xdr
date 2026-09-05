"""Regression fixture for PowerShell Invocation Simplifier — the LSASS payload."""
from workspace.convergence.artifact import Artifact
from workspace.convergence.engine import converge


def _run(payload: str, interpreter: str | None = "powershell") -> str:
    art = Artifact.from_input(payload, interpreter=interpreter)
    result = converge(art)
    return result.final_artifact.content


def test_lsass_get_process_full_payload_folds_to_canonical_command():
    payload = "powershell.exe -NoProfile -Command \"&(('Get-' + 'Process') 'lsass')\""
    out = _run(payload)
    # After concat-fold + case-normalize + invocation-simplify the outer
    # `&(...)` wrapper is gone and the cmdlet + arg become a canonical
    # PowerShell command line.
    assert "Get-Process lsass" in out, f"invocation not simplified · out={out!r}"
    assert "&((" not in out and "&(" not in out, \
        f"call operator wrapper still present · out={out!r}"


def test_simple_invocation_without_outer_parens():
    payload = "powershell.exe -NoProfile -Command \"&('Get-Process') 'lsass'\""
    out = _run(payload)
    assert "Get-Process lsass" in out
    assert "&(" not in out


def test_invocation_no_args():
    payload = "powershell.exe -Command \"&('whoami')\""
    out = _run(payload)
    assert "whoami" in out
    assert "&(" not in out


def test_invocation_composed_with_concat_fold():
    """Full chain: `&(('who'+'ami') 'me')` requires concat then invoke."""
    payload = "powershell.exe -Command \"&(('who' + 'ami') 'me')\""
    out = _run(payload)
    assert "whoami me" in out
    assert "&(" not in out


def test_bash_amp_subshell_not_touched():
    """Rule 19: bash `& (subshell)` must NOT be folded by this PS-only primitive."""
    payload = "#!/bin/bash\nnohup long_running &\n(echo 'in subshell')"
    out = _run(payload, interpreter=None)
    # bash payloads have no PowerShell positive identifier, so the
    # invocation simplifier stays hands-off.
    assert "&" in out
    assert "(echo 'in subshell')" in out


def test_cmd_ampersand_separator_not_touched():
    """CMD uses `&` as a command separator — must not be folded."""
    payload = "dir & echo ('literal')"
    out = _run(payload, interpreter=None)
    assert "&" in out


def test_unsafe_primary_not_folded():
    """If the primary literal has whitespace or specials, don't fold."""
    payload = "powershell.exe -Command \"&('Get Process') 'lsass'\""
    out = _run(payload)
    # Primary contains whitespace → NOT safe to unquote as a cmdlet name.
    # Fold must refuse to fire.
    assert "&(" in out


def test_arg_with_whitespace_kept_quoted():
    payload = "powershell.exe -Command \"&('Get-Item') 'C:\\Program Files'\""
    out = _run(payload)
    # `Get-Item` is safe, arg has a space so it stays quoted.
    assert "Get-Item 'C:\\Program Files'" in out


def test_no_regression_on_plain_powershell_iex():
    """Existing PS payloads must still decode the same way."""
    payload = "powershell.exe -Command \"iex ('Get-Process')\""
    out = _run(payload)
    # `iex` alias expansion is handled by the semantic pass — the
    # invocation simplifier only fires on `&(...)` call operator syntax,
    # not on `iex (...)` alias-invocation.
    assert "iex" in out.lower() or "Invoke-Expression" in out
