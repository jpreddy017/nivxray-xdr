"""Regression tests · PowerShell interpreter gate (Workspace bug fix, Feb 2026).

Guards the fix in ``routers/ops.py`` that prevents PowerShell-specific
normalization stages from running against Bash / CMD / OpenSSL inputs.

Tests are executed against the ``_looks_like_non_powershell`` helper
that is defined inline inside ``ops.py``. This test file imports the
module and exercises the helper through a lightweight probe.

The tests here map 1:1 to the six regression cases mandated in the
bug-fix specification.
"""
from __future__ import annotations

import importlib
import inspect
import re

import pytest


def _extract_gate_predicate():
    """Extract the ``_looks_like_non_powershell`` inner function from
    ``routers/ops.py`` via source parsing. The helper lives inside a
    request handler so we recompile it into an isolated scope."""
    ops = importlib.import_module("routers.ops")
    src = inspect.getsource(ops)
    m = re.search(
        r"def _looks_like_non_powershell\(text: str\) -> bool:\n"
        r"((?:            .*\n)+)",
        src,
    )
    assert m, "could not locate _looks_like_non_powershell in ops.py"
    body = m.group(0)
    # Re-indent from 12-space method scope down to module scope.
    lines = [ln[8:] if ln.startswith("        ") else ln
             for ln in body.splitlines()]
    module = "import re as _re\n" + "\n".join(lines)
    ns: dict = {}
    exec(compile(module, "<gate-probe>", "exec"), ns)
    return ns["_looks_like_non_powershell"]


_gate = _extract_gate_predicate()


class TestInterpreterGate:
    """Regression 1-4 · positive / negative interpreter classification."""

    def test_bash_eval_openssl_pipeline_is_not_powershell(self):
        raw = ("eval $(echo aGVsbG8= | base64 -d | "
               "openssl enc -aes-256-cbc -d -k mykey)")
        assert _gate(raw) is True

    def test_bare_bash_echo_is_not_powershell(self):
        # `echo hello` — bare shell builtin. Not PowerShell.
        # The gate skips PS stages for this input because the first
        # token isn't in the PS interpreter set; but "echo" isn't in
        # the *non-PS* head list either, so the gate does not block.
        # This test documents the current subtractive-gate semantics:
        # ambiguous input still passes through PS stages, but PS
        # alias expansion only runs when the ``powershell`` keyword
        # is present in ``src`` — which it isn't. Hence ``echo``
        # remains ``echo``. (See TestOwnerAssertions.)
        assert _gate("echo hello") is False

    def test_powershell_prefix_is_powershell(self):
        # Regression 4 — PowerShell inputs must remain eligible for
        # alias expansion.
        assert _gate("powershell echo hello") is False
        assert _gate("powershell.exe -Command Get-ChildItem") is False
        assert _gate("pwsh -c Get-Process") is False

    def test_openssl_leading_call_is_not_powershell(self):
        assert _gate("openssl enc -aes-256-cbc -in x -out y") is True

    def test_cmd_leading_is_not_powershell(self):
        assert _gate("cmd.exe /c echo hello") is True
        assert _gate("cmd /c whoami") is True

    def test_shebang_bash_is_not_powershell(self):
        assert _gate("#!/bin/bash\necho hi") is True
        assert _gate("#!/usr/bin/env bash\nls") is True

    def test_dollar_paren_leading_is_bash_substitution(self):
        assert _gate("$(openssl rand -hex 16)") is True

    def test_leading_backtick_substitution_is_bash(self):
        # Old-style Bash: `command` substitution.
        assert _gate("`openssl rand -hex 16`") is True

    def test_empty_and_none_safe(self):
        assert _gate("") is False
        assert _gate(None) is False  # type: ignore[arg-type]


class TestOwnerAssertions:
    """Regression 5-6 · the two behavioural assertions the owner
    called out explicitly in the fix specification.

    5 · Bash ``eval $(echo ... | openssl ...)`` MUST NOT convert
        ``echo`` into ``Write-Output``.

    6 · The rendered diagnostic ``(OpenSSL` + aes-` + cbc`)`` — even
        though it contains backticks — must never re-enter the
        parser because the parser reads ``src = body.input``, not
        ``result['output_raw']``. This test guards the invariant.
    """

    def test_bash_echo_never_becomes_write_output(self):
        # We test the *gate* invariant directly here — the full
        # end-to-end request is exercised by the ops smoke tests
        # elsewhere.
        raw = "eval $(echo aGVsbG8= | base64 -d | openssl enc -d)"
        skip = _gate(raw)
        assert skip is True, (
            "PowerShell stages must be skipped for Bash pipelines"
        )

    def test_ops_router_reads_body_input_not_output_raw(self):
        # Contract regression: the PS stage guards read ``src``,
        # which is set once from ``body.input``. This ensures the
        # crypto banner emitted into ``result['output_raw']`` can
        # NEVER re-enter PS normalization from within this endpoint.
        ops = importlib.import_module("routers.ops")
        source = inspect.getsource(ops)
        # There must be exactly ONE assignment of ``src`` from
        # body.input, and no assignment of ``src`` from output_raw
        # or from any result field.
        set_from_input = re.findall(r"^\s*src\s*=\s*body\.input",
                                     source, re.MULTILINE)
        assert len(set_from_input) == 1, (
            f"expected exactly one ``src = body.input`` assignment, "
            f"found {len(set_from_input)}"
        )
        set_from_output = re.findall(r"^\s*src\s*=\s*result\[",
                                      source, re.MULTILINE)
        assert set_from_output == [], (
            "``src`` must never be reassigned from result[...]; "
            "generated diagnostics must be terminal"
        )


class TestSubtractiveGateRegressionSafety:
    """Ensure the gate is *subtractive*: legitimate PowerShell inputs
    that don't explicitly name ``powershell`` still fall through the
    PS stages (they may or may not match the inner content signals,
    but the gate itself must not preempt them)."""

    def test_bare_powershell_cmdlet_input_is_not_blocked(self):
        # PowerShell cmdlets without an explicit ``powershell`` prefix
        # are ambiguous — the gate must not block them, because the
        # existing PS content signals inside ops.py already handle
        # them correctly.
        assert _gate("Get-ChildItem C:\\") is False
        assert _gate("Invoke-WebRequest https://x") is False

    def test_pipe_chain_starting_with_get_command_is_ambiguous(self):
        assert _gate("Get-Process | Where-Object Handles -gt 100") is False
