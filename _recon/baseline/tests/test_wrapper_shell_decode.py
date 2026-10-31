"""Regression — shell-wrapper decode patterns (Feb 2026).

Locks the wrapper-hint decode fix that handles:
    * `cmd /c echo <hex>`
    * `Write-Output "<hex>"`
    * `certutil -decodehex - <hex>`
    * `$var = '<hex>'`
    * `echo <b64> | base64 -d`
    * `echo <b64> | base64 --decode`
    * `echo <hex> | xxd -r -p`

Before the fix, the wrapper's English score beat the short decoded output
in the winner-picker, so `deterministic_best_decode` returned the un-decoded
wrapper text (chain=[]). Now the walker applies a +0.55 boost when a
wrapper-hint decode succeeds, and the outer selector respects it via
`score_breakdown.score`.
"""
from __future__ import annotations

import pytest

import ops_extended  # noqa: F401 — registers xor-brute etc
from analysis_core import deterministic_best_decode


WRAPPER_CASES = [
    # (input, expected_substring_in_output, expected_ops_in_chain)
    ("cmd /c echo 5762697465",                  "Wbite",       ["extract-payload", "hex-decode"]),
    ("cmd /c echo 68656c6c6f776f726c64",        "helloworld",  ["extract-payload", "hex-decode"]),
    ("cmd /c echo 4d5a90000300000004000000ffff","MZ",          ["extract-payload", "hex-decode"]),
    ("certutil -decodehex - 4d5a90000300",       "MZ",          ["extract-payload", "hex-decode"]),
    ('$var = "5762697465"',                      "Wbite",       ["extract-payload", "hex-decode"]),
    ("Write-Output '4869207468657265'",          "Hi there",    ["extract-payload", "hex-decode"]),
    ("echo 68656c6c6f776f726c64 | xxd -r -p",    "helloworld",  ["extract-payload", "hex-decode"]),
    ("echo V3JpdGU= | base64 -d",                "Write",       ["extract-payload", "base64-decode"]),
    ("echo aGVsbG8gd29ybGQ= | base64 -d",        "hello world", ["extract-payload", "base64-decode"]),
    ("echo SGVsbG8gV29ybGQ | base64 --decode",   "Hello World", ["extract-payload", "base64-decode"]),
]


@pytest.mark.parametrize("payload,expected,expected_ops", WRAPPER_CASES,
                          ids=[f"case-{i}" for i in range(len(WRAPPER_CASES))])
def test_wrapper_decode(payload, expected, expected_ops):
    r = deterministic_best_decode(payload, analysis_mode="deep")
    out = r.get("output") or ""
    chain = [s.get("op") for s in r.get("steps") or []]
    assert expected in out, (
        f"expected {expected!r} in decoded output; got out={out!r} chain={chain}"
    )
    for op in expected_ops:
        assert op in chain, f"expected op {op!r} in chain; got {chain}"


# ─── Regression guards — non-decoded inputs must stay untouched ──────────
NON_DECODE_CASES = [
    "echo hello world",                    # plain text
    "112 111 119 101 114",                 # ascii-decimal → different candidate
    "cmd /c dir",                          # no encoded payload
    "powershell -Command Get-Process",     # plain PowerShell
    "certutil -hashfile file.exe SHA256",  # certutil non-decode subcommand
]


@pytest.mark.parametrize("payload", NON_DECODE_CASES,
                          ids=[f"nodec-{i}" for i in range(len(NON_DECODE_CASES))])
def test_plain_inputs_unchanged(payload):
    r = deterministic_best_decode(payload, analysis_mode="deep")
    chain = [s.get("op") for s in r.get("steps") or []]
    # Plain wrapper text shouldn't trigger a hex or base64 decode.
    if "hex-decode" in chain:
        pytest.fail(f"hex-decode falsely fired on plain input: {payload!r}")
    if "base64-decode" in chain and "extract-payload" not in chain:
        pytest.fail(f"base64-decode falsely fired on plain input: {payload!r}")
