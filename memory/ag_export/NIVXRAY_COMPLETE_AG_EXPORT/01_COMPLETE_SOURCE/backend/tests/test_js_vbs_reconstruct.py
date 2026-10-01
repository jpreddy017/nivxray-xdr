"""RC2.8 · JavaScript + VBScript reconstruction decoders.

Locks the new `js-reconstruct` and `vbs-reconstruct` plugins:

  • JS: String.fromCharCode / atob / unescape
  • VBS: Chr()/ChrW() chain, CreateObject ProgID reveal
"""
from __future__ import annotations

import pytest

from engine import AnalysisContext as _Ctx, Budget as _Bud, Orchestrator
import decoders  # noqa: F401 — triggers plugin registration
from decoders.js_reconstruct import JavaScriptReconstructDecoder
from decoders.vbs_reconstruct import VBScriptReconstructDecoder
from engine.models import Fingerprint


def _fp(payload: str) -> Fingerprint:
    return Fingerprint(
        input_len=len(payload),
        printable_ratio=1.0,
        english_density=0.5,
        entropy=4.0,
        is_binary=False,
    )


def _trace_text(report) -> str:
    hay = (report.output or "")
    for step in report.trace:
        hay += "\n" + (step.preview or "")
    return hay


@pytest.fixture()
def ctx():
    return _Ctx(budget=_Bud(wall_time_ms=4000))


# ---------------------------------------------------------------- #
#  JavaScript
# ---------------------------------------------------------------- #
def test_js_fromcharcode_reveals_alert_xss():
    payload = "eval(String.fromCharCode(97,108,101,114,116,40,39,120,115,115,39,41))"
    report = Orchestrator(_Ctx(budget=_Bud(wall_time_ms=4000))).run(payload)
    hay = _trace_text(report)
    assert "alert" in hay
    assert "xss" in hay
    assert "js-reconstruct" in [s.decoder for s in report.trace]


def test_js_atob_decodes_base64_payload():
    payload = "eval(atob('YWxlcnQoJ3B3bmVkJyk='))"
    report = Orchestrator(_Ctx(budget=_Bud(wall_time_ms=4000))).run(payload)
    hay = _trace_text(report)
    assert "alert" in hay
    assert "pwned" in hay


def test_js_unescape_url_hex():
    payload = "eval(unescape('%61%6c%65%72%74%28%31%29'))"
    report = Orchestrator(_Ctx(budget=_Bud(wall_time_ms=4000))).run(payload)
    hay = _trace_text(report)
    assert "alert" in hay


def test_js_fromcharcode_hex_arguments():
    decoder = JavaScriptReconstructDecoder()
    payload = "String.fromCharCode(0x41, 0x42, 0x43)"
    result = decoder.decode(payload, {}, _Ctx(budget=_Bud(wall_time_ms=4000)))
    assert "ABC" in result.output


def test_js_atob_binary_output_ignored():
    """Binary blob inside atob() shouldn't produce garbage — must be left alone."""
    decoder = JavaScriptReconstructDecoder()
    # base64 of pure random bytes = binary blob → decoder should skip
    payload = "atob('vN3+4Q==')"  # 4 bytes of high-bit binary
    result = decoder.decode(payload, {}, _Ctx(budget=_Bud(wall_time_ms=4000)))
    # Either left as-is or replaced with something printable — the guard
    # in _apply_atob refuses to emit low-printable-ratio replacements.
    assert "atob('vN3+4Q==')" in result.output


def test_js_detect_no_signal(ctx):
    decoder = JavaScriptReconstructDecoder()
    payload = "var x = 1 + 2; console.log(x)"
    r = decoder.detect(payload, _fp(payload), ctx)
    assert r.confidence == 0.0


def test_js_detect_confidence_high_for_atob(ctx):
    decoder = JavaScriptReconstructDecoder()
    payload = "eval(atob('YWJj'))"
    r = decoder.detect(payload, _fp(payload), ctx)
    assert r.confidence >= 0.85


# ---------------------------------------------------------------- #
#  VBScript
# ---------------------------------------------------------------- #
def test_vbs_chr_chain_reveals_msgbox():
    payload = 'Execute(Chr(77) & Chr(115) & Chr(103) & Chr(66) & Chr(111) & Chr(120) & "(""pwned"")")'
    report = Orchestrator(_Ctx(budget=_Bud(wall_time_ms=4000))).run(payload)
    hay = _trace_text(report)
    assert "MsgBox" in hay
    assert "pwned" in hay
    assert "vbs-reconstruct" in [s.decoder for s in report.trace]


def test_vbs_createobject_preserves_progid_and_command():
    """The CreateObject reveal MUST beat extract-wrapper's cmd /c so both
    the ProgID (WScript.Shell) AND the invoked command (cmd.exe) surface."""
    payload = 'CreateObject("WScript.Shell").Run "cmd.exe /c calc.exe"'
    report = Orchestrator(_Ctx(budget=_Bud(wall_time_ms=4000))).run(payload)
    hay = _trace_text(report)
    assert "WScript.Shell" in hay
    assert "cmd.exe" in hay


def test_vbs_chr_chain_direct(ctx):
    decoder = VBScriptReconstructDecoder()
    payload = "Chr(72) & Chr(105)"
    result = decoder.decode(payload, {}, ctx)
    assert "Hi" in result.output


def test_vbs_chrw_unicode_supported(ctx):
    decoder = VBScriptReconstructDecoder()
    payload = "ChrW(77) & ChrW(115) & ChrW(103)"
    result = decoder.decode(payload, {}, ctx)
    assert "Msg" in result.output


def test_vbs_detect_no_signal(ctx):
    decoder = VBScriptReconstructDecoder()
    payload = "Dim x : x = 42 : WScript.Echo x"
    r = decoder.detect(payload, _fp(payload), ctx)
    assert r.confidence == 0.0


def test_vbs_createobject_confidence_beats_extract_wrapper(ctx):
    """CreateObject must beat extract-wrapper (0.95) so VBS-hosted cmd.exe
    payloads don't lose their ProgID."""
    decoder = VBScriptReconstructDecoder()
    payload = 'CreateObject("WScript.Shell").Run "cmd.exe /c calc.exe"'
    r = decoder.detect(payload, _fp(payload), ctx)
    assert r.confidence > 0.95


# ---------------------------------------------------------------- #
#  Zero-false-positive IOC gate
# ---------------------------------------------------------------- #
def test_js_no_false_positive_iocs():
    payload = "eval(atob('YWxlcnQoJ3B3bmVkJyk='))"
    report = Orchestrator(_Ctx(budget=_Bud(wall_time_ms=4000))).run(payload)
    # No URLs / IPs / domains hidden in this payload
    assert len(list(report.findings.iocs.urls)) == 0
    assert len(list(report.findings.iocs.ips)) == 0


def test_vbs_no_false_positive_iocs():
    payload = "Chr(72) & Chr(105)"
    report = Orchestrator(_Ctx(budget=_Bud(wall_time_ms=4000))).run(payload)
    assert len(list(report.findings.iocs.urls)) == 0
    assert len(list(report.findings.iocs.ips)) == 0
