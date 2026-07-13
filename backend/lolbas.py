"""NivXRay — LOLBAS (Living Off The Land Binaries And Scripts) detector.

Curated matcher against known LOLBAS entries. Each rule contains:
- binary name  (matched against argv[0] or first executable-looking token)
- optional argv pattern regex (to distinguish benign vs. abusive use)
- Purposes  (list e.g. ["Download", "Execute", "AWL Bypass"])
- MITRE technique IDs
- description

Source of truth: lolbas-project.github.io  (subset of ~40 most-abused entries)
"""
from __future__ import annotations
import re
from typing import Any, Dict, List

_L: List[Dict[str, Any]] = [
    {"bin": "certutil.exe", "argv": r"-decode|-decodehex|-urlcache|-verifyctl|-split|-encode",
     "purposes": ["Download", "Decode", "AWL Bypass"], "mitre": ["T1140", "T1105", "T1218"],
     "desc": "certutil abused for base64/hex decode of staged payloads and remote download"},
    {"bin": "bitsadmin.exe", "argv": r"/transfer|/create|/addfile|/resume",
     "purposes": ["Download", "Execute"], "mitre": ["T1197", "T1105"],
     "desc": "BITS jobs used to download and execute payloads persistently"},
    {"bin": "mshta.exe", "argv": r"vbscript:|javascript:|https?://|\.hta",
     "purposes": ["Execute", "AWL Bypass"], "mitre": ["T1218.005"],
     "desc": "mshta.exe executing remote HTA / inline vbscript/javascript"},
    {"bin": "rundll32.exe", "argv": r"javascript:|\.dll,|,\w+\s|url\.dll,FileProtocolHandler|shell32\.dll,ShellExec_RunDLL",
     "purposes": ["Execute", "AWL Bypass"], "mitre": ["T1218.011"],
     "desc": "rundll32 abused to execute DLL exports, JavaScript, or shell handlers"},
    {"bin": "regsvr32.exe", "argv": r"/s|/u|/i:|scrobj\.dll|\.sct",
     "purposes": ["Execute", "AWL Bypass"], "mitre": ["T1218.010"],
     "desc": "regsvr32 Squiblydoo — /i /u remote SCT execution bypasses AWL"},
    {"bin": "msiexec.exe", "argv": r"/i\s+https?://|/q|/quiet|/y",
     "purposes": ["Download", "Execute"], "mitre": ["T1218.007"],
     "desc": "msiexec fetching and installing a remote MSI silently"},
    {"bin": "installutil.exe", "argv": r"/logfile=|/LogToConsole=|/U|/uninstall",
     "purposes": ["Execute", "AWL Bypass"], "mitre": ["T1218.004"],
     "desc": "InstallUtil executing .NET assemblies (bypasses AppLocker)"},
    {"bin": "msbuild.exe", "argv": r"\.xml|\.csproj|\.proj",
     "purposes": ["Execute", "Compile"], "mitre": ["T1127.001"],
     "desc": "MSBuild inline task execution — compile+run C# from XML"},
    {"bin": "csc.exe", "argv": r"/target:|/out:|\.cs\b",
     "purposes": ["Compile", "Execute"], "mitre": ["T1027.004"],
     "desc": "In-place C# compilation (payload obfuscation via source-form dropper)"},
    {"bin": "cscript.exe", "argv": r"\.vbs|\.wsf|\.js|//e:|//nologo",
     "purposes": ["Execute"], "mitre": ["T1059.005", "T1059.007"],
     "desc": "cscript executing VBScript/JScript/WSF"},
    {"bin": "wscript.exe", "argv": r"\.vbs|\.wsf|\.js",
     "purposes": ["Execute"], "mitre": ["T1059.005", "T1059.007"],
     "desc": "wscript executing VBS/WSF/JS"},
    {"bin": "wmic.exe", "argv": r"process\s+call\s+create|/node:|/output:|shadowcopy",
     "purposes": ["Execute", "Lateral"], "mitre": ["T1047", "T1490"],
     "desc": "wmic for remote process execution or shadowcopy deletion"},
    {"bin": "powershell.exe", "argv": r"-e(nc|ncoded)?\s|-w\s*hidden|-nop\b|iex\b|invoke-expression|downloadstring|downloadfile",
     "purposes": ["Execute"], "mitre": ["T1059.001"],
     "desc": "PowerShell with encoded or download-and-execute pattern"},
    {"bin": "pwsh.exe", "argv": r"-e(nc|ncoded)?\s|-w\s*hidden|-nop\b|iex\b",
     "purposes": ["Execute"], "mitre": ["T1059.001"],
     "desc": "PowerShell Core (pwsh) with suspicious flags"},
    {"bin": "cmd.exe", "argv": r"/c\s+\S+|/k\s+\S+|\^|for\s+/f",
     "purposes": ["Execute"], "mitre": ["T1059.003"],
     "desc": "cmd.exe with /c chain or caret-obfuscation"},
    {"bin": "reg.exe", "argv": r"\s+add\s+.*(\\Run\\|\\RunOnce\\|CurrentVersion\\Run)|\s+export|\s+import|\s+save",
     "purposes": ["Persistence", "Discovery"], "mitre": ["T1547.001", "T1112"],
     "desc": "reg.exe writing Run key or exporting credentials hives"},
    {"bin": "schtasks.exe", "argv": r"/create|/tr\s|/sc\s",
     "purposes": ["Persistence"], "mitre": ["T1053.005"],
     "desc": "schtasks scheduled-task persistence"},
    {"bin": "at.exe", "argv": r"\d{1,2}:\d{2}",
     "purposes": ["Persistence"], "mitre": ["T1053.002"],
     "desc": "at.exe legacy scheduled task"},
    {"bin": "sc.exe", "argv": r"\s+create\s|\s+config\s.*binPath|\s+failure",
     "purposes": ["Persistence"], "mitre": ["T1543.003"],
     "desc": "Windows service creation / hijacking"},
    {"bin": "netsh.exe", "argv": r"advfirewall|helper|portproxy|add\s+helper|wlan\s+show\s+profile",
     "purposes": ["Defense Evasion", "Discovery"], "mitre": ["T1562.004", "T1090"],
     "desc": "netsh firewall manipulation / portproxy tunnel / wifi profile dump"},
    {"bin": "net.exe", "argv": r"\s+user\s|\s+group\s|\s+use\s|\s+localgroup\s",
     "purposes": ["Discovery", "Lateral"], "mitre": ["T1087.001", "T1078"],
     "desc": "net.exe enumerating users/groups or mapping shares"},
    {"bin": "curl.exe", "argv": r"https?://",
     "purposes": ["Download"], "mitre": ["T1105"],
     "desc": "curl downloading files (LOLBAS on modern Windows)"},
    {"bin": "makecab.exe", "argv": r"\S+\.txt|\S+\.cab|/f",
     "purposes": ["Exfil", "Staging"], "mitre": ["T1560.001"],
     "desc": "makecab used to compress data prior to exfiltration"},
    {"bin": "extrac32.exe", "argv": r"/y|/e|\.cab",
     "purposes": ["Download", "AWL Bypass"], "mitre": ["T1140"],
     "desc": "extrac32 pulling remote CAB and extracting payloads"},
    {"bin": "esentutl.exe", "argv": r"/y|/vss|/d",
     "purposes": ["Credential Access", "File Copy"], "mitre": ["T1003.003"],
     "desc": "esentutl.exe copying NTDS.dit / shadow copies via VSS"},
    {"bin": "vssadmin.exe", "argv": r"delete\s+shadows|create\s+shadow",
     "purposes": ["Impact"], "mitre": ["T1490"],
     "desc": "Shadow-copy deletion (ransomware precursor)"},
    {"bin": "wbadmin.exe", "argv": r"delete\s+catalog|delete\s+systemstatebackup",
     "purposes": ["Impact"], "mitre": ["T1490"],
     "desc": "Backup deletion (ransomware precursor)"},
    {"bin": "bcdedit.exe", "argv": r"/set\s+.*safeboot|/set\s+.*recoveryenabled",
     "purposes": ["Impact"], "mitre": ["T1490"],
     "desc": "Boot config tampering (disable recovery, ransomware)"},
    {"bin": "ftp.exe", "argv": r"-s:|\bopen\s+\S+",
     "purposes": ["Exfil", "Download"], "mitre": ["T1048.003"],
     "desc": "ftp.exe with scripted commands for exfil/download"},
    {"bin": "hh.exe", "argv": r"https?://|\.chm",
     "purposes": ["Execute", "AWL Bypass"], "mitre": ["T1218.001"],
     "desc": "HTML Help executor abused for remote CHM/URL execution"},
    {"bin": "ie4uinit.exe", "argv": r"-basesettings|-BaseSettings",
     "purposes": ["Execute", "AWL Bypass"], "mitre": ["T1218"],
     "desc": "ie4uinit executing commands from INF (bypasses AWL)"},
    {"bin": "gpscript.exe", "argv": r"/logon|/machine",
     "purposes": ["Execute"], "mitre": ["T1218"],
     "desc": "Group policy script execution"},
    {"bin": "msdt.exe", "argv": r"/id\s+PCWDiagnostic|IT_LaunchMethod",
     "purposes": ["Execute", "AWL Bypass"], "mitre": ["T1218"],
     "desc": "MSDT Follina-style execution (CVE-2022-30190)"},
    {"bin": "forfiles.exe", "argv": r"/c\s+.*cmd|/p\s|/s\s",
     "purposes": ["Execute"], "mitre": ["T1059.003"],
     "desc": "forfiles.exe chaining commands"},
    {"bin": "odbcconf.exe", "argv": r"/A\s*\{|REGSVR|DRIVER",
     "purposes": ["Execute", "AWL Bypass"], "mitre": ["T1218"],
     "desc": "odbcconf executing DLLs (AWL bypass)"},
    {"bin": "regasm.exe", "argv": r"/U|\.dll",
     "purposes": ["Execute"], "mitre": ["T1218"],
     "desc": ".NET Registration abused to run arbitrary code"},
    {"bin": "regsvcs.exe", "argv": r"\.dll",
     "purposes": ["Execute"], "mitre": ["T1218"],
     "desc": ".NET Services registration abused to run code"},
    {"bin": "netstat.exe", "argv": r"-ano|-an",
     "purposes": ["Discovery"], "mitre": ["T1049"],
     "desc": "network-connection enumeration (recon)"},
    {"bin": "tasklist.exe", "argv": r"/svc|/m\s|/v",
     "purposes": ["Discovery"], "mitre": ["T1057"],
     "desc": "Process discovery"},
    {"bin": "whoami.exe", "argv": r"/all|/priv|/groups",
     "purposes": ["Discovery"], "mitre": ["T1033"],
     "desc": "Current-user discovery"},
]


def scan_lolbas(text: str) -> List[Dict[str, Any]]:
    """Return LOLBAS matches for a given decoded command line / script."""
    hits: List[Dict[str, Any]] = []
    low = text.lower()
    for rule in _L:
        # locate the binary reference (word boundary, case-insensitive)
        bin_re = re.compile(rf"\b{re.escape(rule['bin'])}\b", re.IGNORECASE)
        for m in bin_re.finditer(text):
            # inspect the ~200 chars after the binary for the argv pattern
            window = text[m.start(): m.start() + 300]
            if rule.get("argv"):
                if not re.search(rule["argv"], window, re.IGNORECASE):
                    continue
            snippet = text[max(0, m.start() - 20): m.end() + 140]
            snippet = re.sub(r"\s+", " ", snippet).strip()
            hits.append({
                "binary": rule["bin"],
                "purposes": rule["purposes"],
                "mitre": rule["mitre"],
                "description": rule["desc"],
                "snippet": snippet[:200],
                "url": f"https://lolbas-project.github.io/lolbas/Binaries/{rule['bin'].replace('.exe','').capitalize()}/",
            })
            break  # one hit per binary
    # dedup by binary
    seen = set()
    unique = []
    for h in hits:
        if h["binary"] in seen: continue
        seen.add(h["binary"])
        unique.append(h)
    return unique
