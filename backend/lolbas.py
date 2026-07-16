"""NivXRay — LOLBAS (Living Off The Land Binaries And Scripts) detector.

Combines a curated set of high-signal argv-pattern rules with the full ~239-entry
official LOLBAS catalog (auto-synced from lolbas-project.github.io).

Layers:
- `_L_DEFAULT` — 40 curated entries with argv regex patterns for high-fidelity matching.
- `_ACTIVE`    — runtime merged catalog: cached-from-source ∪ defaults (defaults win on `bin`).
- Persistent cache lives in MongoDB `lolbas_cache._id = "catalog"`.
"""
from __future__ import annotations
import asyncio
import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import httpx

log = logging.getLogger("nivxray.lolbas")

LOLBAS_API_URL = "https://lolbas-project.github.io/api/lolbas.json"
REFRESH_INTERVAL = timedelta(days=7)

# =============================================================================
# High-fidelity curated defaults (with argv regex)
# =============================================================================
_L_DEFAULT: List[Dict[str, Any]] = [
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
    {"bin": "powershell.exe", "argv": r"-e(?:c|(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:nd?)?)?)?)?)?)?)?)?)?)?)?)?)?\s|-w\s*hidden|-nop\b|iex\b|invoke-expression|downloadstring|downloadfile|get-process|get-service|frombase64string|start-bitstransfer|import-module\s+bitstransfer",
     "purposes": ["Execute", "Download"], "mitre": ["T1059.001", "T1197"],
     "desc": "PowerShell with encoded/hidden/download-and-execute or discovery pattern (incl. BITS-transfer stealthy download)"},
    {"bin": "pwsh.exe", "argv": r"-e(?:c|(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:nd?)?)?)?)?)?)?)?)?)?)?)?)?)?\s|-w\s*hidden|-nop\b|iex\b",
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

    # ─── 2025-2026 additions (L1 · coverage booster) ────────────────
    {"bin": "dotnet.exe", "argv": r"exec\s+\S+\.dll|run\s+--project|fsi\s+|\bnew\s+console",
     "purposes": ["Execute", "AWL Bypass"], "mitre": ["T1218"],
     "desc": ".NET SDK LOLBAS — dotnet.exe used to run unsigned assemblies / F# scripts (2025 emerging)"},
    {"bin": "dnx.exe", "argv": r"\.\/|https?://|\.dll|\.exe",
     "purposes": ["Execute", "AWL Bypass"], "mitre": ["T1218"],
     "desc": ".NET Execution Environment — dnx.exe proxying unsigned code (2025 emerging)"},
    {"bin": "Dxcap.exe", "argv": r"-c\s+\S+|-file\s+\S+\.exe",
     "purposes": ["Execute", "AWL Bypass"], "mitre": ["T1218"],
     "desc": "Dxcap.exe (DirectX capture) proxy-executes arbitrary EXEs (2025 emerging)"},
    {"bin": "desktopimgdownldr.exe", "argv": r"/lockscreenurl:https?://|/eventName:",
     "purposes": ["Download"], "mitre": ["T1105"],
     "desc": "desktopimgdownldr.exe abused to fetch arbitrary URLs (Win10+ built-in downloader)"},
    {"bin": "stordiag.exe", "argv": r"-o\s|schtasks|systeminfo",
     "purposes": ["Execute", "Discovery"], "mitre": ["T1218"],
     "desc": "stordiag.exe launches child processes (schtasks / systeminfo) — LOL proxy"},
    {"bin": "msconfig.exe", "argv": r"-4\s+.*\S+\.dll|\.wtd|\.wtb",
     "purposes": ["Execute", "AWL Bypass"], "mitre": ["T1218"],
     "desc": "msconfig.exe abused via /4 flag to load a rogue DLL"},
    {"bin": "PresentationHost.exe", "argv": r"\.xbap|\.xaml|https?://",
     "purposes": ["Execute", "AWL Bypass"], "mitre": ["T1218"],
     "desc": "PresentationHost.exe launching XBAP / remote XAML (WPF LOLBAS)"},
    {"bin": "Dfsvc.exe", "argv": r"\.application|\.deploy|https?://",
     "purposes": ["Execute"], "mitre": ["T1218"],
     "desc": "ClickOnce Deployment service abused to execute remote .application manifests"},
]

# Defaults, keyed by binary name (lower) so API imports can be merged without overriding.
_DEFAULT_BIN_KEYS = {r["bin"].lower() for r in _L_DEFAULT}

# =============================================================================
# Runtime state
# =============================================================================
_ACTIVE: List[Dict[str, Any]] = list(_L_DEFAULT)
_LAST_SYNC: Optional[str] = None
_LAST_ERROR: Optional[str] = None
_SOURCE_COUNT: int = 0  # count contributed by the remote catalog (excludes defaults)


# =============================================================================
# Normalization
# =============================================================================
def _normalize_api_entry(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Convert one lolbas-project.github.io JSON entry into our internal shape."""
    name = (entry.get("Name") or "").strip()
    if not name:
        return None
    cmds = entry.get("Commands") or []
    mitre_ids: List[str] = []
    purposes: List[str] = []
    usecases: List[str] = []
    for c in cmds:
        mid = (c.get("MitreID") or "").strip()
        if mid and mid not in mitre_ids:
            mitre_ids.append(mid)
        cat = (c.get("Category") or "").strip()
        if cat and cat not in purposes:
            purposes.append(cat)
        uc = (c.get("Usecase") or "").strip()
        if uc and uc not in usecases:
            usecases.append(uc)
    desc = (usecases[0] if usecases else entry.get("Description") or "").strip()
    return {
        "bin": name if name.lower().endswith(".exe") or "." in name else f"{name}.exe",
        "argv": None,  # remote catalog has no argv regex — match on any occurrence
        "purposes": purposes or ["Execute"],
        "mitre": mitre_ids or ["T1218"],
        "desc": desc or f"LOLBAS-listed binary: {name}",
        "url": entry.get("url") or f"https://lolbas-project.github.io/lolbas/Binaries/{name.replace('.exe','')}/",
        "source": "lolbas-api",
    }


def _merge_catalog(remote: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Defaults win on binary-name conflict; remote entries add coverage."""
    merged = list(_L_DEFAULT)
    seen = set(_DEFAULT_BIN_KEYS)
    for e in remote:
        key = e["bin"].lower()
        if key in seen:
            continue
        merged.append(e)
        seen.add(key)
    return merged


# =============================================================================
# Fetch / Cache / Refresh
# =============================================================================
async def _fetch_remote_catalog(timeout: float = 20.0) -> List[Dict[str, Any]]:
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as cli:
        r = await cli.get(LOLBAS_API_URL)
        r.raise_for_status()
        data = r.json()
    normalized: List[Dict[str, Any]] = []
    for e in data:
        n = _normalize_api_entry(e)
        if n:
            normalized.append(n)
    return normalized


async def load_from_db(db) -> None:
    """Load persisted LOLBAS catalog from MongoDB into memory."""
    global _ACTIVE, _LAST_SYNC, _SOURCE_COUNT
    try:
        doc = await db.lolbas_cache.find_one({"_id": "catalog"})
        if doc and doc.get("entries"):
            _SOURCE_COUNT = len(doc["entries"])
            _ACTIVE = _merge_catalog(doc["entries"])
            _LAST_SYNC = doc.get("last_updated")
            log.info(
                "LOLBAS: loaded %d entries from cache (last synced %s, %d total active)",
                _SOURCE_COUNT, _LAST_SYNC, len(_ACTIVE),
            )
    except Exception as e:
        log.warning("LOLBAS: failed to load cache from DB: %s", e)


async def refresh_from_source(db) -> Dict[str, Any]:
    """Fetch the official LOLBAS catalog, normalize, persist, and update runtime.

    On failure (network/parse), preserve the last-good cache and return an error status.
    """
    global _ACTIVE, _LAST_SYNC, _LAST_ERROR, _SOURCE_COUNT
    try:
        remote = await _fetch_remote_catalog()
        if not remote:
            raise RuntimeError("Empty remote catalog")
        ts = datetime.now(timezone.utc).isoformat()
        await db.lolbas_cache.update_one(
            {"_id": "catalog"},
            {"$set": {"entries": remote, "last_updated": ts, "source_url": LOLBAS_API_URL}},
            upsert=True,
        )
        _SOURCE_COUNT = len(remote)
        _ACTIVE = _merge_catalog(remote)
        _LAST_SYNC = ts
        _LAST_ERROR = None
        log.info("LOLBAS: refreshed catalog — %d remote + %d curated = %d total",
                 _SOURCE_COUNT, len(_L_DEFAULT), len(_ACTIVE))
        return {"ok": True, "count": len(_ACTIVE), "source_count": _SOURCE_COUNT,
                "defaults_count": len(_L_DEFAULT), "last_updated": ts}
    except Exception as e:
        _LAST_ERROR = f"{type(e).__name__}: {e}"
        log.warning("LOLBAS: refresh failed (%s) — keeping last-good cache of %d entries",
                    _LAST_ERROR, len(_ACTIVE))
        return {"ok": False, "error": _LAST_ERROR, "count": len(_ACTIVE),
                "last_updated": _LAST_SYNC}


async def maybe_refresh(db, interval: timedelta = REFRESH_INTERVAL) -> Optional[Dict[str, Any]]:
    """If the cache is missing or older than `interval`, refresh in background."""
    if _LAST_SYNC:
        try:
            last = datetime.fromisoformat(_LAST_SYNC)
            if datetime.now(timezone.utc) - last < interval:
                return None
        except ValueError:
            pass
    return await refresh_from_source(db)


def get_status() -> Dict[str, Any]:
    """Public status object for /admin/lolbas/status."""
    return {
        "active_count": len(_ACTIVE),
        "source_count": _SOURCE_COUNT,
        "defaults_count": len(_L_DEFAULT),
        "last_updated": _LAST_SYNC,
        "last_error": _LAST_ERROR,
        "source_url": LOLBAS_API_URL,
    }


# =============================================================================
# Scanner
# =============================================================================
def scan_lolbas(text: str) -> List[Dict[str, Any]]:
    """Return LOLBAS matches for a given decoded command line / script."""
    hits: List[Dict[str, Any]] = []
    seen = set()
    for rule in _ACTIVE:
        bin_name = rule["bin"]
        if bin_name.lower() in seen:
            continue
        bin_re = re.compile(rf"\b{re.escape(bin_name)}\b", re.IGNORECASE)
        m = bin_re.search(text)
        if not m:
            # Also allow name without .exe (e.g. "certutil " instead of "certutil.exe ")
            bare = bin_name.replace(".exe", "")
            if bare == bin_name:
                continue
            bare_re = re.compile(rf"\b{re.escape(bare)}\.exe\b|\b{re.escape(bare)}\s", re.IGNORECASE)
            m = bare_re.search(text)
            if not m:
                continue
        # Enforce argv pattern when provided (high-fidelity curated rules)
        if rule.get("argv"):
            window = text[m.start(): m.start() + 300]
            if not re.search(rule["argv"], window, re.IGNORECASE):
                continue
        snippet = text[max(0, m.start() - 20): m.end() + 140]
        snippet = re.sub(r"\s+", " ", snippet).strip()
        hits.append({
            "binary": bin_name,
            "purposes": rule["purposes"],
            "mitre": rule["mitre"],
            "description": rule["desc"],
            "snippet": snippet[:200],
            "url": rule.get("url") or f"https://lolbas-project.github.io/lolbas/Binaries/{bin_name.replace('.exe','')}/",
            "source": rule.get("source", "curated"),
        })
        seen.add(bin_name.lower())
    return hits
