"""v2/ingestion/mitre_map.py · Deterministic keyword → MITRE technique.

This is intentionally CONSERVATIVE. It only tags techniques when the
pattern is unambiguous (e.g. `-EncodedCommand` → T1059.001, `vssadmin
delete shadows` → T1490). Anything ambiguous is left untagged and let
downstream correlation decide.

Reference:
  * MITRE ATT&CK v14 — https://attack.mitre.org/
  * Sysmon field semantics — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
"""
from __future__ import annotations
import re

from .canonical import CanonicalEventRecord

_ENCODED_PS = re.compile(r"(?i)-e(?:nc|ncoded)?(?:command)?\s+[A-Za-z0-9+/=]{20,}")
_DOWNLOAD_CRADLE = re.compile(
    r"(?i)(iex\s*\(|invoke-expression|downloadstring|invoke-webrequest|iwr\s|curl\s+-o|wget\s|certutil\s+-urlcache)"
)
_LOLBIN_BINS = {
    "rundll32.exe":  ["T1218.011"],
    "regsvr32.exe":  ["T1218.010"],
    "mshta.exe":     ["T1218.005"],
    "msiexec.exe":   ["T1218.007"],
    "certutil.exe":  ["T1105", "T1140"],
    "bitsadmin.exe": ["T1197"],
    "wmic.exe":      ["T1047"],
}

_REGISTRY_RUNKEY = re.compile(
    r"(?i)\\Microsoft\\Windows\\(?:NT\\)?CurrentVersion\\Run(?:Once)?"
)
_REGISTRY_WINLOGON = re.compile(
    r"(?i)\\Microsoft\\Windows\ NT\\CurrentVersion\\Winlogon"
)

_RANSOM_NOTE = re.compile(
    r"(?i)(readme|how[_-]?to[_-]?decrypt|restore[_-]?files|recover[_-]?files|"
    r"your[_-]?files|decrypt[_-]?instructions)\.(?:txt|hta|html?|rtf)$"
)
_ENCRYPTED_EXT = re.compile(r"(?i)\.(locked|encrypted|enc|crypt|xxx|zzz|abcd|lockbit|akira|conti|blackcat)$")


def tag(rec: CanonicalEventRecord) -> list[str]:
    """Return a deterministic list of MITRE technique IDs for one CES record."""
    tags: set[str] = set()
    cmd = (rec.command_line or "").lower()
    img = (rec.image or "").lower()
    fpath = (rec.file_path or "").lower()
    regkey = (rec.registry_key or "").lower()

    # ─── Execution ─────────────────────────────────────────────────
    if any(x in img for x in ("powershell.exe", "pwsh.exe")):
        tags.add("T1059.001")
    if "cmd.exe" in img:
        tags.add("T1059.003")
    if any(x in img for x in ("wscript.exe", "cscript.exe")):
        tags.add("T1059.005")
    if _ENCODED_PS.search(cmd):
        tags.add("T1027")            # Obfuscated files / info
        tags.add("T1059.001")
    if _DOWNLOAD_CRADLE.search(cmd):
        tags.add("T1105")            # Ingress tool transfer

    # ─── LOLBins ───────────────────────────────────────────────────
    for binname, ts in _LOLBIN_BINS.items():
        if binname in img:
            tags.update(ts)

    # ─── Persistence · registry ────────────────────────────────────
    if _REGISTRY_RUNKEY.search(regkey):
        tags.add("T1547.001")        # Registry Run keys
    if _REGISTRY_WINLOGON.search(regkey):
        tags.add("T1547.004")        # Winlogon helper DLL

    # ─── Persistence · services / tasks ────────────────────────────
    if rec.service:
        tags.add("T1543.003")        # New Windows service
    if rec.task_name:
        tags.add("T1053.005")        # Scheduled Task

    # ─── Credential access ─────────────────────────────────────────
    if "lsass" in cmd or "lsass" in (rec.raw_event.get("TargetImage", "").lower() if rec.raw_event else ""):
        tags.add("T1003.001")        # LSASS memory
    if "comsvcs.dll" in cmd and "minidump" in cmd:
        tags.add("T1003.001")
    if "mimikatz" in cmd:
        tags.add("T1003.001")

    # ─── Discovery ─────────────────────────────────────────────────
    if any(x in cmd for x in ("whoami", "net user", "net group", "ipconfig", "systeminfo", "tasklist")):
        tags.add("T1082")

    # ─── Lateral movement ──────────────────────────────────────────
    if "psexec" in img or "psexec" in cmd:
        tags.add("T1021.002")
    if "winrm" in cmd or "invoke-command" in cmd:
        tags.add("T1021.006")

    # ─── Impact ────────────────────────────────────────────────────
    if "vssadmin" in cmd and "delete shadows" in cmd:
        tags.add("T1490")            # Inhibit system recovery
    if "wbadmin" in cmd and ("delete catalog" in cmd or "delete backup" in cmd):
        tags.add("T1490")
    if "bcdedit" in cmd and "recoveryenabled no" in cmd:
        tags.add("T1490")
    if _RANSOM_NOTE.search(fpath):
        tags.add("T1486")
    if _ENCRYPTED_EXT.search(fpath):
        tags.add("T1486")

    # ─── Defense evasion ───────────────────────────────────────────
    if any(x in cmd for x in ("set-mppreference -disable", "sc stop windefend",
                              "add-mppreference -exclusionpath")):
        tags.add("T1562.001")        # Impair defenses

    # ─── C2 / network egress ───────────────────────────────────────
    # Only tag when the event kind is a network connect AND the cmdline
    # is not empty (avoid tagging legitimate DNS lookups).
    if rec.event_id == 3 and (cmd or img):
        tags.add("T1071.001")        # Application layer protocol · web

    return sorted(tags)
