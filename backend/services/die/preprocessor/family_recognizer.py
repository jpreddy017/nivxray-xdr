"""
DIE · Preprocessor · Family Recognizer
──────────────────────────────────────
Recognises command families based on *option patterns*, not only
executable names.  Examples:

    ssh -R                          → reverse-ssh-tunnel
    copy --transfers --max-age      → sync-rclone-style
    vssadmin delete shadows         → shadow-copy-deletion
    wmic product ... uninstall      → software-uninstall
    schtasks /create                → persistence-scheduled-task
    reg add / reg delete            → registry-modification
    nltest /dclist                  → ad-discovery
    net user / net group / net view → account-discovery
    ipconfig /all                   → host-discovery
    quser / query user              → session-discovery

Rule:  "Commonly observed in <family>" — NEVER definitive
attribution (per architectural rule).
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Family:
    id:            str
    label:         str
    tactic:        str
    mitre:         List[str]
    commonly_observed_in: List[str]
    rx:            "re.Pattern"


_FAMILIES: List[Family] = [
    Family(id="reverse-ssh-tunnel", label="Reverse SSH Tunnel",
           tactic="Command and Control", mitre=["T1572", "T1071"],
           commonly_observed_in=["Manual ransomware operators",
                                  "MedusaLocker affiliates",
                                  "Chaos ransomware affiliates"],
           rx=re.compile(r"(?i)\bssh(?:\.exe)?\b.*\s-R\b")),

    Family(id="shadow-copy-deletion", label="Shadow Copy Removal",
           tactic="Impact", mitre=["T1490"],
           commonly_observed_in=["Ryuk","LockBit","Conti","BlackCat",
                                  "Chaos","Medusa","REvil"],
           # Matches classic vssadmin AND the WMI variant that iterates
           # Win32_ShadowCopy objects and calls Delete() on each.
           # WMI variant is preferred by ransomware because it evades
           # vssadmin-based EDR signatures.
           rx=re.compile(
               r"(?i)("
               r"\bvssadmin(?:\.exe)?\s+delete\s+shadows"
               r"|Win32_ShadowCopy\b(?:[^\n]{0,400}?)\.Delete\s*\("
               r"|Get-WmiObject\s+Win32_ShadowCopy"
               r"|Get-CimInstance\s+Win32_ShadowCopy"
               r"|wmic(?:\.exe)?\s+shadowcopy\s+delete"
               r")"
           )),

    Family(id="ad-discovery", label="Active Directory Enumeration",
           tactic="Discovery", mitre=["T1087.002", "T1482"],
           commonly_observed_in=["Cobalt Strike operators",
                                  "Manual ransomware affiliates"],
           rx=re.compile(r"(?i)\bnltest(?:\.exe)?\s+/(?:dclist|domain_trusts|dsgetdc)")),

    Family(id="host-discovery", label="Host Configuration Discovery",
           tactic="Discovery", mitre=["T1082", "T1016"],
           commonly_observed_in=["Manual operators","early-stage ransomware"],
           rx=re.compile(r"(?i)\bipconfig(?:\.exe)?\s+/(?:all|displaydns)")),

    Family(id="session-discovery", label="User Session Discovery",
           tactic="Discovery", mitre=["T1033"],
           commonly_observed_in=["Manual operators","Cobalt Strike"],
           rx=re.compile(r"(?i)\b(?:quser|query\s+user)(?:\.exe)?\b")),

    Family(id="account-discovery", label="Account & Group Discovery",
           tactic="Discovery", mitre=["T1087"],
           commonly_observed_in=["Manual operators"],
           rx=re.compile(r"(?i)\bnet\s+(?:user|group|localgroup|view|accounts)\b")),

    Family(id="persistence-scheduled-task", label="Scheduled Task Persistence",
           tactic="Persistence", mitre=["T1053.005"],
           commonly_observed_in=["Qakbot","IcedID","AsyncRAT"],
           rx=re.compile(r"(?i)\bschtasks(?:\.exe)?\s+/create\b")),

    Family(id="registry-modification", label="Registry Modification",
           tactic="Defense Evasion", mitre=["T1112"],
           commonly_observed_in=["nearly every intrusion set"],
           # Matches classic `reg add|delete`, PowerShell
           # `Set-ItemProperty` / `New-ItemProperty` /
           # `Remove-ItemProperty` on a registry drive path, and the
           # `.NET` `Registry.SetValue()` variant.
           rx=re.compile(
               r"(?i)("
               r"\breg(?:\.exe)?\s+(?:add|delete)\b"
               r"|(?:Set|New|Remove)-ItemProperty[^\n]{0,400}?HK(?:LM|CU|CR|U|CC)[:\\]"
               r"|(?:Set|New|Remove)-Item(?:Property)?[^\n]{0,400}?-Path\s+[\"']?HK"
               r"|\[Microsoft\.Win32\.Registry\][^\n]{0,200}?::(?:SetValue|DeleteValue)"
               r")"
           )),

    Family(id="proxy-tamper", label="Windows Proxy / WinINet Tamper",
           tactic="Defense Evasion", mitre=["T1112", "T1090"],
           commonly_observed_in=["Manual operators","LockBit","BlackBasta",
                                  "Chaos","Medusa"],
           # Matches ProxyEnable / ProxyServer / AutoConfigURL registry
           # writes AND the WinINet API refresh call (InternetSetOption
           # with option 37/39) that ransomware uses to disable
           # corporate proxy monitoring.
           rx=re.compile(
               r"(?i)("
               r"ProxyEnable\b[^\n]{0,80}?-Value\s+0"
               r"|ProxyServer\b[^\n]{0,80}?-Value\s+[\"']{2}"
               r"|AutoConfigURL\b[^\n]{0,80}?-Value\s+[\"']{2}"
               r"|InternetSetOption\s*\([^\n]{0,80}?3[79]"
               r"|wininet\.dll[^\n]{0,120}?InternetSetOption"
               r")"
           )),

    Family(id="software-uninstall", label="WMIC Software Removal",
           tactic="Defense Evasion", mitre=["T1562.001"],
           commonly_observed_in=["Manual ransomware operators"],
           rx=re.compile(r"(?i)\bwmic(?:\.exe)?\s+product\b.*\bcall\b.*\buninstall\b|"
                        r"\bwmic(?:\.exe)?\s+product\s+where\b.*\buninstall\b")),

    Family(id="msi-install", label="MSI Installer Execution",
           tactic="Execution", mitre=["T1218.007"],
           commonly_observed_in=["IcedID","Qakbot","Bumblebee"],
           rx=re.compile(r"(?i)\bmsiexec(?:\.exe)?\s+(?:-|/)i\b|"
                        r"\bmsiexec(?:\.exe)?\s+-Embedding\b")),

    Family(id="sync-rclone-style", label="rclone-style Data Sync",
           tactic="Exfiltration", mitre=["T1567.002", "T1048"],
           commonly_observed_in=["Chaos","Medusa","BlackCat","LockBit"],
           rx=re.compile(r"(?i)(?:\brclone\b|\bcopy\b)\b(?:[^\n]*?)(?:--transfers|--max-age|--multi-thread-streams)")),

    Family(id="rmm-remote-access", label="RMM Remote Access Tool",
           tactic="Command and Control", mitre=["T1219"],
           commonly_observed_in=["Chaos","Medusa","BlackBasta","manual operators"],
           rx=re.compile(r"(?i)\b(anydesk|screenconnect|screen[- ]?connect|"
                        r"simplehelp|simple[- ]?help|"
                        r"splashtop|optitune|teamviewer|"
                        r"quick[- ]?assist|atera|kaseya|connectwise|n-able)\b")),

    Family(id="brute-ratel", label="Brute Ratel C4 Activity",
           tactic="Command and Control", mitre=["T1071", "T1105"],
           commonly_observed_in=["Manual ransomware operators (post-2022)"],
           rx=re.compile(r"(?i)\bbrute[- ]?ratel\b|\bbadger[.-]?dll\b")),

    Family(id="psexec-lateral", label="PsExec Lateral Movement",
           tactic="Lateral Movement", mitre=["T1021.002", "T1570"],
           commonly_observed_in=["Manual operators","LockBit","Conti"],
           rx=re.compile(r"(?i)\b(?:psexec|paexec)(?:\.exe)?\b")),

    Family(id="uac-disable", label="UAC / Defender Tamper",
           tactic="Defense Evasion", mitre=["T1562.001", "T1548.002"],
           commonly_observed_in=["Manual ransomware operators"],
           rx=re.compile(r"(?i)\b(EnableLUA|ConsentPromptBehaviorAdmin|"
                        r"DisableAntiSpyware|Set-MpPreference|Add-MpPreference|"
                        r"UAC\s+disabl(?:ing|e)|disabl(?:ing|e)\s+UAC)\b")),

    Family(id="log-clearing", label="Event Log Clearing / Deletion",
           tactic="Defense Evasion", mitre=["T1070.001"],
           commonly_observed_in=["Manual operators","LockBit","Medusa"],
           rx=re.compile(r"(?i)\b(wevtutil(?:\.exe)?\s+cl|Clear-EventLog|"
                        r"log(?:s)?\s+deleted|deleting?\s+event\s+log(?:s)?)\b")),
]


def recognize_families(command_text: str) -> List[Family]:
    """Return every family whose regex fires against ``command_text``.
    Ordering is stable — families are returned in declaration order.
    """
    if not command_text:
        return []
    return [f for f in _FAMILIES if f.rx.search(command_text)]


def recognize_family(command_text: str) -> Optional[Family]:
    """First matching family (deterministic)."""
    hits = recognize_families(command_text)
    return hits[0] if hits else None


def all_families() -> List[Family]:
    return list(_FAMILIES)
