"""Deterministic rule table.

Each rule pattern-matches a command-line fragment and emits one or
more evidence templates. Rules carry:
  • name / id     — stable identifier (LOLBIN-042 etc.)
  • pattern       — compiled regex, case-insensitive
  • emits         — tuple of (event_kind, action_verb, target_field) tuples
  • confidence    — {"high","medium","low"} — deterministic, evidence-backed
  • mitre         — tuple of ATT&CK technique ids
  • lane_hint     — optional lane override for the primary event

`event_kind` maps directly onto CEM v1 EVENT_KINDS. `target_field`
is a capture-group name or literal string used to extract the target
from the matched text.
"""
from __future__ import annotations
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern
    emits: tuple[tuple[str, str, str], ...]   # (event_kind, action, target_expr)
    confidence: str
    mitre: tuple[str, ...] = ()
    label: str = ""


def _re(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


# Ordered: more specific rules first. The parser applies ALL matching
# rules, so ordering only affects readability of downstream consumers.
RULES: tuple[Rule, ...] = (
    # ─── LOLBINs · execution ────────────────────────────────────────
    Rule("LOLBIN-001", _re(r"\bmsiexec(\.exe)?\b.*?\/i\s+([^\s\"']+\.msi)"),
         (("process_create", "executed", r"msiexec.exe"),
          ("file_write",     "installed", r"$2")),
         "high", ("T1218.007",), "msiexec silent install"),

    Rule("LOLBIN-002", _re(r"\brundll32(\.exe)?\b.*?comsvcs\.dll[^\"']*?#?\+?\d+"),
         (("process_create", "executed", "rundll32.exe"),
          ("memory_alloc",   "dumped_lsass_via_comsvcs", "lsass.exe")),
         "high", ("T1003.001", "T1218.011"), "comsvcs.dll LSASS dump"),

    Rule("LOLBIN-003", _re(r"\bwbadmin(\.exe)?\b\s+start\s+backup"),
         (("process_create", "executed", "wbadmin.exe"),
          ("file_write",     "exported_ntds_or_system_hives", r"ntds.dit|SYSTEM|SECURITY")),
         "high", ("T1003.003", "T1003.002"), "wbadmin credential-hive backup"),

    Rule("LOLBIN-004", _re(r"\bpowershell(\.exe)?\b[^\n]*?-e(?:nc(?:oded(?:command)?)?)?\s+[A-Za-z0-9+/=]{20,}"),
         (("process_create", "executed", "powershell.exe"),
          ("kernel_event",   "ran_encoded_command", "encodedcommand")),
         "high", ("T1059.001", "T1027.010"), "PowerShell -EncodedCommand"),

    Rule("LOLBIN-005", _re(r"\bnltest(\.exe)?\b\s+/dclist"),
         (("process_create", "executed", "nltest.exe"),
          ("kernel_event",   "enumerated_domain_controllers", "nltest /dclist")),
         "medium", ("T1018",), "domain controller enumeration"),

    Rule("LOLBIN-006", _re(r"\bwhoami(\.exe)?\b\s+/groups"),
         (("process_create", "executed", "whoami.exe"),),
         "medium", ("T1033",), "user/group enumeration"),

    Rule("LOLBIN-007", _re(r"\bnet(\.exe)?\b\s+user\s+(\S+)\s+\S+\s+/add\s+/dom"),
         (("process_create", "executed", "net.exe"),
          ("cloud_iam_action","created_domain_user", r"$2")),
         "high", ("T1136.002",), "domain-user creation"),

    Rule("LOLBIN-008", _re(r"\bnet(\.exe)?\b\s+group\s+\"?(?:enterprise|domain)\s+admins\"?\s+(\S+)\s+/add"),
         (("process_create", "executed", "net.exe"),
          ("cloud_iam_action","added_user_to_admins_group", r"$2")),
         "high", ("T1098.007",), "privileged group modification"),

    Rule("LOLBIN-009", _re(r"\bsysteminfo(\.exe)?\b"),
         (("process_create", "executed", "systeminfo.exe"),),
         "medium", ("T1082",), "system enumeration"),

    Rule("LOLBIN-010", _re(r"\bquser(\.exe)?\b"),
         (("process_create", "executed", "quser.exe"),),
         "medium", ("T1033",), "logged-on user enumeration"),

    # ─── Network / RustDesk / SSH tunnel ────────────────────────────
    Rule("NET-001", _re(r"\bssh(\.exe)?\b\s+\S+@(\d{1,3}(?:\.\d{1,3}){3})[^\n]*?-R"),
         (("process_create",   "executed", "ssh.exe"),
          ("network_connect",  "opened_reverse_tunnel", r"$2")),
         "high", ("T1572", "T1090.001"), "reverse SSH tunnel"),

    Rule("NET-002", _re(r"RustDesk\.exe.*?--(?:tray|cm|service)"),
         (("process_create",   "executed", "RustDesk.exe"),
          ("service_install",  "installed_remote_access", "RustDesk")),
         "high", ("T1219",), "RustDesk RMM"),

    # ─── Postgres / Veeam credential mining ─────────────────────────
    Rule("CRED-001", _re(r"\bpsql(\.exe)?\b[^\n]*?VeeamBackup[^\n]*?credentials"),
         (("process_create", "executed", "psql.exe"),
          ("file_write",     "dumped_veeam_credentials_csv", "credentials")),
         "high", ("T1552.001",), "Veeam credentials extraction"),

    # ─── Impact ─────────────────────────────────────────────────────
    Rule("IMPACT-001", _re(r"locker\.exe[^\n]*?-p="),
         (("process_create", "executed", "locker.exe"),
          ("file_write",     "encrypted_files", "locker.exe target"),),
         "high", ("T1486",), "Akira locker execution"),

    Rule("IMPACT-002", _re(r"Get-WmiObject\s+Win32_Shadowcopy\s*\|\s*Remove-WmiObject"),
         (("process_create", "executed", "powershell.exe"),
          ("file_delete",    "removed_volume_shadow_copies", "Win32_Shadowcopy")),
         "high", ("T1490",), "shadow-copy deletion"),

    # ─── Discovery scripts ──────────────────────────────────────────
    Rule("DISC-001", _re(r"Invoke-ShareFinder"),
         (("process_create", "executed", "powershell.exe"),
          ("network_listen", "enumerated_network_shares", "Invoke-ShareFinder")),
         "medium", ("T1135",), "share enumeration"),

    Rule("DISC-002", _re(r"Get-ADComputer[^\n]*?export-csv"),
         (("process_create", "executed", "powershell.exe"),
          ("file_write",     "exported_ad_computer_inventory", "AdComputers.csv")),
         "medium", ("T1087.002",), "AD computer enumeration"),

    Rule("DISC-003", _re(r"Export-DnsServerZone"),
         (("process_create", "executed", "powershell.exe"),
          ("file_write",     "exported_dns_zone", "CORP.lan.txt")),
         "medium", ("T1590.002",), "DNS zone export"),

    # ─── Generic fallback (always fires) ───────────────────────────
    Rule("BASE-000", _re(r"^(?:\"?(?P<img>[A-Za-z]:\\[^\"\s]+|[A-Za-z0-9_.-]+\.(?:exe|dll|ps1|bat|cmd|sh)))"),
         (("process_create", "executed", r"$img"),),
         "low", (), "generic process create"),
)
