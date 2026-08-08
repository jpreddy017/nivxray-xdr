"""IDA · Stage 5 · Deterministic Behavior Generation Layer.

The bridge from raw extracted entities → canonical Behavior objects.
Every Behavior is a first-class semantic object with an ATT&CK
mapping attached.  Multiple downstream consumers (MITRE view,
recommendation engine, evidence-summary narrator, reports, LLM)
read Behaviors — none of them re-implement the mapping.

Architecture (per user directive · 2026-02-05):

    Evidence  (commands, malware_families, LOLBAS, CVEs)
        │
        ▼
    Behavior Generation      ← this module
        │
   ┌────┼──────────────────┐
   ▼    ▼                  ▼
  MITRE  Recommendations  Evidence Summary / Reports / LLM

STRICT contract:
    · Every mapping is a DETERMINISTIC lookup.  No prose inference,
      no regex over narrative, no LLM.
    · A Behavior is emitted ONLY when the input entity was already
      extracted at Stage 4.  Nothing is invented.
    · The Behavior schema is stable and additive; new behavior_types
      require an entry in ``BEHAVIOR_TO_MITRE``.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing      import Any, Dict, List, Optional, Sequence, Tuple


# ══════════════════════════════════════════════════════════════════
# 1. Canonical Behavior schema
# ══════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class Behavior:
    """One canonical semantic behavior observed in an investigation.

    ``mitre`` is populated deterministically from ``behavior_type``
    via ``BEHAVIOR_TO_MITRE`` — callers do not compute it themselves.
    """
    behavior_type: str                          # e.g. "shadow_copy_deletion"
    label:         str                          # analyst-friendly string
    source:        str                          # "command_classifier" | "malware_lookup" | "lolbas_lookup" | "cve_lookup"
    source_ref:    str  = ""                     # e.g. "body.line.37" or the raw command
    confidence:    str  = "deterministic"        # "deterministic" is the only value today
    evidence:      Dict[str, Any] = field(default_factory=dict)
    mitre:         Tuple[str, ...] = ()          # ATT&CK IDs attached by the generator

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["mitre"] = list(self.mitre)
        return d


# ══════════════════════════════════════════════════════════════════
# 2. Canonical Behavior → MITRE map (deterministic, ATT&CK-published)
# ══════════════════════════════════════════════════════════════════
BEHAVIOR_TO_MITRE: Dict[str, Tuple[str, ...]] = {
    # ── Impact ────────────────────────────────────────────────────
    "shadow_copy_deletion":            ("T1490",),
    "inhibit_recovery_wmic":           ("T1490",),
    "inhibit_recovery_bcdedit":        ("T1490",),
    "data_encryption_for_impact":      ("T1486",),

    # ── Defense Evasion (signed-binary proxy) ─────────────────────
    "signed_binary_proxy_msi":         ("T1218.007",),
    "signed_binary_proxy_mshta":       ("T1218.005",),
    "signed_binary_proxy_rundll32":    ("T1218.011",),
    "signed_binary_proxy_regsvr32":    ("T1218.010",),
    "defense_evasion_disable_tool":    ("T1562.001",),

    # ── Command and Control / Remote Access ───────────────────────
    "remote_access_software":          ("T1219",),
    "protocol_tunneling_ssh":          ("T1572", "T1021.004"),
    "ingress_tool_transfer":           ("T1105",),
    "certutil_download":               ("T1105", "T1027"),
    "bitsadmin_transfer":              ("T1197", "T1105"),

    # ── Lateral Movement ──────────────────────────────────────────
    "remote_service_smb":              ("T1021.002",),
    "remote_service_rdp":              ("T1021.001",),
    "lateral_movement_psexec":         ("T1021.002", "T1570"),
    "lateral_movement_impacket":       ("T1021.002", "T1047"),

    # ── Execution ─────────────────────────────────────────────────
    "powershell_execution":            ("T1059.001",),
    "powershell_encoded_command":      ("T1059.001", "T1027"),
    "powershell_download_execute":     ("T1059.001", "T1105"),
    "powershell_in_memory":            ("T1059.001", "T1620"),
    "wmi_execution":                   ("T1047",),
    "scheduled_task_persistence":      ("T1053.005",),
    "scheduled_task_at":               ("T1053.002",),

    # ── Credential Access ─────────────────────────────────────────
    "credential_dumping_lsass":        ("T1003.001",),
    "credential_dumping_mimikatz":     ("T1003.001",),

    # ── Discovery ─────────────────────────────────────────────────
    "discovery_account":               ("T1087",),
    "discovery_domain_trust":          ("T1482",),
    "discovery_system_owner":          ("T1033",),
    "discovery_network_config":        ("T1016",),
    "discovery_host":                  ("T1082",),
    "discovery_ad":                    ("T1087.002",),

    # ── Exfiltration ──────────────────────────────────────────────
    "data_staging_exfil_rclone":       ("T1567.002", "T1020"),

    # ── Persistence ───────────────────────────────────────────────
    "registry_run_key_persistence":    ("T1547.001",),
    "registry_modification":           ("T1112",),

    # ── Initial Access ────────────────────────────────────────────
    "phishing_service":                ("T1566.003",),   # Microsoft Teams / IM
    "phishing_email":                  ("T1566.001",),
    "exploit_public_app":              ("T1190",),
    "quickassist_it_impersonation":    ("T1219", "T1566.004"),

    # ── Browser / Edgecution ──────────────────────────────────────
    "browser_extension_load":          ("T1176",),
    "browser_launch_headless":         ("T1189",),

    # ── Misc ──────────────────────────────────────────────────────
    "archive_extraction":              ("T1140",),
    "self_deletion":                   ("T1070.004",),
}


# ══════════════════════════════════════════════════════════════════
# 3a. Command classifier · returns (label, behavior_type_or_None)
# ══════════════════════════════════════════════════════════════════
def classify_command(cmd: str, head: str) -> Tuple[str, Optional[str]]:
    """Return ``(label, behavior_type)`` for a command string.

    ``label`` is the analyst-facing purpose (same string the legacy
    ``_classify_command_purpose`` returned).  ``behavior_type``
    keys into ``BEHAVIOR_TO_MITRE`` for downstream MITRE derivation.
    Returns ``(label, None)`` when the command is recognized but
    has no canonical behavior (e.g. generic "Command execution").
    """
    c = cmd.lower()
    h = (head or "").lower()

    # ── Impact / shadow copy deletion (T1490) ─────────────────────
    if "vssadmin" in h and ("delete" in c and "shadow" in c):
        return ("Shadow copy deletion", "shadow_copy_deletion")
    if "wmic" in c and "shadowcopy" in c and "delete" in c:
        return ("Shadow copy deletion (WMIC)", "inhibit_recovery_wmic")
    if "bcdedit" in h and ("ignoreallfailures" in c or "recoveryenabled" in c
                              or "safeboot" in c):
        return ("Recovery-boot policy modification", "inhibit_recovery_bcdedit")

    # ── Defense evasion via WMIC uninstall ────────────────────────
    if "wmic" in c and "product" in c and "uninstall" in c:
        return ("Software uninstall (defense evasion)",
                "defense_evasion_disable_tool")

    # ── MSI installer execution (T1218.007) ───────────────────────
    if h in ("msiexec.exe", "msiexec") or "msiexec.exe" in c.split()[0:1]:
        if "-embedding" in c:
            return ("MSI installer child (embedded)", "signed_binary_proxy_msi")
        if "/i " in c or " /i " in c or "/quiet" in c or "/qn" in c:
            return ("MSI installation", "signed_binary_proxy_msi")
        return ("MSI execution", "signed_binary_proxy_msi")

    # ── mshta (T1218.005) / rundll32 (T1218.011) / regsvr32 ───────
    if h in ("mshta.exe", "mshta"):
        return ("MSHTA execution", "signed_binary_proxy_mshta")
    if h in ("rundll32.exe", "rundll32"):
        return ("Rundll32 execution", "signed_binary_proxy_rundll32")
    if h in ("regsvr32.exe", "regsvr32"):
        return ("Regsvr32 execution", "signed_binary_proxy_regsvr32")

    # ── Reverse SSH tunnel (T1572) ────────────────────────────────
    if "ssh.exe" in h or h == "ssh":
        if " -r " in (" " + c + " ") or c.strip().split(".exe", 1)[-1].lstrip().startswith("-r"):
            return ("Reverse SSH tunnel", "protocol_tunneling_ssh")
        if " -l " in c or " -n " in c:
            return ("SSH remote session", "protocol_tunneling_ssh")
        return ("SSH client execution", "protocol_tunneling_ssh")

    # ── Rclone / mass-copy exfil (T1567 / T1020) ──────────────────
    if "rclone" in h or ("copy" in c and "--max-age" in c) \
       or ("--exclude" in c and "*.{" in c) or ("--exclude" in c and "*{" in c):
        return ("Data staging / exfil (rclone-style)",
                "data_staging_exfil_rclone")

    # ── PsExec / Impacket lateral movement ────────────────────────
    if "psexec" in h or "psexec" in c.split()[0:1]:
        return ("Lateral movement via PsExec", "lateral_movement_psexec")
    if "impacket" in c or "wmiexec" in c or "smbexec" in c or "atexec" in c:
        return ("Lateral movement via Impacket", "lateral_movement_impacket")

    # ── Discovery ─────────────────────────────────────────────────
    if h in ("net", "net.exe") and (" user" in c or " group" in c or " localgroup" in c):
        return ("Account / group discovery", "discovery_account")
    if h in ("nltest", "nltest.exe"):
        return ("Domain trust discovery", "discovery_domain_trust")
    if h in ("whoami", "whoami.exe"):
        return ("Current-user discovery", "discovery_system_owner")
    if h in ("quser", "quser.exe"):
        return ("Logged-on user discovery", "discovery_system_owner")
    if h in ("hostname", "hostname.exe"):
        return ("Host discovery", "discovery_host")
    if h in ("ipconfig", "ipconfig.exe"):
        return ("Network config discovery", "discovery_network_config")
    if "adfind" in h or "sharphound" in h or "bloodhound" in h:
        return ("Active Directory discovery", "discovery_ad")

    # ── Registry ──────────────────────────────────────────────────
    if h in ("reg", "reg.exe") and " add " in c:
        if "run" in c:
            return ("Registry Run-key persistence",
                    "registry_run_key_persistence")
        return ("Registry modification", "registry_modification")

    # ── Archive extraction ───────────────────────────────────────
    if "tar" in h and " -xf " in c:
        if "python" in c:
            return ("Unzip Python interpreter stager", "archive_extraction")
        if ".zip" in c or "--passphrase" in c:
            return ("Unzip encrypted payload archive", "archive_extraction")
        return ("Archive extraction", "archive_extraction")

    if "python" in c and ("--version" in c or " -V" in cmd):
        return ("Python interpreter discovery", None)

    # ── Edgecution (browser extension load) ───────────────────────
    if "msedge" in h or "msedge.exe" in c:
        if "load-extension" in c and "headless" in c:
            return ("Microsoft Edge launch (headless, extension load — Edgecution)",
                    "browser_extension_load")
        if "load-extension" in c:
            return ("Microsoft Edge launch (extension load — Edgecution)",
                    "browser_extension_load")
        return ("Microsoft Edge launch", None)

    # ── Self-deletion / cleanup ──────────────────────────────────
    if " del " in c and ("timeout" in c or "start /min" in c or "exit /b" in c):
        return ("Self-deletion of stager", "self_deletion")

    # ── PowerShell family ────────────────────────────────────────
    if h.startswith("powershell") or h.startswith("pwsh"):
        if "get-ciminstance" in c and "win32_process" in c:
            return ("PowerShell process enumeration", "powershell_execution")
        if "invoke-expression" in c or "iex " in c:
            return ("PowerShell in-memory execution", "powershell_in_memory")
        if "downloadstring" in c or "invoke-webrequest" in c or "webclient" in c:
            return ("PowerShell download-and-execute",
                    "powershell_download_execute")
        if "encodedcommand" in c or " -e " in c or " -enc" in c:
            return ("PowerShell encoded command", "powershell_encoded_command")
        return ("PowerShell execution", "powershell_execution")

    # ── cmd /c chained interpreter ───────────────────────────────
    if h.startswith("cmd") and "powershell" in c and "executionpolicy bypass" in c:
        return ("PowerShell execution via CMD (execution-policy bypass)",
                "powershell_execution")
    if h.startswith("cmd") and (" whoami" in c or " nltest" in c or " net user" in c):
        return ("Host / domain reconnaissance", "discovery_account")
    if h.startswith("cmd") and " wmic " in c and " product" in c:
        return ("Software uninstall (defense evasion)",
                "defense_evasion_disable_tool")

    # ── AutoHotkey stager ────────────────────────────────────────
    if "autohotkey" in h or "ahk" in h:
        return ("AutoHotkey stager", None)

    # ── curl / wget / certutil / bitsadmin download ──────────────
    if h in ("curl", "wget", "curl.exe", "wget.exe"):
        return ("Download from remote resource", "ingress_tool_transfer")
    if "certutil" in h and ("-urlcache" in c or "-decode" in c):
        return ("Certutil download / decode", "certutil_download")
    if "bitsadmin" in h and " /transfer" in c:
        return ("BITSAdmin download", "bitsadmin_transfer")

    # ── schtasks ─────────────────────────────────────────────────
    if h == "schtasks" and (" /create" in c or " -create" in c):
        return ("Scheduled-task persistence", "scheduled_task_persistence")

    return ("Command execution", None)


# ══════════════════════════════════════════════════════════════════
# 3b. Malware-family → behavior_type map
# ══════════════════════════════════════════════════════════════════
MALWARE_FAMILY_TO_BEHAVIORS: Dict[str, Tuple[str, ...]] = {
    # Remote-access tools (T1219)
    "AnyDesk":        ("remote_access_software",),
    "ScreenConnect":  ("remote_access_software",),
    "TeamViewer":     ("remote_access_software",),
    "SimpleHelp":     ("remote_access_software",),
    "Quick Assist":   ("quickassist_it_impersonation",),
    "QuickAssist":    ("quickassist_it_impersonation",),
    # Credential-access tools
    "Mimikatz":       ("credential_dumping_mimikatz",),
    "LaZagne":        ("credential_dumping_lsass",),
    # AD-recon tools
    "SharpHound":     ("discovery_ad",),
    "BloodHound":     ("discovery_ad",),
    # Exfil tools
    "RClone":         ("data_staging_exfil_rclone",),
    "Rclone":         ("data_staging_exfil_rclone",),
    "MegaSync":       ("data_staging_exfil_rclone",),
    # Ransomware families surface data-encryption impact
    "BlackCat":       ("data_encryption_for_impact",),
    "ALPHV":          ("data_encryption_for_impact",),
    "BlackBasta":     ("data_encryption_for_impact",),
    "Conti":          ("data_encryption_for_impact",),
    "Ryuk":           ("data_encryption_for_impact",),
    "REvil":          ("data_encryption_for_impact",),
    "LockBit":        ("data_encryption_for_impact",),
    "Play":           ("data_encryption_for_impact",),
    "Akira":          ("data_encryption_for_impact",),
    "Medusa":         ("data_encryption_for_impact",),
    "Rhysida":        ("data_encryption_for_impact",),
    "Chaos":          ("data_encryption_for_impact",),
    # Post-exploit frameworks — treat as tooling references, no
    # behavior emitted unless a matching command/artifact was seen.
    # ("Cobalt Strike"/"Sliver" are C2 frameworks; their presence
    #  in prose alone is not the same as a beacon config being
    #  parsed — we deliberately do not emit a behavior here.)
}


# ══════════════════════════════════════════════════════════════════
# 3c. LOLBAS-binary → behavior_type map
# ══════════════════════════════════════════════════════════════════
LOLBAS_BINARY_TO_BEHAVIORS: Dict[str, Tuple[str, ...]] = {
    "certutil.exe":   ("certutil_download",),
    "bitsadmin.exe":  ("bitsadmin_transfer",),
    "mshta.exe":      ("signed_binary_proxy_mshta",),
    "regsvr32.exe":   ("signed_binary_proxy_regsvr32",),
    "rundll32.exe":   ("signed_binary_proxy_rundll32",),
    "installutil.exe":("signed_binary_proxy_msi",),
    "msbuild.exe":    ("signed_binary_proxy_msi",),
    "msiexec.exe":    ("signed_binary_proxy_msi",),
    "wmic.exe":       ("wmi_execution",),
    "powershell.exe": ("powershell_execution",),
    "cscript.exe":    ("powershell_execution",),
    "wscript.exe":    ("powershell_execution",),
    "schtasks.exe":   ("scheduled_task_persistence",),
    "vssadmin.exe":   ("shadow_copy_deletion",),
    "wbadmin.exe":    ("inhibit_recovery_wmic",),
    "bcdedit.exe":    ("inhibit_recovery_bcdedit",),
}


# ══════════════════════════════════════════════════════════════════
# 3d. CVE → behavior_type map (best-effort · minimal until curated)
# ══════════════════════════════════════════════════════════════════
CVE_TO_BEHAVIORS: Dict[str, Tuple[str, ...]] = {
    "CVE-2024-57727": ("exploit_public_app",),   # SimpleHelp path traversal
}


# ══════════════════════════════════════════════════════════════════
# 4. Public API · generate_behaviors(extraction_dict)
# ══════════════════════════════════════════════════════════════════
def generate_behaviors(extraction: Dict[str, Any]) -> List[Behavior]:
    """Convert a ``report_extractors.extract_all()`` output dict
    into a deterministic list of ``Behavior`` objects.

    Inputs consumed:
        · ``commands``          — each one is classified
        · ``malware_families``  — looked up in MALWARE_FAMILY_TO_BEHAVIORS
        · ``cves``              — looked up in CVE_TO_BEHAVIORS
        · ``body_artifacts``    — LOLBAS binaries in ``file_path`` entries

    Output is deterministic: same input → same list (order-stable).
    """
    behaviors: List[Behavior] = []
    seen_keys: set = set()

    def _emit(b: Behavior) -> None:
        # Dedupe on (behavior_type, source_ref) so the same tool
        # observed in two places emits one behavior with combined
        # provenance.
        key = (b.behavior_type, b.source_ref)
        if key in seen_keys:
            return
        seen_keys.add(key)
        behaviors.append(b)

    # ── 4a. Commands ────────────────────────────────────────────
    for c in (extraction.get("commands") or []):
        cmd  = str(c.get("command") or "")
        exe  = str(c.get("executable") or "")
        head = exe.split("\\")[-1].lower() if exe else ""
        label, btype = classify_command(cmd, head)
        # Also expose the label back onto the command record for the
        # legacy UI path (unchanged behavior).
        c["purpose"] = label
        if btype:
            src_ref = f"body.line.{c.get('line')}" if c.get("line") else "commands"
            _emit(Behavior(
                behavior_type = btype,
                label         = label,
                source        = "command_classifier",
                source_ref    = src_ref,
                evidence      = {"command": cmd, "executable": exe},
                mitre         = BEHAVIOR_TO_MITRE.get(btype, ()),
            ))

    # ── 4b. Malware family lookup ───────────────────────────────
    for m in (extraction.get("malware_families") or []):
        name = m.get("name") if isinstance(m, dict) else str(m)
        if not name:
            continue
        for btype in MALWARE_FAMILY_TO_BEHAVIORS.get(name, ()):
            _emit(Behavior(
                behavior_type = btype,
                label         = _label_for(btype, name),
                source        = "malware_lookup",
                source_ref    = f"malware:{name}",
                evidence      = {"malware_family": name},
                mitre         = BEHAVIOR_TO_MITRE.get(btype, ()),
            ))

    # ── 4c. LOLBAS binary lookup (via body_artifacts file_paths) ─
    for a in (extraction.get("body_artifacts") or []):
        if a.get("type") != "file_path":
            continue
        path = str(a.get("value") or "")
        binname = path.split("\\")[-1].split("/")[-1].lower()
        for btype in LOLBAS_BINARY_TO_BEHAVIORS.get(binname, ()):
            _emit(Behavior(
                behavior_type = btype,
                label         = _label_for(btype, binname),
                source        = "lolbas_lookup",
                source_ref    = f"file_path:{path}",
                evidence      = {"binary": binname, "path": path},
                mitre         = BEHAVIOR_TO_MITRE.get(btype, ()),
            ))

    # ── 4d. CVE lookup ─────────────────────────────────────────
    for c in (extraction.get("cves") or []):
        cid = c.get("id") if isinstance(c, dict) else str(c)
        if not cid:
            continue
        for btype in CVE_TO_BEHAVIORS.get(cid, ()):
            _emit(Behavior(
                behavior_type = btype,
                label         = _label_for(btype, cid),
                source        = "cve_lookup",
                source_ref    = f"cve:{cid}",
                evidence      = {"cve": cid},
                mitre         = BEHAVIOR_TO_MITRE.get(btype, ()),
            ))

    return behaviors


def collect_mitre_from_behaviors(
    behaviors: Sequence[Behavior],
) -> List[Dict[str, Any]]:
    """Return the deduplicated MITRE-technique list derived from a
    behavior sequence.  Same output shape as the legacy
    ``_extract_mitre`` return (`[{'id': 'T1490', ...}, ...]`), with
    an added ``source`` field so consumers can distinguish
    literal-regex hits (`ida.report.mitre`) from behavior-derived
    hits (`ida.behaviors:<behavior_type>`).
    """
    seen: Dict[str, Dict[str, Any]] = {}
    for b in behaviors:
        for tid in b.mitre:
            if tid in seen:
                continue
            seen[tid] = {
                "id":       tid,
                "source":   f"ida.behaviors:{b.behavior_type}",
                "evidence": b.label,
            }
    return list(seen.values())


# ── helpers ─────────────────────────────────────────────────────
def _label_for(btype: str, hint: str) -> str:
    """Produce an analyst-facing label for a lookup-derived Behavior."""
    _PRETTY = {
        "remote_access_software":        f"Remote-access software ({hint})",
        "quickassist_it_impersonation":  f"IT-impersonation via {hint}",
        "credential_dumping_mimikatz":   f"Credential dumping ({hint})",
        "credential_dumping_lsass":      f"Credential dumping via {hint}",
        "discovery_ad":                  f"Active-Directory discovery ({hint})",
        "data_staging_exfil_rclone":     f"Data staging / exfil ({hint})",
        "data_encryption_for_impact":    f"Ransomware family: {hint}",
        "certutil_download":             "certutil download / decode",
        "bitsadmin_transfer":            "BITSAdmin transfer",
        "signed_binary_proxy_msi":       "MSI / MSIExec proxy execution",
        "signed_binary_proxy_mshta":     "mshta proxy execution",
        "signed_binary_proxy_rundll32":  "rundll32 proxy execution",
        "signed_binary_proxy_regsvr32":  "regsvr32 proxy execution",
        "wmi_execution":                 "WMI execution",
        "powershell_execution":          "PowerShell execution",
        "scheduled_task_persistence":    "Scheduled-task persistence",
        "shadow_copy_deletion":          "Shadow copy deletion",
        "inhibit_recovery_wmic":         "Recovery inhibition (WMIC/wbadmin)",
        "inhibit_recovery_bcdedit":     "Recovery inhibition (bcdedit)",
        "exploit_public_app":            f"Exploit public-facing app ({hint})",
    }
    return _PRETTY.get(btype, btype.replace("_", " ").capitalize())


__all__ = [
    "Behavior",
    "BEHAVIOR_TO_MITRE",
    "MALWARE_FAMILY_TO_BEHAVIORS",
    "LOLBAS_BINARY_TO_BEHAVIORS",
    "CVE_TO_BEHAVIORS",
    "classify_command",
    "generate_behaviors",
    "collect_mitre_from_behaviors",
]
