"""IDA · Stage 5 · Deterministic Behavior Generation Layer.

The bridge from raw extracted entities → canonical Behavior objects.
Behavior is the semantic contract; every framework projection
(ATT&CK, kill-chain, impacts, D3FEND, NIST, CIS) lives in its own
module under ``services.ida.projections`` so adding a new framework
never requires editing this file.

Architecture:

    Evidence   (commands, malware_families, LOLBAS, CVEs)
        │
        ▼
    Behavior Generation     ← this module (framework-agnostic)
        │
    ┌───┼───────────────────────────────┐
    ▼   ▼                               ▼
  MITRE  Kill-chain / Impacts    Evidence Summary / Reports / LLM
                                         │
                                         ▼
                                Recommendation Engine

STRICT contract:
    · Deterministic lookups only.  No prose inference, no regex over
      narrative, no LLM.
    · A Behavior is emitted ONLY when the input entity was already
      extracted at Stage 4.  Nothing is invented.
    · The Behavior schema is framework-neutral.  ATT&CK / kill-chain /
      impact tags live in ``services.ida.projections`` and are
      computed on-demand.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing      import Any, Dict, List, Optional, Sequence, Tuple

from .projections.mitre       import BEHAVIOR_TO_MITRE, project_to_mitre
from .projections.kill_chain  import (
    BEHAVIOR_TO_KILL_CHAIN, project_to_kill_chain,
)
from .projections.impact      import BEHAVIOR_TO_IMPACTS, project_to_impacts


# ══════════════════════════════════════════════════════════════════
# 1. Canonical Behavior schema  (framework-neutral · minimal)
# ══════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class Behavior:
    """One canonical semantic behavior observed in an investigation.

    Framework-agnostic — Behavior has no ATT&CK, no kill-chain, no
    impact fields.  Callers derive those via the corresponding
    projection function in ``services.ida.projections``.

    Fields:
      · ``behavior_type``  — key into every projection map
      · ``label``          — analyst-facing string
      · ``source``         — extractor name that emitted this
                              behavior (``command_classifier`` |
                              ``malware_lookup`` |
                              ``lolbas_lookup`` | ``cve_lookup``)
      · ``source_ref``     — origin ref (``body.line.37`` |
                              ``malware:Medusa`` | ``cve:...``)
      · ``provenance``     — evidence origin quality:
                              ``command_execution`` (live command),
                              ``malware_reference`` (family name),
                              ``lolbas_binary_reference`` (file_path
                                artifact),
                              ``cve_reference`` (CVE id),
                              [future] ``tool_reference`` (Tool-
                                Mention Extractor emits this)
      · ``confidence``     — ``deterministic`` today
      · ``evidence``       — the raw entity that triggered emission
      · ``observed_at``    — references (not timestamps) to the exact
                              artifact / entity / evidence-index the
                              behavior derives from — trivially
                              answers "which artifact generated this
                              behavior?" without evidence-collection
                              search.  Shape (all keys optional)::

                                  {"artifact_id":    str,
                                   "entity_id":      str,
                                   "evidence_index": int,
                                   "line":           int}
    """
    behavior_type:   str
    label:           str
    source:          str
    source_ref:      str  = ""
    provenance:      str  = "command_execution"
    confidence:      str  = "deterministic"
    evidence:        Dict[str, Any] = field(default_factory=dict)
    observed_at:     Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Stable content-hash id · used for dedupe + provenance."""
        h = hashlib.sha1()
        h.update(self.behavior_type.encode("utf-8"))
        h.update(b"\x00")
        h.update(self.source_ref.encode("utf-8"))
        h.update(b"\x00")
        h.update(self.provenance.encode("utf-8"))
        return h.hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["id"] = self.id
        return d


# ══════════════════════════════════════════════════════════════════
# 2. Lookup tables · Behavior emission
#    (framework projections live in services.ida.projections.*)
# ══════════════════════════════════════════════════════════════════
MALWARE_FAMILY_TO_BEHAVIORS: Dict[str, Tuple[str, ...]] = {
    # Remote-access tools
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
    # Ransomware families
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
}


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


CVE_TO_BEHAVIORS: Dict[str, Tuple[str, ...]] = {
    "CVE-2024-57727": ("exploit_public_app",),
}


# ══════════════════════════════════════════════════════════════════
# 3. classify_command  (kept public for the URL adapter path)
# ══════════════════════════════════════════════════════════════════
def classify_command(cmd: str, head: str) -> Tuple[str, Optional[str]]:
    """Return ``(label, behavior_type)`` for a command string.

    ``behavior_type`` is None when the command is recognized but
    has no canonical behavior (e.g. generic execution).
    """
    c = cmd.lower()
    h = (head or "").lower()

    if "vssadmin" in h and ("delete" in c and "shadow" in c):
        return ("Shadow copy deletion", "shadow_copy_deletion")
    if "wmic" in c and "shadowcopy" in c and "delete" in c:
        return ("Shadow copy deletion (WMIC)", "inhibit_recovery_wmic")
    if "bcdedit" in h and ("ignoreallfailures" in c or "recoveryenabled" in c
                              or "safeboot" in c):
        return ("Recovery-boot policy modification", "inhibit_recovery_bcdedit")

    if "wmic" in c and "product" in c and "uninstall" in c:
        return ("Software uninstall (defense evasion)",
                "defense_evasion_disable_tool")

    if h in ("msiexec.exe", "msiexec") or "msiexec.exe" in c.split()[0:1]:
        if "-embedding" in c:
            return ("MSI installer child (embedded)", "signed_binary_proxy_msi")
        if "/i " in c or " /i " in c or "/quiet" in c or "/qn" in c:
            return ("MSI installation", "signed_binary_proxy_msi")
        return ("MSI execution", "signed_binary_proxy_msi")

    if h in ("mshta.exe", "mshta"):
        return ("MSHTA execution", "signed_binary_proxy_mshta")
    if h in ("rundll32.exe", "rundll32"):
        return ("Rundll32 execution", "signed_binary_proxy_rundll32")
    if h in ("regsvr32.exe", "regsvr32"):
        return ("Regsvr32 execution", "signed_binary_proxy_regsvr32")

    if "ssh.exe" in h or h == "ssh":
        if " -r " in (" " + c + " ") or c.strip().split(".exe", 1)[-1].lstrip().startswith("-r"):
            return ("Reverse SSH tunnel", "protocol_tunneling_ssh")
        if " -l " in c or " -n " in c:
            return ("SSH remote session", "protocol_tunneling_ssh")
        return ("SSH client execution", "protocol_tunneling_ssh")

    if "rclone" in h or ("copy" in c and "--max-age" in c) \
       or ("--exclude" in c and "*.{" in c) or ("--exclude" in c and "*{" in c):
        return ("Data staging / exfil (rclone-style)",
                "data_staging_exfil_rclone")

    if "psexec" in h or "psexec" in c.split()[0:1]:
        return ("Lateral movement via PsExec", "lateral_movement_psexec")
    if "impacket" in c or "wmiexec" in c or "smbexec" in c or "atexec" in c:
        return ("Lateral movement via Impacket", "lateral_movement_impacket")

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

    if h in ("reg", "reg.exe") and " add " in c:
        if "run" in c:
            return ("Registry Run-key persistence",
                    "registry_run_key_persistence")
        return ("Registry modification", "registry_modification")

    if "tar" in h and " -xf " in c:
        if "python" in c:
            return ("Unzip Python interpreter stager", "archive_extraction")
        if ".zip" in c or "--passphrase" in c:
            return ("Unzip encrypted payload archive", "archive_extraction")
        return ("Archive extraction", "archive_extraction")

    if "python" in c and ("--version" in c or " -V" in cmd):
        return ("Python interpreter discovery", None)

    if "msedge" in h or "msedge.exe" in c:
        if "load-extension" in c and "headless" in c:
            return ("Microsoft Edge launch (headless, extension load — Edgecution)",
                    "browser_extension_load")
        if "load-extension" in c:
            return ("Microsoft Edge launch (extension load — Edgecution)",
                    "browser_extension_load")
        return ("Microsoft Edge launch", None)

    if " del " in c and ("timeout" in c or "start /min" in c or "exit /b" in c):
        return ("Self-deletion of stager", "self_deletion")

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

    if h.startswith("cmd") and "powershell" in c and "executionpolicy bypass" in c:
        return ("PowerShell execution via CMD (execution-policy bypass)",
                "powershell_execution")
    if h.startswith("cmd") and (" whoami" in c or " nltest" in c or " net user" in c):
        return ("Host / domain reconnaissance", "discovery_account")
    if h.startswith("cmd") and " wmic " in c and " product" in c:
        return ("Software uninstall (defense evasion)",
                "defense_evasion_disable_tool")

    if "autohotkey" in h or "ahk" in h:
        return ("AutoHotkey stager", None)

    if h in ("curl", "wget", "curl.exe", "wget.exe"):
        return ("Download from remote resource", "ingress_tool_transfer")
    if "certutil" in h and ("-urlcache" in c or "-decode" in c):
        return ("Certutil download / decode", "certutil_download")
    if "bitsadmin" in h and " /transfer" in c:
        return ("BITSAdmin download", "bitsadmin_transfer")

    if h == "schtasks" and (" /create" in c or " -create" in c):
        return ("Scheduled-task persistence", "scheduled_task_persistence")

    return ("Command execution", None)


# ══════════════════════════════════════════════════════════════════
# 4. Public API · generate_behaviors + aggregator
# ══════════════════════════════════════════════════════════════════
def generate_behaviors(extraction: Dict[str, Any]) -> List[Behavior]:
    """Convert a ``report_extractors.extract_all()`` output dict
    into a deterministic list of ``Behavior`` objects."""
    behaviors: List[Behavior] = []
    seen_keys: set = set()

    def _emit(b: Behavior) -> None:
        key = (b.behavior_type, b.source_ref)
        if key in seen_keys:
            return
        seen_keys.add(key)
        behaviors.append(b)

    for c in (extraction.get("commands") or []):
        cmd  = str(c.get("command") or "")
        exe  = str(c.get("executable") or "")
        head = exe.split("\\")[-1].lower() if exe else ""
        label, btype = classify_command(cmd, head)
        c["purpose"] = label
        if btype:
            src_ref = f"body.line.{c.get('line')}" if c.get("line") else "commands"
            _emit(Behavior(
                behavior_type = btype,      label = label,
                source        = "command_classifier",
                source_ref    = src_ref,
                provenance    = "command_execution",
                evidence      = {"command": cmd, "executable": exe},
            ))

    for m in (extraction.get("malware_families") or []):
        name = m.get("name") if isinstance(m, dict) else str(m)
        if not name:
            continue
        for btype in MALWARE_FAMILY_TO_BEHAVIORS.get(name, ()):
            _emit(Behavior(
                behavior_type = btype,      label = _label_for(btype, name),
                source        = "malware_lookup",
                source_ref    = f"malware:{name}",
                provenance    = "malware_reference",
                evidence      = {"malware_family": name},
            ))

    for a in (extraction.get("body_artifacts") or []):
        if a.get("type") != "file_path":
            continue
        path = str(a.get("value") or "")
        binname = path.split("\\")[-1].split("/")[-1].lower()
        for btype in LOLBAS_BINARY_TO_BEHAVIORS.get(binname, ()):
            _emit(Behavior(
                behavior_type = btype,      label = _label_for(btype, binname),
                source        = "lolbas_lookup",
                source_ref    = f"file_path:{path}",
                provenance    = "lolbas_binary_reference",
                evidence      = {"binary": binname, "path": path},
            ))

    for c in (extraction.get("cves") or []):
        cid = c.get("id") if isinstance(c, dict) else str(c)
        if not cid:
            continue
        for btype in CVE_TO_BEHAVIORS.get(cid, ()):
            _emit(Behavior(
                behavior_type = btype,      label = _label_for(btype, cid),
                source        = "cve_lookup",
                source_ref    = f"cve:{cid}",
                provenance    = "cve_reference",
                evidence      = {"cve": cid},
            ))

    return behaviors


def collect_mitre_from_behaviors(
    behaviors: Sequence[Behavior],
) -> List[Dict[str, Any]]:
    """Back-compat shim · use ``projections.mitre.project_to_mitre``.
    Kept so any legacy caller can migrate without a lockstep change."""
    return project_to_mitre(behaviors)


def collect_outcome_inputs_from_behaviors(
    behaviors: Sequence[Behavior],
    *,
    provenance_whitelist: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Aggregate Behaviors into the engine-facing fields the v2
    Evidence-Driven Recommendation Engine consumes on the
    ``InvestigationOutcome``.

    Composes independent projections — this is where the pipeline
    "collects the projections" per-consumer; the Behavior itself
    remains framework-neutral.

    Returns::

        {
          "behaviors":        [str, ...]   # kill-chain tag list
          "impacts":          [str, ...]   # impact-family tag list
          "mitre_techniques": [str, ...]   # ATT&CK id list
          "provenance":       {behavior_id: {...}, ...}
        }
    """
    if provenance_whitelist:
        subset = [b for b in behaviors if b.provenance in provenance_whitelist]
    else:
        subset = list(behaviors)

    tids = {m["id"] for m in project_to_mitre(subset)}
    prov: Dict[str, Any] = {}
    for b in subset:
        prov[b.id] = {
            "behavior_type":   b.behavior_type,
            "label":           b.label,
            "source":          b.source,
            "provenance":      b.provenance,
            "source_ref":      b.source_ref,
            "confidence":      b.confidence,
            "mitre":           list(BEHAVIOR_TO_MITRE.get(b.behavior_type, ())),
            "kill_chain_tags": list(BEHAVIOR_TO_KILL_CHAIN.get(
                                        b.behavior_type, ())),
            "impact_tags":     list(BEHAVIOR_TO_IMPACTS.get(
                                        b.behavior_type, ())),
        }
    return {
        "behaviors":        project_to_kill_chain(subset),
        "impacts":          project_to_impacts(subset),
        "mitre_techniques": sorted(tids),
        "provenance":       prov,
    }


# ── helpers ─────────────────────────────────────────────────────
def _label_for(btype: str, hint: str) -> str:
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
        "inhibit_recovery_bcdedit":      "Recovery inhibition (bcdedit)",
        "exploit_public_app":            f"Exploit public-facing app ({hint})",
    }
    return _PRETTY.get(btype, btype.replace("_", " ").capitalize())


__all__ = [
    "Behavior",
    "MALWARE_FAMILY_TO_BEHAVIORS",
    "LOLBAS_BINARY_TO_BEHAVIORS",
    "CVE_TO_BEHAVIORS",
    "classify_command",
    "generate_behaviors",
    "collect_mitre_from_behaviors",
    "collect_outcome_inputs_from_behaviors",
    # Re-exports so tests still import from the old namespace.
    "BEHAVIOR_TO_MITRE",
    "BEHAVIOR_TO_KILL_CHAIN",
    "BEHAVIOR_TO_IMPACTS",
]
