"""
NivXRay · Behavior Knowledge Base (BKB)
────────────────────────────────────────

Static knowledge base that maps every classifier-emitted behavior
label to its canonical semantics — techniques, tactics, severity,
evidence requirements, recommendations, and references.

Architecture (per user directive 2026-02-09):

    Evidence → Canonicalizer → Classifier → Behavior label
        │
        ▼
    BKB.lookup(label)  →  BehaviorSpec (static knowledge)
        │
        ▼
    BehaviorCluster (per-investigation SSOT)
        │
        ▼
    Every projection (Attack Chain / MITRE Summary /
    Observed Behaviour / Recommendations / Reports)

The Registry is READ-ONLY, DETERMINISTIC, and STATIC — it never
invents behaviors and never consumes runtime state.  DIE
per-command MITRE observations live elsewhere (on the command's
own `investigation.techniques[]`) and MUST NOT be folded into
cluster attribution.

Contract (P0.16 · Behavior Knowledge Base v1):
    · One canonical BehaviorSpec per classifier label.
    · `canonical_techniques` and `canonical_tactics` are the
      SINGLE truth used by every Workspace projection.
    · `lookup(label)` returns None for unknown labels — callers
      MUST handle that (a missing entry ≠ a match on the empty
      set).
    · Every mutation to the Registry is a schema change and must
      bump ``BKB_SCHEMA_VERSION``.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple


BKB_SCHEMA_VERSION = "1.0"


# ══════════════════════════════════════════════════════════════════
# Data model
# ══════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class BehaviorSpec:
    label:                str                       # classifier output
    display_name:         str
    category:             str                        # human bucket
    severity:             str                        # low | medium | high | critical
    canonical_techniques: Tuple[Dict[str, str], ...]  # ({id, name}, …)
    canonical_tactics:    Tuple[str, ...]            # canonical (lowercase, underscore) tactics
    confidence_model:     str                        # deterministic | heuristic
    evidence_required:    Tuple[str, ...]            # evidence markers
    recommendations:      Tuple[str, ...]            # short analyst hints
    references:           Tuple[str, ...]            # citation slugs

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Serialize tuples → lists for JSON friendliness.
        d["canonical_techniques"] = list(self.canonical_techniques)
        d["canonical_tactics"]    = list(self.canonical_tactics)
        d["evidence_required"]    = list(self.evidence_required)
        d["recommendations"]      = list(self.recommendations)
        d["references"]           = list(self.references)
        return d


# ══════════════════════════════════════════════════════════════════
# Registry authoring helpers
# ══════════════════════════════════════════════════════════════════
def _t(tid: str, name: str) -> Dict[str, str]:
    return {"id": tid, "name": name}


def _spec(label: str, *,
              display_name:    Optional[str] = None,
              category:        str,
              severity:        str,
              techniques:      List[Dict[str, str]],
              tactics:         Optional[List[str]] = None,
              confidence:      str = "deterministic",
              evidence:        Tuple[str, ...] = (),
              recs:            Tuple[str, ...] = (),
              refs:            Tuple[str, ...] = ("mitre-attack",)) -> BehaviorSpec:
    # If tactics not supplied, resolve deterministically from techniques.
    if tactics is None:
        # Import late to avoid a circular dep during module load.
        from services.ice.correlate import tactic_for
        resolved = []
        for t in techniques:
            tt = tactic_for(t["id"])
            if tt and tt not in resolved:
                resolved.append(tt)
        tactics = resolved
    return BehaviorSpec(
        label                = label,
        display_name         = display_name or label,
        category             = category,
        severity             = severity,
        canonical_techniques = tuple(techniques),
        canonical_tactics    = tuple(tactics),
        confidence_model     = confidence,
        evidence_required    = evidence,
        recommendations      = recs,
        references           = refs,
    )


# ══════════════════════════════════════════════════════════════════
# Registry v1 — every classifier label mapped canonically
# ══════════════════════════════════════════════════════════════════
_REGISTRY: Dict[str, BehaviorSpec] = {}


def _add(spec: BehaviorSpec) -> None:
    if spec.label in _REGISTRY:
        raise RuntimeError(f"duplicate BKB entry: {spec.label!r}")
    _REGISTRY[spec.label] = spec


# ---- Execution (T1053 / T1059 / T1047 / T1204) ----------
_add(_spec("Scheduled Task create",
              category="Execution", severity="high",
              techniques=[_t("T1053.005", "Scheduled Task")],
              evidence=("schtasks_create",),
              recs=("Review scheduled tasks under \\Windows\\ that were created within the incident window",)))
_add(_spec("Scheduled Task remote create",
              category="Lateral Movement", severity="high",
              techniques=[_t("T1053.005", "Scheduled Task"),
                              _t("T1021.002", "Remote Services · SMB/Windows Admin Shares")],
              evidence=("schtasks_remote",),
              recs=("Verify /s host was a legitimate admin action",)))
_add(_spec("Scheduled-task persistence",
              category="Persistence", severity="high",
              techniques=[_t("T1053.005", "Scheduled Task")]))
_add(_spec("PowerShell execution",
              category="Execution", severity="medium",
              techniques=[_t("T1059.001", "PowerShell")]))
_add(_spec("PowerShell in-memory execution",
              category="Execution", severity="high",
              techniques=[_t("T1059.001", "PowerShell")],
              evidence=("iex", "invoke-expression"),
              recs=("Correlate with outbound URL fetches in same session",)))
_add(_spec("PowerShell download-and-execute",
              category="Execution", severity="high",
              techniques=[_t("T1059.001", "PowerShell"),
                              _t("T1105",    "Ingress Tool Transfer")]))
_add(_spec("PowerShell encoded command",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1059.001", "PowerShell"),
                              _t("T1027",    "Obfuscated Files or Information")]))
_add(_spec("PowerShell hidden window",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1059.001", "PowerShell"),
                              _t("T1564.003", "Hide Artifacts · Hidden Window")]))
_add(_spec("PowerShell hidden window IEX",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1059.001", "PowerShell"),
                              _t("T1564.003", "Hide Artifacts · Hidden Window")]))
_add(_spec("PowerShell execution-policy bypass",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1059.001", "PowerShell"),
                              _t("T1562.001", "Impair Defenses · Disable or Modify Tools")]))
_add(_spec("PowerShell execution via CMD (execution-policy bypass)",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1059.001", "PowerShell"),
                              _t("T1562.001", "Impair Defenses · Disable or Modify Tools")]))
_add(_spec("PowerShell process enumeration",
              category="Discovery", severity="medium",
              techniques=[_t("T1057",     "Process Discovery"),
                              _t("T1059.001", "PowerShell")]))

# ---- WMI / WinRM ----------
_add(_spec("WMI process create",
              category="Execution", severity="high",
              techniques=[_t("T1047", "Windows Management Instrumentation")]))
_add(_spec("Remote WMI process create",
              category="Lateral Movement", severity="critical",
              techniques=[_t("T1047",     "Windows Management Instrumentation"),
                              _t("T1021.006", "Remote Services · WinRM")]))
_add(_spec("WMI invoke-method",
              category="Execution", severity="medium",
              techniques=[_t("T1047", "Windows Management Instrumentation")]))
_add(_spec("Remote WMI invoke-method",
              category="Lateral Movement", severity="high",
              techniques=[_t("T1047", "Windows Management Instrumentation")]))
_add(_spec("WMI process discovery",
              category="Discovery", severity="low",
              techniques=[_t("T1057", "Process Discovery")]))
_add(_spec("WMI event subscription persistence",
              category="Persistence", severity="high",
              techniques=[_t("T1546.003", "Event Triggered Execution · WMI Subscription")]))
_add(_spec("WinRM / PowerShell remote session",
              category="Lateral Movement", severity="high",
              techniques=[_t("T1021.006", "Remote Services · WinRM")]))
_add(_spec("WinRS remote command",
              category="Lateral Movement", severity="high",
              techniques=[_t("T1021.006", "Remote Services · WinRM")]))

# ---- LOLBin proxy execution ----------
_add(_spec("Mshta proxy execution",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1218.005", "System Binary Proxy Execution · Mshta")]))
_add(_spec("Rundll32 proxy execution",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1218.011", "System Binary Proxy Execution · Rundll32")]))
_add(_spec("Regsvr32 proxy execution",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1218.010", "System Binary Proxy Execution · Regsvr32")]))
_add(_spec("Installutil proxy execution",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1218.004", "System Binary Proxy Execution · InstallUtil")]))
_add(_spec("MSBuild proxy execution",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1127.001", "Trusted Developer Utilities · MSBuild")]))
_add(_spec("WScript execution",
              category="Execution", severity="medium",
              techniques=[_t("T1059.005", "Command and Scripting Interpreter · Visual Basic")]))
_add(_spec("CScript execution",
              category="Execution", severity="medium",
              techniques=[_t("T1059.005", "Command and Scripting Interpreter · Visual Basic")]))
_add(_spec("COM hijack (regsvr32)",
              category="Persistence", severity="high",
              techniques=[_t("T1546.015", "Event Triggered Execution · Component Object Model Hijacking")]))

# ---- Credential Access ----------
_add(_spec("LSASS memory dump (procdump)",
              category="Credential Access", severity="critical",
              techniques=[_t("T1003.001", "OS Credential Dumping · LSASS Memory")]))
_add(_spec("Process memory dump (procdump)",
              category="Credential Access", severity="high",
              techniques=[_t("T1003", "OS Credential Dumping")]))
_add(_spec("LSASS memory dump (comsvcs)",
              category="Credential Access", severity="critical",
              techniques=[_t("T1003.001", "OS Credential Dumping · LSASS Memory")]))
_add(_spec("Credential dumping (mimikatz)",
              category="Credential Access", severity="critical",
              techniques=[_t("T1003.001", "OS Credential Dumping · LSASS Memory")]))
_add(_spec("NTDS.dit extraction (ntdsutil)",
              category="Credential Access", severity="critical",
              techniques=[_t("T1003.003", "OS Credential Dumping · NTDS")]))
_add(_spec("SAM/SECURITY hive dump (reg save)",
              category="Credential Access", severity="critical",
              techniques=[_t("T1003.002", "OS Credential Dumping · Security Account Manager")]))

# ---- Defense Evasion overlays ----------
_add(_spec("Windows Defender exclusion add",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1562.001", "Impair Defenses · Disable or Modify Tools")]))
_add(_spec("Windows Defender configure (disable)",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1562.001", "Impair Defenses · Disable or Modify Tools")]))
_add(_spec("Windows Defender service tamper",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1562.001", "Impair Defenses · Disable or Modify Tools")]))
_add(_spec("Event log clear (wevtutil)",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1070.001", "Indicator Removal · Clear Windows Event Logs")]))
_add(_spec("Event log clear (PowerShell)",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1070.001", "Indicator Removal · Clear Windows Event Logs")]))
_add(_spec("Self-deletion of stager",
              category="Defense Evasion", severity="medium",
              techniques=[_t("T1070.004", "Indicator Removal · File Deletion")]))
_add(_spec("Registry modification",
              category="Defense Evasion", severity="medium",
              techniques=[_t("T1112", "Modify Registry")]))

# ---- Impact ----------
_add(_spec("Shadow copy deletion",
              category="Impact", severity="critical",
              techniques=[_t("T1490", "Inhibit System Recovery")]))
_add(_spec("Recovery inhibit (bcdedit)",
              category="Impact", severity="high",
              techniques=[_t("T1490", "Inhibit System Recovery")]))
_add(_spec("Backup catalog deletion (wbadmin)",
              category="Impact", severity="high",
              techniques=[_t("T1490", "Inhibit System Recovery")]))

# ---- Discovery ----------
_add(_spec("Current-user discovery",
              category="Discovery", severity="low",
              techniques=[_t("T1033", "System Owner / User Discovery")]))
_add(_spec("Host / domain reconnaissance",
              category="Discovery", severity="low",
              techniques=[_t("T1016", "System Network Configuration Discovery")]))
_add(_spec("Net view (remote share/system discovery)",
              category="Discovery", severity="low",
              techniques=[_t("T1018", "Remote System Discovery"),
                              _t("T1135", "Network Share Discovery")]))
_add(_spec("ARP table discovery",
              category="Discovery", severity="low",
              techniques=[_t("T1016", "System Network Configuration Discovery")]))
_add(_spec("Route table discovery",
              category="Discovery", severity="low",
              techniques=[_t("T1016", "System Network Configuration Discovery")]))
_add(_spec("System information discovery",
              category="Discovery", severity="low",
              techniques=[_t("T1082", "System Information Discovery")]))
_add(_spec("User session discovery (quser)",
              category="Discovery", severity="low",
              techniques=[_t("T1033", "System Owner / User Discovery")]))
_add(_spec("Active Directory query (dsquery)",
              category="Discovery", severity="medium",
              techniques=[_t("T1087.002", "Account Discovery · Domain Account")]))
_add(_spec("Python interpreter discovery",
              category="Discovery", severity="low",
              techniques=[_t("T1518", "Software Discovery")]))

# ---- Persistence ----------
_add(_spec("Registry Run-key persistence",
              category="Persistence", severity="high",
              techniques=[_t("T1547.001", "Registry Run Keys / Startup Folder")]))
_add(_spec("Startup folder persistence",
              category="Persistence", severity="high",
              techniques=[_t("T1547.001", "Registry Run Keys / Startup Folder")]))
_add(_spec("Windows Service create (persistence)",
              category="Persistence", severity="high",
              techniques=[_t("T1543.003", "Create or Modify System Process · Windows Service")]))

# ---- C2 / Ingress ----------
_add(_spec("Certutil download / decode",
              category="Command and Control", severity="high",
              techniques=[_t("T1105", "Ingress Tool Transfer"),
                              _t("T1140", "Deobfuscate/Decode Files or Information")]))
_add(_spec("BITSAdmin download",
              category="Command and Control", severity="high",
              techniques=[_t("T1105", "Ingress Tool Transfer"),
                              _t("T1197", "BITS Jobs")]))
_add(_spec("Download from remote resource",
              category="Command and Control", severity="medium",
              techniques=[_t("T1105", "Ingress Tool Transfer")]))

# ---- Lateral Movement ----------
_add(_spec("Lateral movement via PsExec",
              category="Lateral Movement", severity="critical",
              techniques=[_t("T1021.002", "Remote Services · SMB/Windows Admin Shares"),
                              _t("T1569.002", "System Services · Service Execution")]))
_add(_spec("Lateral movement via Impacket",
              category="Lateral Movement", severity="critical",
              techniques=[_t("T1021.002", "Remote Services · SMB/Windows Admin Shares")]))
_add(_spec("SSH client execution",
              category="Lateral Movement", severity="medium",
              techniques=[_t("T1021.004", "Remote Services · SSH")]))
_add(_spec("SSH remote session",
              category="Lateral Movement", severity="medium",
              techniques=[_t("T1021.004", "Remote Services · SSH")]))

# ---- RMM (Command and Control · T1219) ----------
for _label in ("AnyDesk RMM execution", "TeamViewer RMM execution",
                 "ScreenConnect RMM execution", "Atera RMM execution",
                 "Splashtop RMM execution", "LogMeIn RMM execution",
                 "Syncro RMM execution", "NinjaRMM execution",
                 "Kaseya RMM execution"):
    _add(_spec(_label, category="Command and Control", severity="high",
                  techniques=[_t("T1219", "Remote Access Software")]))

# ---- Miscellaneous ----------
_add(_spec("Tasklist / running process enumeration",
              category="Discovery", severity="low",
              techniques=[_t("T1057", "Process Discovery")]))
_add(_spec("Service enumeration",
              category="Discovery", severity="low",
              techniques=[_t("T1007", "System Service Discovery")]))
_add(_spec("Network share enumeration",
              category="Discovery", severity="low",
              techniques=[_t("T1135", "Network Share Discovery")]))
_add(_spec("Firewall configuration",
              category="Defense Evasion", severity="medium",
              techniques=[_t("T1562.004", "Impair Defenses · Disable or Modify System Firewall")]))
_add(_spec("Hostname / OS discovery",
              category="Discovery", severity="low",
              techniques=[_t("T1082", "System Information Discovery")]))
_add(_spec("AutoHotkey stager",
              category="Execution", severity="medium",
              techniques=[_t("T1059.006", "Command and Scripting Interpreter · Python/AutoHotkey")]))
_add(_spec("Microsoft Edge launch",
              category="Execution", severity="low",
              techniques=[_t("T1204.002", "User Execution · Malicious File")]))
_add(_spec("Archive extraction",
              category="Defense Evasion", severity="low",
              techniques=[_t("T1140", "Deobfuscate / Decode Files or Information")]))
_add(_spec("Unzip Python interpreter stager",
              category="Defense Evasion", severity="medium",
              techniques=[_t("T1140", "Deobfuscate / Decode Files or Information")]))
_add(_spec("Unzip encrypted payload archive",
              category="Defense Evasion", severity="medium",
              techniques=[_t("T1140", "Deobfuscate / Decode Files or Information")]))
_add(_spec("Remote-access software execution",
              category="Command and Control", severity="high",
              techniques=[_t("T1219", "Remote Access Software")]))

# ---- Legacy label aliases (services/ida/behaviors.py) ----------
# Different producer, same canonical semantics.  Aliases keep the
# BKB comprehensive without renaming legacy call sites.
_add(_spec("MSHTA execution", display_name="Mshta proxy execution",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1218.005", "System Binary Proxy Execution · Mshta")]))
_add(_spec("Regsvr32 execution", display_name="Regsvr32 proxy execution",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1218.010", "System Binary Proxy Execution · Regsvr32")]))
_add(_spec("Rundll32 execution", display_name="Rundll32 proxy execution",
              category="Defense Evasion", severity="high",
              techniques=[_t("T1218.011", "System Binary Proxy Execution · Rundll32")]))


# ══════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════
def lookup(label: str) -> Optional[BehaviorSpec]:
    """Return the canonical BehaviorSpec for a classifier label, or
    None if the label has no BKB entry.  Never raises."""
    if not label or not isinstance(label, str):
        return None
    return _REGISTRY.get(label)


def has(label: str) -> bool:
    return bool(label) and label in _REGISTRY


def labels() -> List[str]:
    """All known behavior labels (sorted for determinism)."""
    return sorted(_REGISTRY.keys())


def as_purpose_to_mitre() -> Dict[str, List[Dict[str, str]]]:
    """Compatibility view — same shape as ICE's legacy
    ``_PURPOSE_TO_MITRE`` dict, so downstream call sites that
    can't be refactored in this sprint keep working."""
    return {spec.label: list(spec.canonical_techniques)
                for spec in _REGISTRY.values()}


def snapshot() -> Dict[str, Any]:
    """Deterministic snapshot of the whole registry, JSON-safe."""
    return {
        "schema_version": BKB_SCHEMA_VERSION,
        "count":          len(_REGISTRY),
        "entries":        {k: v.to_dict() for k, v in sorted(_REGISTRY.items())},
    }


__all__ = ["BehaviorSpec", "BKB_SCHEMA_VERSION",
                "lookup", "has", "labels",
                "as_purpose_to_mitre", "snapshot"]
