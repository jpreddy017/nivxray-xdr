"""
ICE · Investigation Correlation Engine
──────────────────────────────────────
Frozen 2026-03-01 · P0 · Rule R21.

Rule R21 · **Correlation Happens Once**

    Between recursive investigation and any projection, the platform
    MUST run a single deterministic correlation pass that turns
    isolated per-artifact investigations into coherent higher-order
    objects: behavior clusters, attack phases, kill-chain ordering,
    a unified timeline, and an incident graph.  Every downstream
    projection (Evidence Explorer, Attack Story, Timeline, Knowledge
    Graph, NIST IR Report, exports) reads from ICE — never from raw
    per-artifact investigations directly.

Analysis happens once.  Projection happens many times.

This module is that engine.  It is:
  · Deterministic (no LLM, no network)
  · Read-only w.r.t. its inputs (the SSOT block emitted upstream)
  · Additive — every consumer keeps working; ICE just adds richer
    correlated objects alongside the raw artifacts.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional


# ══════════════════════════════════════════════════════════════════
# 1. MITRE ATT&CK technique → tactic mapping (deterministic pack)
# ══════════════════════════════════════════════════════════════════
# Covers the techniques the platform currently produces from IDA-4
# and per-command investigation.  Grows organically; downstream
# projections rely on this table to place a technique into a phase.
_TECHNIQUE_TO_TACTIC: Dict[str, str] = {
    "T1059":     "execution",
    "T1059.001": "execution",              # PowerShell
    "T1059.003": "execution",              # Windows Command Shell
    "T1059.005": "execution",              # Visual Basic
    "T1059.006": "execution",              # Python
    "T1053.005": "execution",              # Scheduled Task
    "T1204":     "execution",              # User Execution
    "T1078":     "initial_access",         # Valid Accounts
    "T1566":     "initial_access",         # Phishing
    "T1105":     "command_and_control",    # Ingress Tool Transfer
    "T1140":     "defense_evasion",        # Deobfuscate / Decode
    "T1027":     "defense_evasion",        # Obfuscated Files or Info
    "T1218":     "defense_evasion",        # Signed Binary Proxy Exec
    "T1218.005": "defense_evasion",        # Mshta
    "T1218.010": "defense_evasion",        # Regsvr32
    "T1218.011": "defense_evasion",        # Rundll32
    "T1562":     "defense_evasion",
    "T1562.001": "defense_evasion",        # Disable or Modify Tools
    "T1564":     "defense_evasion",
    "T1564.003": "defense_evasion",        # Hidden Window
    "T1070":     "defense_evasion",        # Indicator Removal
    "T1070.004": "defense_evasion",        # File Deletion
    "T1176":     "persistence",            # Browser Extensions
    "T1547":     "persistence",
    "T1547.001": "persistence",            # Registry Run Keys
    "T1543":     "persistence",
    "T1057":     "discovery",              # Process Discovery
    "T1082":     "discovery",              # System Info Discovery
    "T1033":     "discovery",              # System Owner / User Discovery
    "T1016":     "discovery",              # System Network Config
    "T1087":     "discovery",              # Account Discovery
    "T1003":     "credential_access",      # OS Credential Dumping
    "T1003.001": "credential_access",      # LSASS Memory
    "T1003.002": "credential_access",      # SAM
    "T1003.003": "credential_access",      # NTDS
    "T1555":     "credential_access",
    "T1021":     "lateral_movement",
    "T1021.001": "lateral_movement",       # RDP
    "T1021.002": "lateral_movement",       # SMB
    "T1021.006": "lateral_movement",       # WinRM
    "T1005":     "collection",             # Data from Local System
    "T1114":     "collection",             # Email Collection
    "T1041":     "exfiltration",           # Exfil over C2
    "T1020":     "exfiltration",           # Automated Exfiltration
    "T1567":     "exfiltration",
    "T1567.002": "exfiltration",           # Exfil to Cloud Storage
    "T1486":     "impact",                 # Data Encrypted for Impact
    "T1490":     "impact",                 # Inhibit System Recovery
    "T1219":     "command_and_control",    # Remote Access Tools
    "T1071":     "command_and_control",    # Application Layer Protocol
    "T1071.004": "command_and_control",    # DNS
    "T1572":     "command_and_control",    # Protocol Tunneling  (e.g. reverse SSH `-R`)
    "T1112":     "defense_evasion",        # Modify Registry
    "T1190":     "initial_access",         # Exploit Public-Facing Application
    "T1218.004": "defense_evasion",        # InstallUtil
    "T1218.007": "defense_evasion",        # Msiexec
    "T1127":     "defense_evasion",        # Trusted Developer Utilities
    "T1127.001": "defense_evasion",        # MSBuild
    "T1543.003": "persistence",            # Windows Service
    "T1546":     "persistence",            # Event Triggered Execution
    "T1546.003": "persistence",            # WMI Event Subscription
    "T1546.015": "persistence",            # COM Hijacking
    "T1018":     "discovery",              # Remote System Discovery
    "T1135":     "discovery",              # Network Share Discovery
    "T1489":     "impact",                 # Service Stop
    "T1003.006": "credential_access",      # DCSync
    "T1482":     "discovery",              # Domain Trust Discovery
    "T1087.002": "discovery",              # Domain Account Discovery
    "T1047":     "execution",              # Windows Management Instrumentation
    "T1070.001": "defense_evasion",        # Clear Windows Event Logs
}


# ══════════════════════════════════════════════════════════════════
# Purpose-label → MITRE bridge  (2026-02-08 · P0.14 · trajectory-gap fix)
# ══════════════════════════════════════════════════════════════════
# The per-command DIE analyzer produces `techniques[]` from a mixture
# of PS-AST / cmd-AST / LOLBAS detection.  A few analyst-recognised
# TTPs — reverse SSH tunnel, WMIC-based product uninstall, rclone
# exfil — surface a stable purpose label but no MITRE tag because
# the AST pattern hits the SHELL, not a LOLBAS technique.  Rather
# than duplicate that knowledge in each AST, we bridge it once here
# at the cluster layer using the purpose label the classifier
# already emits.  Every entry is a well-published mapping.
_PURPOSE_TO_MITRE: Dict[str, List[Dict[str, str]]] = {
    "Reverse SSH tunnel": [
        {"id": "T1572", "name": "Protocol Tunneling"},
    ],
    "Software uninstall (defense evasion)": [
        {"id": "T1562.001", "name": "Impair Defenses · Disable or Modify Tools"},
    ],
    "Data staging / exfil (rclone-style)": [
        {"id": "T1567.002", "name": "Exfiltration to Cloud Storage"},
        {"id": "T1020",    "name": "Automated Exfiltration"},
    ],
    "Registry modification": [
        {"id": "T1112", "name": "Modify Registry"},
    ],
    "Registry Run-key persistence": [
        {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"},
    ],
    "Self-deletion of stager": [
        {"id": "T1070.004", "name": "Indicator Removal · File Deletion"},
    ],
    "Archive extraction": [
        {"id": "T1140", "name": "Deobfuscate / Decode Files or Information"},
    ],
    "Unzip Python interpreter stager": [
        {"id": "T1140", "name": "Deobfuscate / Decode Files or Information"},
    ],
    "Unzip encrypted payload archive": [
        {"id": "T1140", "name": "Deobfuscate / Decode Files or Information"},
    ],
    "Microsoft Edge launch (extension load — Edgecution)": [
        {"id": "T1176", "name": "Browser Extensions"},
    ],
    "Microsoft Edge launch (headless, extension load — Edgecution)": [
        {"id": "T1176", "name": "Browser Extensions"},
    ],
    "Lateral movement via PsExec": [
        {"id": "T1021.002", "name": "SMB / Windows Admin Shares"},
    ],
    "Lateral movement via Impacket": [
        {"id": "T1021.002", "name": "SMB / Windows Admin Shares"},
    ],
    "Account / group discovery": [
        {"id": "T1087", "name": "Account Discovery"},
    ],
    "Domain trust discovery": [
        {"id": "T1482", "name": "Domain Trust Discovery"},
    ],
    "Current-user discovery": [
        {"id": "T1033", "name": "System Owner / User Discovery"},
    ],
    "Host discovery": [
        {"id": "T1082", "name": "System Information Discovery"},
        {"id": "T1016", "name": "System Network Configuration Discovery"},
    ],
    "Active Directory discovery": [
        {"id": "T1087.002", "name": "Domain Account Discovery"},
    ],
    "PowerShell in-memory execution": [
        {"id": "T1059.001", "name": "Command and Scripting Interpreter · PowerShell"},
    ],
    "PowerShell download-and-execute": [
        {"id": "T1059.001", "name": "Command and Scripting Interpreter · PowerShell"},
        {"id": "T1105",     "name": "Ingress Tool Transfer"},
    ],
    "PowerShell encoded command": [
        {"id": "T1059.001", "name": "Command and Scripting Interpreter · PowerShell"},
        {"id": "T1027",     "name": "Obfuscated Files or Information"},
    ],
    "MSI installation": [
        {"id": "T1218.007", "name": "System Binary Proxy Execution · Msiexec"},
    ],
    "MSI installer child (embedded)": [
        {"id": "T1218.007", "name": "System Binary Proxy Execution · Msiexec"},
    ],
    "MSI execution": [
        {"id": "T1218.007", "name": "System Binary Proxy Execution · Msiexec"},
    ],
    "Shadow copy deletion": [
        {"id": "T1490", "name": "Inhibit System Recovery"},
    ],
    "Shadow copy deletion (WMIC)": [
        {"id": "T1490", "name": "Inhibit System Recovery"},
    ],
    # ── P0.15A · Canonicalizer-unlocked labels (Octlurk campaign) ──
    "Scheduled Task remote create": [
        {"id": "T1053.005", "name": "Scheduled Task"},
        {"id": "T1021.002", "name": "SMB / Windows Admin Shares"},
    ],
    "Scheduled Task create": [
        {"id": "T1053.005", "name": "Scheduled Task"},
    ],
    "Scheduled Task query": [
        {"id": "T1053.005", "name": "Scheduled Task"},
    ],
    "Scheduled Task": [
        {"id": "T1053.005", "name": "Scheduled Task"},
    ],
    "Windows Service create (persistence)": [
        {"id": "T1543.003", "name": "Windows Service"},
    ],
    "Windows Service failure-action configure": [
        {"id": "T1543.003", "name": "Windows Service"},
    ],
    "Windows Service start": [
        {"id": "T1543.003", "name": "Windows Service"},
    ],
    "Windows Service configure": [
        {"id": "T1543.003", "name": "Windows Service"},
    ],
    "Process discovery (tasklist)": [
        {"id": "T1057", "name": "Process Discovery"},
    ],
    "Process termination": [
        {"id": "T1489", "name": "Service Stop"},
    ],
    "Domain-controllers enumeration": [
        {"id": "T1018", "name": "Remote System Discovery"},
    ],
    "Credential dumping (secretsdump-family)": [
        {"id": "T1003",     "name": "OS Credential Dumping"},
        {"id": "T1003.006", "name": "DCSync"},
    ],
    "Ping (C2 beacon / DNS resolution)": [
        {"id": "T1071.004", "name": "DNS"},
        {"id": "T1018",     "name": "Remote System Discovery"},
    ],
    "Remote-access software execution": [
        {"id": "T1219", "name": "Remote Access Software"},
    ],

    # ── 2026-02-09 · Command classifier expansion (Priority 1) ────
    # Every new label added to `_classify_command_purpose` above
    # must have a deterministic MITRE mapping here or the label
    # will silently vanish from the trajectory / summary panels.

    # LOLBin proxy execution
    "Mshta proxy execution": [
        {"id": "T1218.005", "name": "System Binary Proxy Execution · Mshta"},
    ],
    "Rundll32 proxy execution": [
        {"id": "T1218.011", "name": "System Binary Proxy Execution · Rundll32"},
    ],
    "Regsvr32 proxy execution": [
        {"id": "T1218.010", "name": "System Binary Proxy Execution · Regsvr32"},
    ],
    "Installutil proxy execution": [
        {"id": "T1218.004", "name": "System Binary Proxy Execution · InstallUtil"},
    ],
    "MSBuild proxy execution": [
        {"id": "T1127.001", "name": "Trusted Developer Utilities · MSBuild"},
    ],
    "WScript execution": [
        {"id": "T1059.005", "name": "Command and Scripting Interpreter · Visual Basic"},
    ],
    "CScript execution": [
        {"id": "T1059.005", "name": "Command and Scripting Interpreter · Visual Basic"},
    ],

    # Credential Access
    "LSASS memory dump (procdump)": [
        {"id": "T1003.001", "name": "OS Credential Dumping · LSASS Memory"},
    ],
    "Process memory dump (procdump)": [
        {"id": "T1003", "name": "OS Credential Dumping"},
    ],
    "LSASS memory dump (comsvcs)": [
        {"id": "T1003.001", "name": "OS Credential Dumping · LSASS Memory"},
    ],
    "Credential dumping (mimikatz)": [
        {"id": "T1003.001", "name": "OS Credential Dumping · LSASS Memory"},
    ],
    "NTDS.dit extraction (ntdsutil)": [
        {"id": "T1003.003", "name": "OS Credential Dumping · NTDS"},
    ],
    "SAM/SECURITY hive dump (reg save)": [
        {"id": "T1003.002", "name": "OS Credential Dumping · Security Account Manager"},
    ],

    # Defense Evasion · Defender tampering
    "Windows Defender exclusion add": [
        {"id": "T1562.001", "name": "Impair Defenses · Disable or Modify Tools"},
    ],
    "Windows Defender configure (disable)": [
        {"id": "T1562.001", "name": "Impair Defenses · Disable or Modify Tools"},
    ],
    "Windows Defender service tamper": [
        {"id": "T1562.001", "name": "Impair Defenses · Disable or Modify Tools"},
    ],

    # Defense Evasion · Log clearing
    "Event log clear (wevtutil)": [
        {"id": "T1070.001", "name": "Indicator Removal · Clear Windows Event Logs"},
    ],
    "Event log clear (PowerShell)": [
        {"id": "T1070.001", "name": "Indicator Removal · Clear Windows Event Logs"},
    ],

    # Impact · Recovery inhibit
    "Recovery inhibit (bcdedit)": [
        {"id": "T1490", "name": "Inhibit System Recovery"},
    ],
    "Backup catalog deletion (wbadmin)": [
        {"id": "T1490", "name": "Inhibit System Recovery"},
    ],

    # Execution / Lateral Movement · WMI
    "Remote WMI process create": [
        {"id": "T1047",     "name": "Windows Management Instrumentation"},
        {"id": "T1021.006", "name": "Remote Services · Windows Remote Management"},
    ],
    "WMI process create": [
        {"id": "T1047", "name": "Windows Management Instrumentation"},
    ],
    "WMI process discovery": [
        {"id": "T1057", "name": "Process Discovery"},
    ],
    "Remote WMI invoke-method": [
        {"id": "T1047", "name": "Windows Management Instrumentation"},
    ],
    "WMI invoke-method": [
        {"id": "T1047", "name": "Windows Management Instrumentation"},
    ],

    # Lateral movement · WinRM
    "WinRM / PowerShell remote session": [
        {"id": "T1021.006", "name": "Remote Services · Windows Remote Management"},
    ],
    "WinRS remote command": [
        {"id": "T1021.006", "name": "Remote Services · Windows Remote Management"},
    ],

    # Discovery · commonly missed
    "Net view (remote share/system discovery)": [
        {"id": "T1018", "name": "Remote System Discovery"},
        {"id": "T1135", "name": "Network Share Discovery"},
    ],
    "ARP table discovery": [
        {"id": "T1016", "name": "System Network Configuration Discovery"},
    ],
    "Route table discovery": [
        {"id": "T1016", "name": "System Network Configuration Discovery"},
    ],
    "System information discovery": [
        {"id": "T1082", "name": "System Information Discovery"},
    ],
    "User session discovery (quser)": [
        {"id": "T1033", "name": "System Owner / User Discovery"},
    ],
    "Active Directory query (dsquery)": [
        {"id": "T1087.002", "name": "Account Discovery · Domain Account"},
    ],

    # Persistence · startup / WMI / COM
    "Startup folder persistence": [
        {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"},
    ],
    "WMI event subscription persistence": [
        {"id": "T1546.003", "name": "Event Triggered Execution · WMI Subscription"},
    ],
    "COM hijack (regsvr32)": [
        {"id": "T1546.015", "name": "Event Triggered Execution · Component Object Model Hijacking"},
    ],

    # PowerShell overlays
    "PowerShell hidden window IEX": [
        {"id": "T1059.001", "name": "Command and Scripting Interpreter · PowerShell"},
        {"id": "T1564.003", "name": "Hide Artifacts · Hidden Window"},
    ],
    "PowerShell hidden window": [
        {"id": "T1059.001", "name": "Command and Scripting Interpreter · PowerShell"},
        {"id": "T1564.003", "name": "Hide Artifacts · Hidden Window"},
    ],
    "PowerShell execution-policy bypass": [
        {"id": "T1059.001", "name": "Command and Scripting Interpreter · PowerShell"},
        {"id": "T1562.001", "name": "Impair Defenses · Disable or Modify Tools"},
    ],
    "PowerShell execution": [
        {"id": "T1059.001", "name": "Command and Scripting Interpreter · PowerShell"},
    ],

    # RMM / Remote-access software (T1219 · Command & Control)
    "AnyDesk RMM execution": [
        {"id": "T1219", "name": "Remote Access Software"},
    ],
    "TeamViewer RMM execution": [
        {"id": "T1219", "name": "Remote Access Software"},
    ],
    "ScreenConnect RMM execution": [
        {"id": "T1219", "name": "Remote Access Software"},
    ],
    "Atera RMM execution": [
        {"id": "T1219", "name": "Remote Access Software"},
    ],
    "Splashtop RMM execution": [
        {"id": "T1219", "name": "Remote Access Software"},
    ],
    "LogMeIn RMM execution": [
        {"id": "T1219", "name": "Remote Access Software"},
    ],
    "Syncro RMM execution": [
        {"id": "T1219", "name": "Remote Access Software"},
    ],
    "NinjaRMM execution": [
        {"id": "T1219", "name": "Remote Access Software"},
    ],
    "Kaseya RMM execution": [
        {"id": "T1219", "name": "Remote Access Software"},
    ],

    # ── 2026-02-09 · Gap fill exposed by MITRE Consistency CI ────
    # Pre-existing classifier labels that had no _PURPOSE_TO_MITRE
    # entry.  Filling them makes the projection layer honest —
    # every label the classifier can emit now bridges to MITRE.
    "AutoHotkey stager": [
        {"id": "T1059.006", "name": "Command and Scripting Interpreter · Python/AutoHotkey"},
    ],
    "BITSAdmin download": [
        {"id": "T1105", "name": "Ingress Tool Transfer"},
        {"id": "T1197", "name": "BITS Jobs"},
    ],
    "Certutil download / decode": [
        {"id": "T1105", "name": "Ingress Tool Transfer"},
        {"id": "T1140", "name": "Deobfuscate/Decode Files or Information"},
    ],
    "Download from remote resource": [
        {"id": "T1105", "name": "Ingress Tool Transfer"},
    ],
    "Host / domain reconnaissance": [
        {"id": "T1016", "name": "System Network Configuration Discovery"},
    ],
    "Microsoft Edge launch": [
        {"id": "T1204.002", "name": "User Execution · Malicious File"},
    ],
    "PowerShell execution via CMD (execution-policy bypass)": [
        {"id": "T1059.001", "name": "Command and Scripting Interpreter · PowerShell"},
        {"id": "T1562.001", "name": "Impair Defenses · Disable or Modify Tools"},
    ],
    "PowerShell process enumeration": [
        {"id": "T1057", "name": "Process Discovery"},
        {"id": "T1059.001", "name": "Command and Scripting Interpreter · PowerShell"},
    ],
    "Python interpreter discovery": [
        {"id": "T1518", "name": "Software Discovery"},
    ],
    "SSH client execution": [
        {"id": "T1021.004", "name": "Remote Services · SSH"},
    ],
    "SSH remote session": [
        {"id": "T1021.004", "name": "Remote Services · SSH"},
    ],
    "Scheduled-task persistence": [
        {"id": "T1053.005", "name": "Scheduled Task"},
    ],
    # NOTE: "Command execution" is the DELIBERATE catch-all fallback
    # (services/ida/report_extractors.py:998) — it has no MITRE
    # mapping by design because the technique is unknown.  It's
    # excluded from the consistency check via a tolerant B2M rule.
}


def _mitre_from_purpose(purpose: str) -> List[Dict[str, str]]:
    """Bridge — return the deterministic MITRE mapping for a
    recognised purpose label, or [] if unknown.  Never invents."""
    if not purpose:
        return []
    entries = _PURPOSE_TO_MITRE.get(purpose)
    if not entries:
        return []
    out: List[Dict[str, str]] = []
    for e in entries:
        out.append({
            "id":     e["id"],
            "name":   e["name"],
            "tactic": tactic_for(e["id"]) or "",
        })
    return out


# ══════════════════════════════════════════════════════════════════
# Public · lazy re-enrichment for stored SSOTs (2026-02-08 · P0.14)
# ══════════════════════════════════════════════════════════════════
def enrich_clusters_in_place(clusters: List[Dict[str, Any]]) -> int:
    """Apply the purpose-bridge + canonical ``mitre_tactics[]`` to a
    list of behaviour clusters in place.  Idempotent — safe to run
    on any cluster shape (freshly built or loaded from Mongo).
    Returns the number of clusters that received a new mapping so
    callers can log the enrichment ratio.

    Used by the read-side of ``/api/cases/{id}`` so cases persisted
    before the bridge existed benefit automatically without any
    write-side migration.
    """
    if not isinstance(clusters, list):
        return 0
    changed = 0
    for c in clusters:
        if not isinstance(c, dict):
            continue
        mitre = c.get("mitre")
        if not isinstance(mitre, list):
            mitre = []
            c["mitre"] = mitre
        # Bridge · fill empty mitre[] from purpose label.
        if not mitre:
            bridged = _mitre_from_purpose(c.get("label") or c.get("title") or "")
            if bridged:
                c["mitre"] = bridged
                changed += 1
                mitre = bridged
        # Canonical plural · always derived — never overwritten if
        # the caller already provided a plural (respects R21 · single
        # source of truth) unless it is falsy.
        if not c.get("mitre_tactics"):
            c["mitre_tactics"] = sorted({
                _TACTIC_LABEL.get(m.get("tactic"), m.get("tactic"))
                for m in mitre
                if isinstance(m, dict) and m.get("tactic")
            })
        # Primary tactic · deterministic fallback for consumers that
        # still key off the singular.
        if not c.get("primary_tactic"):
            counts: Dict[str, int] = {}
            for m in mitre:
                t = isinstance(m, dict) and m.get("tactic")
                if t:
                    counts[t] = counts.get(t, 0) + 1
            if counts:
                c["primary_tactic"] = max(counts, key=counts.get)
    return changed

# Kill-chain ordering — the analyst-facing sequence.
_TACTIC_ORDER: List[str] = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
]

_TACTIC_LABEL: Dict[str, str] = {
    "initial_access":       "Initial Access",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion":      "Defense Evasion",
    "credential_access":    "Credential Access",
    "discovery":            "Discovery",
    "lateral_movement":     "Lateral Movement",
    "collection":           "Collection",
    "command_and_control":  "Command and Control",
    "exfiltration":         "Exfiltration",
    "impact":               "Impact",
}


def tactic_for(technique_id: str) -> Optional[str]:
    """Return the ATT&CK tactic id for a technique.  Handles the
    parent-technique fallback (e.g., T1059.999 → T1059) so future
    unknown sub-techniques still get placed."""
    if not technique_id:
        return None
    tid = technique_id.upper()
    if tid in _TECHNIQUE_TO_TACTIC:
        return _TECHNIQUE_TO_TACTIC[tid]
    parent = tid.split(".", 1)[0]
    return _TECHNIQUE_TO_TACTIC.get(parent)


# ══════════════════════════════════════════════════════════════════
# 2. Correlator
# ══════════════════════════════════════════════════════════════════
def correlate(ssot: Dict[str, Any]) -> Dict[str, Any]:
    """Run the deterministic correlation pass over a canonical
    investigation object.  Returns the ICE block that lives at
    `SSOT.ice`.

    Rule R21 · v3 (2026-03-01):  Every projection SHOULD read the
    top-level `incident{}` object (also returned here so the caller
    can promote it onto SSOT).  `SSOT.ice.*` remains as the raw
    correlator surface for engines that need per-piece access —
    IVE / NIST IR / STIX / exports all consume `incident{}`.
    """
    ext = (ssot or {}).get("report_extraction") or {}
    commands       = ext.get("commands") or []
    investigations = ext.get("command_investigations") or []

    behavior_clusters = _build_behavior_clusters(commands, investigations)
    # ── Add Evidence Strength per cluster (separate from confidence). ──
    _attach_evidence_strength(behavior_clusters, ssot)
    attack_phases     = _build_attack_phases(behavior_clusters)
    mitre_matrix      = _build_mitre_matrix(ssot, investigations)
    timeline          = _build_timeline(commands, ext.get("timeline") or [])
    incident_graph    = _build_incident_graph(ssot, behavior_clusters)
    completeness      = _build_completeness(ssot, ext, investigations)
    readiness         = _build_investigation_readiness(ssot, ext, investigations, completeness)
    gaps              = _build_investigation_gaps(ssot, ext, investigations)
    recommendations   = _build_recommended_actions(behavior_clusters, gaps, readiness)
    incident_summary  = _build_incident(ssot, behavior_clusters, attack_phases,
                                          mitre_matrix, readiness)

    # ── Universal provenance envelope ──
    prof = (ssot or {}).get("document_profile") or {}
    acq  = (ssot or {}).get("acquired_document") or {}
    provenance = {
        "source_url":       acq.get("url") or acq.get("final_url") or "",
        "source_vendor":    prof.get("vendor") or acq.get("sitename") or "",
        "source_title":     prof.get("title") or acq.get("title") or "",
        "fetched_at_ms":    acq.get("duration_ms"),
        "acquired_bytes":   acq.get("fetched_bytes"),
    }

    # ── Unified Incident SSOT (Rule R21 · v3) ──
    # Every downstream projection reads THIS.  The `ice` block below
    # remains for engines that need raw per-piece access, but new
    # consumers must consume `incident{}` exclusively.
    incident = {
        "summary":          incident_summary,
        "behaviors":        behavior_clusters,
        "phases":           attack_phases,
        "mitre":            mitre_matrix,
        "timeline":         timeline,
        "graph":            incident_graph,
        "evidence":         {
            "commands":       commands,
            "investigations": investigations,
            "actors":         ext.get("threat_actors") or [],
            "malware":        ext.get("malware_families") or [],
        },
        "completeness":     completeness,
        "readiness":        readiness,
        "gaps":             gaps,
        "recommendations":  recommendations,
        "provenance":       provenance,
    }

    return {
        # ── Unified incident (recommended surface for every consumer) ──
        "incident":              incident,
        # ── Legacy per-piece surface (kept for backwards-compat with
        # projections that were built against the flat ICE shape).
        "behavior_clusters":     behavior_clusters,
        "attack_phases":         attack_phases,
        "mitre_matrix":          mitre_matrix,
        "timeline":              timeline,
        "incident_graph":        incident_graph,
        "evidence_completeness": completeness,
        "investigation_readiness": readiness,
        "investigation_gaps":    gaps,
        "recommended_actions":   recommendations,
        "provenance":            provenance,
        "totals": {
            "clusters":     len(behavior_clusters),
            "phases":       len(attack_phases),
            "mitre":        len(mitre_matrix),
            "timeline":     len(timeline),
            "graph_nodes":  len(incident_graph.get("nodes", [])),
            "graph_edges":  len(incident_graph.get("edges", [])),
            "gaps":         len(gaps),
            "recommended":  len(recommendations),
        },
    }


def _attach_evidence_strength(clusters: List[Dict[str, Any]],
                                ssot: Dict[str, Any]) -> None:
    """Every cluster gets an `evidence_strength ∈ {strong, moderate,
    weak}` label based on independent corroborating sources.

    Sources counted (max 5):
      1. Vendor-published mention (article names the behavior)
      2. Command evidence (≥1 supporting command)
      3. MITRE mapping (≥1 technique)
      4. LOLBAS mapping (≥1 lolbin)
      5. Timeline or telemetry evidence (article-published timeline OR
         command source_ref present)

    Strong = 4-5 sources · Moderate = 2-3 · Weak = 0-1
    """
    article = ((ssot or {}).get("acquired_document") or {}).get("article_text") or ""
    lower_article = article.lower()
    ext = (ssot or {}).get("report_extraction") or {}
    has_timeline = bool(ext.get("totals", {}).get("timeline", 0))
    for c in clusters:
        sources = []
        # 1. Vendor mention — is the cluster label named in the article?
        label = (c.get("label") or "").lower()
        head_words = [w for w in label.split() if len(w) > 4][:2]
        vendor_hit = bool(head_words) and all(w in lower_article for w in head_words)
        if vendor_hit:               sources.append("vendor")
        if c.get("command_count"):   sources.append("commands")
        if c.get("mitre"):           sources.append("mitre")
        if c.get("lolbins"):         sources.append("lolbas")
        if has_timeline or c.get("sources"): sources.append("telemetry")
        n = len(sources)
        strength = "strong" if n >= 4 else "moderate" if n >= 2 else "weak"
        c["evidence_strength"]  = strength
        c["evidence_sources"]   = sources


# ══════════════════════════════════════════════════════════════════
# 3. Individual correlators
# ══════════════════════════════════════════════════════════════════
def _build_behavior_clusters(commands: List[Dict[str, Any]],
                              investigations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group commands by their per-command purpose label (assigned by
    IDA-4's classifier).  Each cluster carries:
        · label            — the purpose name
        · commands[]        — the raw command list
        · mitre[]           — technique ids (deduped)
        · lolbins[]         — lolbin names (deduped)
        · languages[]       — languages seen in the cluster
        · primary_tactic    — the tactic most techniques resolve to
        · confidence        — high / medium / low
    Ordering is insertion order (which is reading order of the source
    document — deterministic and analyst-friendly).
    """
    groups: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for i, cmd in enumerate(commands):
        key = cmd.get("purpose") or "Uncategorised"
        if key not in groups:
            order.append(key)
            groups[key] = {
                "label":           key,
                "commands":        [],
                "mitre":           [],
                "lolbins":         [],
                "languages":       set(),
                "sources":         [],
            }
        g = groups[key]
        g["commands"].append(cmd)
        ci = investigations[i] if i < len(investigations) else {}
        for t in (ci.get("techniques") or []):
            tid = (t.get("id") or "").upper()
            if tid and tid not in [m["id"] for m in g["mitre"]]:
                g["mitre"].append({
                    "id":     tid,
                    "name":   t.get("name") or "",
                    "tactic": tactic_for(tid),
                })
        for lb in (ci.get("lolbins") or []):
            name = (lb.get("binary") or "").lower()
            if name and name not in g["lolbins"]:
                g["lolbins"].append(name)
        if ci.get("language"):
            g["languages"].add(ci["language"])
        if cmd.get("source"):
            g["sources"].append(cmd["source"])

    out: List[Dict[str, Any]] = []
    for k in order:
        g = groups[k]
        # ── Purpose-bridge (2026-02-08 · P0.14) ─────────────────
        # If per-command DIE didn't tag any MITRE for the cluster
        # but the classifier assigned a recognised purpose label,
        # inject the deterministic mapping so downstream projections
        # (Trajectory diagram, NIST report, Attack Chain) don't drop
        # the node.  Never invents — only uses `_PURPOSE_TO_MITRE`.
        if not g["mitre"]:
            bridged = _mitre_from_purpose(g["label"])
            for bm in bridged:
                if bm["id"] not in [m["id"] for m in g["mitre"]]:
                    g["mitre"].append(bm)
        # Primary tactic = most common tactic across the cluster's mitre.
        tactic_counts: Dict[str, int] = {}
        for m in g["mitre"]:
            if m["tactic"]:
                tactic_counts[m["tactic"]] = tactic_counts.get(m["tactic"], 0) + 1
        primary_tactic = max(tactic_counts, key=tactic_counts.get) if tactic_counts else None
        # Canonical plural — union of tactic labels the projections
        # read (see TrajectoryDiagram Rule R22).  Uses the human
        # tactic label (e.g. "Command and Control") because that is
        # what the frontend swim-lane keys on.
        mitre_tactics = sorted({
            _TACTIC_LABEL.get(m["tactic"], m["tactic"])
            for m in g["mitre"]
            if m.get("tactic")
        })
        conf = "high" if g["mitre"] else ("medium" if g["lolbins"] else "low")
        out.append({
            "label":          g["label"],
            "commands":       g["commands"],
            "command_count":  len(g["commands"]),
            "mitre":          g["mitre"],
            "mitre_tactics":  mitre_tactics,
            "lolbins":        g["lolbins"],
            "languages":      sorted(g["languages"]),
            "primary_tactic": primary_tactic,
            "confidence":     conf,
            "sources":        g["sources"],
        })
    return out


def _build_attack_phases(clusters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group behavior clusters into MITRE kill-chain phases and
    return them in canonical kill-chain order.  Each phase carries
    the clusters + a union of MITRE ids.
    """
    by_tactic: Dict[str, Dict[str, Any]] = {}
    for c in clusters:
        tactic = c.get("primary_tactic")
        if not tactic:
            continue
        if tactic not in by_tactic:
            by_tactic[tactic] = {
                "tactic":         tactic,
                "label":          _TACTIC_LABEL.get(tactic, tactic),
                "clusters":       [],
                "mitre":          [],
                "command_count":  0,
            }
        entry = by_tactic[tactic]
        entry["clusters"].append(c["label"])
        entry["command_count"] += c["command_count"]
        for m in c["mitre"]:
            if m["id"] not in entry["mitre"]:
                entry["mitre"].append(m["id"])

    out: List[Dict[str, Any]] = []
    for tactic in _TACTIC_ORDER:
        if tactic in by_tactic:
            out.append(by_tactic[tactic])
    return out


def _build_mitre_matrix(ssot: Dict[str, Any],
                         investigations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Dedupe MITRE hits across vendor-published + command-derived,
    tagging every entry with `source ∈ {vendor, command}` and its
    parent tactic.
    """
    seen: Dict[str, Dict[str, Any]] = {}
    # Vendor-published (from top-level SSOT.mitre — filled by IDA-4
    # over article text).
    for t in (ssot.get("mitre") or []):
        tid = (t.get("id") or "").upper()
        if not tid:
            continue
        src = t.get("source") or "vendor"
        # Normalise: `ida.command_investigation` → `command`
        if src == "ida.command_investigation":
            src = "command"
        elif src == "ida.report.mitre":
            src = "vendor"
        seen[tid] = {
            "id":     tid,
            "name":   t.get("name") or "",
            "tactic": tactic_for(tid),
            "source": src,
        }
    # Command-derived (from recursive investigations)
    for ci in investigations:
        for t in (ci.get("techniques") or []):
            tid = (t.get("id") or "").upper()
            if not tid:
                continue
            if tid not in seen:
                seen[tid] = {
                    "id":     tid,
                    "name":   t.get("name") or "",
                    "tactic": tactic_for(tid),
                    "source": "command",
                }
    return sorted(seen.values(), key=lambda m: (
        _TACTIC_ORDER.index(m["tactic"]) if m.get("tactic") in _TACTIC_ORDER else 999,
        m["id"],
    ))


def _build_timeline(commands: List[Dict[str, Any]],
                     article_timeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Combine article-published timeline events with a per-command
    "execution order" pseudo-timeline (line-number based).  Article
    events come first (they carry real dates), then command order.
    """
    out: List[Dict[str, Any]] = []
    for e in article_timeline or []:
        out.append({
            "kind":  "article",
            "date":  e.get("date"),
            "event": e.get("event"),
            "source": e.get("source"),
        })
    for i, c in enumerate(commands or [], start=1):
        out.append({
            "kind":    "execution",
            "step":    i,
            "event":   c.get("purpose") or "Command execution",
            "command": c.get("command"),
            "source":  c.get("source"),
        })
    return out


def _build_incident_graph(ssot: Dict[str, Any],
                           clusters: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic incident graph.  Nodes:
        · incident (root)
        · actor(s)
        · malware(s)
        · behavior cluster(s)
    Edges connect the incident to actors, actors to behaviors, and
    behaviors to malware (when the article mentions them).  Kept
    small and deterministic — the Knowledge Graph projection
    (IDA-6) will grow this later.
    """
    ext = (ssot or {}).get("report_extraction") or {}
    actors  = ext.get("threat_actors") or []
    malware = ext.get("malware_families") or []
    prof    = ssot.get("document_profile") or {}
    vendor  = prof.get("vendor") or ""
    title   = prof.get("title") or ""

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    incident_id = "incident:root"
    nodes.append({"id": incident_id, "kind": "incident",
                   "label": title or "Incident", "vendor": vendor})

    for a in actors:
        aid = f"actor:{a['name']}"
        nodes.append({"id": aid, "kind": "actor", "label": a["name"]})
        edges.append({"from": incident_id, "to": aid, "kind": "attributed_to"})
    for m in malware:
        mid = f"malware:{m['name']}"
        nodes.append({"id": mid, "kind": "malware", "label": m["name"]})
        edges.append({"from": incident_id, "to": mid, "kind": "involves"})
    for c in clusters:
        cid = f"behavior:{c['label']}"
        nodes.append({
            "id":              cid,
            "kind":            "behavior",
            "label":           c["label"],
            "primary_tactic":  c.get("primary_tactic"),
            "command_count":   c["command_count"],
            "mitre":           [m["id"] for m in c["mitre"]],
        })
        edges.append({"from": incident_id, "to": cid, "kind": "observed"})

    return {"nodes": nodes, "edges": edges}


def _build_completeness(ssot: Dict[str, Any],
                         ext: Dict[str, Any],
                         investigations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic evidence-completeness surface.  Same shape as
    the SSOT-carried block described in IR_REPORT_CONTRACT.md:
        state ∈ {complete, relative, missing, not_available}
    """
    totals = ext.get("totals") or {}
    commands = ext.get("commands") or []
    okc = sum(1 for ci in investigations if ci.get("language") and not ci.get("error"))
    errc = sum(1 for ci in investigations if ci.get("error"))

    # Body-artifact counts by type — the report_extraction dict has a
    # single `body_artifacts` list, not per-type buckets, so we tally
    # here for the completeness dimensions.
    body = ext.get("body_artifacts") or []
    n_url  = sum(1 for a in body if a.get("type") == "url")
    n_hash = sum(1 for a in body if a.get("type") == "hash")
    n_ip   = sum(1 for a in body if a.get("type") == "ip")
    n_dom  = sum(1 for a in body if a.get("type") == "domain")
    n_reg  = sum(1 for a in body if a.get("type") == "registry_key")

    def _state(count: int, applicable: bool = True) -> str:
        if not applicable:
            return "not_available"
        if count > 0:
            return "complete"
        return "missing"

    # MITRE — count from ALL sources: article-body regex hits, DIE
    # per-command investigations, and SSOT.mitre (preprocessor +
    # command investigations).  `report_extraction.totals.mitre`
    # alone under-counts because most techniques on this pipeline
    # are inferred recursively, not written as `T1234` in prose.
    ssot_mitre = ssot.get("mitre") or []
    n_mitre = len({(t.get("id") or "").upper()
                    for t in ssot_mitre if t.get("id")}) or totals.get("mitre", 0)

    lolbas_count = len({(lb.get("binary") or "").lower()
                          for ci in investigations
                          for lb in (ci.get("lolbins") or [])})
    n_actors  = totals.get("actors", 0)
    n_malware = totals.get("malware", 0)
    n_yara    = totals.get("yara", 0)
    n_sigma   = totals.get("sigma", 0)
    n_time    = totals.get("timeline", 0)

    dims: List[Dict[str, Any]] = [
        {"dim": "Commands",  "state": _state(len(commands)),
         "found": len(commands), "investigated": okc, "errors": errc},
        {"dim": "MITRE",     "state": _state(n_mitre),
         "found": n_mitre},
        {"dim": "LOLBAS",    "state": _state(lolbas_count),
         "found": lolbas_count},
        {"dim": "IOCs (URLs+Hashes+IPs+Domains)",
         "state": _state(n_url + n_hash + n_ip + n_dom),
         "found": n_url + n_hash + n_ip + n_dom,
         "breakdown": {"urls": n_url, "hashes": n_hash, "ips": n_ip, "domains": n_dom}},
        {"dim": "Registry",  "state": _state(n_reg), "found": n_reg},
        {"dim": "Timeline",  "state": "complete" if n_time > 0 else "relative",
         "found": n_time},
        {"dim": "YARA",      "state": _state(n_yara), "found": n_yara},
        {"dim": "Sigma",     "state": _state(n_sigma), "found": n_sigma},
        {"dim": "Threat Actor", "state": _state(n_actors), "found": n_actors},
        {"dim": "Malware",   "state": _state(n_malware), "found": n_malware},
    ]
    applicable = [d for d in dims if d["state"] != "not_available"]
    complete   = sum(1 for d in applicable if d["state"] == "complete")
    relative   = sum(1 for d in applicable if d["state"] == "relative")
    pct = int(round((complete + 0.5 * relative) / max(1, len(applicable)) * 100))
    return {
        "dimensions": dims,
        "overall_percent": pct,
        "complete_count":  complete,
        "relative_count":  relative,
        "applicable":      len(applicable),
    }


# ══════════════════════════════════════════════════════════════════
# 4. Incident model + investigation readiness (Rule R21 · v2)
# ══════════════════════════════════════════════════════════════════
def _build_incident(ssot: Dict[str, Any],
                     clusters: List[Dict[str, Any]],
                     phases:   List[Dict[str, Any]],
                     mitre:    List[Dict[str, Any]],
                     readiness: Dict[str, Any]) -> Dict[str, Any]:
    """Root incident object.  Every downstream projection (NIST IR
    Report, Executive Dashboard, exports) reads THIS.

    Deterministic scoring:
      · severity   ← highest MITRE tactic weight in the kill chain
                     (impact / exfiltration = critical,
                      command_and_control / lateral_movement = high,
                      persistence / defense_evasion = medium, else low).
      · confidence ← ratio of high-confidence clusters × readiness %.
      · objective  ← longest-command-cluster label (analyst-friendly).
    """
    ext = (ssot or {}).get("report_extraction") or {}
    prof = ssot.get("document_profile") or {}
    actors  = ext.get("threat_actors") or []
    malware = ext.get("malware_families") or []

    # Severity by highest tactic weight observed.
    weight = {
        "impact": 5, "exfiltration": 5, "credential_access": 4,
        "command_and_control": 4, "lateral_movement": 4,
        "privilege_escalation": 3, "persistence": 3,
        "defense_evasion": 3, "collection": 2,
        "discovery": 2, "execution": 2, "initial_access": 2,
    }
    top_w = 0
    for p in phases:
        top_w = max(top_w, weight.get(p["tactic"], 1))
    severity = ("critical" if top_w >= 5 else "high" if top_w >= 4
                else "medium" if top_w >= 3 else "low")

    # Confidence: mean cluster confidence × readiness fraction.
    conf_score = {"high": 1.0, "medium": 0.6, "low": 0.3}
    if clusters:
        c_mean = sum(conf_score.get(c["confidence"], 0.3) for c in clusters) / len(clusters)
    else:
        c_mean = 0.0
    ready_pct = readiness.get("overall_percent", 0) / 100.0
    confidence_pct = int(round(c_mean * (0.5 + 0.5 * ready_pct) * 100))

    # Objective — best analyst-facing summary label.
    biggest = max(clusters, key=lambda c: c["command_count"], default=None)
    objective = biggest["label"] if biggest else "Investigation in progress"

    return {
        "id":                 "incident:root",
        "title":              prof.get("title") or "Threat Investigation",
        "vendor":             prof.get("vendor") or "",
        "actor":              actors[0]["name"] if actors else None,
        "malware":            [m["name"] for m in malware],
        "objective":          objective,
        "severity":           severity,
        "confidence_percent": confidence_pct,
        "status":             "under_investigation",
        "tactics_observed":   [p["tactic"] for p in phases],
        "cluster_count":      len(clusters),
        "mitre_count":        len(mitre),
    }


def _build_investigation_readiness(ssot: Dict[str, Any],
                                    ext: Dict[str, Any],
                                    investigations: List[Dict[str, Any]],
                                    completeness: Dict[str, Any]) -> Dict[str, Any]:
    """Progress-bar view: how ready is this investigation for
    reporting?  Deterministic percentages per dimension so the
    frontend renders bars, not vague states."""
    total_cmds = len(ext.get("commands") or [])
    ok_cmds    = sum(1 for ci in investigations
                       if ci.get("language") and not ci.get("error"))
    ioc_kinds  = sum(1 for k in ("urls", "hashes", "ips", "domains")
                       if (ext.get(k) or []) or ext.get("totals", {}).get("artifacts", 0) > 0)
    ioc_pct    = min(100, ioc_kinds * 25)

    bars = [
        {"dim": "Commands",   "percent": int(round((ok_cmds / max(1, total_cmds)) * 100))
                                        if total_cmds else 0,
         "state": "complete" if total_cmds and ok_cmds == total_cmds else "partial"
                                        if ok_cmds else "missing"},
        {"dim": "IOCs",       "percent": ioc_pct,
         "state": "complete" if ioc_pct >= 80 else "partial" if ioc_pct else "missing"},
        {"dim": "Behaviors",  "percent": 100 if total_cmds else 0,
         "state": "complete" if total_cmds else "missing"},
        {"dim": "Timeline",   "percent": 60 if (ext.get("totals", {}).get("timeline", 0)) else 20,
         "state": "partial" if not ext.get("totals", {}).get("timeline", 0) else "complete"},
        {"dim": "Network",    "percent": 20,
         "state": "partial",
         "hint":  "Enrich URL / IP artifacts via IOC lane (Talos, XForce, VT)"},
        {"dim": "Memory",     "percent": 0,
         "state": "missing",
         "hint":  "Collect a memory image from the affected host"},
        {"dim": "EDR",        "percent": 0,
         "state": "missing",
         "hint":  "Pull EDR telemetry for the affected host and time window"},
        {"dim": "Report",     "percent": 100 if total_cmds else 0,
         "state": "complete" if total_cmds else "missing"},
    ]
    applicable = [b for b in bars if b["state"] != "not_available"]
    overall = int(round(sum(b["percent"] for b in applicable) / max(1, len(applicable))))

    # Recommended next step = the highest-value missing dimension.
    weights = {"Memory": 4, "EDR": 4, "Network": 3, "Timeline": 2,
               "IOCs":   2, "Commands": 1, "Behaviors": 1, "Report": 1}
    missing = [b for b in bars if b["state"] in ("missing", "partial")]
    missing.sort(key=lambda b: weights.get(b["dim"], 0), reverse=True)
    next_step = None
    if missing:
        b = missing[0]
        next_step = b.get("hint") or f"Improve `{b['dim']}` coverage"
    return {
        "bars":              bars,
        "overall_percent":   overall,
        "recommended_next":  next_step,
        "confidence_label":  "high" if overall >= 75 else "medium" if overall >= 40 else "low",
    }


def _build_investigation_gaps(ssot: Dict[str, Any],
                               ext: Dict[str, Any],
                               investigations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deterministic gap list — the specific evidence the analyst
    should collect next.  Ordered by investigative value."""
    gaps: List[Dict[str, Any]] = []
    if not (ext.get("totals", {}).get("timeline", 0)):
        gaps.append({"dim": "Timeline",
                      "reason": "No article-published timeline; execution order is relative only.",
                      "action": "Correlate command execution with EDR / process telemetry."})
    if not (ext.get("totals", {}).get("cves", 0)):
        gaps.append({"dim": "CVEs",
                      "reason": "No CVEs referenced in the acquired document.",
                      "action": "Cross-reference commands + malware against NVD / vendor advisories."})
    if not (ext.get("totals", {}).get("yara", 0)):
        gaps.append({"dim": "YARA",
                      "reason": "No YARA rules published with this report.",
                      "action": "Author internal YARA from extracted malware family + IOC set."})
    gaps.append({"dim": "Memory",
                  "reason": "No memory acquisition performed.",
                  "action": "Collect memory image from affected host(s)."})
    gaps.append({"dim": "EDR Telemetry",
                  "reason": "No EDR telemetry ingested for this incident.",
                  "action": "Pull EDR process / network / file events for the affected host + window."})
    return gaps


def _build_recommended_actions(clusters: List[Dict[str, Any]],
                                gaps: List[Dict[str, Any]],
                                readiness: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Analyst-facing next steps.  Deterministic — every action is
    tied to a specific gap or behavior cluster so the analyst can
    trace WHY it was recommended."""
    actions: List[Dict[str, Any]] = []
    # Top gap → immediate action.
    if readiness.get("recommended_next"):
        actions.append({"priority": "P1",
                         "title":   readiness["recommended_next"],
                         "reason":  "Highest-value evidence dimension currently missing."})
    # Behavior-cluster-specific actions.
    labels = {c["label"].lower() for c in clusters}
    if any("extension" in l for l in labels):
        actions.append({"priority": "P2",
                         "title":   "Block malicious browser extensions in Group Policy",
                         "reason":  "Behavior cluster indicates browser-extension persistence (T1176)."})
    if any("self-deletion" in l for l in labels):
        actions.append({"priority": "P2",
                         "title":   "Enable command-line auditing (Event ID 4688 with cmdline)",
                         "reason":  "Self-deletion cluster suggests attempts to erase execution history."})
    if any("execution-policy bypass" in l for l in labels):
        actions.append({"priority": "P2",
                         "title":   "Enforce Constrained-Language mode for PowerShell",
                         "reason":  "Execution-policy bypass observed in PowerShell command chain."})
    for g in gaps[:2]:
        actions.append({"priority": "P3",
                         "title":   g["action"],
                         "reason":  f"Investigation gap: {g['dim']}."})
    return actions

