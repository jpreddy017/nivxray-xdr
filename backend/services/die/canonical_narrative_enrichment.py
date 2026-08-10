"""Phase 5.W · Canonical narrative enrichment (2026-08-10).

When a URL / DOCX / vendor-narrative investigation produces MITRE
techniques but the deterministic legacy analyst_narrative generator
(stage-based, command-line oriented) produces empty
executive_summary / analyst_summary / recommended_actions / etc.,
this module fills those fields deterministically from the observed
MITRE techniques + tactics + IOCs + LOLBAS.

Design contract:
- Pure function (no I/O, no clock, no network, no random).
- Additive: only fills EMPTY fields; never overwrites populated
  content produced by the legacy generator.
- Same input → same output.
"""
from __future__ import annotations
from typing import Any, Dict, List, Set


# ── Per-technique detail catalog ─────────────────────────────────
# Each entry: description + concrete containment recommendation +
# Sigma-hunt one-liner + YARA-string idea.
_TECHNIQUE_CATALOG: Dict[str, Dict[str, str]] = {
    "T1027": {
        "name": "Obfuscated Files or Information",
        "action": "Alert on high-entropy PowerShell script blocks (>4.5 bits/char) and Base64 strings longer than 1 KB inside `-EncodedCommand` payloads.",
        "sigma": "Sigma: process powershell.exe command_line contains `-enc` OR `-encodedcommand` with base64 length > 1000",
        "yara":  'YARA: regex /-(e|enc|encodedcommand)\\s+[A-Za-z0-9+/]{200,}={0,2}/i',
    },
    "T1059.001": {
        "name": "PowerShell",
        "action": "Enable PowerShell Script Block Logging (EventID 4104) and Module Logging on all workstations; forward to SIEM and hunt for `IEX`, `Invoke-Expression`, `FromBase64String`, and `DownloadString` invocations.",
        "sigma": "Sigma: EventID 4104 script_block_text contains any of (`IEX`, `Invoke-Expression`, `DownloadString`, `FromBase64String`, `[Convert]::FromBase64String`)",
        "yara":  'YARA: strings "IEX", "Invoke-Expression", "DownloadString", "FromBase64String"',
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "action": "Baseline legitimate `cmd.exe` invocations from LOB apps; alert on cmd.exe child processes spawned by Office / browser / Outlook.",
        "sigma": "Sigma: parent_image ends_with (`winword.exe`, `excel.exe`, `outlook.exe`, `acrord32.exe`, `chrome.exe`) AND child_image ends_with `cmd.exe`",
        "yara":  'YARA: string "cmd.exe /c" combined with office suite parent process',
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "action": "Block untrusted domains at proxy/DNS; hunt for `certutil -urlcache`, `bitsadmin /transfer`, `curl.exe`, `Invoke-WebRequest`, and `wget.exe` invocations from user workstations.",
        "sigma": "Sigma: process any_of (`certutil.exe -urlcache`, `bitsadmin.exe /transfer`, `curl.exe`, `wget.exe`) OR powershell.exe with `Invoke-WebRequest`/`iwr`/`Net.WebClient`",
        "yara":  'YARA: strings "certutil.exe -urlcache", "bitsadmin /transfer", "Invoke-WebRequest", "DownloadFile"',
    },
    "T1218.010": {
        "name": "Regsvr32",
        "action": "Alert on `regsvr32.exe` invocations with `/i:` HTTP URLs (Squiblydoo) or `/u /s /n` scriptlet inclusion; block SCT downloads at the proxy.",
        "sigma": "Sigma: process regsvr32.exe command_line contains any_of (`/i:http`, `/i:\\\\\\\\`, `scrobj.dll`)",
        "yara":  'YARA: regex /regsvr32.*\\/i:https?:\\/\\//i',
    },
    "T1218.011": {
        "name": "Rundll32",
        "action": "Baseline signed-DLL entrypoints commonly invoked via rundll32; alert on rundll32.exe loading DLLs from `%TEMP%`, `%APPDATA%`, or a UNC path.",
        "sigma": "Sigma: process rundll32.exe with DLL argument in (%TEMP%, %APPDATA%, \\\\\\\\*)",
        "yara":  'YARA: regex /rundll32.exe\\s+(%TEMP%|%APPDATA%|\\\\\\\\[^\\s,]+),/i',
    },
    "T1564.003": {
        "name": "Hide Artifacts: Hidden Window",
        "action": "Detect PowerShell / cmd invocations with `-WindowStyle Hidden`, `-w hidden`, or `/min` — these are strong indicators of interactive malware execution.",
        "sigma": "Sigma: process powershell.exe command_line contains any_of (`-w hidden`, `-windowstyle hidden`, `-noni -w hidden`)",
        "yara":  'YARA: strings "-WindowStyle Hidden", "-w hidden", "/min"',
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "action": "Alert on `Set-MpPreference -DisableRealtimeMonitoring`, `sc stop WinDefend`, `reg add ... EnableLUA=0`, and any modification of `HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender`.",
        "sigma": "Sigma: powershell Set-MpPreference OR reg.exe modifying `\\Windows Defender\\DisableAntiSpyware`",
        "yara":  'YARA: strings "DisableRealtimeMonitoring", "DisableAntiSpyware", "sc stop WinDefend"',
    },
    "T1053.005": {
        "name": "Scheduled Task/Job",
        "action": "Baseline scheduled-task creation events; alert on `schtasks /create` from a non-service account or with `/ru SYSTEM` invoked by an interactive session.",
        "sigma": "Sigma: schtasks.exe command_line contains `/create` AND user not in service-account list",
        "yara":  'YARA: string "schtasks /create" combined with "/ru SYSTEM"',
    },
    "T1219": {
        "name": "Remote Access Software",
        "action": "Baseline RMM tools approved for IT; block execution of unmanaged copies (AnyDesk, TeamViewer, ScreenConnect, Splashtop, Quick Assist) from user workstations.",
        "sigma": "Sigma: process any_of (anydesk.exe, teamviewer.exe, screenconnect.*, splashtop.exe, quickassist.exe) NOT from managed_path",
        "yara":  'YARA: strings "AnyDesk", "ScreenConnect", "TeamViewer", "SimpleHelp", "QuickAssist"',
    },
    "T1071":     {"name": "Application Layer Protocol",
                  "action": "Baseline outbound HTTP/HTTPS/DNS from workstations; hunt for beacon-like periodic requests to newly-registered domains.",
                  "sigma": "Sigma: network_connection with beaconing interval and destination in newly_registered_domains",
                  "yara":  'YARA: strings that look like C2 URI patterns (e.g. `/api/v1/`, `/gate.php`)'},
    "T1204.002": {"name": "User Execution: Malicious File",
                  "action": "Deliver mandatory phishing awareness to affected users; hunt for Office → cmd/powershell child-process chains in the last 7 days.",
                  "sigma": "Sigma: parent_image any_of (winword.exe, excel.exe, powerpnt.exe, outlook.exe) AND child_image any_of (cmd.exe, powershell.exe, wscript.exe, mshta.exe)",
                  "yara":  'YARA: OLE stream indicators combined with obfuscated VBA'},
    "T1486":     {"name": "Data Encrypted for Impact",
                  "action": "Isolate affected hosts immediately; block file writes with encrypted-file extensions at the file-server level; validate offline backups.",
                  "sigma": "Sigma: mass file rename events + file extension change to non-standard suffixes",
                  "yara":  'YARA: ransomware note strings + AES-key blob patterns'},
    "T1003":     {"name": "OS Credential Dumping",
                  "action": "Block Mimikatz-family binaries via AV signature; audit LSASS handle access with SACL; enable Credential Guard on all Windows 10/11 endpoints.",
                  "sigma": "Sigma: process access to lsass.exe with GrantedAccess containing 0x1010",
                  "yara":  'YARA: strings "sekurlsa::", "lsadump::", "!Kappa Kappa Kappa"'},
}


# ── Tactic → risk / objective / recommendation mapping ───────────
_TACTIC_META: Dict[str, Dict[str, Any]] = {
    "initial_access":       {"risk": "High",     "objective": "Establish a foothold in the environment",
                             "action": "Investigate the delivery vector (phishing email, watering-hole, exposed service); harden that surface."},
    "execution":            {"risk": "Medium",   "objective": "Execute attacker code on the endpoint",
                             "action": "Enable AMSI on all endpoints; enforce Constrained Language Mode for non-admin PowerShell; disable Office macros from the internet zone."},
    "persistence":          {"risk": "High",     "objective": "Maintain access across reboots",
                             "action": "Audit all persistence primitives created in the last 24 h (Run keys, scheduled tasks, services, WMI subscriptions); remove any not authored by service accounts."},
    "privilege_escalation": {"risk": "High",     "objective": "Elevate to administrator or SYSTEM",
                             "action": "Patch known LPE CVEs; enable LSA Protection and Credential Guard; audit local admin group membership."},
    "defense_evasion":      {"risk": "High",     "objective": "Evade EDR / AV detection",
                             "action": "Alert on any tampering with Defender, Sysmon, or EDR services; deploy tamper-protection where available."},
    "credential_access":    {"risk": "Critical", "objective": "Steal credentials for lateral movement",
                             "action": "Rotate any credentials that may have been exposed; enable Credential Guard; monitor LSASS handle access."},
    "discovery":            {"risk": "Medium",   "objective": "Understand the environment before moving laterally",
                             "action": "Correlate reconnaissance commands with the parent process to identify the attacker session; hunt for identical patterns on other hosts."},
    "lateral_movement":     {"risk": "Critical", "objective": "Spread to additional hosts",
                             "action": "Isolate affected hosts; audit SMB / RDP / WinRM sessions in the last 24 h; hunt for PsExec / WMIC-remote / Impacket-style activity."},
    "collection":           {"risk": "High",     "objective": "Collect files for exfiltration",
                             "action": "Alert on rclone / 7z / rar staging in `%TEMP%`, `%APPDATA%`; look for large-file archives written before external network activity."},
    "command_and_control":  {"risk": "High",     "objective": "Maintain a channel to attacker infrastructure",
                             "action": "Block observed C2 IOCs at the proxy / firewall / DNS; hunt for other hosts beaconing to the same infrastructure."},
    "exfiltration":         {"risk": "Critical", "objective": "Move data out of the environment",
                             "action": "Block egress to observed exfil destinations; validate DLP alerts for the past 7 days; determine data-loss scope."},
    "impact":               {"risk": "Critical", "objective": "Destructive or extortion action (ransomware, wiper, defacement)",
                             "action": "Isolate the host now; validate offline backups; convene the IR + legal + comms bridge; do NOT pay before consulting counsel."},
}


_TACTIC_ORDER = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
]


def _tactic_title(t: str) -> str:
    return (t or "").replace("_", " ").title()


def _risk_rank(r: str) -> int:
    return {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}.get(r, 0)


def enrich_narrative(narrative: Dict[str, Any],
                     mitre_techniques: List[Dict[str, Any]],
                     iocs: Dict[str, Any] | None = None,
                     lolbas: List[Dict[str, Any]] | None = None,
                     source_url: str | None = None) -> Dict[str, Any]:
    """Fill EMPTY narrative fields deterministically from observed
    MITRE techniques + IOCs + LOLBAS. Never overwrites populated
    content.
    """
    if not isinstance(narrative, dict):
        narrative = {}
    if not mitre_techniques:
        return narrative

    # ── Build tactic index ────────────────────────────────────────
    tactics_seen: Set[str] = set()
    tech_by_tactic: Dict[str, List[Dict[str, Any]]] = {}
    for t in mitre_techniques:
        if not isinstance(t, dict):
            continue
        tid = t.get("id")
        tac = t.get("tactic")
        if not tid or not tac or tac == "unknown":
            continue
        tactics_seen.add(tac)
        tech_by_tactic.setdefault(tac, []).append(t)

    if not tactics_seen:
        return narrative

    tactics_sorted = [t for t in _TACTIC_ORDER if t in tactics_seen]
    total_tech = len({t.get("id") for t in mitre_techniques if isinstance(t, dict) and t.get("id")})

    # ── Executive Summary (only if empty) ─────────────────────────
    if not (narrative.get("executive_summary") or "").strip():
        tac_phrases = [
            f"**{_tactic_title(tac)}** ({len(tech_by_tactic[tac])} tech.)"
            for tac in tactics_sorted
        ]
        src_hint = ""
        if source_url:
            src_hint = f" derived from `{source_url}`"
        narrative["executive_summary"] = (
            f"Investigation surface{src_hint} exposes {total_tech} MITRE ATT&CK "
            f"technique(s) mapped across {len(tactics_sorted)} tactic(s): "
            + ", ".join(tac_phrases) + ". "
            f"The observed progression indicates active adversary tradecraft, "
            f"prioritise containment against the highest-risk tactic first."
        )

    # ── Analyst Summary (only if empty) ───────────────────────────
    if not (narrative.get("analyst_summary") or "").strip():
        lines: List[str] = []
        for tac in tactics_sorted:
            ids = [t.get("id") for t in tech_by_tactic[tac]]
            names = [(_TECHNIQUE_CATALOG.get(i, {}).get("name")
                      or next((tt.get("name") for tt in tech_by_tactic[tac]
                               if tt.get("id") == i and tt.get("name")), i))
                     for i in ids]
            lines.append(
                f"During **{_tactic_title(tac)}** the analyst observed "
                + ", ".join(f"`{i}` ({n})" for i, n in zip(ids, names)) + "."
            )
        narrative["analyst_summary"] = " ".join(lines)

    # ── Recommended Actions (only if empty list / missing) ────────
    existing_actions = narrative.get("recommended_actions") or []
    if not existing_actions:
        actions: List[str] = []
        # Per-tactic bucket action (deduped).
        seen_action_text: Set[str] = set()
        for tac in tactics_sorted:
            meta = _TACTIC_META.get(tac) or {}
            atxt = meta.get("action")
            if atxt and atxt not in seen_action_text:
                actions.append(f"[{_tactic_title(tac)}] {atxt}")
                seen_action_text.add(atxt)
        # Per-technique concrete action.
        for tac in tactics_sorted:
            for t in tech_by_tactic[tac]:
                tid = t.get("id")
                entry = _TECHNIQUE_CATALOG.get(tid)
                if entry and entry.get("action") and entry["action"] not in seen_action_text:
                    actions.append(f"[{tid}] {entry['action']}")
                    seen_action_text.add(entry["action"])
        # IOC-driven action.
        if isinstance(iocs, dict):
            url_list = iocs.get("url") or []
            ip_list  = iocs.get("ip") or []
            if url_list:
                actions.append(f"[IOC] Block or sink-hole the {len(url_list)} observed URL indicator(s) at proxy/DNS.")
            if ip_list:
                actions.append(f"[IOC] Block the {len(ip_list)} observed IP indicator(s) at the perimeter firewall and hunt for other hosts communicating with them.")
        narrative["recommended_actions"] = actions

    # ── Behavior Summary table (only if empty / missing) ──────────
    if not narrative.get("behavior_summary"):
        rows: List[Dict[str, str]] = []
        for tac in tactics_sorted:
            meta = _TACTIC_META.get(tac) or {}
            techs = tech_by_tactic[tac]
            tech_ids = ", ".join(t.get("id") for t in techs if t.get("id"))
            rows.append({
                "phase":      _tactic_title(tac),
                "kill_chain": meta.get("kill_chain") or _tactic_title(tac),
                "activity":   f"{len(techs)} technique(s) observed ({tech_ids}). "
                              f"Attacker objective: {meta.get('objective', '—')}.",
            })
        narrative["behavior_summary"] = rows

    # ── Overall Assessment (only if empty / missing) ──────────────
    if not narrative.get("overall_assessment"):
        risks = [_TACTIC_META.get(t, {}).get("risk", "Low") for t in tactics_sorted]
        top_risk = max(risks, key=_risk_rank) if risks else "Low"
        # Determine primary objective from the highest-risk tactic present.
        primary_tac = max(tactics_sorted, key=lambda t: _risk_rank(_TACTIC_META.get(t, {}).get("risk", "Low")))
        primary_objective = _TACTIC_META.get(primary_tac, {}).get("objective", "Unclear")
        # Progress % = fraction of the 12 canonical tactics touched, weighted by risk.
        progress = min(100, int(len(tactics_sorted) / len(_TACTIC_ORDER) * 100
                                + _risk_rank(top_risk) * 10))
        # Confidence: High if ≥5 techniques across ≥3 tactics.
        if total_tech >= 5 and len(tactics_sorted) >= 3:
            conf = "High"
        elif total_tech >= 3 or len(tactics_sorted) >= 2:
            conf = "Medium"
        else:
            conf = "Low"
        narrative["overall_assessment"] = {
            "risk":                 top_risk,
            "primary_objective":    primary_objective,
            "attack_progress_pct":  progress,
            "confidence":           conf,
        }

    # ── Likely Objective (only if empty / missing) ────────────────
    if not narrative.get("likely_objective"):
        objs: List[str] = []
        for tac in tactics_sorted:
            o = _TACTIC_META.get(tac, {}).get("objective")
            if o and o not in objs:
                objs.append(o)
        narrative["likely_objective"] = objs

    # ── Sigma / YARA hunts (only if empty) ────────────────────────
    if not (narrative.get("sigma_hunts") or []):
        sigmas: List[str] = []
        for tac in tactics_sorted:
            for t in tech_by_tactic[tac]:
                s = (_TECHNIQUE_CATALOG.get(t.get("id")) or {}).get("sigma")
                if s and s not in sigmas:
                    sigmas.append(s)
        narrative["sigma_hunts"] = sigmas

    if not (narrative.get("yara_ideas") or []):
        yaras: List[str] = []
        for tac in tactics_sorted:
            for t in tech_by_tactic[tac]:
                y = (_TECHNIQUE_CATALOG.get(t.get("id")) or {}).get("yara")
                if y and y not in yaras:
                    yaras.append(y)
        narrative["yara_ideas"] = yaras

    return narrative


def synth_chain_steps_from_progression(progression: List[Dict[str, Any]]
                                       ) -> List[Dict[str, Any]]:
    """Build a legacy-shape chain.steps[] from
    narrative.attack_progression so the linear AttackChainView and
    ReportTab render on URL / DOCX / narrative inputs where the
    legacy `analyze_chain()` produced nothing.
    """
    if not progression:
        return []
    steps: List[Dict[str, Any]] = []
    for i, stage in enumerate(progression):
        if not isinstance(stage, dict):
            continue
        mitre_items = stage.get("mitre") or []
        # Coerce list-of-str or list-of-dict → list-of-str technique ids.
        tech_ids: List[str] = []
        for m in mitre_items:
            if isinstance(m, dict) and m.get("id"):
                tech_ids.append(m["id"])
            elif isinstance(m, str):
                tech_ids.append(m)
        steps.append({
            "index":         i,
            "node_id":       f"progression-{i}",
            "depth":         0,
            "kind":          "tactic",
            "source":        "root" if i == 0 else "progression",
            "artifact_type": stage.get("tactic") or stage.get("stage") or "tactic",
            "verdict":       "malicious",
            "label":         stage.get("title") or stage.get("tactic"),
            "case_name":     stage.get("title") or _tactic_title(stage.get("tactic", "")),
            "techniques":    tech_ids,
            "snippet":       stage.get("narrative", ""),
            "evidence":      "canonical narrative MITRE progression",
        })
    return steps


__all__ = ["enrich_narrative", "synth_chain_steps_from_progression",
           "_TECHNIQUE_CATALOG", "_TACTIC_META", "_TACTIC_ORDER"]
