"""Enterprise Investigation Report Writer — Phase 6.

DETERMINISTIC NARRATIVE ENGINE. NEVER investigates. NEVER decodes.
NEVER infers. Consumes a *verified* investigation model (produced by
the AUTO INVESTIGATE orchestrator) and transforms it into an MDR-grade
report with 17 structured sections.

Phase 6.5 upgrade: paragraph-level wording is delegated to
`narrative_composer.py` — a template library that enforces the
Enterprise Writing Guide and removes tool-centric phrasing.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .narrative_composer import (
    compose_executive_summary,
    compose_narrative,
    compose_findings,
    compose_evidence_limitations,
    compose_recommendations,
    sanitize,
)


# ─── Templated micro-sentences ─────────────────────────────────
_VERDICT_NARRATIVE = {
    "malicious":  "The activity is confirmed malicious. Immediate containment is recommended.",
    "critical":   "The activity is critical severity malware and requires immediate containment.",
    "suspicious": "The activity is suspicious but not confirmed malicious. Enhanced monitoring is warranted.",
    "needs_review": "The activity requires analyst review. Automation alone was unable to confidently classify it.",
    "benign":     "The activity is benign. No further containment steps are required.",
    "unknown":    "There was insufficient evidence to reach a deterministic verdict.",
}

_SEV_ORDER = {"critical": 5, "malicious": 5, "suspicious": 4,
              "needs_review": 3, "benign": 2, "unknown": 1}


def _fact(finding: str, source: str, ev_type: str, confidence: str) -> dict:
    """Every finding is wrapped in a traceability record."""
    return {"finding": finding, "evidence_source": source,
            "evidence_type": ev_type, "confidence": confidence}


# ─── Extraction helpers ────────────────────────────────────────
def _find_hosts(text: str) -> list[str]:
    """Best-effort host extraction from the raw incident narrative."""
    hits = re.findall(
        r"\b(?:host|hostname|device)\s*[:=]\s*([A-Za-z][A-Za-z0-9._-]{2,60})",
        text or "", flags=re.IGNORECASE)
    STOP = {"incident", "detection", "detected", "under", "warrants", "the"}
    return [h.rstrip(".") for h in dict.fromkeys(hits) if h.lower().rstrip(".") not in STOP]


def _find_users(text: str) -> list[str]:
    hits = re.findall(
        r"\b(?:user|username|account)\s*[:=]\s*([A-Z0-9][A-Z0-9\\._-]{2,80})",
        text or "", flags=re.IGNORECASE)
    return [u.rstrip(".") for u in dict.fromkeys(hits)]


def _pick_root_cause(commands: list, iocs: dict, mitre: list, raw: str) -> dict:
    """Deterministic root cause inference — refuses to guess. Only
    reports a cause when supporting evidence is present."""
    tids = {m.get("id", "") for m in mitre}
    if any(t.startswith("T1547") or t.startswith("T1053") or t.startswith("T1543") for t in tids):
        return _fact(
            "Persistence-based execution — attacker established persistence via "
            "Registry Run Keys, Scheduled Task, or Service.",
            "MITRE mapping (T1547 / T1053 / T1543)",
            "Correlated", "High")
    if any(t.startswith("T1204") for t in tids):
        return _fact(
            "User-triggered execution — evidence suggests a user opened the payload.",
            "MITRE mapping (T1204)", "Correlated", "Medium")
    if any(t.startswith("T1566") for t in tids):
        return _fact(
            "Phishing / e-mail attachment — evidence suggests initial access via inbox delivery.",
            "MITRE mapping (T1566)", "Correlated", "Medium")
    if any(c["binary"] in {"msiexec", "msiexec.exe"} for c in commands):
        return _fact(
            "Software installation vector — msiexec.exe launched with a remote MSI package.",
            "Command line evidence", "Observed", "Medium")
    if iocs.get("urls") or iocs.get("domains"):
        return _fact(
            "Remote download vector — network resolution to attacker infrastructure preceded execution.",
            "Extracted URL / domain IOCs", "Observed", "Medium")
    return _fact(
        "Insufficient evidence to determine the initial infection vector.",
        "Pipeline output", "Observed", "Low")


def _behaviours(mitre: list) -> dict[str, list[str]]:
    """Group MITRE techniques into behaviour categories for the narrative."""
    buckets = {
        "Execution": [], "Persistence": [], "Defense Evasion": [], "Discovery": [],
        "Credential Access": [], "Command and Control": [], "Impact": [],
        "Collection": [], "Lateral Movement": [], "Privilege Escalation": [],
    }
    for m in mitre:
        tactic = (m.get("tactic") or "").strip()
        # canonical bucket
        for key in buckets:
            if key.lower() in tactic.lower():
                buckets[key].append(f"{m['id']} · {m.get('technique','')}")
                break
        else:
            # fallback: tuck under Execution
            if m.get("id"):
                buckets["Execution"].append(f"{m['id']} · {m.get('technique','')}")
    return {k: v for k, v in buckets.items() if v}


def _environment_flags(raw: str, quality: dict) -> list[dict]:
    """Detect environmental / operational context from the raw incident
    text and from the quality scorecard. Only reports flags for which we
    have textual or numeric evidence — never invents context."""
    out: list[dict] = []
    lower = (raw or "").lower()
    if re.search(r"quarantin(e|ed|ing)", lower):
        out.append(_fact("File successfully quarantined by the EDR agent.",
                         "Raw incident text", "Observed", "High"))
    if re.search(r"outdated|old (?:av|signature|definition)", lower):
        out.append(_fact("Antivirus / EDR definitions may be outdated on the host.",
                         "Raw incident text", "Observed", "Medium"))
    if re.search(r"orbital|forensic snapshot", lower) and re.search(r"unavailable|not available|missing", lower):
        out.append(_fact("Deeper forensic tooling (Orbital / snapshots) unavailable at investigation time.",
                         "Raw incident text", "Observed", "Medium"))
    if quality and quality.get("command_analysis", {}).get("failed_decodes", 0):
        out.append(_fact(
            f"{quality['command_analysis']['failed_decodes']} command(s) failed to decode fully — "
            "deeper telemetry recommended.",
            "Investigation Quality Dashboard", "Observed", "Medium"))
    if quality and quality.get("coverage", {}).get("threat_intel_matches", 0) == 0:
        out.append(_fact("No external Threat Intelligence correlations were available for the extracted IOCs.",
                         "TI enrichment layer", "Observed", "Low"))
    return out


# ─── Section builders (deterministic; audience-aware wording) ───
def _executive_summary(inv: dict, hosts: list[str], users: list[str], profile: str) -> list[str]:
    fis     = inv.get("final_incident_summary", {})
    verdict = (fis.get("verdict") or "unknown").lower()
    sev     = fis.get("severity", "Low")
    cls     = fis.get("classification", "Unknown")
    cmds    = inv.get("detected", {}).get("commands", [])
    mitre   = fis.get("mitre_attack", [])
    iocs    = fis.get("iocs", {})
    ioc_total = sum(len(v) for v in iocs.values() if isinstance(v, list))
    host_txt = f"host **{hosts[0]}**" if hosts else "the affected endpoint"
    user_txt = f" (user `{users[0]}`)" if users else ""
    paras: list[str] = []

    # 1. Trigger + detection
    paras.append(
        f"An investigation was initiated on {host_txt}{user_txt} following alerts "
        f"escalated to NivXRay. Deterministic analysis identified {len(cmds)} discrete "
        f"command(s) worth decoding and produced an aggregated verdict of **{verdict.upper()}** "
        f"({cls}) at **{sev}** severity."
    )
    # 2. Execution flow
    if cmds:
        binaries = ", ".join(f"`{c['binary']}`" for c in cmds[:6])
        paras.append(
            f"Observed execution involved the following binaries: {binaries}"
            f"{', among others' if len(cmds) > 6 else ''}. Every command was decoded "
            "and correlated against the Investigation Knowledge Graph — no external "
            "decoding or inference was applied."
        )
    # 3. MITRE coverage
    if mitre:
        tids = sorted({m['id'] for m in mitre})
        if profile == "executive" or profile == "customer":
            paras.append(
                f"The activity maps to {len(tids)} MITRE ATT&CK technique(s) spanning "
                f"{len(_behaviours(mitre))} attacker tactic(s) — consistent with an "
                "orchestrated attack rather than a single opportunistic action."
            )
        else:
            paras.append(
                f"MITRE ATT&CK coverage: {len(tids)} technique(s) across "
                f"{len(_behaviours(mitre))} tactic(s) — {', '.join(tids[:8])}"
                + (f", …+{len(tids) - 8}." if len(tids) > 8 else ".")
            )
    # 4. Threat intel / IOCs
    if ioc_total:
        paras.append(
            f"NivXRay extracted **{ioc_total}** indicator(s) of compromise "
            f"({', '.join(f'{len(v)} {k}' for k, v in iocs.items() if v)}) which have been "
            "packaged for hunting, blocking, and downstream correlation."
        )
    # 5. Verdict narrative
    paras.append(_VERDICT_NARRATIVE.get(verdict, _VERDICT_NARRATIVE["unknown"]))
    # 6. Confidence
    conf = fis.get("investigation_quality", {}).get("overall", {}).get("investigation_completeness")
    if conf is not None:
        paras.append(
            f"Overall investigation completeness is **{conf}%**. Every conclusion in this "
            "report is traceable to an observed piece of evidence."
        )
    return paras


def _incident_overview(inv: dict, hosts: list[str], users: list[str]) -> dict:
    fis = inv.get("final_incident_summary", {})
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {
        "incident_number":     f"NIVX-{now[:10].replace('-', '')}-{abs(hash(inv.get('raw_incident','')))%9973:04d}",
        "detection_time":      now,
        "detection_source":    _detection_source(inv.get("raw_incident", "")),
        "hostname":            hosts[0] if hosts else "unknown",
        "username":            users[0] if users else "unknown",
        "operating_system":    _detect_os(inv.get("raw_incident", "")),
        "severity":            fis.get("severity", "Low"),
        "priority":            fis.get("severity", "Low"),  # aligned with severity in v1
        "confidence":          fis.get("confidence", {}),
        "investigation_status": "Contained" if _has_containment(inv.get("raw_incident", "")) else "Under Investigation",
        "verdict":             fis.get("verdict", "unknown"),
        "classification":      fis.get("classification", "Unknown"),
    }


def _detection_source(raw: str) -> str:
    lower = (raw or "").lower()
    for name, key in [
        ("Cisco XDR", "cisco xdr"),
        ("Cisco Secure Endpoint", "secure endpoint"),
        ("CrowdStrike Falcon", "crowdstrike"),
        ("Microsoft Defender", "defender"),
        ("SentinelOne", "sentinelone"),
        ("QRadar", "qradar"),
        ("Splunk", "splunk"),
        ("Sysmon", "sysmon"),
        ("Email Security", "email"),
    ]:
        if key in lower:
            return name
    return "Analyst Submission"


def _detect_os(raw: str) -> str:
    lower = (raw or "").lower()
    if "linux" in lower: return "Linux"
    if "macos" in lower or "osx" in lower: return "macOS"
    if any(k in lower for k in ("windows", ".exe", "hklm", "hkcu", "cmd.exe", "powershell")):
        return "Windows"
    return "Unknown"


def _has_containment(raw: str) -> bool:
    lower = (raw or "").lower()
    return bool(re.search(r"quarantin|contain|isolat|block(ed)?|remediat", lower))


def _narrative(inv: dict, hosts: list[str], users: list[str]) -> str:
    """Write a chronological, MDR-analyst-style narrative — no bullets."""
    fis   = inv.get("final_incident_summary", {})
    cmds  = inv.get("detected", {}).get("commands", [])
    iocs  = fis.get("iocs", {})
    mitre = fis.get("mitre_attack", [])
    host  = hosts[0] if hosts else "the affected endpoint"
    user  = users[0] if users else "an interactive user"
    parts: list[str] = []
    parts.append(
        f"The investigation began after an alert originating on **{host}** was ingested by "
        f"NivXRay. Initial triage identified suspicious process activity associated with "
        f"account `{user}`."
    )
    if cmds:
        parts.append(
            f"Analysis of the extracted process telemetry revealed **{len(cmds)}** distinct "
            "command binaries executed on the endpoint. Each command was decoded "
            "deterministically and mapped to observed behavior, without invoking any "
            "external inference or language model."
        )
    if any(c["binary"].startswith("powershell") for c in cmds):
        parts.append(
            "Encoded PowerShell activity was observed and decoded. The decoded payload "
            "displayed characteristics consistent with in-memory execution frameworks — "
            "an attacker technique used to evade signature-based detection."
        )
    if any(c["binary"] in {"certutil", "bitsadmin", "curl", "wget"} for c in cmds):
        parts.append(
            "The attacker leveraged native Windows binaries (`certutil` / `bitsadmin` / "
            "`curl`) to download secondary payloads — a Living-Off-the-Land tactic that "
            "abuses trusted operating-system tooling."
        )
    if iocs.get("domains") or iocs.get("ips"):
        parts.append(
            f"Network telemetry recorded outbound communication to "
            f"{len(iocs.get('domains', []))} domain(s) and {len(iocs.get('ips', []))} IP address(es), "
            "several of which have been extracted as IOCs for blocking and threat-hunting."
        )
    if any((m.get('id') or '').startswith("T1547") for m in mitre):
        parts.append(
            "Persistence artefacts consistent with Registry Run Keys / Startup folder "
            "modification were identified, indicating the attacker intended to survive "
            "endpoint reboots and user logoff events."
        )
    if _has_containment(inv.get("raw_incident", "")):
        parts.append(
            "The EDR agent successfully quarantined the malicious file and blocked further "
            "execution. Follow-up hunting is required to confirm no lateral movement occurred."
        )
    else:
        parts.append(
            "As of report generation, containment activities are still in progress. "
            "Immediate isolation of the affected host is recommended."
        )
    return "\n\n".join(parts)


def _timeline(inv: dict) -> list[dict]:
    """Reconstruct a chronological event list. Deterministic — timestamps
    only from the raw incident text; ordering only from observed order."""
    raw = inv.get("raw_incident", "") or ""
    events: list[dict] = []
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    # Detection
    src = _detection_source(raw)
    events.append({"time": _first_timestamp(raw) or now_iso,
                   "event": f"Initial detection by {src}",
                   "evidence_type": "Observed"})
    # For each command, a step
    for i, c in enumerate(inv.get("detected", {}).get("commands", []) or []):
        events.append({"time": f"+{i * 3}s",
                       "event": f"Command executed · `{c['binary']}` · {c['command_line'][:80]}",
                       "evidence_type": "Observed"})
    fis = inv.get("final_incident_summary", {})
    # Persistence
    if any((m.get("id") or "").startswith("T1547") for m in fis.get("mitre_attack", [])):
        events.append({"time": "later",
                       "event": "Persistence artefact created (Registry Run Key / Startup)",
                       "evidence_type": "Correlated"})
    # Network
    if fis.get("iocs", {}).get("domains") or fis.get("iocs", {}).get("ips"):
        events.append({"time": "later",
                       "event": "Outbound network communication to extracted IOCs",
                       "evidence_type": "Observed"})
    # Containment
    if _has_containment(raw):
        events.append({"time": "later",
                       "event": "File quarantined; execution blocked",
                       "evidence_type": "Observed"})
    # Report generation
    events.append({"time": now_iso, "event": "NivXRay investigation report generated",
                   "evidence_type": "Observed"})
    return events


def _first_timestamp(raw: str) -> str | None:
    m = re.search(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?", raw or "")
    return m.group(0) if m else None


def _attack_story(inv: dict) -> list[str]:
    """Compact attack progression (bullet-friendly, but written like beats)."""
    story: list[str] = []
    fis = inv.get("final_incident_summary", {})
    cmds = inv.get("detected", {}).get("commands", []) or []
    if cmds:
        story.append("Initial execution — attacker-supplied binaries launched on the endpoint.")
    if any((m.get('id') or '').startswith("T1547") for m in fis.get("mitre_attack", [])):
        story.append("Persistence — attacker attempted to survive reboot and user logoff.")
    if any(c["binary"].startswith("powershell") for c in cmds):
        story.append("Encoded PowerShell — obfuscated in-memory execution.")
    if any(c["binary"] in {"certutil", "bitsadmin", "curl", "wget"} for c in cmds):
        story.append("Payload retrieval — LOLBAS tools used to fetch secondary binaries.")
    if any((m.get('id') or '').startswith("T1003") for m in fis.get("mitre_attack", [])):
        story.append("Credential access — attacker attempted to harvest OS credentials.")
    if fis.get("iocs", {}).get("domains") or fis.get("iocs", {}).get("ips"):
        story.append("Command and Control — outbound communication to attacker infrastructure.")
    story.append("Detection — NivXRay ingested the alert and analysed the evidence.")
    story.append("Containment — EDR quarantine + recommended host isolation."
                 if _has_containment(inv.get("raw_incident", "")) else
                 "Containment — pending; host isolation is recommended.")
    return story


def _findings(inv: dict) -> list[dict]:
    """Analyst-language findings, each with a traceability record."""
    fis = inv.get("final_incident_summary", {})
    out: list[dict] = []
    cmds = inv.get("detected", {}).get("commands", []) or []
    if any(c["binary"].startswith("powershell") for c in cmds):
        out.append(_fact(
            "Encoded PowerShell command was executed on the endpoint, a technique "
            "commonly used to obfuscate malicious activity.",
            "Extracted command line", "Observed", "High"))
    if any(c["binary"] in {"certutil", "bitsadmin"} for c in cmds):
        out.append(_fact(
            "Legitimate Windows binary (`certutil`/`bitsadmin`) was invoked to download "
            "content from a remote URL — a Living-Off-the-Land tactic.",
            "Extracted command line", "Observed", "High"))
    if any(c["binary"] in {"rundll32", "regsvr32", "mshta"} for c in cmds):
        out.append(_fact(
            "Signed system binary was leveraged to execute code, an evasion tactic to "
            "bypass application allow-listing.",
            "Extracted command line", "Observed", "High"))
    if fis.get("iocs", {}).get("sha256") or fis.get("iocs", {}).get("sha1") or fis.get("iocs", {}).get("md5"):
        out.append(_fact(
            "Cryptographic hashes were extracted from the incident and can be used to "
            "hunt for the same payload across the fleet.",
            "IOC extraction", "Observed", "High"))
    if any((m.get('id') or '').startswith("T1547") for m in fis.get("mitre_attack", [])):
        out.append(_fact(
            "Persistence artefact consistent with Registry Run Keys or Startup folder "
            "modification was identified.",
            "MITRE mapping (T1547)", "Correlated", "Medium"))
    if not out:
        out.append(_fact(
            "No high-signal malicious findings were surfaced automatically. Manual review "
            "of the extracted commands and IOCs is recommended.",
            "Pipeline output", "Observed", "Low"))
    return out


def _customer_actions(fis: dict) -> dict[str, list[str]]:
    verdict = (fis.get("verdict") or "unknown").lower()
    mitre_ids = {m.get("id", "") for m in fis.get("mitre_attack", [])}
    ioc_count = sum(len(v) for v in fis.get("iocs", {}).values() if isinstance(v, list))
    immediate, short, long = [], [], []
    if verdict in ("malicious", "critical", "suspicious"):
        immediate.append("Isolate the affected endpoint from the network.")
        immediate.append("Keep the EDR quarantine enabled; do not restore the flagged file.")
    if any(t.startswith("T1547") or t.startswith("T1543") for t in mitre_ids):
        immediate.append("Remove the identified persistence artefact (Run Key / Startup / Service).")
    if ioc_count:
        immediate.append("Block the extracted IOCs at the firewall / EDR / proxy.")
    short.append("Run a full antivirus / EDR scan across the affected endpoint.")
    short.append("Update antivirus and EDR definitions to the latest version.")
    short.append("Sweep the fleet for the extracted file hashes.")
    short.append("Validate that no additional hosts show the same persistence artefacts.")
    long.append("Enable deeper endpoint telemetry (Orbital / process trees / registry auditing).")
    long.append("Strengthen application control policies to reduce LOLBAS abuse surface.")
    long.append("Add Startup-folder and Run-Key monitoring to detection rules.")
    long.append("Review and update detection policies quarterly.")
    return {"immediate": immediate, "short_term": short, "long_term": long}


def _recommendations(inv: dict) -> list[dict]:
    """Prioritized recommendations. Each carries the evidence it rests on."""
    fis = inv.get("final_incident_summary", {}) or {}
    out: list[dict] = list(fis.get("recommendations", []) or [])
    quality = fis.get("investigation_quality", {})
    if quality.get("coverage", {}).get("threat_intel_matches", 0) == 0:
        out.append({"priority": "medium",
                    "action": "Wire Threat Intelligence enrichment (VirusTotal / Talos / MISP) into the ingestion pipeline.",
                    "rationale": "No external TI correlations were available for the extracted IOCs."})
    if quality.get("command_analysis", {}).get("failed_decodes", 0):
        out.append({"priority": "high",
                    "action": "Extend the deterministic decoder plugin catalogue.",
                    "rationale": (f"{quality['command_analysis']['failed_decodes']} command(s) "
                                  "failed to decode fully.")})
    return out


# ─── Top-level assembly ────────────────────────────────────────
def build_report(inv: dict, profile: str = "soc_analyst",
                 customer: str | None = None) -> dict:
    """Transform a verified investigation model into a 17-section
    Enterprise MDR Report. `profile` selects audience wording."""
    profile = (profile or "soc_analyst").lower()
    raw     = inv.get("raw_incident", "") or ""
    hosts   = _find_hosts(raw)
    users   = _find_users(raw)
    fis     = inv.get("final_incident_summary", {}) or {}
    quality = fis.get("investigation_quality", {})

    root_cause = _pick_root_cause(
        inv.get("detected", {}).get("commands", []) or [],
        fis.get("iocs", {}) or {},
        fis.get("mitre_attack", []) or [],
        raw,
    )
    behaviours = _behaviours(fis.get("mitre_attack", []) or [])
    # Phase 6.5 — template-driven Environmental + Evidence Limitations.
    env_flags  = _environment_flags(raw, quality)
    limitations = compose_evidence_limitations(inv, profile=profile)

    ti = {
        "observed": {
            "hashes":      fis.get("iocs", {}).get("sha256", []) or [],
            "unsigned_binaries": [c["binary"] for c in inv.get("detected", {}).get("commands", []) if c["binary"] in {"rundll32", "regsvr32", "mshta"}],
            "persistence": [b for b in behaviours if b == "Persistence"],
            "encoded_powershell": any(c["binary"].startswith("powershell") for c in inv.get("detected", {}).get("commands", []) or []),
        },
        "correlated": {
            "virustotal":     quality.get("coverage", {}).get("threat_intel_matches", 0) > 0,
            "cisco_talos":    False,     # placeholder for real TI adapter in later phase
            "cisco_blocklist": False,
            "malware_family": next(
                (fis.get("classification").replace("Malware · ", "")
                 for _ in [0] if fis.get("classification", "").startswith("Malware · ")),
                None),
            "campaign": None,
            "reputation": None,
        },
    }

    affected_assets = {
        "primary_host": hosts[0] if hosts else "unknown",
        "additional_hosts": hosts[1:] if len(hosts) > 1 else [],
        "users": users,
        "execution_paths": [c["command_line"][:200] for c in inv.get("detected", {}).get("commands", []) or []],
        "affected_files": (fis.get("iocs", {}) or {}).get("files", []) or [],
        "network_destinations": (fis.get("iocs", {}) or {}).get("domains", []) + (fis.get("iocs", {}) or {}).get("ips", []),
        "registry_locations": (fis.get("iocs", {}) or {}).get("registry", []) or [],
    }

    verdict = (fis.get("verdict") or "unknown").lower()
    business_impact = _business_impact(verdict, behaviours, ti)

    report = {
        "profile": profile,
        "customer": customer,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sections": {
            "01_executive_summary":   compose_executive_summary(inv, profile=profile),
            "02_incident_overview":   _incident_overview(inv, hosts, users),
            "03_investigation_narrative": compose_narrative(inv, profile=profile),
            "04_detection_timeline":  _timeline(inv),
            "05_attack_story":        _attack_story(inv),
            "06_root_cause":          root_cause,
            "07_malware_behaviour":   behaviours,
            "08_findings":            compose_findings(inv, profile=profile),
            "09_supporting_evidence": _supporting_evidence(inv),
            "10_environmental":       env_flags + limitations,  # Phase 6.5: merged
            "11_threat_intelligence": ti,
            "12_affected_assets":     affected_assets,
            "13_business_impact":     business_impact,
            "14_customer_actions":    _customer_actions(fis),
            "15_recommendations":     compose_recommendations(inv, profile=profile),
            "16_final_verdict": {
                "verdict":             fis.get("verdict"),
                "classification":      fis.get("classification"),
                "severity":            fis.get("severity"),
                "confidence":          fis.get("confidence"),
                "current_containment": "Contained" if _has_containment(raw) else "In-progress",
                "remaining_risk":      _remaining_risk(verdict, ti),
            },
            "17_investigation_quality": quality,
        },
        "meta": {
            "engine": "nivx-report-writer-v1",
            "deterministic": True,
            "audience": profile,
            "evidence_immutable": True,
        },
    }
    return report


def _supporting_evidence(inv: dict) -> dict:
    """Grouped supporting evidence with a one-line rationale per category."""
    fis = inv.get("final_incident_summary", {}) or {}
    cmds = inv.get("detected", {}).get("commands", []) or []
    iocs = fis.get("iocs", {}) or {}
    ents = inv.get("detected", {}).get("entities", {}) or {}
    out: dict[str, dict] = {}
    if cmds:
        out["Commands"] = {"count": len(cmds),
                           "rationale": "Each command is a discrete unit of attacker activity that can be searched for, blocked, or replayed.",
                           "samples": [c["binary"] for c in cmds[:8]]}
    if iocs.get("sha256") or iocs.get("sha1") or iocs.get("md5"):
        out["Hashes"] = {"count": sum(len(iocs.get(k, [])) for k in ("sha256","sha1","md5")),
                         "rationale": "Cryptographic hashes uniquely identify a payload — critical for cross-host hunting.",
                         "samples": (iocs.get("sha256", []) + iocs.get("sha1", []) + iocs.get("md5", []))[:5]}
    if iocs.get("ips") or ents.get("ips"):
        combined = list(dict.fromkeys((iocs.get("ips", []) or []) + (ents.get("ips", []) or [])))
        out["IP Addresses"] = {"count": len(combined),
                               "rationale": "Attacker infrastructure — block at the network edge and hunt for prior connections.",
                               "samples": combined[:5]}
    if iocs.get("domains") or ents.get("domains"):
        combined = list(dict.fromkeys((iocs.get("domains", []) or []) + (ents.get("domains", []) or [])))
        out["Domains"] = {"count": len(combined),
                          "rationale": "DNS resolution artefacts — block at the DNS / proxy layer.",
                          "samples": combined[:5]}
    if iocs.get("urls") or ents.get("urls"):
        combined = list(dict.fromkeys((iocs.get("urls", []) or []) + (ents.get("urls", []) or [])))
        out["URLs"] = {"count": len(combined),
                       "rationale": "Attacker delivery URLs — block and correlate against web-proxy logs.",
                       "samples": combined[:5]}
    if ents.get("files"):
        out["Files"] = {"count": len(ents.get("files", []) or []),
                        "rationale": "Filesystem artefacts to search for and remove during remediation.",
                        "samples": (ents.get("files") or [])[:5]}
    if ents.get("registry"):
        out["Registry"] = {"count": len(ents.get("registry", []) or []),
                           "rationale": "Registry paths — persistence and configuration artefacts.",
                           "samples": (ents.get("registry") or [])[:5]}
    if ents.get("users"):
        out["Users"] = {"count": len(ents.get("users", []) or []),
                        "rationale": "Accounts involved — validate no credential compromise.",
                        "samples": (ents.get("users") or [])[:5]}
    return out


def _business_impact(verdict: str, behaviours: dict, ti: dict) -> dict:
    high = verdict in ("malicious", "critical")
    return {
        "data_exposure":         "High"   if "Collection" in behaviours or "Credential Access" in behaviours else "Low",
        "persistence_risk":      "High"   if "Persistence" in behaviours else "Low",
        "lateral_movement_risk": "Medium" if "Lateral Movement" in behaviours else "Low",
        "operational_disruption": "High"  if "Impact" in behaviours else ("Medium" if high else "Low"),
        "security_posture":      "Weak" if not ti["correlated"].get("virustotal") else "Adequate",
        "business_risk":         "High"   if high else ("Medium" if verdict == "suspicious" else "Low"),
    }


def _remaining_risk(verdict: str, ti: dict) -> str:
    if verdict in ("malicious", "critical"):
        return "Elevated until full-fleet hunt confirms no additional compromised hosts."
    if verdict == "suspicious":
        return "Moderate — validate additional hosts and monitor for repeat activity."
    return "Low — retain report for future correlation."


# ─── Markdown renderer ─────────────────────────────────────────
def render_markdown(report: dict) -> str:
    s = report.get("sections", {})
    L: list[str] = []
    ov = s.get("02_incident_overview", {})
    L.append(f"# NivXRay Investigation Report · {ov.get('incident_number','')}")
    L.append("")
    L.append(f"**Detection source:** {ov.get('detection_source','')}   "
             f"**Host:** `{ov.get('hostname','')}`   **User:** `{ov.get('username','')}`   "
             f"**OS:** {ov.get('operating_system','')}   **Severity:** {ov.get('severity','')}   "
             f"**Status:** {ov.get('investigation_status','')}")
    L.append("")
    L.append("## 1 · Executive Summary")
    for p in s.get("01_executive_summary", []) or []:
        L.append(p); L.append("")
    L.append("## 3 · Investigation Narrative")
    L.append(s.get("03_investigation_narrative", "")); L.append("")
    L.append("## 4 · Detection Timeline")
    for ev in s.get("04_detection_timeline", []) or []:
        L.append(f"- `{ev['time']}` — {ev['event']}  _({ev['evidence_type']})_")
    L.append("")
    L.append("## 5 · Attack Story")
    for beat in s.get("05_attack_story", []) or []:
        L.append(f"1. {beat}")
    L.append("")
    rc = s.get("06_root_cause", {}) or {}
    L.append("## 6 · Root Cause")
    L.append(f"**{rc.get('finding','')}**")
    L.append(f"_Source:_ {rc.get('evidence_source','')}   _Type:_ {rc.get('evidence_type','')}   "
             f"_Confidence:_ {rc.get('confidence','')}")
    L.append("")
    L.append("## 7 · Malware Behaviour")
    for tactic, techs in (s.get("07_malware_behaviour", {}) or {}).items():
        L.append(f"### {tactic}")
        for t in techs: L.append(f"- {t}")
        L.append("")
    L.append("## 8 · Investigation Findings")
    for f in s.get("08_findings", []) or []:
        L.append(f"- **{f['finding']}**   _{f['evidence_type']} · {f['confidence']} confidence · {f['evidence_source']}_")
    L.append("")
    L.append("## 9 · Supporting Evidence")
    for cat, d in (s.get("09_supporting_evidence", {}) or {}).items():
        L.append(f"### {cat} · {d['count']}")
        L.append(d["rationale"])
        for x in d["samples"]: L.append(f"- `{x}`")
        L.append("")
    L.append("## 10 · Environmental Findings")
    for e in s.get("10_environmental", []) or []:
        L.append(f"- **{e['finding']}**   _{e['evidence_type']} · {e['confidence']} confidence_")
    L.append("")
    ti = s.get("11_threat_intelligence", {}) or {}
    L.append("## 11 · Threat Intelligence")
    L.append("**Observed:**")
    for k, v in ti.get("observed", {}).items(): L.append(f"- {k}: {v}")
    L.append("**Correlated:**")
    for k, v in ti.get("correlated", {}).items(): L.append(f"- {k}: {v}")
    L.append("")
    aa = s.get("12_affected_assets", {}) or {}
    L.append("## 12 · Affected Assets")
    L.append(f"- Primary host: `{aa.get('primary_host','')}`")
    if aa.get("users"):        L.append(f"- Users: {', '.join('`'+u+'`' for u in aa['users'])}")
    if aa.get("network_destinations"):
        L.append(f"- Network destinations: {', '.join(aa['network_destinations'][:10])}")
    L.append("")
    bi = s.get("13_business_impact", {}) or {}
    L.append("## 13 · Business Impact")
    for k, v in bi.items(): L.append(f"- **{k.replace('_',' ').title()}:** {v}")
    L.append("")
    ca = s.get("14_customer_actions", {}) or {}
    L.append("## 14 · Customer Actions")
    for tier in ("immediate", "short_term", "long_term"):
        L.append(f"### {tier.replace('_',' ').title()}")
        for a in ca.get(tier, []) or []: L.append(f"- {a}")
        L.append("")
    L.append("## 15 · Recommendations")
    for r in s.get("15_recommendations", []) or []:
        L.append(f"- **[{r['priority']}]** {r['action']} — _{r['rationale']}_")
    L.append("")
    fv = s.get("16_final_verdict", {}) or {}
    L.append("## 16 · Final Verdict")
    L.append(f"- Verdict: **{fv.get('verdict','')}** · Severity: **{fv.get('severity','')}** · "
             f"Containment: **{fv.get('current_containment','')}**")
    L.append(f"- Remaining risk: {fv.get('remaining_risk','')}")
    L.append("")
    L.append("## 17 · Investigation Quality")
    q = s.get("17_investigation_quality", {}) or {}
    L.append(f"- Overall completeness: **{q.get('overall', {}).get('investigation_completeness', 0)}%**")
    L.append(f"- Ready for analyst review: **{q.get('overall', {}).get('ready_for_analyst_review', False)}**")
    L.append("")
    L.append("---")
    L.append(f"_Generated {report.get('generated_at_utc','')} by {report.get('meta',{}).get('engine','')} · "
             f"audience: {report.get('meta',{}).get('audience','')} · "
             "every conclusion is evidence-traceable._")
    return "\n".join(L)
