"""
Investigation Summary Narrative · Rule R22 · 2026-03-02
────────────────────────────────────────────────────────
DETERMINISTIC 9-section narrative synthesiser.  Zero LLM.  Reads
the SSOT / incident / investigation_inputs and produces the
analyst-ready summary block described in the L4 architecture:

    executive_summary     — 2-3 sentence template
    analyst_summary       — one-paragraph ticket/email-ready block
    behavior_summary      — bulleted observed behaviours
    attack_intent         — one paragraph
    impact_assessment     — bullets + likelihood
    mitre_summary         — grouped by tactic
    ioc_intelligence      — per-IOC card (external fields "pending")
    recommendations       — Immediate · Threat Hunting · Containment
    evidence_confidence   — roll-up

Every string is templated from static verbs / nouns keyed on the
observed behaviors and MITRE tactics — no free-form text and no
network calls.  The output is stable for identical inputs so the
Investigation Quality Gate can regression-test it.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════
# Static vocabularies
# ═══════════════════════════════════════════════════════════════════
TACTIC_LABEL = {
    "initial_access":       "Initial Access",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion":      "Defense Evasion",
    "credential_access":    "Credential Access",
    "discovery":            "Discovery",
    "lateral_movement":     "Lateral Movement",
    "collection":           "Collection",
    "command_and_control":  "Command & Control",
    "exfiltration":         "Exfiltration",
    "impact":               "Impact",
}

# Which observable behaviour bullets to surface, keyed on the raw
# behaviour label produced by ICE.  We match sub-strings so noisy
# labels still resolve.
_BEHAVIOR_HINTS: List[Tuple[str, str]] = [
    ("powershell",             "PowerShell execution"),
    ("encoded",                "Base64 / obfuscated payload"),
    ("obfuscat",               "Command-line obfuscation"),
    ("download",               "Payload download"),
    ("in-memory",              "In-memory execution"),
    ("memory only",            "In-memory execution"),
    ("iex",                    "In-memory execution"),
    ("reflect",                "Reflective code loading"),
    ("registry",               "Registry modification"),
    ("scheduled task",         "Persistence via scheduled task"),
    ("schtasks",               "Persistence via scheduled task"),
    ("service",                "Persistence via service creation"),
    ("run key",                "Persistence via Run key"),
    ("startup",                "Persistence via startup folder"),
    ("credential",             "Credential access"),
    ("lsass",                  "LSASS memory access"),
    ("process discover",       "Process discovery"),
    ("process listing",        "Process discovery"),
    ("network discover",       "Network discovery"),
    ("host discover",          "Host discovery"),
    ("lateral",                "Lateral movement preparation"),
    ("wmi",                    "WMI execution"),
    ("dns",                    "DNS-based command & control"),
    ("http",                   "HTTP-based command & control"),
    ("beacon",                 "C2 beaconing"),
    ("exfiltrat",              "Data exfiltration"),
    ("archive",                "Data staging / archiving"),
    ("rclone",                 "Cloud data exfiltration (rclone)"),
    ("tar ",                   "Data staging via tar"),
    ("cleanup",                "Self cleanup"),
    ("delete",                 "Artifact deletion"),
    ("wipe",                   "Log or artifact wiping"),
    ("quick assist",           "Remote assistance abuse (Quick Assist)"),
    ("msedge",                 "Browser abuse (Edge)"),
    ("edge --load-extension",  "Browser abuse (Edge extension)"),
]

_IMPACT_BY_TACTIC: Dict[str, str] = {
    "initial_access":       "Initial compromise",
    "execution":            "Arbitrary code execution",
    "persistence":          "Persistent foothold",
    "privilege_escalation": "Privilege escalation",
    "defense_evasion":      "Detection evasion",
    "credential_access":    "Credential theft",
    "discovery":            "Environment reconnaissance",
    "lateral_movement":     "Lateral movement preparation",
    "collection":           "Data collection",
    "command_and_control":  "Remote command execution",
    "exfiltration":         "Data exfiltration",
    "impact":               "Destructive impact",
}

_HUNT_QUERIES: List[Tuple[str, str]] = [
    ("powershell",           "powershell.exe -EncodedCommand OR -enc"),
    ("encoded",              "process_command_line contains 'FromBase64String'"),
    ("iex",                  "process_command_line contains 'IEX' OR 'Invoke-Expression'"),
    ("msedge",               "msedge.exe --load-extension"),
    ("quick assist",         "quickassist.exe"),
    ("tar ",                 "tar.exe -xf"),
    ("rclone",               "rclone.exe"),
    ("schtasks",             "schtasks.exe /create"),
    ("service",              "sc.exe create"),
    ("wmi",                  "wmic.exe process call create"),
    ("lsass",                "OpenProcess with LSASS handle"),
    ("registry",             "reg.exe add HKCU\\..\\Run"),
    ("rundll",               "rundll32.exe with suspicious args"),
    ("dns",                  "unusual DNS TXT / long labels"),
]


# ═══════════════════════════════════════════════════════════════════
# Public entry
# ═══════════════════════════════════════════════════════════════════
def build_narrative(session: Dict[str, Any]) -> Dict[str, Any]:
    """Produce the L4 analyst narrative block for a Session envelope.

    Never mutates the session.  Safe on partial input — every
    section degrades to a factual "not observed" placeholder when
    data is missing.
    """
    inc     = session.get("incident") or {}
    inputs  = session.get("investigation_inputs") or []
    ready   = (inc.get("readiness") or {}) if inc else {}
    prof    = session.get("document_profile") or {}
    acq     = session.get("acquired_document") or {}
    isum    = inc.get("summary") if inc else {}
    isum    = isum or {}

    behaviours   = _observed_behaviours(inc, inputs)
    tactics      = _tactics_observed(inc)
    mitre        = inc.get("mitre") or [] if inc else []
    iocs         = _extract_iocs(inputs)
    counts       = _counts(session, inputs)
    verdict      = _verdict_signals(isum, counts, behaviours)

    return {
        "executive_summary": _executive_summary(prof, acq, verdict,
                                                 behaviours, tactics),
        "analyst_summary":   _analyst_summary(verdict, behaviours,
                                                mitre, counts),
        "behavior_summary":  behaviours,
        "attack_intent":     _attack_intent(tactics, behaviours,
                                              verdict),
        "impact_assessment": _impact_assessment(tactics),
        "mitre_summary":     _mitre_summary(mitre),
        "ioc_intelligence":  _ioc_intelligence(iocs),
        "recommendations":   _recommendations(behaviours, tactics),
        "evidence_confidence": _evidence_confidence(counts, ready),
        "verdict":           verdict,
    }


# ═══════════════════════════════════════════════════════════════════
# Section builders
# ═══════════════════════════════════════════════════════════════════
def _executive_summary(prof: Dict[str, Any],
                        acq: Dict[str, Any],
                        verdict: Dict[str, Any],
                        behaviours: List[Dict[str, Any]],
                        tactics: List[str]) -> Dict[str, Any]:
    src = prof.get("vendor") or acq.get("sitename") or "the submitted input"
    title = prof.get("title") or acq.get("title") or None
    top_verbs = [b["label"] for b in behaviours[:5]]
    ta = ", ".join(TACTIC_LABEL.get(t, t) for t in tactics[:3]) or "reconnaissance"
    verbs_txt = _joined(top_verbs) or "no notable evasion or execution behaviour"
    para = (
        f"The submitted evidence ({src}"
        + (f" — “{title}”" if title else "")
        + f") exhibits {verbs_txt}. "
        f"The behavior chain aligns with the {ta} phase(s) of the ATT&CK kill "
        f"chain and is consistent with the class of activity observed in "
        f"multi-stage {verdict.get('descriptor') or 'malicious'} operations."
    )
    return {
        "paragraph": para,
        "risk":       verdict.get("risk"),
        "confidence": verdict.get("confidence_percent"),
    }


def _analyst_summary(verdict: Dict[str, Any],
                      behaviours: List[Dict[str, Any]],
                      mitre: List[Dict[str, Any]],
                      counts: Dict[str, int]) -> str:
    verbs = _joined([b["label"] for b in behaviours[:5]]) \
              or "no notable execution or evasion behaviour"
    tech  = ", ".join(sorted({m.get("id") for m in mitre if m.get("id")})[:6]) \
              or "no MITRE mapping"
    ioc_line = ""
    ioc_total = sum((counts.get(k) or 0) for k in ("url", "hash", "ip", "domain"))
    if ioc_total:
        ioc_line = f" {ioc_total} indicator(s) were extracted and correlated against known techniques."
    return (
        f"The analysed evidence exhibits {verbs}. "
        f"Observed behaviour maps to MITRE ATT&CK techniques {tech}."
        f"{ioc_line} "
        f"Based on the collected evidence, this activity is assessed as "
        f"{verdict.get('label') or 'suspicious'} "
        f"with {verdict.get('confidence_label') or 'medium'} confidence. "
        f"{verdict.get('recommendation') or 'Immediate containment and endpoint investigation are recommended.'}"
    )


def _observed_behaviours(incident: Dict[str, Any],
                          inputs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return a deduped, ordered list of analyst-friendly behaviour
    bullets, computed from ICE cluster labels + raw command text."""
    seen: List[str] = []
    hay: List[str] = []
    for b in (incident.get("behaviors") or []):
        hay.append((b.get("label") or "").lower())
    for i in inputs:
        v = (i.get("value") or i.get("preview") or "").lower()
        if v: hay.append(v)
        s = (i.get("investigation") or {}).get("stage") or {}
        if s.get("purpose"):  hay.append(str(s["purpose"]).lower())
        if s.get("family"):   hay.append(str(s["family"]).lower())

    out: List[Dict[str, Any]] = []
    joined = " ".join(hay)
    for needle, label in _BEHAVIOR_HINTS:
        if needle in joined and label not in seen:
            seen.append(label)
            out.append({"label": label, "confidence": "observed"})
    return out


def _attack_intent(tactics: List[str],
                    behaviours: List[Dict[str, Any]],
                    verdict: Dict[str, Any]) -> str:
    if not tactics and not behaviours:
        return (
            "Insufficient evidence to determine attacker intent; the "
            "investigation is inconclusive on this dimension."
        )
    primary = TACTIC_LABEL.get(tactics[0], "Execution") if tactics else "Execution"
    verbs = _joined([b["label"].lower() for b in behaviours[:3]]) or "the observed activity"
    return (
        f"The activity appears designed to achieve {primary.lower()} "
        f"while minimising forensic visibility. Its primary objective "
        f"is to enable {verbs} across the compromised endpoint. "
        f"No destructive impact was observed in the submitted evidence "
        f"itself; however, the tradecraft is consistent with the initial "
        f"stages of a multi-step {verdict.get('descriptor') or 'malicious'} operation."
    )


def _impact_assessment(tactics: List[str]) -> Dict[str, Any]:
    bullets = []
    for t in tactics:
        b = _IMPACT_BY_TACTIC.get(t)
        if b and b not in bullets:
            bullets.append(b)
    if not bullets:
        bullets = ["Impact not directly observed in submitted evidence."]
    lk = "High" if any(t in tactics for t in ("execution", "persistence",
                                                 "credential_access",
                                                 "lateral_movement",
                                                 "exfiltration",
                                                 "impact")) else "Medium"
    return {"bullets": bullets, "likelihood": lk}


def _mitre_summary(mitre: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_tactic: Dict[str, List[Dict[str, Any]]] = {}
    for m in mitre:
        tac = (m.get("tactic") or "execution").lower().replace(" ", "_")
        by_tactic.setdefault(tac, []).append({
            "id":   m.get("id"),
            "name": m.get("name") or "",
        })
    out = []
    order = ["initial_access", "execution", "persistence",
              "privilege_escalation", "defense_evasion",
              "credential_access", "discovery",
              "lateral_movement", "collection",
              "command_and_control", "exfiltration", "impact"]
    for k in order + [k for k in by_tactic if k not in order]:
        if k in by_tactic:
            out.append({
                "tactic": TACTIC_LABEL.get(k, k.replace("_", " ").title()),
                "techniques": by_tactic[k],
            })
    return out


def _ioc_intelligence(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build per-IOC intelligence cards.  External fields carry a
    "pending" source stamp so the UI can render them greyed until
    OSINT integrations are wired."""
    cards = []
    for i in iocs:
        card = {
            "kind":         i["kind"],
            "value":        i["value"],
            "section":      i.get("section"),
            "source_paste": i.get("source") or "extracted",
            "reputation":       {"verdict": "unknown", "source": "pending"},
            "virustotal":       {"ratio":   None,      "source": "pending"},
            "abuseipdb":        {"score":   None,      "source": "pending"},
            "passive_dns":      {"first_seen": None,   "last_seen": None,
                                  "source": "pending"},
            "asn":              {"number": None, "org": None, "source": "pending"},
            "whois":            {"registrar": None, "country": None,
                                  "source": "pending"},
            "related_malware":  [],
            "related_urls":     [],
            "related_hashes":   [],
        }
        cards.append(card)
    return cards


def _recommendations(behaviours: List[Dict[str, Any]],
                      tactics: List[str]) -> Dict[str, List[str]]:
    labels = {b["label"].lower() for b in behaviours}
    hay    = " ".join(labels)
    immediate = []
    hunting   = []
    containment = []

    if any(x in hay for x in ("powershell", "in-memory", "obfuscated",
                                "reflective")):
        immediate.append("Kill running PowerShell processes on affected hosts")
    immediate.extend([
        "Isolate the affected host from the network",
        "Preserve volatile memory (collect memory image)",
        "Preserve event logs and endpoint telemetry",
    ])
    if any(x in hay for x in ("download", "beacon", "http", "dns", "c2")):
        immediate.append("Block resolved domains and destination IPs at the perimeter")
    if any(x in hay for x in ("credential", "lsass")):
        immediate.append("Force credential rotation for exposed accounts")

    for needle, query in _HUNT_QUERIES:
        if needle in hay:
            hunting.append(query)
    if not hunting:
        hunting.append("Baseline unusual parent-child process trees on impacted hosts")

    containment.extend([
        "Disable involved user accounts and rotate credentials",
        "Review lateral movement paths from the affected host",
        "Monitor DNS beaconing over the following 72 hours",
        "Review recently-created scheduled tasks and services",
    ])
    if "credential" in hay or "lsass" in hay:
        containment.insert(0, "Reset domain admin and service-account credentials")

    return {
        "immediate":   immediate,
        "hunting":     hunting,
        "containment": containment,
    }


def _evidence_confidence(counts: Dict[str, int],
                          readiness: Dict[str, Any]) -> Dict[str, Any]:
    total_cmd = counts.get("commands", 0)
    invd      = counts.get("investigated", 0)
    mitre_n   = counts.get("mitre", 0)
    ioc_n     = sum((counts.get(k) or 0) for k in ("url", "hash", "ip", "domain"))
    return {
        "commands":    {"total": total_cmd, "investigated": invd},
        "mitre":       {"count": mitre_n, "state": "mapped" if mitre_n else "none"},
        "iocs":        {"count": ioc_n, "state": "correlated" if ioc_n else "none"},
        "threat_intel": {"state": "pending",
                          "detail": "Connect VT / AbuseIPDB in Integrations"},
        "completeness_percent": readiness.get("overall_percent") or 0,
        "confidence_label":     readiness.get("confidence_label") or "low",
    }


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════
def _joined(items: List[str]) -> str:
    xs = [x for x in items if x]
    if not xs:      return ""
    if len(xs) == 1: return xs[0]
    if len(xs) == 2: return f"{xs[0]} and {xs[1]}"
    return ", ".join(xs[:-1]) + f", and {xs[-1]}"


def _tactics_observed(incident: Dict[str, Any]) -> List[str]:
    seen: List[str] = []
    for p in (incident.get("phases") or []):
        t = p.get("tactic")
        if t and t not in seen:
            seen.append(t)
    for b in (incident.get("behaviors") or []):
        t = b.get("primary_tactic")
        if t and t not in seen:
            seen.append(t)
    return seen


def _extract_iocs(inputs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for i in inputs:
        t = i.get("type")
        if t in ("url", "hash", "ip", "domain"):
            out.append({
                "kind":    t,
                "value":   i.get("value"),
                "section": i.get("section"),
                "source":  i.get("source"),
            })
    return out


def _counts(session: Dict[str, Any],
             inputs: List[Dict[str, Any]]) -> Dict[str, int]:
    inc = session.get("incident") or {}
    counts: Dict[str, int] = {}
    for i in inputs:
        counts[i["type"]] = counts.get(i["type"], 0) + 1
    counts["commands"] = sum(counts.get(k, 0)
                                for k in ("command", "powershell", "cmd", "bash"))
    counts["investigated"] = sum(1 for i in inputs
                                    if i.get("status") == "investigated")
    counts["mitre"] = len(inc.get("mitre") or [])
    return counts


def _verdict_signals(isum: Dict[str, Any],
                      counts: Dict[str, int],
                      behaviours: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Roll up a compact verdict signal (risk / label / confidence /
    descriptor / recommendation) that other sections can quote so
    the tone stays consistent."""
    sev  = (isum.get("severity") or "").lower()
    conf = isum.get("confidence_percent") or 0
    n    = len(behaviours)
    if sev == "critical" or (n >= 4 and conf >= 70):
        return {
            "risk":              "Critical",
            "label":             "malicious",
            "descriptor":        "malicious",
            "confidence_percent": max(conf, 90),
            "confidence_label":  "high",
            "recommendation":    "Immediate containment and endpoint investigation are recommended.",
        }
    if sev == "high" or (n >= 3 and conf >= 60):
        return {
            "risk":              "High",
            "label":             "malicious",
            "descriptor":        "malicious",
            "confidence_percent": max(conf, 80),
            "confidence_label":  "high",
            "recommendation":    "Isolate the host and perform full endpoint triage.",
        }
    if sev == "medium" or n >= 2:
        return {
            "risk":              "Medium",
            "label":             "suspicious",
            "descriptor":        "suspicious",
            "confidence_percent": max(conf, 60),
            "confidence_label":  "medium",
            "recommendation":    "Escalate for endpoint analyst review.",
        }
    return {
        "risk":              "Low",
        "label":             "inconclusive",
        "descriptor":        "suspicious",
        "confidence_percent": max(conf, 30),
        "confidence_label":  "low",
        "recommendation":    "Continue monitoring; no immediate action required.",
    }
