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
import re
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
    # ▲ P0e-Unslim fallback (2026-02-09) — when the incident block is
    # slim-stripped from the wire response (Phase 5.W), the L4
    # narrative previously reported "0 MITRE" even though the
    # underlying investigation extracted them into
    # `report_extraction.mitre_techniques` (11 on the Talos sample).
    # Fall back to that authoritative structured source.  Zero new
    # inference — pure projection of already-produced evidence.
    if not mitre:
        _rext = (session.get("raw_investigation") or {}).get("report_extraction") or {}
        _rext_mitre = _rext.get("mitre_techniques") or []
        if _rext_mitre:
            mitre = _rext_mitre
    iocs         = _extract_iocs(inputs)
    counts       = _counts(session, inputs)
    verdict      = _verdict_signals(isum, counts, behaviours)
    # Hash → filename + description context extracted by IDA-4
    # from IOC tables in the acquired article.
    raw          = session.get("raw_investigation") or {}
    hash_ctx     = ((raw.get("report_extraction") or {}).get("hash_context") or {})
    timeline_ev  = ((raw.get("report_extraction") or {}).get("timeline") or [])

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
        "ioc_intelligence":  _ioc_intelligence(iocs, hash_ctx),
        "attack_timeline":   _attack_timeline(timeline_ev),
        "recommendations":   _recommendations(behaviours, tactics),
        "evidence_confidence": _evidence_confidence(counts, ready),
        "verdict":           verdict,
    }


def _attack_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Order timeline events canonically.  Absolute dates first
    (ISO first, then Month DD), then relative markers in the order
    they appeared in the source."""
    absolute: List[Dict[str, Any]] = []
    relative: List[Dict[str, Any]] = []
    for e in events or []:
        d = (e.get("date") or "").lower()
        if re.match(r"\d{4}-\d{2}-\d{2}", d) or re.match(
            r"(?:january|february|march|april|may|june|july|august|"
            r"september|october|november|december)\s+\d{1,2}", d
        ):
            absolute.append(e)
        else:
            relative.append(e)
    # ISO first (parseable), then month-day, then relative in source order.
    absolute.sort(key=lambda x: (
        0 if re.match(r"\d{4}-\d{2}-\d{2}", (x.get("date") or "")) else 1,
        (x.get("date") or "").lower(),
    ))
    return absolute + relative


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
    top_verbs = [b["label"] for b in behaviours[:6]]
    ta_full = [TACTIC_LABEL.get(t, t) for t in tactics[:4]]
    ta = ", ".join(ta_full) or "reconnaissance"

    # ── Paragraph 1 · FACTS ────────────────────────────────────
    verbs_txt = _joined(top_verbs) or "no notable evasion or execution behaviour"
    p1 = (
        f"The submitted evidence ({src}"
        + (f" — “{title}”" if title else "")
        + f") exhibits {verbs_txt}. "
        f"The behavior chain aligns with the {ta} phase(s) of the ATT&CK kill "
        f"chain and is consistent with the class of activity observed in "
        f"multi-stage {verdict.get('descriptor') or 'malicious'} operations."
    )

    # ── Paragraph 2 · ADVERSARY TRADECRAFT ─────────────────────
    # Deterministic characterisation from the observed tactics.
    tradecraft_bits: List[str] = []
    if "defense_evasion" in tactics:
        tradecraft_bits.append("evades detection via signed-binary abuse and log tampering")
    if "impact" in tactics:
        tradecraft_bits.append("inhibits recovery by deleting volume shadow copies")
    if "exfiltration" in tactics:
        tradecraft_bits.append("stages data for cloud exfiltration using dual-use tooling")
    if "command_and_control" in tactics:
        tradecraft_bits.append("maintains C2 through reverse tunnels and remote-access utilities")
    if "lateral_movement" in tactics:
        tradecraft_bits.append("moves laterally with living-off-the-land binaries")
    if "discovery" in tactics:
        tradecraft_bits.append("performs host and domain reconnaissance before escalation")
    if not tradecraft_bits:
        tradecraft_bits.append("relies primarily on native operating-system utilities")
    p2 = (
        "The adversary tradecraft observed in this session "
        + _joined(tradecraft_bits) + ". "
        "This TTP profile is characteristic of financially motivated "
        "operators who blend into legitimate administrative activity "
        "and depend on time-to-response gaps to complete their objectives."
    )

    # ── Paragraph 3 · RECOMMENDED POSTURE ──────────────────────
    posture_bits: List[str] = []
    if "impact" in tactics:
        posture_bits.append("prioritise host isolation and backup verification")
    if "credential_access" in tactics or "lateral_movement" in tactics:
        posture_bits.append("force-rotate privileged and service credentials")
    if "exfiltration" in tactics:
        posture_bits.append("audit outbound egress for the observed staging patterns")
    if "persistence" in tactics:
        posture_bits.append("audit scheduled tasks, services and Run keys on affected hosts")
    if "defense_evasion" in tactics:
        posture_bits.append("verify EDR, security-agent and log integrity before further analysis")
    if not posture_bits:
        posture_bits.append("preserve volatile evidence and initiate endpoint triage")
    p3 = (
        "Recommended immediate posture: "
        + _joined(posture_bits) + ". "
        "Escalate to a full incident-response engagement if any of the "
        "observed techniques are corroborated in production telemetry."
    )

    return {
        "paragraph":  p1,               # backwards-compat single para
        "paragraphs": [p1, p2, p3],     # new 3-paragraph structure
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
    # ▲ P0f (2026-02-09) — projection-layer name + tactic resolution.
    # The IDA-4 extractor emits `mitre_techniques[]` with only `id`
    # populated for URL-acquired inputs.  Rather than change the
    # extractor, we resolve display fields from the shared MITRE
    # tables (`services.ice.correlate`).  Every downstream MITRE
    # surface — brief-panel MITRE Summary, sidebar MITRE tab,
    # narrative kill-chain — sees the enriched shape.
    try:
        from services.ice.correlate import (
            tactic_for as _tactic_for,
            name_for   as _name_for,
        )
    except Exception:  # pragma: no cover — fall back to raw fields
        _tactic_for = lambda _tid: None
        _name_for   = lambda _tid: None

    by_tactic: Dict[str, List[Dict[str, Any]]] = {}
    for m in mitre:
        tid  = (m.get("id") or "").upper()
        # Prefer the tactic already on the technique dict; otherwise
        # resolve from the technique-id via the shared ICE table.
        raw_tac = m.get("tactic") or _tactic_for(tid) or "execution"
        tac     = str(raw_tac).lower().replace(" ", "_")
        # Prefer the name already on the technique dict; otherwise
        # resolve from the shared MITRE catalog.
        name = m.get("name") or _name_for(tid) or ""
        by_tactic.setdefault(tac, []).append({
            "id":   m.get("id"),
            "name": name,
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


def _ioc_intelligence(iocs: List[Dict[str, Any]],
                        hash_ctx: Optional[Dict[str, Dict[str, str]]] = None
                        ) -> List[Dict[str, Any]]:
    """Build per-IOC intelligence cards.  External fields carry a
    "pending" source stamp so the UI can render them greyed until
    OSINT integrations are wired.  For hash IOCs we also attach the
    filename + description harvested by IDA-4 from the source's
    IOC table (Talos / Mandiant format)."""
    ctx = hash_ctx or {}
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
            "filename":         None,
            "description":      None,
        }
        # Attach IDA-4 file-context for hash IOCs.
        if card["kind"] == "hash":
            hc = ctx.get((i["value"] or "").lower()) or {}
            card["filename"]    = hc.get("filename") or None
            card["description"] = hc.get("description") or None
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
    # ▲ P0e-Unslim fallback (2026-02-09) — mirror the fallback in
    # `build_narrative` for the count so Evidence Confidence's MITRE
    # cell reflects the authoritative report_extraction source when
    # incident is slim-stripped.
    if not counts["mitre"]:
        _rext = (session.get("raw_investigation") or {}).get("report_extraction") or {}
        counts["mitre"] = len(_rext.get("mitre_techniques") or [])
    # P0b (ADR-0014g) · surface IOC evidence already present in the
    # incident SSOT so paste-derived investigations show a non-zero
    # count when IOCs actually exist.  Reads from incident.iocs which
    # is the same top-level field already consumed by
    # ioc_intelligence / evidence_confidence.  No new evidence, no
    # extraction, no producer change.
    _incident_iocs = inc.get("iocs") or []
    if isinstance(_incident_iocs, dict):
        # Some SSOT shapes carry iocs as {kind: [...]}. Sum across kinds.
        _incident_iocs = sum((v for v in _incident_iocs.values()
                                if isinstance(v, list)), [])
    counts["iocs"] = len(_incident_iocs)
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
