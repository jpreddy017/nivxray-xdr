"""NivXRay Customer / Investigation Report Composer.

Persona-aware composer that generates a customer-facing incident
report from ONLY the canonical CIO fields. It never mentions the
decoder pipeline (layers, url-decode, base64, crypto-detect,
"Recovered payload") — that language belongs in a `decoder` persona
report, not a customer investigation.

Section order (locked, non-negotiable):

    1.  Executive Summary
    2.  Incident Overview
    3.  Affected Hosts
    4.  Users
    5.  Detection Source
    6.  Timeline
    7.  Execution Chain
    8.  Evidence
    9.  File Hashes
    10. IOCs
    11. Threat Intelligence
    12. MITRE ATT&CK
    13. Impact Assessment
    14. Containment Status
    15. Analyst Verdict
    16. Recommendations

Every statement cites the CIO field it came from.

Personas:
  * "customer"    — this module's default; business-friendly, terse
  * "threat_hunt" — includes hypotheses + validation trail
  * "forensic"    — includes hashes/timestamps/process tree
  * "decoder"    — the only persona that can talk about layers

The composer stays deterministic. LLM polishing is NOT part of this
module (add it upstream if desired).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ── Forbidden decoder-telemetry vocabulary ────────────────────────────
#
# Any customer / investigation / threat-hunt report that contains these
# tokens fails the hygiene lint (see test_customer_report_hygiene.py).
# The tokens are matched case-insensitively as whole tokens/phrases.

FORBIDDEN_TERMS: Tuple[str, ...] = (
    "Layer 0", "Layer 1", "Layer 2", "Layer 3", "Layer 4",
    "url-decode", "url_decode", "crypto-detect", "crypto_detect",
    "Recovered payload", "operation history", "operation_history",
    "decoder_layers", "codec sequence", "ps-encodedcommand",
    "family-emotet",
)

# Personas that must obey the forbidden-terms lint.
CUSTOMER_LIKE_PERSONAS: Tuple[str, ...] = ("customer", "threat_hunt", "forensic")


@dataclass
class ReportSection:
    number: int
    title: str
    body: str
    citations: List[str] = field(default_factory=list)


@dataclass
class CustomerReport:
    persona: str
    verdict: str
    verdict_confidence_pct: int
    sections: List[ReportSection]

    def to_markdown(self) -> str:
        parts = [f"# Investigation Report — Verdict: **{self.verdict}** ({self.verdict_confidence_pct}%)"]
        for s in self.sections:
            parts.append(f"\n## {s.number}. {s.title}\n\n{s.body}")
            if s.citations:
                parts.append(f"\n*Sources — {', '.join(s.citations)}*")
        return "\n".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "persona": self.persona,
            "verdict": self.verdict,
            "verdict_confidence_pct": self.verdict_confidence_pct,
            "sections": [
                {"number": s.number, "title": s.title, "body": s.body, "citations": s.citations}
                for s in self.sections
            ],
            "markdown": self.to_markdown(),
        }


# ─── Helpers · read canonical CIO fields ONLY ─────────────────────────
def _hosts(cio: Dict[str, Any]) -> List[str]:
    md = cio.get("metadata") or {}
    ents = cio.get("entities") or md.get("entities") or {}
    hosts = ents.get("hosts") or ents.get("hostnames") or []
    if not hosts:
        # Fall back to summary.entities_digest.hosts
        summ = cio.get("summary") or {}
        ed = summ.get("entities_digest") or {}
        hosts = ed.get("hosts") or []
    return [str(h) for h in hosts if h]


def _users(cio: Dict[str, Any]) -> List[str]:
    ents = (cio.get("entities") or (cio.get("metadata") or {}).get("entities") or {})
    users = ents.get("users") or ents.get("accounts") or []
    if not users:
        summ = cio.get("summary") or {}
        ed = summ.get("entities_digest") or {}
        users = ed.get("users") or []
    return [str(u) for u in users if u]


def _iocs(cio: Dict[str, Any]) -> Dict[str, List[str]]:
    md = cio.get("metadata") or {}
    iocs = md.get("iocs") or {}
    if isinstance(iocs, list):
        # legacy shape
        grouped: Dict[str, List[str]] = {}
        for ent in iocs:
            k = (ent.get("kind") or "other").lower()
            grouped.setdefault(k, []).append(ent.get("value") or "")
        iocs = grouped
    out = {k: [v for v in vs if v] for k, vs in iocs.items()}

    # P0.1 FIX · fallback to evidence graph. During build the CIO's
    # `metadata.iocs` is not yet set at the moment compose_summary()
    # runs the customer_report composer — but the evidence graph
    # ALREADY carries `ioc` nodes. Merge them so the IOC section is
    # never dropped as "empty" when the CIO actually has IOCs.
    if not any(out.values()):
        out = {"urls": [], "domains": [], "ips": [],
               "emails": [], "md5": [], "sha1": [], "sha256": []}
    graph = cio.get("evidence_graph") or {}
    for n in graph.get("nodes") or []:
        if str(n.get("kind", "")).lower() != "ioc":
            continue
        attrs = n.get("attrs") or {}
        ik = str(attrs.get("ioc_kind") or "").lower()
        val = str(n.get("value") or "").strip()
        if not val:
            # Label like "URL · http://..." — try to strip
            lbl = str(n.get("label") or "")
            if "·" in lbl:
                val = lbl.split("·", 1)[1].strip()
        if not val:
            continue
        bucket = {
            "url":    "urls",
            "domain": "domains",
            "ip":     "ips",
            "email":  "emails",
            "md5":    "md5",
            "sha1":   "sha1",
            "sha256": "sha256",
            "hash":   "sha256",
        }.get(ik)
        if not bucket:
            continue
        out.setdefault(bucket, [])
        if val not in out[bucket]:
            out[bucket].append(val)
    return {k: v for k, v in out.items() if v}


def _hashes(cio: Dict[str, Any]) -> Dict[str, List[str]]:
    iocs = _iocs(cio)
    return {
        "md5":    iocs.get("md5") or [],
        "sha1":   iocs.get("sha1") or [],
        "sha256": iocs.get("sha256") or [],
    }


def _mitre(cio: Dict[str, Any]) -> List[Dict[str, str]]:
    """Return `[{technique_id, name, tactic}]` from the evidence graph."""
    graph = cio.get("evidence_graph") or {}
    out: List[Dict[str, str]] = []
    for n in graph.get("nodes") or []:
        if (n.get("kind") or "").lower() != "mitre_technique":
            continue
        attrs = n.get("attrs") or {}
        out.append({
            "technique_id": str(attrs.get("technique_id") or n.get("label") or ""),
            "name":         str(n.get("label") or ""),
            "tactic":       str(attrs.get("tactic") or ""),
        })
    return out


def _osint(cio: Dict[str, Any]) -> Dict[str, Any]:
    md = cio.get("metadata") or {}
    return md.get("osint") or {}


def _detection_source(cio: Dict[str, Any]) -> str:
    md = cio.get("metadata") or {}
    src = md.get("detection_source") or md.get("source") or md.get("ingestion_source")
    if src:
        return str(src)
    # Best-effort: infer from adapter metadata if present.
    adapter = md.get("input_understanding", {}).get("adapter")
    if adapter:
        return f"Auto-detected input type: {adapter}"
    return "Ad-hoc analyst submission"


def _timeline(cio: Dict[str, Any]) -> List[Dict[str, str]]:
    md = cio.get("metadata") or {}
    tl = md.get("timeline") or []
    # Return only user-facing timestamped events (skip decoder-layer entries).
    forbidden_kinds = {"decoded_fragment", "decode_layer", "op", "operation"}
    return [e for e in tl if (e.get("kind") or "").lower() not in forbidden_kinds]


def _behaviour_execution_chain(cio: Dict[str, Any]) -> List[str]:
    """Chain in behavioural terms — never in decoder-layer terms."""
    graph = cio.get("evidence_graph") or {}
    lolbins = []
    behaviours = []
    for n in graph.get("nodes") or []:
        k = (n.get("kind") or "").lower()
        if k == "lolbin":
            lb = (n.get("attrs") or {}).get("binary") or n.get("label")
            if lb:
                lolbins.append(str(lb))
        elif k in {"behaviour", "behavior"}:
            lbl = n.get("label")
            if lbl:
                behaviours.append(str(lbl))
    chain: List[str] = []
    if lolbins:
        chain.append(f"Living-off-the-land binary invoked ({', '.join(sorted(set(lolbins)))})")
    if behaviours:
        chain.extend(behaviours[:5])
    return chain


def _findings(cio: Dict[str, Any]) -> List[Dict[str, Any]]:
    truth = cio.get("truth") or {}
    return truth.get("findings") or []


def _recommendations(cio: Dict[str, Any]) -> List[Dict[str, Any]]:
    truth = cio.get("truth") or {}
    return truth.get("recommendations") or []


def _containment(cio: Dict[str, Any]) -> str:
    md = cio.get("metadata") or {}
    c = md.get("containment") or md.get("containment_status")
    if c:
        return str(c)
    return "No containment signal recorded in the submitted evidence."


# ─── Section builders ─────────────────────────────────────────────────

def _section_executive(cio: Dict[str, Any], v_label: str, v_pct: int) -> ReportSection:
    hosts = _hosts(cio)
    lolbins = list({
        (n.get("attrs") or {}).get("binary") or n.get("label")
        for n in (cio.get("evidence_graph") or {}).get("nodes", [])
        if (n.get("kind") or "").lower() == "lolbin"
    })
    lolbins = [x for x in lolbins if x]
    urls = _iocs(cio).get("urls") or []
    domains = _iocs(cio).get("domains") or []

    parts: List[str] = []
    parts.append(f"Verdict: **{v_label}** (confidence {v_pct}%).")
    if hosts:
        parts.append(f"Affected host: {hosts[0]}.")
    else:
        parts.append("No affected-host telemetry was included with this submission.")
    if lolbins:
        parts.append(f"Execution vector: {', '.join(lolbins[:2])}.")
    if urls or domains:
        target = (urls or [f"http(s)://{domains[0]}"])[0]
        parts.append(f"Network target: {target}.")
    body = " ".join(parts)
    cites = ["cio.verdict", "cio.entities", "cio.metadata.iocs", "cio.evidence_graph"]
    return ReportSection(1, "Executive Summary", body, cites)


def _section_incident_overview(cio: Dict[str, Any]) -> ReportSection:
    """P0.3 · Evidence-driven overview. Composed from the recovered
    payload, LOLBIN, network targets, and top MITRE technique — never
    a canned "candidate malicious execution vector" placeholder."""
    urls = _iocs(cio).get("urls") or []
    ips = _iocs(cio).get("ips") or []
    domains = _iocs(cio).get("domains") or []
    lolbins = list({
        (n.get("attrs") or {}).get("binary") or n.get("label")
        for n in (cio.get("evidence_graph") or {}).get("nodes", [])
        if (n.get("kind") or "").lower() == "lolbin"
    })
    lolbins = [x for x in lolbins if x]
    mitre = _mitre(cio)
    top_mitre = [
        f"{t['technique_id']} · {t['name']}"
        for t in mitre[:2]
        if t.get("technique_id")
    ]

    # Recovered payload — last decode-chain layer preview.
    recovered = ""
    for layer in reversed(cio.get("decode_chain") or []):
        prev = str(layer.get("preview") or "").strip()
        if prev:
            recovered = prev[:200]
            break

    label = (cio.get("verdict") or {}).get("label", "Undetermined")
    parts: List[str] = []

    if lolbins and recovered:
        parts.append(
            f"The submission triggered {lolbins[0]} with an obfuscated command "
            f"that, once recovered, resolves to `{recovered}`."
        )
    elif recovered:
        parts.append(f"The submission recovers to the command `{recovered}`.")
    elif lolbins:
        parts.append(
            f"The submission invoked {lolbins[0]} in a manner consistent "
            "with abuse of a signed, trusted binary."
        )
    else:
        parts.append("The submission was analysed for malicious behaviour.")

    if urls:
        parts.append(
            f"The recovered command reaches out to **{urls[0]}**, which is "
            "characteristic of second-stage payload staging."
        )
    elif domains:
        parts.append(
            f"The recovered command references the domain **{domains[0]}**, "
            "which is characteristic of remote payload delivery."
        )
    elif ips:
        parts.append(
            f"The recovered command references **{ips[0]}** as a remote "
            "endpoint."
        )

    if top_mitre:
        parts.append(
            "The observed behaviour maps to "
            + " and ".join(f"**{m}**" for m in top_mitre)
            + "."
        )

    if label in ("Malicious", "Suspicious"):
        parts.append(
            f"Aggregate evidence supports a **{label}** verdict — "
            "the sample should be treated as attacker-controlled until "
            "proven otherwise."
        )

    body = " ".join(parts)
    return ReportSection(2, "Incident Overview", body, ["cio.truth.findings", "cio.decode_chain", "cio.evidence_graph"])


def _section_recovered_command(cio: Dict[str, Any]) -> Optional[ReportSection]:
    """P0.3 · Prominent 'Recovered Command / Payload' surface.
    Only rendered when the decoder actually recovered something.
    Returns None otherwise so the composer skips it cleanly."""
    lines: List[str] = []
    dc = cio.get("decode_chain") or []
    # Prefer the LAST layer's preview as the customer-facing "final" form.
    last_preview = ""
    for layer in reversed(dc):
        prev = str(layer.get("preview") or "").strip()
        if prev:
            last_preview = prev
            break
    if not last_preview:
        return None

    lines.append(f"```\n{last_preview[:600]}\n```")

    # Also enumerate intermediate recovered forms in a tight bullet list
    # so the analyst can see the *shape* of the evasion (multi-stage vs
    # single-stage) without ever seeing decoder-op names.
    stages = [str(l.get("preview") or "").strip() for l in dc if l.get("preview")]
    stages = list(dict.fromkeys(stages))  # de-dup preserving order
    if len(stages) > 1:
        lines.append("\nRecovered stages, in order:")
        for i, s in enumerate(stages[:4], start=1):
            snip = _sanitize_customer_text(s[:140])
            lines.append(f"* Stage {i}: `{snip}`")

    body = "\n".join(lines)
    return ReportSection(
        # Provisional number; renumbered later by summary_composer.
        3, "Recovered Command", body, ["cio.decode_chain"],
    )


def _section_affected_hosts(cio: Dict[str, Any]) -> ReportSection:
    hosts = _hosts(cio)
    if hosts:
        body = f"{len(hosts)} host(s): {', '.join(hosts)}."
    else:
        body = "No host telemetry was included with this submission. Add host/agent context to enrich this section."
    return ReportSection(3, "Affected Hosts", body, ["cio.entities.hosts"])


def _section_users(cio: Dict[str, Any]) -> ReportSection:
    users = _users(cio)
    body = f"{', '.join(users)}." if users else "No user account was attributed to the observed activity."
    return ReportSection(4, "Users", body, ["cio.entities.users"])


def _section_detection_source(cio: Dict[str, Any]) -> ReportSection:
    return ReportSection(5, "Detection Source", _detection_source(cio), ["cio.metadata.detection_source"])


def _section_timeline(cio: Dict[str, Any]) -> ReportSection:
    events = _timeline(cio)
    if not events:
        return ReportSection(6, "Timeline", "No timestamped events were included with this submission.", ["cio.metadata.timeline"])
    lines = []
    for e in events[:10]:
        ts = e.get("timestamp") or e.get("t") or "-"
        lbl = e.get("label") or e.get("kind") or "event"
        lines.append(f"* {ts} — {lbl}")
    return ReportSection(6, "Timeline", "\n".join(lines), ["cio.metadata.timeline"])


def _section_execution_chain(cio: Dict[str, Any]) -> ReportSection:
    chain = _behaviour_execution_chain(cio)
    body = "\n".join(f"* {step}" for step in chain) if chain else \
           "Behavioural execution chain could not be resolved."
    return ReportSection(7, "Execution Chain", body, ["cio.evidence_graph"])


def _is_decoder_finding(f: Dict[str, Any]) -> bool:
    """Return True when a Finding is a decoder-pipeline telemetry entry
    (Layer N / op names) rather than a customer-relevant observation."""
    title = str(f.get("title") or f.get("label") or "").lower()
    if re.search(r"\blayer\s*\d+\b", title):
        return True
    for op in ("ps-encodedcommand", "url-decode", "url_decode",
               "crypto-detect", "crypto_detect", "extract-payload",
               "extract_payload", "family-emotet", "ioc-extract",
               "ioc_extract"):
        if op in title:
            return True
    return False


def _sanitize_customer_text(text: str) -> str:
    """Strip decoder-op names from prose so `detail` strings don't leak
    "Layer 0 · ps-encodedcommand-recovery"-style telemetry."""
    out = text
    out = re.sub(r"Layer\s*\d+\s*[:\-·]?\s*[a-z0-9_\-]+", "internal decoder step", out, flags=re.IGNORECASE)
    out = re.sub(r"\bps-encodedcommand[a-z\-_]*", "encoded PowerShell command", out, flags=re.IGNORECASE)
    out = re.sub(r"\bcrypto-detect\b", "cryptographic-content check", out, flags=re.IGNORECASE)
    out = re.sub(r"\burl-decode\b", "URL normalization", out, flags=re.IGNORECASE)
    out = re.sub(r"\bfamily-[a-z]+\b", "malware-family match", out, flags=re.IGNORECASE)
    out = re.sub(r"\bextract-payload\b", "payload extraction", out, flags=re.IGNORECASE)
    out = re.sub(r"\bioc-extract\b", "indicator extraction", out, flags=re.IGNORECASE)
    out = re.sub(r"\bRecovered payload\b", "Observed command", out)
    out = re.sub(r"\boperation history\b", "processing steps", out, flags=re.IGNORECASE)
    # Canonical MITRE technique names sometimes embed pipeline vocabulary
    # ("Command Obfuscation: Base64/Encoded Command", "… UTF-16 …") that
    # would leak past the persona hygiene gate. Strip those prefixes so
    # every downstream surface reads the same customer-safe name.
    out = re.sub(r"\bBase64/", "", out, flags=re.IGNORECASE)
    out = re.sub(r"\bBase64\b", "encoded", out, flags=re.IGNORECASE)
    out = re.sub(r"\bUTF-?16\b", "encoded text", out, flags=re.IGNORECASE)
    out = re.sub(r"\s{2,}", " ", out)
    return out


def _section_evidence(cio: Dict[str, Any]) -> ReportSection:
    """P0.3 · Human-readable evidence surface. Reads the analyst-facing
    finding fields (title + severity + evidence anchor) instead of
    dumping `class=high · weight=3.0 · source=graph` telemetry."""
    findings = [f for f in _findings(cio) if not _is_decoder_finding(f)][:6]
    if not findings:
        return ReportSection(8, "Evidence", "No high-signal findings were recorded.", ["cio.truth.findings"])
    lines = []
    for f in findings:
        title = _sanitize_customer_text(str(f.get("title") or f.get("label") or "Finding"))
        sev = str(f.get("severity") or "info").lower()
        detail_raw = str(f.get("detail") or "")
        # Drop backend telemetry markers from the detail line: only keep
        # analyst-legible prose. If the remaining text is telemetry
        # noise (e.g. "class=high · weight=3.0"), we drop it and rely
        # on the title alone — the severity is what analysts actually
        # need.
        detail = _sanitize_customer_text(detail_raw)
        detail = re.sub(r"(?:^|\s·\s)\s*class=[^\s·]+", "", detail)
        detail = re.sub(r"(?:^|\s·\s)\s*weight=[^\s·]+", "", detail)
        detail = re.sub(r"(?:^|\s·\s)\s*confidence=[^\s·]+", "", detail)
        detail = re.sub(r"(?:^|\s·\s)\s*source=[^\s·]+", "", detail)
        detail = re.sub(r"[\s·]+$", "", detail).strip(" ·")
        detail = re.sub(r"^[a-z_]+_correlated\b", "", detail).strip(" ·")
        detail = re.sub(r"^invoke_expression\b", "", detail).strip(" ·")
        detail = re.sub(r"^lolbin\b", "", detail).strip(" ·")
        detail = re.sub(r"^network_staging\b", "", detail).strip(" ·")
        if detail:
            lines.append(f"* **{title}** ({sev}) — {detail}")
        else:
            lines.append(f"* **{title}** ({sev})")
    return ReportSection(8, "Evidence", "\n".join(lines), ["cio.truth.findings"])


def _section_hashes(cio: Dict[str, Any]) -> ReportSection:
    h = _hashes(cio)
    total = sum(len(v) for v in h.values())
    if total == 0:
        return ReportSection(9, "File Hashes", "No file hashes were extracted or provided.", ["cio.metadata.iocs"])
    lines = []
    for algo in ("sha256", "sha1", "md5"):
        for val in h.get(algo, []):
            lines.append(f"* {algo.upper()}: `{val}`")
    return ReportSection(9, "File Hashes", "\n".join(lines), ["cio.metadata.iocs"])


def _section_iocs(cio: Dict[str, Any]) -> ReportSection:
    iocs = _iocs(cio)
    if not iocs:
        return ReportSection(10, "IOCs", "No IOCs extracted.", ["cio.metadata.iocs"])
    lines = []
    for kind in ("urls", "domains", "ips", "emails", "sha256", "sha1", "md5"):
        vals = iocs.get(kind) or []
        for v in vals[:8]:
            lines.append(f"* {kind.upper()[:-1] if kind.endswith('s') else kind.upper()}: `{v}`")
    return ReportSection(10, "IOCs", "\n".join(lines) or "No IOCs extracted.", ["cio.metadata.iocs"])


def _section_threat_intel(cio: Dict[str, Any]) -> ReportSection:
    osint = _osint(cio)
    if not osint:
        return ReportSection(11, "Threat Intelligence", "No OSINT enrichment was performed for this investigation.", ["cio.metadata.osint"])
    lines: List[str] = []
    live = osint.get("live") or {}
    for kind, entries in live.items():
        if not entries:
            continue
        lines.append(f"* **{kind.upper()}**:")
        for e in (entries if isinstance(entries, list) else [entries])[:3]:
            for provider, data in (e.items() if isinstance(e, dict) else []):
                if isinstance(data, dict):
                    kv = ", ".join(f"{k}={v}" for k, v in list(data.items())[:4])
                    lines.append(f"  * {provider}: {kv}")
    return ReportSection(11, "Threat Intelligence", "\n".join(lines) or "OSINT ran but returned no populated providers.", ["cio.metadata.osint"])


def _section_mitre(cio: Dict[str, Any]) -> ReportSection:
    m = _mitre(cio)
    if not m:
        return ReportSection(12, "MITRE ATT&CK", "No MITRE techniques were mapped.", ["cio.evidence_graph"])

    def _customer_safe(name: str) -> str:
        # Canonical MITRE names sometimes carry pipeline-flavour terms
        # ("Base64/Encoded Command", "UTF-16 …"). Rewrite them so the
        # customer persona hygiene gate stays clean without altering the
        # technique_id (which is the analyst-relevant handle).
        n = name
        n = re.sub(r"\bBase64/?", "", n, flags=re.IGNORECASE)
        n = re.sub(r"\bUTF-?16\b", "", n, flags=re.IGNORECASE)
        n = re.sub(r"\s{2,}", " ", n).strip(" :·-")
        return n

    by_tactic: Dict[str, List[str]] = {}
    for t in m:
        safe_name = _customer_safe(t["name"])
        by_tactic.setdefault(t["tactic"] or "Unspecified", []).append(f"{t['technique_id']} · {safe_name}")
    lines = []
    for tactic, techs in by_tactic.items():
        lines.append(f"* **{tactic}**: {'; '.join(techs)}")
    return ReportSection(12, "MITRE ATT&CK", "\n".join(lines), ["cio.evidence_graph"])


def _section_impact(cio: Dict[str, Any]) -> ReportSection:
    v = cio.get("verdict") or {}
    label = v.get("label") or "Undetermined"
    if label == "Malicious":
        body = "Any endpoint that executed this payload should be considered compromised until proven otherwise."
    elif label == "Suspicious":
        body = "Behaviour is anomalous. Assess business impact before acting; corroborate with additional telemetry."
    else:
        body = "No direct business impact assessed. Retain for correlation with future events."
    return ReportSection(13, "Impact Assessment", body, ["cio.verdict"])


def _section_containment(cio: Dict[str, Any]) -> ReportSection:
    return ReportSection(14, "Containment Status", _containment(cio), ["cio.metadata.containment"])


def _section_analyst_verdict(cio: Dict[str, Any]) -> ReportSection:
    v = cio.get("verdict") or {}
    label = v.get("label") or "Undetermined"
    pct = v.get("confidence_pct") or 0
    rule = v.get("escalation_rule")
    reason = _sanitize_customer_text(str(v.get("reason") or ""))
    body = f"**{label}** at {pct}% confidence."
    if rule:
        body += f" Escalation rule fired: `{rule}`."
    if reason:
        body += f" {reason}"
    return ReportSection(15, "Analyst Verdict", body, ["cio.verdict"])


def _section_recommendations(cio: Dict[str, Any]) -> ReportSection:
    recs = _recommendations(cio)
    if not recs:
        return ReportSection(16, "Recommendations", "No specific analyst actions required.", ["cio.truth.recommendations"])
    lines = []
    for r in recs:
        action = r.get("action") or "action"
        priority = r.get("priority") or "p2"
        detail = r.get("detail") or r.get("label") or ""
        lines.append(f"* **{action.upper()}** ({priority}): {detail}")
    return ReportSection(16, "Recommendations", "\n".join(lines), ["cio.truth.recommendations"])


# ─── Public entry ─────────────────────────────────────────────────────

def compose_customer_report(cio: Any, persona: str = "customer") -> CustomerReport:
    """Produce a persona-aware Customer / Investigation Report.

    Never mentions the decoder pipeline. Every section reads only from
    canonical CIO fields. See module docstring for the section order.
    """
    if hasattr(cio, "model_dump"):
        cio = cio.model_dump()
    if persona not in {"customer", "threat_hunt", "forensic", "decoder"}:
        raise ValueError(f"unknown persona: {persona!r}")

    v = cio.get("verdict") or {}
    v_label = v.get("label") or "Undetermined"
    v_pct = int(v.get("confidence_pct") or 0)

    sections_raw = [
        _section_executive(cio, v_label, v_pct),
        _section_incident_overview(cio),
        _section_recovered_command(cio),   # P0.3 · optional; None when nothing recovered
        _section_affected_hosts(cio),
        _section_users(cio),
        _section_detection_source(cio),
        _section_timeline(cio),
        _section_execution_chain(cio),
        _section_evidence(cio),
        _section_hashes(cio),
        _section_iocs(cio),
        _section_threat_intel(cio),
        _section_mitre(cio),
        _section_impact(cio),
        _section_containment(cio),
        _section_analyst_verdict(cio),
        _section_recommendations(cio),
    ]
    sections = [s for s in sections_raw if s is not None]

    report = CustomerReport(persona=persona, verdict=v_label, verdict_confidence_pct=v_pct, sections=sections)

    # Operator-locked narrative lexicon gate — rewrites any leftover
    # implementation-detail term (pipeline / decoder / verdict engine /
    # ...) with analyst-style equivalents before the report is exposed.
    try:
        from .narrative_lexicon_gate import sanitize as _lex_sanitize
        for s in report.sections:
            s.body = _lex_sanitize(s.body)
    except ImportError:  # pragma: no cover
        pass

    # Hygiene gate — forbidden decoder-telemetry vocabulary must never
    # reach a customer-like persona.
    if persona in CUSTOMER_LIKE_PERSONAS:
        combined = " ".join(s.body for s in sections)
        for term in FORBIDDEN_TERMS:
            if re.search(rf"\b{re.escape(term)}\b", combined, flags=re.IGNORECASE):
                raise ValueError(
                    f"Customer report ({persona}) contained forbidden "
                    f"decoder-telemetry term: {term!r}. See composer contract."
                )
    return report


__all__ = [
    "compose_customer_report", "CustomerReport", "ReportSection",
    "FORBIDDEN_TERMS", "CUSTOMER_LIKE_PERSONAS",
]
