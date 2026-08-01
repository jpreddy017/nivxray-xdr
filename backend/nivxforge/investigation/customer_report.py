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
    return {k: [v for v in vs if v] for k, vs in iocs.items()}


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
    truth = cio.get("truth") or {}
    findings = [f for f in (truth.get("findings") or []) if not _is_decoder_finding(f)]
    top = findings[0] if findings else {}
    body = (top.get("detail") or top.get("title") or
            "Behavioural analysis identified the observed input as a "
            "candidate malicious execution vector.")
    body = _sanitize_customer_text(str(body))
    return ReportSection(2, "Incident Overview", body, ["cio.truth.findings"])


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
    out = re.sub(r"\burl-decode\b", "URL decode", out, flags=re.IGNORECASE)
    out = re.sub(r"\bfamily-[a-z]+\b", "malware-family match", out, flags=re.IGNORECASE)
    out = re.sub(r"\bextract-payload\b", "payload extraction", out, flags=re.IGNORECASE)
    out = re.sub(r"\bioc-extract\b", "indicator extraction", out, flags=re.IGNORECASE)
    out = re.sub(r"\bRecovered payload\b", "Observed command", out)
    out = re.sub(r"\boperation history\b", "processing steps", out, flags=re.IGNORECASE)
    return out


def _section_evidence(cio: Dict[str, Any]) -> ReportSection:
    findings = [f for f in _findings(cio) if not _is_decoder_finding(f)][:5]
    if not findings:
        return ReportSection(8, "Evidence", "No high-signal findings were recorded.", ["cio.truth.findings"])
    lines = []
    for f in findings:
        title = _sanitize_customer_text(str(f.get("title") or f.get("label") or "Finding"))
        sev = f.get("severity") or "info"
        detail = _sanitize_customer_text(str(f.get("detail") or ""))
        lines.append(f"* **{title}** — severity {sev}. {detail}")
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
    by_tactic: Dict[str, List[str]] = {}
    for t in m:
        by_tactic.setdefault(t["tactic"] or "Unspecified", []).append(f"{t['technique_id']} · {t['name']}")
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

    sections = [
        _section_executive(cio, v_label, v_pct),
        _section_incident_overview(cio),
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

    report = CustomerReport(persona=persona, verdict=v_label, verdict_confidence_pct=v_pct, sections=sections)

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
