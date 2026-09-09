"""
NIST SP 800-61 r2 · Incident Report renderer (2026-03-02)
─────────────────────────────────────────────────────────
DETERMINISTIC.  Zero LLM.

Provides two renderers over a Session envelope:

  render_markdown(session) → str
  render_pdf(session)      → bytes

The markdown structure mirrors the L4 architecture blueprint (9
sections + Analyst Summary + IOC Intelligence).  The PDF uses
reportlab (already installed) with a Cisco-XDR-styled cover page +
per-section pages.
"""
from __future__ import annotations
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph, Spacer, PageBreak, SimpleDocTemplate,
    Table, TableStyle,
)

from .summary_narrative import build_narrative


# ═══════════════════════════════════════════════════════════════════
# Markdown
# ═══════════════════════════════════════════════════════════════════
def render_markdown(session: Dict[str, Any]) -> str:
    inc  = session.get("incident") or {}
    narr = session.get("summary_narrative") or build_narrative(session)
    sum_ = inc.get("summary") or {}
    ready = inc.get("readiness") or {}
    rec   = narr.get("recommendations") or {}
    prov  = inc.get("provenance") or {}
    lines: List[str] = []

    lines.append("# NIST SP 800-61 r2 · Incident Report")
    lines.append("")
    lines.append(f"- **Session**: {session.get('session_id', 'n/a')}")
    lines.append(f"- **Generated**: {datetime.now(timezone.utc).isoformat()}")
    src = f"{prov.get('source_vendor') or ''} · {prov.get('source_url') or ''}".strip(" ·")
    if src: lines.append(f"- **Source**: {src}")
    lines.append("")

    # 1 · Executive Summary
    ex = narr.get("executive_summary") or {}
    lines.append("## 1. Executive Investigation Summary")
    lines.append("")
    if ex.get("paragraph"): lines.append(ex["paragraph"])
    lines.append("")
    lines.append(f"**Overall Risk**: {ex.get('risk') or 'Unknown'}   |   "
                  f"**Confidence**: {ex.get('confidence') or 0}%")
    lines.append("")

    # 2 · Analyst Summary
    lines.append("## 2. Analyst Summary")
    lines.append("")
    lines.append(narr.get("analyst_summary") or "_No analyst summary available._")
    lines.append("")

    # 3 · Behavior Summary
    lines.append("## 3. Observed Behaviour")
    lines.append("")
    behaviors = narr.get("behavior_summary") or []
    if behaviors:
        for b in behaviors:
            lines.append(f"- ✓ {b.get('label')}")
    else:
        lines.append("_No behaviours observed._")
    lines.append("")

    # 4 · Attack Intent
    lines.append("## 4. Attack Intent")
    lines.append("")
    lines.append(narr.get("attack_intent") or "_Not determined._")
    lines.append("")

    # 5 · Impact Assessment
    imp = narr.get("impact_assessment") or {}
    lines.append("## 5. Potential Impact")
    lines.append("")
    for b in (imp.get("bullets") or []):
        lines.append(f"- {b}")
    lines.append("")
    lines.append(f"**Likelihood**: {imp.get('likelihood') or 'Unknown'}")
    lines.append("")

    # 6 · MITRE Summary
    lines.append("## 6. MITRE ATT&CK Summary")
    lines.append("")
    for group in (narr.get("mitre_summary") or []):
        lines.append(f"### {group['tactic']}")
        for t in group.get("techniques") or []:
            lines.append(f"- **{t.get('id')}** {t.get('name') or ''}")
        lines.append("")
    if not narr.get("mitre_summary"):
        lines.append("_No MITRE mapping._")
        lines.append("")

    # 7 · IOC Intelligence
    lines.append("## 7. IOC Intelligence")
    lines.append("")
    iocs = narr.get("ioc_intelligence") or []
    if iocs:
        lines.append("| Kind | Indicator | Reputation | VT | AbuseIPDB | Passive DNS |")
        lines.append("|------|-----------|------------|----|-----------|--------------|")
        for i in iocs:
            vt = _fmt_pending(i.get("virustotal"), "ratio")
            ai = _fmt_pending(i.get("abuseipdb"), "score")
            pd = _fmt_pending(i.get("passive_dns"), "first_seen")
            rep = i.get("reputation", {}).get("verdict") or "unknown"
            lines.append(f"| {i['kind']} | `{i['value']}` | {rep} | {vt} | {ai} | {pd} |")
        lines.append("")
        lines.append("_Fields marked `pending` require an OSINT integration (VT / AbuseIPDB / Passive DNS)._")
    else:
        lines.append("_No IOCs correlated._")
    lines.append("")

    # 8 · Recommendations
    lines.append("## 8. Recommendations")
    lines.append("")
    for bucket, label in (("immediate", "Immediate"),
                            ("hunting",   "Threat Hunting"),
                            ("containment", "Containment")):
        lines.append(f"### {label}")
        for item in rec.get(bucket) or []:
            lines.append(f"- {item}")
        lines.append("")

    # 9 · Evidence Confidence
    ec = narr.get("evidence_confidence") or {}
    lines.append("## 9. Evidence Confidence")
    lines.append("")
    cmd = ec.get("commands") or {}
    lines.append(f"- **Commands**: {cmd.get('investigated', 0)}/{cmd.get('total', 0)} investigated")
    lines.append(f"- **MITRE**: {(ec.get('mitre') or {}).get('count', 0)} technique(s) mapped")
    lines.append(f"- **IOCs**: {(ec.get('iocs') or {}).get('count', 0)} correlated")
    lines.append(f"- **Threat Intelligence**: {(ec.get('threat_intel') or {}).get('state', 'pending')}")
    lines.append(f"- **Evidence Completeness**: {ec.get('completeness_percent', 0)}%")
    lines.append("")

    # 10 · Readiness + gaps
    lines.append("## 10. Investigation Readiness")
    lines.append("")
    lines.append(f"- Overall: **{ready.get('overall_percent') or 0}%** · "
                  f"{(ready.get('confidence_label') or 'n/a')}")
    if ready.get("recommended_next"):
        lines.append(f"- Next: {ready['recommended_next']}")
    for b in (ready.get("bars") or []):
        lines.append(f"  - {b.get('dim')}: {b.get('percent')}% ({b.get('state')})")
    lines.append("")

    # Provenance
    lines.append("## 11. Provenance")
    lines.append("")
    lines.append(f"- Source URL: {prov.get('source_url') or '—'}")
    lines.append(f"- Source Vendor: {prov.get('source_vendor') or '—'}")
    lines.append(f"- Source Title: {prov.get('source_title') or '—'}")
    lines.append(f"- Fetched Bytes: {prov.get('acquired_bytes') or '—'}")
    lines.append("")
    lines.append("---")
    lines.append("_Generated deterministically from the SSOT._")
    return "\n".join(lines)


def _fmt_pending(field: Any, key: str) -> str:
    if not field: return "—"
    if field.get("source") == "pending": return "_pending_"
    v = field.get(key)
    return str(v) if v is not None else "—"


# ═══════════════════════════════════════════════════════════════════
# PDF (reportlab · deterministic)
# ═══════════════════════════════════════════════════════════════════
_GREEN = colors.HexColor("#0d3d24")
_ACCENT = colors.HexColor("#3ddc84")
_DARK   = colors.HexColor("#001a0d")
_SUBTLE = colors.HexColor("#7ee6a8")
_TEXT   = colors.HexColor("#c5f5d6")


def _styles():
    ss = getSampleStyleSheet()
    return {
        "title":  ParagraphStyle("t",  parent=ss["Heading1"], fontSize=22,
                                   textColor=colors.white, leading=26),
        "h2":     ParagraphStyle("h2", parent=ss["Heading2"], fontSize=13,
                                   textColor=_GREEN, spaceBefore=12,
                                   spaceAfter=6, leading=16),
        "h3":     ParagraphStyle("h3", parent=ss["Heading3"], fontSize=11,
                                   textColor=colors.HexColor("#333"),
                                   spaceBefore=8, spaceAfter=4, leading=14),
        "body":   ParagraphStyle("b", parent=ss["BodyText"], fontSize=10,
                                   leading=14, alignment=TA_LEFT,
                                   textColor=colors.HexColor("#222")),
        "meta":   ParagraphStyle("m", parent=ss["BodyText"], fontSize=9,
                                   textColor=colors.HexColor("#555"),
                                   leading=12),
        "eyebrow": ParagraphStyle("e", parent=ss["BodyText"], fontSize=8,
                                    textColor=_SUBTLE, leading=10,
                                    spaceAfter=4),
        "coverEyebrow": ParagraphStyle("ce", parent=ss["BodyText"], fontSize=9,
                                          textColor=_ACCENT, leading=11,
                                          spaceAfter=6),
        "coverBody":    ParagraphStyle("cb", parent=ss["BodyText"], fontSize=11,
                                          textColor=colors.white, leading=15),
    }


def _cover_page(story: List, session: Dict[str, Any],
                  narr: Dict[str, Any], st: Dict[str, ParagraphStyle]):
    sid   = session.get("session_id") or "n/a"
    when  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    inc   = session.get("incident") or {}
    isum  = inc.get("summary") or {}
    ex    = narr.get("executive_summary") or {}
    prof  = session.get("document_profile") or {}
    src   = prof.get("vendor") or (session.get("acquired_document") or {}).get("sitename") or "—"
    title = isum.get("title") or prof.get("title") or "Investigation"

    story.append(Paragraph("NIVXRAY · INCIDENT REPORT", st["coverEyebrow"]))
    story.append(Paragraph(title, st["title"]))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph(f"Session {sid} · Generated {when}", st["meta"]))
    story.append(Spacer(1, 0.35 * inch))

    tbl = Table(
        [
            ["Actor",      isum.get("actor") or "unattributed"],
            ["Objective",  isum.get("objective") or "under investigation"],
            ["Severity",   (isum.get("severity") or "unknown").upper()],
            ["Confidence", f"{isum.get('confidence_percent') or 0}%"],
            ["Risk",       ex.get("risk") or "Unknown"],
            ["Source",     src],
        ],
        colWidths=[1.4 * inch, 5.2 * inch],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef7f0")),
        ("BACKGROUND", (1, 0), (1, -1), colors.white),
        ("TEXTCOLOR",  (0, 0), (0, -1), _GREEN),
        ("TEXTCOLOR",  (1, 0), (1, -1), colors.HexColor("#111")),
        ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 10),
        ("LEFTPADDING",(0, 0), (-1, -1), 8),
        ("RIGHTPADDING",(0, 0),(-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ("BOX",        (0, 0), (-1, -1), 0.4, colors.HexColor("#cfd8d0")),
        ("INNERGRID",  (0, 0), (-1, -1), 0.3, colors.HexColor("#e2ebe4")),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.35 * inch))

    story.append(Paragraph("EXECUTIVE SUMMARY", st["eyebrow"]))
    paragraphs = ex.get("paragraphs") or [ex.get("paragraph") or "—"]
    for p in paragraphs:
        story.append(Paragraph(p, st["body"]))
        story.append(Spacer(1, 0.06 * inch))
    story.append(Spacer(1, 0.1 * inch))

    story.append(Paragraph("ANALYST SUMMARY", st["eyebrow"]))
    story.append(Paragraph(narr.get("analyst_summary") or "—", st["body"]))
    story.append(PageBreak())


def _section_paragraphs(story, heading, body_html, st):
    story.append(Paragraph(heading, st["h2"]))
    if isinstance(body_html, list):
        for line in body_html:
            story.append(Paragraph(line, st["body"]))
    else:
        story.append(Paragraph(body_html, st["body"]))
    story.append(Spacer(1, 0.1 * inch))


def render_pdf(session: Dict[str, Any]) -> bytes:
    narr = session.get("summary_narrative") or build_narrative(session)
    inc  = session.get("incident") or {}
    isum = inc.get("summary") or {}
    ready = inc.get("readiness") or {}
    raw   = session.get("raw_investigation") or {}
    ext   = raw.get("report_extraction") or {}
    comp  = inc.get("completeness") or {}

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
        topMargin=0.7 * inch,  bottomMargin=0.7 * inch,
        title=f"NivXRay Incident Report {session.get('session_id') or ''}",
    )
    st = _styles()
    story: List = []

    # ── COVER (dark card) ────────────────────────────────────────
    cover = Table(
        [[""]], colWidths=[7.1 * inch], rowHeights=[0.05 * inch],
    )
    cover.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), _ACCENT)]))
    story.append(cover)
    story.append(Spacer(1, 0.15 * inch))
    _cover_page(story, session, narr, st)

    # ── Observed behaviour ──────────────────────────────────────
    bs = [f"• {b.get('label')}" for b in (narr.get("behavior_summary") or [])]
    _section_paragraphs(story, "3 · Observed Behaviour",
                          bs or ["No behaviours observed."], st)

    # ── Attack intent ───────────────────────────────────────────
    _section_paragraphs(story, "4 · Attack Intent",
                          narr.get("attack_intent") or "—", st)

    # ── Impact ──────────────────────────────────────────────────
    imp = narr.get("impact_assessment") or {}
    _section_paragraphs(story, "5 · Potential Impact",
                          [f"• {b}" for b in (imp.get("bullets") or [])] +
                          [f"<b>Likelihood:</b> {imp.get('likelihood') or 'Unknown'}"],
                          st)

    # ── Attack Lifecycle (NIST DE-1 / DE-2) ─────────────────────
    # A per-tactic walkthrough with observed commands, matching the
    # depth vendors publish in their engagement reports.
    _attack_lifecycle_section(story, inc, ext, st)

    # ── Attack Timeline (dated events from acquired source) ─────
    _timeline_section(story, narr, ext, st)

    # ── Threat Actors + Malware Families + CVEs ─────────────────
    _actors_malware_cves_section(story, ext, st)

    # ── Command Lines Observed (deterministic evidence) ─────────
    _commands_section(story, ext, st)

    # ── Registry Modifications + File Artifacts observed ────────
    _artifacts_section(story, ext, st)

    # ── MITRE ───────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("10 · MITRE ATT&amp;CK Summary", st["h2"]))
    for g in (narr.get("mitre_summary") or []):
        story.append(Paragraph(g["tactic"], st["h3"]))
        for t in g.get("techniques") or []:
            story.append(Paragraph(
                f"<b>{t.get('id') or ''}</b> — {t.get('name') or ''}", st["body"],
            ))
    if not narr.get("mitre_summary"):
        story.append(Paragraph("No MITRE mapping.", st["body"]))

    # ── IOC intelligence table ──────────────────────────────────
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph("11 · IOC Intelligence", st["h2"]))
    iocs = narr.get("ioc_intelligence") or []
    if iocs:
        data = [["KIND", "INDICATOR", "FILENAME / CONTEXT", "REPUTATION", "VT"]]
        for i in iocs[:40]:
            fn   = i.get("filename")    or ""
            desc = i.get("description") or ""
            context = (fn + (f"  ({desc})" if desc else "")) or "—"
            data.append([
                i["kind"].upper(),
                (i.get("value") or "")[:52],
                context[:52],
                (i.get("reputation") or {}).get("verdict") or "unknown",
                _fmt_pending(i.get("virustotal"), "ratio"),
            ])
        tbl = Table(data, colWidths=[0.55*inch, 2.6*inch, 2.2*inch,
                                        0.85*inch, 0.7*inch])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), _GREEN),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 7.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING",(0, 0), (-1, -1), 4),
            ("TOPPADDING",  (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",(0,0), (-1, -1), 3),
            ("BOX",         (0, 0), (-1, -1), 0.4, colors.HexColor("#cfd8d0")),
            ("INNERGRID",   (0, 0), (-1, -1), 0.3, colors.HexColor("#e2ebe4")),
            ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(tbl)
        story.append(Paragraph(
            "<i>Filename / context extracted from the source's IOC table. "
            "Reputation columns marked <b>pending</b> require an OSINT integration.</i>",
            st["meta"],
        ))
    else:
        story.append(Paragraph("No IOCs correlated.", st["body"]))

    # ── Recommendations — full NIST bucketing ───────────────────
    rec = narr.get("recommendations") or {}
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph("12 · Recommendations (NIST SP 800-61 r2)", st["h2"]))
    for bucket, label in (
        ("immediate",   "Immediate Response"),
        ("containment", "Containment"),
        ("eradication", "Eradication"),
        ("recovery",    "Recovery"),
        ("hunting",     "Threat Hunting"),
        ("lessons",     "Lessons Learned / Post-Incident"),
    ):
        items = rec.get(bucket) or _default_recs(bucket, inc, ext)
        if not items:
            continue
        story.append(Paragraph(label, st["h3"]))
        for item in items:
            story.append(Paragraph(f"• {item}", st["body"]))

    # ── Evidence Confidence + Gaps ──────────────────────────────
    ec  = narr.get("evidence_confidence") or {}
    cmd = ec.get("commands") or {}
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph("13 · Evidence Confidence", st["h2"]))
    for line in [
        f"<b>Commands:</b> {cmd.get('investigated', 0)}/{cmd.get('total', 0)} investigated",
        f"<b>MITRE:</b> {(ec.get('mitre') or {}).get('count', 0)} techniques mapped",
        f"<b>IOCs:</b> {(ec.get('iocs') or {}).get('count', 0)} correlated",
        f"<b>Threat Intelligence:</b> {(ec.get('threat_intel') or {}).get('state', 'pending')}",
        f"<b>Evidence Completeness:</b> {ec.get('completeness_percent', 0)}%",
    ]:
        story.append(Paragraph(line, st["body"]))

    # Evidence coverage breakdown per dimension
    if comp.get("dimensions"):
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph("Coverage by Evidence Dimension", st["h3"]))
        data = [["DIMENSION", "STATE", "FOUND"]]
        for d in comp["dimensions"]:
            state = d.get("state") or "—"
            found = d.get("found")
            if found is None:
                found = "—"
            data.append([d.get("dim") or "—", state.upper(), str(found)])
        tbl = Table(data, colWidths=[3.4*inch, 1.4*inch, 1.4*inch])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), _GREEN),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 9),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",(0, 0), (-1, -1), 6),
            ("TOPPADDING",  (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",(0,0), (-1, -1), 3),
            ("BOX",         (0, 0), (-1, -1), 0.4, colors.HexColor("#cfd8d0")),
            ("INNERGRID",   (0, 0), (-1, -1), 0.3, colors.HexColor("#e2ebe4")),
        ]))
        story.append(tbl)

    # ── Readiness ───────────────────────────────────────────────
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph("14 · Investigation Readiness", st["h2"]))
    story.append(Paragraph(
        f"<b>Overall:</b> {ready.get('overall_percent') or 0}% · "
        f"{(ready.get('confidence_label') or 'n/a').upper()}",
        st["body"],
    ))
    if ready.get("recommended_next"):
        story.append(Paragraph(f"<b>Next:</b> {ready['recommended_next']}", st["body"]))

    story.append(Spacer(1, 0.25 * inch))
    story.append(Paragraph(
        "Generated deterministically from the SSOT · Zero LLM · "
        f"NivXRay Incident Report · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        st["meta"],
    ))
    doc.build(story)
    buf.seek(0)
    return buf.getvalue()


# ═══════════════════════════════════════════════════════════════════
# NIST-depth section builders (deterministic, SSOT-driven)
# ═══════════════════════════════════════════════════════════════════
_TACTIC_ORDER = [
    ("initial_access",       "Initial Access"),
    ("execution",            "Execution"),
    ("persistence",          "Persistence"),
    ("privilege_escalation", "Privilege Escalation"),
    ("defense_evasion",      "Defense Evasion"),
    ("credential_access",    "Credential Access"),
    ("discovery",            "Discovery"),
    ("lateral_movement",     "Lateral Movement"),
    ("collection",           "Collection"),
    ("command_and_control",  "Command and Control"),
    ("exfiltration",         "Exfiltration"),
    ("impact",               "Impact"),
]


def _attack_lifecycle_section(story, inc, ext, st):
    """Walk the MITRE kill chain and, per tactic, list the behaviors
    (with MITRE IDs) and the actual observed commands.  Mirrors the
    per-tactic walkthrough Talos / Mandiant / CrowdStrike publish."""
    behaviors = inc.get("behaviors") or []
    if not behaviors:
        return
    by_tactic: Dict[str, List[Dict[str, Any]]] = {}
    for b in behaviors:
        t = b.get("primary_tactic") or "execution"
        by_tactic.setdefault(t, []).append(b)

    story.append(PageBreak())
    story.append(Paragraph("6 · Attack Lifecycle (Cyber Kill Chain × MITRE ATT&amp;CK)",
                              st["h2"]))
    story.append(Paragraph(
        "The observed activity mapped to the MITRE ATT&amp;CK tactics below. "
        "Each phase lists the behaviors NivXRay derived from the source, "
        "the MITRE technique IDs, and the actual command line evidence.",
        st["body"],
    ))

    any_shown = False
    for key, label in _TACTIC_ORDER:
        bucket = by_tactic.get(key) or []
        if not bucket:
            continue
        any_shown = True
        story.append(Paragraph(label, st["h3"]))
        for b in bucket:
            mitre_ids = ", ".join([m.get("id") or "" for m in (b.get("mitre") or [])]) or "—"
            story.append(Paragraph(
                f"<b>{b.get('label')}</b>  <font color='#555'>[{mitre_ids}]</font>  "
                f"— {b.get('command_count', 0)} observed · confidence <b>{b.get('confidence','low').upper()}</b>",
                st["body"],
            ))
            for c in (b.get("commands") or [])[:3]:
                cmd = c.get("command") or ""
                if cmd:
                    story.append(Paragraph(
                        f"&nbsp;&nbsp;&nbsp;<font color='#374151' face='Courier'>{_escape(cmd[:220])}</font>",
                        st["body"],
                    ))
        story.append(Spacer(1, 0.08 * inch))
    if not any_shown:
        story.append(Paragraph("No behaviors mapped to tactics yet.", st["body"]))


def _timeline_section(story, narr, ext, st):
    """Render the reconstructed attack timeline — ordered dated
    events extracted from the acquired article."""
    events = (narr.get("attack_timeline")
              or ext.get("timeline")
              or [])
    if not events:
        return
    story.append(Spacer(1, 0.12 * inch))
    story.append(Paragraph(
        f"6.5 · Attack Timeline ({len(events)} dated event(s))", st["h2"],
    ))
    story.append(Paragraph(
        "Chronological events NivXRay reconstructed from the acquired "
        "source's narrative — absolute dates first, then relative markers.",
        st["meta"],
    ))
    data = [["DATE", "EVENT"]]
    for e in events[:20]:
        data.append([(e.get("date") or "—")[:40],
                       (e.get("event") or "")[:180]])
    tbl = Table(data, colWidths=[1.3*inch, 5.4*inch])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), _GREEN),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",(0, 0), (-1, -1), 5),
        ("TOPPADDING",  (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0,0), (-1, -1), 3),
        ("BOX",         (0, 0), (-1, -1), 0.4, colors.HexColor("#cfd8d0")),
        ("INNERGRID",   (0, 0), (-1, -1), 0.3, colors.HexColor("#e2ebe4")),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(tbl)


def _actors_malware_cves_section(story, ext, st):
    """Threat Actors + Malware Families + CVEs — deterministic
    extraction from the acquired article."""
    actors  = ext.get("threat_actors")     or []
    malware = ext.get("malware_families")  or []
    cves    = ext.get("cves")              or []
    if not (actors or malware or cves):
        return
    story.append(Spacer(1, 0.12 * inch))
    story.append(Paragraph("7 · Attribution &amp; Named Signals", st["h2"]))

    if actors:
        story.append(Paragraph("Threat Actor(s)", st["h3"]))
        for a in actors:
            story.append(Paragraph(f"• <b>{a.get('name')}</b>", st["body"]))
    if malware:
        story.append(Paragraph("Malware / Toolset Referenced", st["h3"]))
        for m in malware:
            story.append(Paragraph(f"• <b>{m.get('name')}</b>", st["body"]))
    if cves:
        story.append(Paragraph("CVEs Referenced", st["h3"]))
        for c in cves:
            cid = c.get("id") or "—"
            story.append(Paragraph(f"• <b>{cid}</b>", st["body"]))


def _commands_section(story, ext, st):
    """Full command-line evidence: executable + arguments per command."""
    cmds = ext.get("commands") or []
    if not cmds:
        return
    story.append(Spacer(1, 0.12 * inch))
    story.append(Paragraph(f"8 · Command Lines Observed ({len(cmds)})", st["h2"]))
    story.append(Paragraph(
        "Each row shows the atomic command NivXRay reconstructed from the "
        "source, its purpose classification, and its argument list. "
        "Command line is the primary investigation object; the executable "
        "path is an embedded artifact.",
        st["meta"],
    ))
    data = [["#", "PURPOSE", "EXECUTABLE", "ARGS"]]
    for i, c in enumerate(cmds[:20], start=1):
        exe  = c.get("executable") or "—"
        args = c.get("arguments")  or []
        args_str = " ".join(args)
        if len(args_str) > 90:
            args_str = args_str[:88] + "…"
        data.append([str(i),
                       (c.get("purpose") or "—")[:32],
                       exe[:34],
                       args_str])
    tbl = Table(data, colWidths=[0.3*inch, 2.0*inch, 2.2*inch, 2.6*inch])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), _GREEN),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME",    (2, 1), (-1, -1), "Courier"),
        ("FONTSIZE",    (0, 0), (-1, -1), 7.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",(0, 0), (-1, -1), 4),
        ("TOPPADDING",  (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0,0), (-1, -1), 3),
        ("BOX",         (0, 0), (-1, -1), 0.4, colors.HexColor("#cfd8d0")),
        ("INNERGRID",   (0, 0), (-1, -1), 0.3, colors.HexColor("#e2ebe4")),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(tbl)


def _artifacts_section(story, ext, st):
    """Registry Modifications + File Artifacts + Embedded IOCs
    surfaced in the source."""
    body = ext.get("body_artifacts") or []
    if not body:
        return
    reg = [a for a in body if a.get("type") == "registry_key"]
    fp  = [a for a in body if a.get("type") == "file_path"]
    if not (reg or fp):
        return
    story.append(Spacer(1, 0.12 * inch))
    story.append(Paragraph("9 · Host Artifacts", st["h2"]))
    if reg:
        story.append(Paragraph(f"Registry Modifications ({len(reg)})", st["h3"]))
        for r in reg[:10]:
            can = r.get("canonical") or r.get("value") or ""
            story.append(Paragraph(
                f"<font face='Courier'>{_escape(can[:150])}</font>", st["body"],
            ))
    if fp:
        story.append(Paragraph(f"File Paths Referenced ({len(fp)})", st["h3"]))
        for p in fp[:12]:
            val = p.get("value") or ""
            story.append(Paragraph(
                f"<font face='Courier'>{_escape(val[:150])}</font>", st["body"],
            ))


def _default_recs(bucket: str, inc: Dict[str, Any],
                    ext: Dict[str, Any]) -> List[str]:
    """Deterministic fall-through recommendations for NIST buckets
    that ICE didn't populate.  Keeps every phase covered."""
    if bucket == "eradication":
        return [
            "Remove attacker-installed persistence (services, scheduled tasks, RMM agents) from every affected host",
            "Rotate all credentials the attacker had access to, including service accounts and stored browser secrets",
            "Rebuild or re-image hosts where the attacker obtained SYSTEM or Domain Admin privileges",
            "Purge attacker-controlled binaries identified in the IOC table from all endpoints and file shares",
        ]
    if bucket == "recovery":
        return [
            "Restore encrypted or exfiltrated data from clean backups after eradication is verified",
            "Bring rebuilt hosts back online in a phased manner with enhanced monitoring for 30 days",
            "Validate that all detection rules covering the observed techniques are enabled and firing",
            "Re-baseline endpoint / network telemetry so future anomalies are detected earlier",
        ]
    if bucket == "lessons":
        return [
            "Conduct a post-incident review documenting the timeline, dwell time, and every decision point",
            "Update playbooks so the observed techniques (see MITRE section) trigger automated response next time",
            "Verify logging retention covers at least the observed dwell time; extend if shorter",
            "Restrict use of dual-use / LOLBAS tooling (PowerShell, wmic, msiexec, ssh.exe) via allow-listing",
        ]
    return []


def _escape(s: str) -> str:
    return (s.replace("&", "&amp;")
              .replace("<", "&lt;")
              .replace(">", "&gt;"))
