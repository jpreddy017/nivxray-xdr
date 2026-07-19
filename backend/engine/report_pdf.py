"""Analyst Report — PDF renderer.

Reuses the section structure of `report.to_markdown()` but emits a
platform-neutral PDF via reportlab (pure Python, no wkhtmltopdf/Cairo/Pango
system dependency).

Guarantees
----------
* Pure Python: no external binaries, no fonts fetched at runtime.
* Deterministic layout: same input → identical PDF byte-stream modulo the
  reportlab-inserted CreationDate metadata (which we strip).
* Section order matches Markdown export so exports can be cross-referenced.
"""
from __future__ import annotations

import io
import re

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .models import AnalystReport

# ------------------------------------------------------------------- styles --
_STYLES = getSampleStyleSheet()
_H1 = ParagraphStyle("H1", parent=_STYLES["Heading1"], fontSize=18, spaceAfter=12,
                    textColor=colors.HexColor("#0f172a"))
_H2 = ParagraphStyle("H2", parent=_STYLES["Heading2"], fontSize=13, spaceBefore=14,
                    spaceAfter=6, textColor=colors.HexColor("#0369a1"))
_BODY = ParagraphStyle("Body", parent=_STYLES["BodyText"], fontSize=10, leading=13,
                      textColor=colors.HexColor("#1e293b"))
_MONO = ParagraphStyle("Mono", parent=_BODY, fontName="Courier", fontSize=8, leading=10)
_SMALL = ParagraphStyle("Small", parent=_BODY, fontSize=8, leading=10,
                       textColor=colors.HexColor("#64748b"))

_TABLE_STYLE = TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e0f2fe")),
    ("TEXTCOLOR",  (0, 0), (-1, 0), colors.HexColor("#0f172a")),
    ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE",   (0, 0), (-1, -1), 8),
    ("LEADING",    (0, 0), (-1, -1), 10),
    ("VALIGN",     (0, 0), (-1, -1), "TOP"),
    ("GRID",       (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
     [colors.white, colors.HexColor("#f8fafc")]),
])


def _esc(s: str) -> str:
    """Escape reportlab's Paragraph mini-HTML."""
    if s is None:
        return ""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))


def _p(text: str, style=_BODY) -> Paragraph:
    return Paragraph(_esc(text), style)


def to_pdf(report: AnalystReport, *, title: str = "NivXRay Analyst Report") -> bytes:
    """Render an AnalystReport to a PDF byte-stream."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.5 * inch, bottomMargin=0.5 * inch,
        title=title, author="NivXRay MCIP",
        subject="Malware Command Intelligence Report",
    )
    story: list = []
    story.append(_p(title, _H1))
    story.append(_p("Deterministic Malware Command Intelligence — powered by NivXRay",
                    _SMALL))
    story.append(Spacer(1, 8))

    findings = report.findings

    # 1. Executive summary
    story.append(_p("Executive Summary", _H2))
    story.append(_p(report.executive_summary or "(No summary generated.)"))

    # 2. Verdict panel
    story.append(_p("Verdict", _H2))
    verdict_rows = [
        ["Field", "Value"],
        ["Verdict",       findings.verdict.upper()],
        ["Risk Score",    f"{findings.risk_score} / 100"],
        ["Terminal",      report.terminal],
        ["Stopping Reason", report.stopped_reason or "n/a"],
        ["Elapsed",       f"{report.elapsed_ms} ms"],
        ["Engine",        report.engine],
    ]
    t = Table(verdict_rows, colWidths=[1.6 * inch, 5.4 * inch])
    t.setStyle(_TABLE_STYLE)
    story.append(t)

    # 2b. Confidence breakdown
    if report.confidence_breakdown.contributions:
        story.append(_p("Why This Score", _H2))
        rows = [["Source", "Points", "Evidence"]]
        for c in report.confidence_breakdown.contributions:
            rows.append([c.source, f"+{c.points}", _esc(c.detail)[:280]])
        rows.append(["Total (capped at 100)",
                     str(report.confidence_breakdown.total), ""])
        t = Table(rows, colWidths=[1.4 * inch, 0.8 * inch, 4.8 * inch])
        t.setStyle(_TABLE_STYLE)
        story.append(t)

    # 3. Malware family
    if findings.family.family and findings.family.family != "unknown":
        story.append(_p("Malware Family", _H2))
        fam_rows = [
            ["Field", "Value"],
            ["Family",     findings.family.family],
            ["Confidence", f"{findings.family.confidence * 100:.0f}%"],
        ]
        for e in findings.family.evidence[:5]:
            fam_rows.append(["Evidence", _esc(e)[:400]])
        t = Table(fam_rows, colWidths=[1.6 * inch, 5.4 * inch])
        t.setStyle(_TABLE_STYLE)
        story.append(t)

    # 4. Decode timeline
    story.append(_p("Decode Timeline", _H2))
    if report.trace:
        rows = [["#", "Plugin", "Conf", "In→Out", "Time", "Why"]]
        for i, s in enumerate(report.trace, 1):
            rows.append([
                str(i), s.decoder, f"{s.confidence * 100:.0f}%",
                f"{s.in_len}→{s.out_len}", f"{s.exec_ms}ms",
                _esc(s.why)[:200],
            ])
        t = Table(rows, colWidths=[0.3 * inch, 1.4 * inch, 0.6 * inch,
                                   0.9 * inch, 0.6 * inch, 3.2 * inch])
        t.setStyle(_TABLE_STYLE)
        story.append(t)
    else:
        story.append(_p("No transforms were applied — payload appears to be plaintext."))

    # 5. IOCs
    ioc_sections = [
        ("URLs",              findings.iocs.urls),
        ("IPs",               findings.iocs.ips),
        ("Domains",           findings.iocs.domains),
        ("Emails",            findings.iocs.emails),
        ("MD5",               findings.iocs.md5),
        ("SHA-1",             findings.iocs.sha1),
        ("SHA-256",           findings.iocs.sha256),
        ("Bitcoin Addresses", findings.iocs.bitcoin_addresses),
        ("File Paths",        findings.iocs.file_paths),
    ]
    non_empty = [(k, v) for k, v in ioc_sections if v]
    if non_empty:
        story.append(_p("Indicators of Compromise", _H2))
        for label, items in non_empty:
            story.append(_p(f"{label} ({len(items)})", _BODY))
            for it in items[:50]:
                story.append(_p(f"• {_esc(it)}", _MONO))

    # 6. MITRE ATT&CK
    if findings.mitre_techniques:
        story.append(_p("MITRE ATT&CK Mapping", _H2))
        rows = [["Technique", "Name", "Tactic", "Source", "Evidence"]]
        for h in findings.mitre_techniques:
            rows.append([h.id, h.technique or "-", h.tactic or "-",
                         h.source, _esc(h.evidence)[:200]])
        t = Table(rows, colWidths=[0.8 * inch, 1.5 * inch, 1.2 * inch,
                                   0.9 * inch, 2.6 * inch])
        t.setStyle(_TABLE_STYLE)
        story.append(t)

    # 7. LOLBAS
    if findings.lolbas:
        story.append(_p("LOLBAS Detection", _H2))
        rows = [["Binary", "Technique", "Evidence"]]
        for h in findings.lolbas:
            rows.append([h.binary, h.technique_id or "-", _esc(h.evidence)[:280]])
        t = Table(rows, colWidths=[1.5 * inch, 1.2 * inch, 4.3 * inch])
        t.setStyle(_TABLE_STYLE)
        story.append(t)

    # 8. Tradecraft
    if findings.tradecraft:
        story.append(_p("Tradecraft Flags", _H2))
        rows = [["Flag", "Severity", "Evidence"]]
        for tc in findings.tradecraft:
            rows.append([tc.flag, tc.severity, _esc(tc.evidence)[:300]])
        t = Table(rows, colWidths=[1.4 * inch, 0.9 * inch, 4.7 * inch])
        t.setStyle(_TABLE_STYLE)
        story.append(t)

    # 9. Investigation recommendations
    if report.investigation_steps:
        story.append(_p("Recommended Investigation Steps", _H2))
        for i, rec in enumerate(report.investigation_steps, 1):
            story.append(_p(
                f"<b>{i}. [{rec.priority.upper()}]</b> {_esc(rec.action)}"))
            if rec.rationale:
                story.append(_p(_esc(rec.rationale), _SMALL))

    # 10. Plugin execution report
    if report.plugin_report.entries:
        story.append(PageBreak())
        story.append(_p("Plugin Execution Report", _H2))
        b = report.plugin_report.budget_snapshot
        story.append(_p(
            f"Layers run: {report.plugin_report.layers_run} · "
            f"Total time: {report.plugin_report.total_time_ms} ms · "
            f"Budget: depth ≤ {b.get('max_depth', '?')}, "
            f"branches ≤ {b.get('max_branches', '?')}, "
            f"wall-time ≤ {b.get('wall_time_ms', '?')} ms "
            f"(used {b.get('elapsed_ms', '?')} ms).",
            _SMALL))
        rows = [["Layer", "Plugin", "Outcome", "Conf", "Reason", "Time"]]
        for e in report.plugin_report.entries[:60]:
            rows.append([
                str(e.layer), e.plugin, e.outcome,
                f"{e.detect_confidence * 100:.0f}%",
                _esc(e.reason or e.detect_reason)[:150],
                f"{e.exec_ms}ms",
            ])
        t = Table(rows, colWidths=[0.4 * inch, 1.5 * inch, 1.1 * inch,
                                   0.5 * inch, 3.0 * inch, 0.5 * inch])
        t.setStyle(_TABLE_STYLE)
        story.append(t)

    # 11. Final decoded output preview
    story.append(_p("Final Decoded Output (Preview)", _H2))
    preview = report.output[:2000] if report.output else "(empty)"
    story.append(_p(_esc(preview).replace("\n", "<br/>"), _MONO))
    if report.output and len(report.output) > 2000:
        story.append(_p(f"... {len(report.output) - 2000} more chars truncated",
                        _SMALL))

    story.append(Spacer(1, 12))
    story.append(_p(
        "Report generated by NivXRay MCIP · deterministic · offline-first.",
        _SMALL))

    doc.build(story)
    return _strip_metadata(buf.getvalue())


def _strip_metadata(pdf: bytes) -> bytes:
    """Strip CreationDate + ModDate + ID from the PDF so identical AnalystReports
    yield byte-identical PDFs. Enables analyst-friendly diffing across runs."""
    pdf = re.sub(rb"/CreationDate\s*\([^)]*\)", b"/CreationDate (D:00000000000000)", pdf)
    pdf = re.sub(rb"/ModDate\s*\([^)]*\)", b"/ModDate (D:00000000000000)", pdf)
    pdf = re.sub(rb"/ID\s*\[<[^>]+><[^>]+>\]", b"/ID [<00><00>]", pdf)
    return pdf
