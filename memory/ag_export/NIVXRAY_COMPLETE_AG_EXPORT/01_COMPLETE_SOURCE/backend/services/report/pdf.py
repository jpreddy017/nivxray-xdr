"""Round 39 · Step 5 · Investigation Report PDF renderer.

**Owner rule (locked):** the PDF renderer is a *projection* of the
existing Investigation Report contract composed by
:func:`services.report.service.compose`.  It MUST NOT recompute any
report content, invent new sections, or re-order the four owner-locked
sections.  If a section is empty in the contract, it renders empty in
the PDF — never fabricated.

Section order (matches contract):
    1. Executive Summary          (SYSTEM + ANALYST blocks)
    2. Technical Summary          🔒 Evidence-derived · read-only
    3. Supporting Evidence        (SYSTEM cards + ANALYST notes)
    4. Recommendations            (SYSTEM + ANALYST)

Provenance badges are preserved on every block:
    · Evidence-derived 🔒
    · NivXRay generated
    · Analyst added
    · Analyst edited

Round 43 · Presentation enhancement · optional branded cover page +
footer page numbers.  The cover is *optional* (``cover=True`` by
default; ``cover=False`` restores the Step 5 exact export).  The
cover draws its data from the *existing* ``report["header"]`` — no
duplicate model.
"""
from __future__ import annotations
from io import BytesIO
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, Flowable,
)


# ─────────────────────────────────────────────────────────────────────
# Owner-locked visual grammar
# ─────────────────────────────────────────────────────────────────────
BRAND_PURPLE    = colors.HexColor("#7c3aed")
BRAND_INK       = colors.HexColor("#0f172a")
MUTED_INK       = colors.HexColor("#475569")
HAIRLINE        = colors.HexColor("#e2e8f0")
EVIDENCE_LOCK   = colors.HexColor("#334155")
BADGE_SYSTEM    = colors.HexColor("#1e40af")
BADGE_ANALYST   = colors.HexColor("#166534")
BADGE_EDITED    = colors.HexColor("#78350f")
BADGE_LOCK      = colors.HexColor("#3f3f46")


SECTION_TITLES = [
    ("executive_summary",   "1 · Executive Summary"),
    ("technical_summary",   "2 · Technical Summary"),
    ("supporting_evidence", "3 · Supporting Evidence"),
    ("recommendations",     "4 · Recommendations"),
]


def _styles():
    ss = getSampleStyleSheet()
    return {
        "h1":     ParagraphStyle("h1",     parent=ss["Heading1"],
                                          fontName="Helvetica-Bold", fontSize=20,
                                          leading=24, textColor=BRAND_INK,
                                          spaceAfter=6),
        "h2":     ParagraphStyle("h2",     parent=ss["Heading2"],
                                          fontName="Helvetica-Bold", fontSize=13,
                                          leading=16, textColor=BRAND_PURPLE,
                                          spaceBefore=12, spaceAfter=6),
        "h3":     ParagraphStyle("h3",     parent=ss["Heading3"],
                                          fontName="Helvetica-Bold", fontSize=10.5,
                                          leading=13, textColor=BRAND_INK,
                                          spaceBefore=6, spaceAfter=2),
        "body":   ParagraphStyle("body",   parent=ss["BodyText"],
                                          fontName="Helvetica", fontSize=9.5,
                                          leading=13, textColor=BRAND_INK),
        "muted":  ParagraphStyle("muted",  parent=ss["BodyText"],
                                          fontName="Helvetica-Oblique", fontSize=8.5,
                                          leading=11, textColor=MUTED_INK),
        "mono":   ParagraphStyle("mono",   parent=ss["BodyText"],
                                          fontName="Courier", fontSize=8.5,
                                          leading=11, textColor=BRAND_INK),
        "badge":  ParagraphStyle("badge",  parent=ss["BodyText"],
                                          fontName="Helvetica-Bold", fontSize=7.5,
                                          leading=9, textColor=colors.white),
        "eyebrow":ParagraphStyle("eyebrow",parent=ss["BodyText"],
                                          fontName="Helvetica-Bold", fontSize=8,
                                          leading=10, textColor=BRAND_PURPLE),
    }


def _origin_badge(origin: str, edited: bool = False,
                       read_only: bool = False) -> str:
    """Return the provenance badge label matching the frontend contract."""
    if read_only:
        return "EVIDENCE-DERIVED"
    if origin == "SYSTEM":
        return "NIVXRAY GENERATED"
    if origin == "ANALYST" and edited:
        return "ANALYST EDITED"
    if origin == "ANALYST":
        return "ANALYST ADDED"
    return (origin or "SYSTEM").upper()


def _badge_color(label: str):
    if label == "EVIDENCE-DERIVED":  return BADGE_LOCK
    if label == "NIVXRAY GENERATED": return BADGE_SYSTEM
    if label == "ANALYST ADDED":     return BADGE_ANALYST
    if label == "ANALYST EDITED":    return BADGE_EDITED
    return MUTED_INK


def _badge(label: str, styles) -> Table:
    color = _badge_color(label)
    t = Table([[Paragraph(label, styles["badge"])]],
                colWidths=[85])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def _header_row(report: Dict[str, Any], styles) -> List[Any]:
    hdr = report.get("header") or {}
    left = Paragraph("<b>NivXRay XDR</b> · Investigation Report", styles["eyebrow"])
    ident = Paragraph(hdr.get("title") or report.get("incident_id"), styles["h1"])
    meta_parts = []
    for label, val in (("Incident", report.get("incident_id")),
                            ("Tenant",   report.get("tenant_id")),
                            ("Priority", hdr.get("priority")),
                            ("State",    hdr.get("state")),
                            ("Verdict",  hdr.get("verdict")),
                            ("Host",     hdr.get("host")),
                            ("Detection", hdr.get("detection"))):
        if val:
            meta_parts.append(f"<b>{label}:</b> {val}")
    meta = Paragraph(" &nbsp; · &nbsp; ".join(meta_parts), styles["muted"])
    gen = Paragraph(f"Generated at {report.get('generated_at','')}",
                        styles["muted"])
    return [left, ident, meta, gen,
              Table([[""]], colWidths=[6.5 * inch], rowHeights=[1],
                        style=TableStyle([("LINEABOVE", (0, 0), (-1, -1),
                                                 0.8, BRAND_PURPLE)])),
              Spacer(1, 6)]


def _render_block(block: Dict[str, Any], styles,
                       read_only: bool = False) -> List[Any]:
    """Render a single report block (SYSTEM or ANALYST)."""
    origin  = block.get("origin") or ("SYSTEM" if block.get("system") else "SYSTEM")
    edited  = bool(block.get("edited_at") or block.get("edited"))
    badge_label = _origin_badge(origin, edited=edited, read_only=read_only)
    parts: List[Any] = []
    title = block.get("title")
    header_row: List[Any] = [_badge(badge_label, styles)]
    if title:
        header_row.append(Paragraph(f"<b>{title}</b>", styles["h3"]))
    else:
        header_row.append(Paragraph("", styles["h3"]))
    t = Table([header_row], colWidths=[95, 5.9 * inch])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    parts.append(t)
    content = block.get("content") or block.get("summary") or ""
    if content:
        parts.append(Paragraph(_escape(content), styles["body"]))
    evrefs = block.get("evidence_refs") or block.get("source_evidence_ids") or []
    if evrefs:
        parts.append(Paragraph(
            "Evidence: " + " · ".join(evrefs[:6]),
            styles["mono"]))
    author = block.get("author_email")
    stamp  = block.get("created_at") or block.get("generated_at")
    if author or stamp:
        parts.append(Paragraph(
            " · ".join([x for x in (author, stamp) if x]),
            styles["muted"]))
    parts.append(Spacer(1, 6))
    return parts


def _escape(text: str) -> str:
    return (str(text).replace("&", "&amp;")
                          .replace("<", "&lt;")
                          .replace(">", "&gt;"))


def _render_executive(section: Dict[str, Any], styles) -> List[Any]:
    parts: List[Any] = []
    for b in section.get("system_blocks") or []:
        parts.extend(_render_block(b, styles))
    for b in section.get("analyst_blocks") or []:
        parts.extend(_render_block(b, styles))
    if not parts:
        parts.append(Paragraph("No executive summary blocks composed.",
                                       styles["muted"]))
    return parts


def _render_technical(section: Dict[str, Any], styles) -> List[Any]:
    parts: List[Any] = []
    parts.append(_badge("EVIDENCE-DERIVED", styles))
    parts.append(Spacer(1, 4))
    parts.append(Paragraph(
        ("100 % evidence-derived · analyst-writes refused at "
          "service boundary (owner rule §11)."),
        styles["muted"]))
    parts.append(Spacer(1, 4))
    for g in section.get("groups") or []:
        rows = g.get("rows") or []
        if not rows:
            continue
        parts.append(Paragraph(g.get("name") or "", styles["h3"]))
        data = [[Paragraph(f"<b>{_escape(r.get('label',''))}</b>",
                                     styles["body"]),
                     Paragraph(_escape(str(r.get("value", ""))),
                                     styles["body"])]
                    for r in rows]
        tbl = Table(data, colWidths=[1.7 * inch, 4.6 * inch])
        tbl.setStyle(TableStyle([
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, HAIRLINE),
            ("VALIGN",    (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        parts.append(tbl)
        parts.append(Spacer(1, 6))
    evrefs = section.get("evidence_refs") or []
    if evrefs:
        parts.append(Paragraph("Evidence: " + " · ".join(evrefs[:8]),
                                        styles["mono"]))
    if not (section.get("groups") or []):
        parts.append(Paragraph("No evidence-derived facts composed.",
                                       styles["muted"]))
    return parts


def _render_supporting(section: Dict[str, Any], styles) -> List[Any]:
    parts: List[Any] = []
    for b in section.get("system_blocks") or []:
        parts.extend(_render_block(b, styles))
    for b in section.get("analyst_blocks") or []:
        parts.extend(_render_block(b, styles))
    if not parts:
        parts.append(Paragraph("No supporting evidence composed.",
                                       styles["muted"]))
    return parts


def _render_recommendations(section: Dict[str, Any], styles) -> List[Any]:
    parts: List[Any] = []
    for b in section.get("system_blocks") or []:
        parts.extend(_render_block(b, styles))
    for b in section.get("analyst_blocks") or []:
        parts.extend(_render_block(b, styles))
    if not parts:
        parts.append(Paragraph("No recommendations composed.",
                                       styles["muted"]))
    return parts


_SECTION_RENDERERS = {
    "executive_summary":   _render_executive,
    "technical_summary":   _render_technical,
    "supporting_evidence": _render_supporting,
    "recommendations":     _render_recommendations,
}


def render(report: Dict[str, Any], cover: bool = True) -> bytes:
    """Render the four-section report contract to a branded PDF.

    Input MUST be the envelope returned by
    :func:`services.report.service.compose`.

    Round 43 · ``cover`` (default ``True``) controls whether an
    optional NivXRay XDR branded cover page is prepended.  Setting
    ``cover=False`` restores the exact Step 5 export byte-for-byte
    equivalent (minus the page-number footer, which is now always
    on — non-configurable).

    MISSING contract: if ``state=MISSING`` a one-page honest error
    PDF is returned regardless of the ``cover`` flag — we never
    fabricate a cover page for a missing incident.
    """
    styles = _styles()
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=LETTER,
                                 leftMargin=0.6 * inch,
                                 rightMargin=0.6 * inch,
                                 topMargin=0.5 * inch,
                                 bottomMargin=0.5 * inch,
                                 title="NivXRay Investigation Report",
                                 author="NivXRay XDR")
    story: List[Any] = []

    if report.get("state") == "MISSING":
        # Honest MISSING PDF · no cover · no fabricated footer content.
        story.append(Paragraph("NivXRay Investigation Report", styles["h1"]))
        story.append(Paragraph(
            f"Report unavailable: {report.get('reason','incident not found')}.",
            styles["body"]))
        doc.build(story, canvasmaker=NumberedCanvas)
        return buf.getvalue()

    if cover:
        story.extend(_build_cover(report, styles))
        story.append(PageBreak())

    story.extend(_header_row(report, styles))

    sections = report.get("sections") or {}
    for key, title in SECTION_TITLES:
        story.append(Paragraph(title, styles["h2"]))
        renderer = _SECTION_RENDERERS[key]
        section  = sections.get(key) or {}
        story.extend(renderer(section, styles))
        story.append(Spacer(1, 4))

    story.append(Spacer(1, 8))
    story.append(Table([[""]], colWidths=[6.5 * inch], rowHeights=[1],
                              style=TableStyle([("LINEABOVE", (0, 0), (-1, -1),
                                                        0.5, HAIRLINE)])))
    story.append(Paragraph(
        ("Report is a projection of the Investigation Report contract · "
          "no fabrication · owner rule §11."),
        styles["muted"]))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────
# Round 43 · Cover page + numbered footer
# ─────────────────────────────────────────────────────────────────────
class NumberedCanvas(Canvas):
    """Two-pass canvas that stamps ``Page X of Y`` on every page.

    Round 43 · presentation-only.  The report content is unchanged;
    each page just gets a subtle right-aligned footer.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[Dict[str, Any]] = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page_footer(total)
            super().showPage()
        super().save()

    def _draw_page_footer(self, total: int) -> None:
        self.setFont("Helvetica", 7.5)
        self.setFillColor(MUTED_INK)
        page_w, _ = LETTER
        # Left: standing brand mark.
        self.drawString(0.6 * inch, 0.35 * inch,
                              "NivXRay XDR · Investigation Report")
        # Right: page numbering.
        self.drawRightString(page_w - 0.6 * inch, 0.35 * inch,
                                       f"Page {self._pageNumber} of {total}")


def _build_cover(report: Dict[str, Any], styles) -> List[Any]:
    """Build the optional branded cover page.

    Owner rule: data flows from the *existing* ``report["header"]``
    and top-level fields.  No duplicate contract, no reinterpretation.
    """
    hdr = report.get("header") or {}
    parts: List[Any] = [
        Spacer(1, 1.4 * inch),
        Paragraph("<b>NivXRay XDR</b>", ParagraphStyle(
            "cover_brand", parent=styles["h1"], fontSize=28, leading=32,
            textColor=BRAND_PURPLE)),
        Paragraph("Investigation Report", ParagraphStyle(
            "cover_sub", parent=styles["h1"], fontSize=16, leading=20,
            textColor=BRAND_INK)),
        Spacer(1, 0.4 * inch),
        Table([[""]], colWidths=[6.5 * inch], rowHeights=[1],
                style=TableStyle([("LINEABOVE", (0, 0), (-1, -1),
                                          1.2, BRAND_PURPLE)])),
        Spacer(1, 0.35 * inch),
        Paragraph(hdr.get("title") or report.get("incident_id") or "",
                        ParagraphStyle("cover_title", parent=styles["h1"],
                                             fontSize=22, leading=26,
                                             textColor=BRAND_INK)),
        Spacer(1, 0.15 * inch),
        Paragraph(f"Incident ID · <b>{report.get('incident_id','')}</b>",
                        styles["body"]),
        Spacer(1, 0.35 * inch),
    ]

    # Facts panel · data all from the existing report envelope.
    verdict = (hdr.get("verdict") or "").upper() or "—"
    priority = hdr.get("priority") or "—"
    state    = hdr.get("state") or "—"
    detection = hdr.get("detection") or "—"
    host     = hdr.get("host") or "—"
    tenant   = report.get("tenant_id") or "—"

    def _cell(label: str, value: str, tone_hex: str = "#0f172a"):
        return Table([
            [Paragraph(f"<font color='#64748b'>{label}</font>", styles["muted"])],
            [Paragraph(f"<font color='{tone_hex}'>{_escape(value)}</font>",
                            ParagraphStyle("cf", parent=styles["body"],
                                                 fontSize=12, leading=15,
                                                 fontName="Helvetica-Bold"))],
        ], colWidths=[3.1 * inch],
              style=TableStyle([("LEFTPADDING",   (0, 0), (-1, -1), 8),
                                        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                                        ("TOPPADDING",    (0, 0), (-1, -1), 4),
                                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                                        ("BACKGROUND",    (0, 0), (-1, -1),
                                          colors.HexColor("#f8fafc")),
                                        ("LINEBELOW",     (0, 0), (-1, -1),
                                          0.4, HAIRLINE)]))

    grid = Table([
        [_cell("VERDICT",  verdict, tone_hex="#7c3aed"),
          _cell("PRIORITY", priority)],
        [_cell("INVESTIGATION STATE", state),
          _cell("DETECTION",           detection)],
        [_cell("HOST",   host),
          _cell("TENANT", tenant)],
    ], colWidths=[3.1 * inch, 3.1 * inch],
       style=TableStyle([("LEFTPADDING",  (0, 0), (-1, -1), 0),
                                 ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                 ("TOPPADDING",   (0, 0), (-1, -1), 2),
                                 ("BOTTOMPADDING",(0, 0), (-1, -1), 2)]))
    parts.append(grid)
    parts.append(Spacer(1, 0.5 * inch))

    parts.append(Paragraph(
        (f"<b>Generated at</b> {report.get('generated_at','')}"),
        styles["muted"]))
    parts.append(Spacer(1, 0.08 * inch))
    parts.append(Paragraph(
        ("Every fact in this report is a projection of the "
          "NivXRay Investigation Report contract.  Provenance badges "
          "(EVIDENCE-DERIVED · NIVXRAY GENERATED · ANALYST ADDED · "
          "ANALYST EDITED) are preserved on every block.  No content "
          "is fabricated — empty sections render empty."),
        styles["muted"]))
    return parts
