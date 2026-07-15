"""NivXRay Auto-Generated PDF User Guide.

Builds a styled PDF from the YAML-backed documentation registry.
Preserves a professional cover page, TOC, and section styling; all
content is pulled dynamically from `docs/features/*.yaml` and
`docs/workflows/*.yaml`.

Public entry-point:
    create_user_guide(audience: str = "user", out_path: str | Path | None = None) -> bytes
        - Returns the PDF as bytes.
        - If `out_path` is provided, also writes the PDF to disk.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate, Frame, NextPageTemplate, PageBreak, PageTemplate,
    Image as RLImage, Paragraph, Spacer, Table, TableStyle,
)

from docs import list_features, list_workflows, guide_stats

# Optional SVG embed — svglib is bundled with reportlab, but guard the
# import in case a slim environment strips it.
try:
    from svglib.svglib import svg2rlg  # type: ignore
except Exception:  # pragma: no cover
    svg2rlg = None

_ASSETS_DIR = Path(__file__).parent / "assets"
_SCREENSHOTS_DIR = Path(__file__).parent / "screenshots"


# -------------------------------------------------------------------
# Brand palette — mirrors NivXRay's dark cyber aesthetic on paper.
# -------------------------------------------------------------------
BRAND_INK = colors.HexColor("#0f172a")       # deep slate
BRAND_MINT = colors.HexColor("#0f766e")      # teal accent (readable on white)
BRAND_MINT_LT = colors.HexColor("#7ee3c9")   # soft mint for chips
BRAND_AMBER = colors.HexColor("#b45309")     # workflow accent
BRAND_MUTED = colors.HexColor("#475569")     # secondary text
BRAND_RULE = colors.HexColor("#cbd5e1")      # hair rules
BRAND_CODE_BG = colors.HexColor("#f1f5f9")   # code chip background


# -------------------------------------------------------------------
# Paragraph styles
# -------------------------------------------------------------------
def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    styles: Dict[str, ParagraphStyle] = {}

    styles["CoverTitle"] = ParagraphStyle(
        "CoverTitle", parent=base["Title"], fontName="Helvetica-Bold",
        fontSize=42, leading=48, alignment=TA_CENTER, textColor=BRAND_INK,
        spaceAfter=8,
    )
    styles["CoverSub"] = ParagraphStyle(
        "CoverSub", parent=base["Normal"], fontName="Helvetica",
        fontSize=14, leading=20, alignment=TA_CENTER, textColor=BRAND_MINT,
        spaceAfter=4,
    )
    styles["CoverMeta"] = ParagraphStyle(
        "CoverMeta", parent=base["Normal"], fontName="Helvetica",
        fontSize=10, leading=14, alignment=TA_CENTER, textColor=BRAND_MUTED,
    )
    styles["H1"] = ParagraphStyle(
        "H1", parent=base["Heading1"], fontName="Helvetica-Bold",
        fontSize=22, leading=28, textColor=BRAND_INK,
        spaceBefore=6, spaceAfter=10, keepWithNext=True,
    )
    styles["H2"] = ParagraphStyle(
        "H2", parent=base["Heading2"], fontName="Helvetica-Bold",
        fontSize=15, leading=20, textColor=BRAND_MINT,
        spaceBefore=14, spaceAfter=6, keepWithNext=True,
    )
    styles["H3"] = ParagraphStyle(
        "H3", parent=base["Heading3"], fontName="Helvetica-Bold",
        fontSize=12, leading=16, textColor=BRAND_INK,
        spaceBefore=10, spaceAfter=4, keepWithNext=True,
    )
    styles["Body"] = ParagraphStyle(
        "Body", parent=base["BodyText"], fontName="Helvetica",
        fontSize=10, leading=14, textColor=BRAND_INK, spaceAfter=4,
    )
    styles["Muted"] = ParagraphStyle(
        "Muted", parent=styles["Body"], textColor=BRAND_MUTED, fontSize=9,
        leading=12,
    )
    styles["Bullet"] = ParagraphStyle(
        "Bullet", parent=styles["Body"], leftIndent=14, bulletIndent=2,
        spaceAfter=2,
    )
    styles["Code"] = ParagraphStyle(
        "Code", parent=styles["Body"], fontName="Courier",
        fontSize=9, leading=12, textColor=BRAND_INK,
        backColor=BRAND_CODE_BG, borderPadding=4, leftIndent=6, rightIndent=6,
    )
    styles["TocEntry"] = ParagraphStyle(
        "TocEntry", parent=styles["Body"], fontSize=11, leading=16,
    )
    styles["WorkflowStep"] = ParagraphStyle(
        "WorkflowStep", parent=styles["Body"], leftIndent=10, spaceAfter=3,
    )
    return styles


# -------------------------------------------------------------------
# Small helpers
# -------------------------------------------------------------------
def _esc(text: Any) -> str:
    """Escape untrusted text for reportlab paragraph mini-XML."""
    if text is None:
        return ""
    s = str(text)
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;"))


def _chip(label: str) -> str:
    return (f'<font backColor="#f1f5f9" color="#0f766e">'
            f'&nbsp;{_esc(label)}&nbsp;</font>')


def _bullets(items: Optional[List[str]], styles: Dict[str, ParagraphStyle]) -> List[Any]:
    out: List[Any] = []
    if not items:
        return out
    for it in items:
        out.append(Paragraph(f"• {_esc(it)}", styles["Bullet"]))
    return out


def _hr(color=BRAND_RULE) -> Table:
    """A thin horizontal rule spanning the page frame width."""
    t = Table([[""]], colWidths=[6.5 * inch], rowHeights=[0.5])
    t.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, color),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return t


# -------------------------------------------------------------------
# Page decorations
# -------------------------------------------------------------------
def _draw_page_chrome(canvas, doc):
    """Header + footer painted on every non-cover page."""
    canvas.saveState()
    w, h = LETTER
    # Header brand strip
    canvas.setFillColor(BRAND_INK)
    canvas.rect(0, h - 0.35 * inch, w, 0.35 * inch, fill=1, stroke=0)
    canvas.setFillColor(BRAND_MINT_LT)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(0.6 * inch, h - 0.23 * inch, "NIVXRAY")
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica", 9)
    canvas.drawRightString(w - 0.6 * inch, h - 0.23 * inch,
                           "Auto-generated User Guide")

    # Footer
    canvas.setFillColor(BRAND_MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(0.6 * inch, 0.4 * inch,
                      f"© {datetime.now(timezone.utc).year} NivXRay")
    canvas.drawRightString(w - 0.6 * inch, 0.4 * inch, f"Page {doc.page}")
    canvas.setStrokeColor(BRAND_RULE)
    canvas.setLineWidth(0.4)
    canvas.line(0.6 * inch, 0.55 * inch, w - 0.6 * inch, 0.55 * inch)
    canvas.restoreState()


def _draw_cover(canvas, doc):
    """Full-bleed cover page — dark backdrop with mint accents."""
    canvas.saveState()
    w, h = LETTER
    # Backdrop
    canvas.setFillColor(BRAND_INK)
    canvas.rect(0, 0, w, h, fill=1, stroke=0)
    # Mint accent bar
    canvas.setFillColor(BRAND_MINT_LT)
    canvas.rect(0, h - 1.0 * inch, w, 0.10 * inch, fill=1, stroke=0)
    canvas.rect(0, 0.9 * inch, w, 0.06 * inch, fill=1, stroke=0)

    # Watermark grid dots
    canvas.setFillColor(colors.HexColor("#1e293b"))
    for x in range(0, int(w), 24):
        for y in range(int(1.1 * inch), int(h - 1.2 * inch), 24):
            canvas.circle(x, y, 0.6, fill=1, stroke=0)

    canvas.restoreState()


# -------------------------------------------------------------------
# Section builders
# -------------------------------------------------------------------
def _build_cover(styles: Dict[str, ParagraphStyle], audience: str,
                 stats: Dict[str, Any]) -> List[Any]:
    story: List[Any] = []
    story.append(Spacer(1, 2.2 * inch))
    # White-on-dark titles (cover page has dark backdrop drawn via _draw_cover)
    cover_title = ParagraphStyle(
        "CoverTitleWhite", parent=styles["CoverTitle"],
        textColor=colors.white, fontSize=44, leading=52,
    )
    cover_sub = ParagraphStyle(
        "CoverSubMint", parent=styles["CoverSub"],
        textColor=BRAND_MINT_LT, fontSize=15,
    )
    cover_meta = ParagraphStyle(
        "CoverMetaLight", parent=styles["CoverMeta"],
        textColor=colors.HexColor("#94a3b8"),
    )
    story.append(Paragraph("NivXRay", cover_title))
    story.append(Paragraph(
        f"{audience.title()} Guide", cover_sub))
    story.append(Spacer(1, 0.4 * inch))
    story.append(Paragraph(
        "CyberChef-style decoder &amp; threat-analysis platform",
        cover_meta))
    story.append(Spacer(1, 1.6 * inch))

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    story.append(Paragraph(
        f"{stats.get('features', 0)} features &nbsp;·&nbsp; "
        f"{stats.get('workflows', 0)} workflows &nbsp;·&nbsp; "
        f"{len(stats.get('categories') or [])} categories",
        cover_meta))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph(
        f"Auto-generated on {ts} · Audience: <b>{audience}</b>",
        cover_meta))
    story.append(NextPageTemplate("content"))
    story.append(PageBreak())
    return story


def _build_toc(styles: Dict[str, ParagraphStyle],
               workflows: List[Dict[str, Any]],
               by_category: Dict[str, List[Dict[str, Any]]]) -> List[Any]:
    story: List[Any] = [Paragraph("Table of Contents", styles["H1"]),
                        _hr(), Spacer(1, 8)]
    if workflows:
        story.append(Paragraph("Task-Oriented Workflows", styles["H2"]))
        for w in workflows:
            story.append(Paragraph(
                f"→ {_esc(w.get('title', w.get('id')))}",
                styles["TocEntry"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Features by Category", styles["H2"]))
    for cat in sorted(by_category.keys()):
        story.append(Paragraph(
            f"<b>{_esc(cat)}</b> — {len(by_category[cat])} entries",
            styles["TocEntry"]))
        for f in by_category[cat]:
            story.append(Paragraph(
                f"&nbsp;&nbsp;&nbsp;• {_esc(f.get('title', f.get('id')))}",
                styles["Body"]))
    story.append(PageBreak())
    return story


def _embed_screenshots(doc_id: str, styles: Dict[str, ParagraphStyle],
                        max_width_in: float = 6.5) -> List[Any]:
    """Return reportlab flowables for every captured screenshot of a doc.

    Files are read from `docs/screenshots/{doc_id}/step_*.png`. If the
    directory doesn't exist or is empty, returns an empty list so the
    caller can call it unconditionally.
    """
    shot_dir = _SCREENSHOTS_DIR / doc_id
    if not shot_dir.exists():
        return []
    files = sorted(shot_dir.glob("step_*.png"))
    if not files:
        return []
    out: List[Any] = []
    for i, path in enumerate(files, 1):
        try:
            img = RLImage(str(path))
            # Scale to fit content width while preserving aspect ratio.
            aspect = img.imageHeight / max(1, img.imageWidth)
            img.drawWidth = max_width_in * inch
            img.drawHeight = max_width_in * inch * aspect
            # Cap very tall screenshots at ~8 inches so they don't own an entire page.
            if img.drawHeight > 8 * inch:
                scale = (8 * inch) / img.drawHeight
                img.drawHeight *= scale
                img.drawWidth *= scale
            out.append(Spacer(1, 4))
            out.append(Paragraph(
                f"<font color='#94a3b8' size='8'>Screenshot {i}</font>",
                styles["Muted"]))
            out.append(img)
            out.append(Spacer(1, 6))
        except Exception:
            # Corrupt file — skip rather than kill the export.
            continue
    return out


def _build_workflow(w: Dict[str, Any],
                    styles: Dict[str, ParagraphStyle]) -> List[Any]:
    story: List[Any] = []
    story.append(Paragraph(
        f"<font color='#b45309'>◆</font> "
        f"{_esc(w.get('title', w.get('id')))}", styles["H3"]))
    if w.get("purpose"):
        story.append(Paragraph(f"<i>{_esc(w['purpose'])}</i>", styles["Muted"]))
    steps = w.get("steps") or []
    for i, step in enumerate(steps, 1):
        story.append(Paragraph(
            f"<b>Step {i} — {_esc(step.get('title', ''))}</b>",
            styles["WorkflowStep"]))
        if step.get("action"):
            story.append(Paragraph(
                f"<b>Action:</b> {_esc(step['action'])}",
                styles["WorkflowStep"]))
        if step.get("expected"):
            story.append(Paragraph(
                f"<b>Expected:</b> "
                f"<font color='#475569'>{_esc(step['expected'])}</font>",
                styles["WorkflowStep"]))
    # Inline captured screenshots for this workflow.
    story.extend(_embed_screenshots(w.get("id", ""), styles))
    if w.get("related_features"):
        chips = " ".join(_chip(r) for r in w["related_features"])
        story.append(Spacer(1, 3))
        story.append(Paragraph(f"<b>Related:</b> {chips}", styles["Muted"]))
    story.append(Spacer(1, 6))
    story.append(_hr())
    story.append(Spacer(1, 6))
    return story


def _build_feature(f: Dict[str, Any],
                   styles: Dict[str, ParagraphStyle]) -> List[Any]:
    story: List[Any] = []
    story.append(Paragraph(_esc(f.get("title", f.get("id", "?"))),
                           styles["H3"]))
    meta = (f"<font color='#475569'>id:</font> "
            f"<font face='Courier'>{_esc(f.get('id', ''))}</font> · "
            f"<font color='#475569'>category:</font> "
            f"{_esc(f.get('category', '?'))} · "
            f"<font color='#475569'>audience:</font> "
            f"{_esc(f.get('audience', 'user'))}")
    story.append(Paragraph(meta, styles["Muted"]))

    if f.get("purpose"):
        story.append(Paragraph(f"<b>Purpose.</b> {_esc(f['purpose'])}",
                               styles["Body"]))

    def _section(label: str, items: Optional[List[str]]):
        if not items:
            return
        story.append(Spacer(1, 2))
        story.append(Paragraph(f"<b>{label}</b>", styles["Body"]))
        story.extend(_bullets(items, styles))

    _section("When to use", f.get("when_to_use"))
    _section("Supported formats", f.get("supported_formats"))
    _section("Confidence rules", f.get("confidence_rules"))
    _section("Common errors", f.get("common_errors"))
    _section("Tips", f.get("tips"))

    if f.get("examples"):
        story.append(Spacer(1, 2))
        story.append(Paragraph("<b>Examples</b>", styles["Body"]))
        for ex in f["examples"]:
            body = (f"<b>Input:</b> {_esc(ex.get('input', ''))}<br/>"
                    f"<b>Output:</b> {_esc(ex.get('output', ''))}")
            if ex.get("notes"):
                body += (f"<br/><i>"
                         f"<font color='#b45309'>Note:</font> "
                         f"{_esc(ex['notes'])}</i>")
            story.append(Paragraph(body, styles["Code"]))
            story.append(Spacer(1, 3))

    if f.get("related"):
        chips = " ".join(_chip(r) for r in f["related"])
        story.append(Spacer(1, 3))
        story.append(Paragraph(f"<b>Related:</b> {chips}", styles["Muted"]))

    # Inline captured screenshots for this feature (Phase 1 · User Guide).
    story.extend(_embed_screenshots(f.get("id", ""), styles))

    story.append(Spacer(1, 6))
    story.append(_hr())
    story.append(Spacer(1, 6))
    return story


# -------------------------------------------------------------------
# Main entry-point
# -------------------------------------------------------------------
def create_user_guide(
    audience: str = "user",
    out_path: Optional[Union[str, Path]] = None,
) -> bytes:
    """Build the styled NivXRay User Guide PDF.

    Args:
        audience: one of "user", "admin", "developer", "all"
        out_path: optional path to also write the PDF to disk

    Returns:
        The PDF as raw bytes.
    """
    audience = audience if audience in {"user", "admin", "developer", "all"} else "user"

    feats = list_features(audience=None if audience == "all" else audience)
    wfs = list_workflows()
    stats = guide_stats()

    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for f in feats:
        by_cat.setdefault(f.get("category") or "Uncategorised", []).append(f)

    styles = _styles()
    buf = io.BytesIO()

    doc = BaseDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
        title=f"NivXRay {audience.title()} Guide",
        author="NivXRay", subject="Auto-generated documentation",
    )
    frame_content = Frame(
        doc.leftMargin, doc.bottomMargin,
        doc.width, doc.height, id="content",
    )
    frame_cover = Frame(
        0, 0, LETTER[0], LETTER[1], id="cover",
        leftPadding=0.6 * inch, rightPadding=0.6 * inch,
        topPadding=0.6 * inch, bottomPadding=0.6 * inch,
    )
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[frame_cover], onPage=_draw_cover),
        PageTemplate(id="content", frames=[frame_content],
                     onPage=_draw_page_chrome),
    ])

    story: List[Any] = []
    story.extend(_build_cover(styles, audience, stats))
    story.extend(_build_toc(styles, wfs, by_cat))

    # ─── 5W1H analyst flow diagram + anatomy diagrams (User Guide) ───
    def _embed_svg(name: str, heading: str, sub: str = ""):
        svg_path = _ASSETS_DIR / name
        if svg2rlg is None or not svg_path.exists():
            return
        try:
            drawing = svg2rlg(str(svg_path))
            max_w = 7.3 * inch
            if drawing.width > 0:
                scale = max_w / drawing.width
                drawing.width *= scale
                drawing.height *= scale
                drawing.scale(scale, scale)
            story.append(Paragraph(heading, styles["H1"]))
            if sub:
                story.append(Paragraph(sub, styles["Muted"]))
            story.append(Spacer(1, 8))
            story.append(drawing)
            story.append(PageBreak())
        except Exception:
            pass

    _embed_svg("analyst_flow.svg", "Analyst Flow — 5W1H",
               "Follow the arrows. Every step answers one of the six analyst questions.")
    _embed_svg("auto_investigate_pipeline.svg",
               "Auto-Investigate · Pipeline Anatomy",
               "One click → six stages → verdict. Each stage emits to the timeline.")
    _embed_svg("attack_graph_anatomy.svg",
               "Attack Graph · Node Anatomy",
               "Nodes are colour-coded, edges label the transformation that produced them.")
    _embed_svg("decoding_chain_anatomy.svg",
               "Decoding Chain · Stage Anatomy",
               "Each stage is atomic: input bytes → operation → output bytes.")

    if wfs:
        story.append(Paragraph("Task-Oriented Workflows", styles["H1"]))
        story.append(Paragraph(
            "Real analyst workflows — start here. Each workflow chains the "
            "features below into an investigation.", styles["Muted"]))
        story.append(_hr())
        story.append(Spacer(1, 8))
        for w in wfs:
            story.extend(_build_workflow(w, styles))
        story.append(PageBreak())

    story.append(Paragraph("Features by Category", styles["H1"]))
    story.append(_hr())
    story.append(Spacer(1, 8))
    for cat in sorted(by_cat.keys()):
        story.append(Paragraph(_esc(cat), styles["H2"]))
        for f in by_cat[cat]:
            story.extend(_build_feature(f, styles))

    doc.build(story)
    data = buf.getvalue()
    buf.close()

    if out_path:
        Path(out_path).write_bytes(data)

    return data
