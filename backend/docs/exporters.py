"""HTML + DOCX exporters for the NivXRay auto-generated user guide.

Public entry-points
    generate_html(audience='user') -> str    (standalone HTML)
    generate_docx(audience='user') -> bytes  (DOCX bytes)

Both reuse `docs.generate_guide()` for the Markdown source so the three
export formats (Markdown/HTML/DOCX/PDF) never drift apart.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any, Dict, List

import markdown as md_lib
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, RGBColor

from docs import generate_guide, guide_stats, list_features, list_workflows


# ---------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------
_HTML_CSS = """
:root { color-scheme: dark; }
body {
  margin: 0; padding: 40px 60px 80px;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  background: #0f172a; color: #c9d1d9; line-height: 1.65;
  max-width: 960px; margin-left: auto; margin-right: auto;
}
header.cover {
  background: linear-gradient(135deg, #0f172a, #1e293b);
  color: white; padding: 60px 40px; margin: -40px -60px 40px;
  border-bottom: 3px solid #7ee3c9;
}
header.cover h1 { font-size: 42px; margin: 0 0 8px; letter-spacing: -0.02em; }
header.cover .sub { color: #7ee3c9; font-size: 16px; letter-spacing: 0.02em; }
header.cover .meta { color: #94a3b8; font-size: 13px; margin-top: 24px; }
h1 { color: #f8fafc; font-size: 28px; margin-top: 40px; letter-spacing: -0.01em; }
h2 { color: #7ee3c9; font-size: 20px; margin-top: 32px;
     border-bottom: 1px solid rgba(126,227,201,0.20); padding-bottom: 4px; }
h3 { color: #f8fafc; font-size: 16px; margin-top: 24px; }
p, li { font-size: 14px; }
code, pre {
  font-family: 'JetBrains Mono', 'Courier New', monospace;
  background: rgba(148,163,184,0.10); color: #f8fafc;
  padding: 2px 6px; border-radius: 3px; font-size: 13px;
}
pre { padding: 12px 14px; overflow-x: auto; border-left: 3px solid #7ee3c9; }
blockquote { border-left: 3px solid #f59e0b; padding-left: 14px;
             color: #94a3b8; font-style: italic; }
hr { border: none; border-top: 1px solid rgba(148,163,184,0.20); margin: 32px 0; }
a { color: #7ee3c9; text-decoration: none; border-bottom: 1px dotted #7ee3c9; }
footer {
  margin-top: 60px; padding-top: 20px;
  border-top: 1px solid rgba(148,163,184,0.20);
  font-size: 11px; color: #64748b; text-align: center;
}
"""


def generate_html(audience: str = "user") -> str:
    audience = audience if audience in {"user", "admin", "developer", "all"} else "user"
    guide_md = generate_guide(audience=audience)
    body = md_lib.markdown(
        guide_md,
        extensions=["fenced_code", "tables", "toc"],
        output_format="html5",
    )
    stats = guide_stats()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Inline the 5W1H analyst flow SVG right below the cover banner.
    flow_svg = ""
    try:
        from pathlib import Path as _P
        svg_path = _P(__file__).parent / "assets" / "analyst_flow.svg"
        if svg_path.exists():
            raw = svg_path.read_text(encoding="utf-8")
            # Strip the XML prolog so the SVG embeds cleanly inline.
            if raw.startswith("<?xml"):
                raw = raw.split("?>", 1)[-1]
            flow_svg = (
                '<section style="margin:24px 0 32px;padding:20px;'
                'background:rgba(126,227,201,0.04);border-left:3px solid #7ee3c9;'
                'border-radius:4px;">'
                '<h2 style="margin-top:0;">Analyst Flow · 5W1H</h2>'
                '<p style="color:#94a3b8;font-size:13px;margin-top:0;">'
                'Follow the arrows. Every step answers one of the six analyst '
                'questions (What · Where · When · Why · How · Which) and loops '
                'back into the learning system.</p>'
                f'<div style="text-align:center;overflow-x:auto;">{raw}</div>'
                '</section>'
            )
    except Exception:
        pass

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NivXRay — {audience.title()} Guide</title>
<style>{_HTML_CSS}</style>
</head><body>
<header class="cover">
  <h1>NivXRay</h1>
  <div class="sub">{audience.title()} Guide · CyberChef-style Decoder &amp; Threat Analysis</div>
  <div class="meta">
    {stats.get('features', 0)} features &nbsp;·&nbsp;
    {stats.get('workflows', 0)} workflows &nbsp;·&nbsp;
    {len(stats.get('categories') or [])} categories &nbsp;·&nbsp;
    Auto-generated {ts}
  </div>
</header>
{flow_svg}
<main>{body}</main>
<footer>© {datetime.now(timezone.utc).year} NivXRay · Auto-generated from
<code>docs/features/*.yaml</code> and <code>docs/workflows/*.yaml</code>.</footer>
</body></html>
"""


# ---------------------------------------------------------------------
# DOCX
# ---------------------------------------------------------------------
_MINT = RGBColor(0x0F, 0x76, 0x6E)
_INK = RGBColor(0x0F, 0x17, 0x2A)
_MUTED = RGBColor(0x47, 0x55, 0x69)
_AMBER = RGBColor(0xB4, 0x53, 0x09)


def _para(doc: Document, text: str, *, bold: bool = False, italic: bool = False,
          size: int = 11, color: RGBColor = _INK, align=None) -> None:
    p = doc.add_paragraph()
    if align is not None:
        p.alignment = align
    run = p.add_run(text)
    run.bold = bold
    run.italic = italic
    run.font.size = Pt(size)
    run.font.color.rgb = color


def _bullet(doc: Document, items: List[str]) -> None:
    for it in items:
        doc.add_paragraph(str(it), style="List Bullet")


def _feature_section(doc: Document, f: Dict[str, Any]) -> None:
    doc.add_heading(f.get("title", f.get("id", "?")), level=3)
    _para(doc,
          f"id: {f.get('id', '')}   ·   category: {f.get('category', '?')}   "
          f"·   audience: {f.get('audience', 'user')}",
          italic=True, size=9, color=_MUTED)
    if f.get("purpose"):
        _para(doc, f["purpose"], size=11)
    for label, key in (("When to use", "when_to_use"),
                       ("Supported formats", "supported_formats"),
                       ("Confidence rules", "confidence_rules"),
                       ("Common errors", "common_errors"),
                       ("Tips", "tips")):
        vals = f.get(key) or []
        if vals:
            _para(doc, label, bold=True, size=11, color=_MINT)
            _bullet(doc, [str(v) for v in vals])
    exs = f.get("examples") or []
    if exs:
        _para(doc, "Examples", bold=True, size=11, color=_MINT)
        for ex in exs:
            p = doc.add_paragraph()
            r1 = p.add_run(f"Input: {ex.get('input', '')}\n")
            r1.font.name = "Consolas"; r1.font.size = Pt(9)
            r2 = p.add_run(f"Output: {ex.get('output', '')}")
            r2.font.name = "Consolas"; r2.font.size = Pt(9)
            if ex.get("notes"):
                _para(doc, ex["notes"], italic=True, size=9, color=_AMBER)
    if f.get("related"):
        _para(doc, "Related: " + ", ".join(f["related"]),
              italic=True, size=9, color=_MUTED)


def _workflow_section(doc: Document, w: Dict[str, Any]) -> None:
    doc.add_heading(w.get("title", w.get("id", "?")), level=3)
    if w.get("purpose"):
        _para(doc, w["purpose"], italic=True, color=_MUTED, size=10)
    for i, step in enumerate(w.get("steps") or [], 1):
        _para(doc, f"Step {i} — {step.get('title', '')}", bold=True, color=_INK)
        if step.get("action"):
            _para(doc, f"Action: {step['action']}", size=10)
        if step.get("expected"):
            _para(doc, f"Expected: {step['expected']}", size=10, color=_MUTED)
    if w.get("related_features"):
        _para(doc, "Related features: " + ", ".join(w["related_features"]),
              italic=True, size=9, color=_MUTED)


def generate_docx(audience: str = "user") -> bytes:
    audience = audience if audience in {"user", "admin", "developer", "all"} else "user"
    doc = Document()

    # Cover
    _para(doc, "NivXRay", bold=True, size=36, color=_INK,
          align=WD_ALIGN_PARAGRAPH.CENTER)
    _para(doc, f"{audience.title()} Guide", size=14, color=_MINT,
          align=WD_ALIGN_PARAGRAPH.CENTER)
    _para(doc, "CyberChef-style decoder & threat analysis platform",
          italic=True, size=10, color=_MUTED, align=WD_ALIGN_PARAGRAPH.CENTER)
    stats = guide_stats()
    _para(doc,
          f"{stats.get('features', 0)} features  ·  "
          f"{stats.get('workflows', 0)} workflows  ·  "
          f"{len(stats.get('categories') or [])} categories",
          size=9, color=_MUTED, align=WD_ALIGN_PARAGRAPH.CENTER)
    _para(doc, f"Auto-generated {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
          size=9, color=_MUTED, align=WD_ALIGN_PARAGRAPH.CENTER)
    doc.add_page_break()

    # Workflows
    wfs = list_workflows()
    if wfs:
        doc.add_heading("Task-Oriented Workflows", level=1)
        _para(doc,
              "Real analyst workflows — start here. Each workflow chains the "
              "features below into an investigation.",
              italic=True, color=_MUTED, size=10)
        for w in wfs:
            _workflow_section(doc, w)
        doc.add_page_break()

    # Features by category
    feats = list_features(audience=None if audience == "all" else audience)
    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for f in feats:
        by_cat.setdefault(f.get("category") or "Uncategorised", []).append(f)
    doc.add_heading("Features by Category", level=1)
    for cat in sorted(by_cat.keys()):
        doc.add_heading(cat, level=2)
        for f in by_cat[cat]:
            _feature_section(doc, f)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()
