"""Per-payload / per-feature one-page cheat sheet exporter.

Generates a compact single-page PDF or HTML for a single feature or
workflow. Great for printing, pinning on a monitor, or attaching to a
SOC ticket.

Public API:
    generate_cheatsheet_html(doc_id: str) -> str
    generate_cheatsheet_pdf(doc_id: str) -> bytes
"""
from __future__ import annotations

import base64
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate, Frame, Image as RLImage, PageTemplate,
    Paragraph, Spacer,
)

from docs import get_feature, get_workflow

_SCREENSHOTS_DIR = Path(__file__).parent / "screenshots"


def _resolve(doc_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    d = get_feature(doc_id)
    if d:
        return d, "feature"
    d = get_workflow(doc_id)
    if d:
        return d, "workflow"
    return None, None


# ---------------------------------------------------------------------
# HTML cheat sheet
# ---------------------------------------------------------------------
_CS_CSS = """
* { box-sizing: border-box; }
body { margin:0; padding:0; background:#0f172a; color:#c9d1d9;
       font-family: 'Inter', -apple-system, Helvetica, sans-serif;
       min-height:100vh; }
.sheet { max-width: 880px; margin: 0 auto; padding: 24px 32px 48px; }
h1 { color:#f8fafc; font-size: 26px; margin: 0 0 4px; letter-spacing:-0.01em; }
h1 .kind { color:#7ee3c9; font-size:12px; letter-spacing:0.24em;
           text-transform:uppercase; display:block; margin-bottom:4px; }
h2 { color:#7ee3c9; font-size: 13px; letter-spacing:0.20em;
     text-transform:uppercase; margin: 20px 0 6px;
     border-bottom:1px solid rgba(126,227,201,0.20); padding-bottom:4px; }
.purpose { color:#94a3b8; font-style:italic; font-size:14px; margin-bottom:8px; }
ul { margin:6px 0 0; padding-left: 22px; }
li { margin: 3px 0; font-size:13px; }
.chip { display:inline-block; padding:2px 8px; border-radius:3px;
        background:rgba(148,163,184,0.10); color:#c9d1d9; font-size:11px;
        margin: 2px 4px 2px 0; font-family:'JetBrains Mono', monospace; }
.chip.amber { background:rgba(245,158,11,0.12); color:#f59e0b; }
.chip.rose  { background:rgba(244,63,94,0.12);  color:#f43f5e; }
.chip.mint  { background:rgba(126,227,201,0.10); color:#7ee3c9; }
.stage { display:flex; gap:6px; align-items:center; margin: 6px 0;
         font-size:12px; }
.stage .num { background:#a78bfa; color:#0f172a; width:22px; height:22px;
              border-radius:11px; display:inline-flex; align-items:center;
              justify-content:center; font-weight:700; font-size:11px; }
pre { background:#0b1220; border-left:2px solid #7ee3c9; padding:8px 10px;
      font-family:'JetBrains Mono', monospace; font-size:11px;
      overflow:auto; margin: 4px 0 12px; border-radius:2px;
      color:#c9d1d9; white-space:pre-wrap; word-break:break-all; }
.two-col { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
.meta { color:#64748b; font-size:11px; margin-top:16px; text-align:center; }
img.shot { max-width:100%; border-radius:3px; margin:8px 0; display:block;
           border:1px solid rgba(148,163,184,0.20); background:#0b1220; }
header.hdr { border-bottom:2px solid #7ee3c9; padding-bottom:12px;
             margin-bottom:12px; }
header.hdr .brand { font-size:10px; letter-spacing:0.3em;
                    color:#7ee3c9; margin-bottom:4px; }
"""


def _chip_html(items: List[str], klass: str = "") -> str:
    return "".join(f'<span class="chip {klass}">{i}</span>' for i in items or [])


def _shot_data_uri(doc_id: str, n: int = 1) -> str:
    p = _SCREENSHOTS_DIR / doc_id / f"step_{n}.png"
    if not p.exists():
        return ""
    return "data:image/png;base64," + base64.b64encode(p.read_bytes()).decode()


def _extract_iocs_and_mitre(doc: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Best-effort surfacing of IOCs & MITRE from the YAML body."""
    iocs: List[str] = []
    mitre: List[str] = []
    blob = " ".join(str(v) for v in doc.values() if isinstance(v, (str, list)))
    import re
    mitre = sorted(set(re.findall(r"T\d{4}(?:\.\d{3})?", blob)))
    for pat in (r"https?://[^\s\)]+", r"\b[a-fA-F0-9]{32,64}\b",
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b"):
        iocs.extend(m.rstrip(".,)]}") for m in re.findall(pat, blob))
    return list(dict.fromkeys(iocs))[:6], mitre[:8]


def generate_cheatsheet_html(doc_id: str) -> str:
    doc, kind = _resolve(doc_id)
    if not doc:
        return f"<!doctype html><html><body>Unknown page: {doc_id}</body></html>"
    iocs, mitre = _extract_iocs_and_mitre(doc)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Chain / steps for workflows
    stages_html = ""
    if kind == "workflow":
        for i, s in enumerate(doc.get("steps") or [], 1):
            stages_html += (
                f'<div class="stage"><span class="num">{i}</span>'
                f'<span><b>{s.get("title", "")}</b> — {s.get("action", "")}</span></div>'
            )

    examples_html = ""
    if kind == "feature":
        for ex in (doc.get("examples") or [])[:2]:
            examples_html += (
                f'<pre><b>Input:</b> {ex.get("input", "")}\n'
                f'<b>Output:</b> {ex.get("output", "")}'
                + (f'\n<i>Note: {ex.get("notes")}</i>' if ex.get("notes") else "")
                + '</pre>'
            )

    when = doc.get("when_to_use") or []
    tips = doc.get("tips") or []
    errors = doc.get("common_errors") or []
    related = doc.get("related") or doc.get("related_features") or []

    shot_uri = _shot_data_uri(doc_id, 1)
    shot_html = f'<img class="shot" src="{shot_uri}" alt="{doc_id} screenshot" />' if shot_uri else ""

    ioc_block = ""
    if iocs:
        ioc_block = "<h2>IOC signatures</h2><pre>" + "\n".join(iocs) + "</pre>"

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{doc.get('title','?')} · Cheat Sheet</title>
<style>{_CS_CSS}</style></head>
<body><div class="sheet">
  <header class="hdr">
    <div class="brand">NIVXRAY · CHEAT SHEET</div>
    <h1><span class="kind">{kind or '?'}</span>{doc.get('title', doc_id)}</h1>
    <div class="purpose">{doc.get('purpose', '')}</div>
  </header>

  {shot_html}

  <div class="two-col">
    <div>
      {"<h2>Decode Chain / Steps</h2>" + stages_html if stages_html else ""}
      {"<h2>When to use</h2><ul>" + "".join(f"<li>{w}</li>" for w in when) + "</ul>" if when else ""}
      {"<h2>Analyst tips</h2><ul>" + "".join(f"<li>{t}</li>" for t in tips) + "</ul>" if tips else ""}
    </div>
    <div>
      {"<h2>Sample</h2>" + examples_html if examples_html else ""}
      {"<h2>MITRE ATT&amp;CK</h2>" + _chip_html(mitre, "amber") if mitre else ""}
      {ioc_block}
      {"<h2>Common errors</h2><ul>" + "".join(f"<li>{e}</li>" for e in errors) + "</ul>" if errors else ""}
      {"<h2>Related</h2>" + _chip_html(related, "mint") if related else ""}
    </div>
  </div>

  <div class="meta">Auto-generated {ts} · NivXRay · one-page cheat sheet for {doc_id}</div>
</div></body></html>
"""


# ---------------------------------------------------------------------
# PDF cheat sheet (single page, LETTER)
# ---------------------------------------------------------------------
def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "H1": ParagraphStyle("H1", parent=base["Title"], fontSize=20,
                              leading=24, textColor=colors.HexColor("#0f172a"),
                              spaceAfter=4),
        "Kind": ParagraphStyle("Kind", parent=base["Normal"], fontSize=9,
                                textColor=colors.HexColor("#0f766e"),
                                leading=12),
        "Purpose": ParagraphStyle("Purpose", parent=base["Normal"], fontSize=11,
                                   textColor=colors.HexColor("#475569"),
                                   leading=14, spaceAfter=6),
        "H2": ParagraphStyle("H2", parent=base["Heading2"], fontSize=11,
                              leading=14, textColor=colors.HexColor("#0f766e"),
                              spaceBefore=6, spaceAfter=4),
        "Body": ParagraphStyle("Body", parent=base["BodyText"], fontSize=9,
                                leading=12, textColor=colors.HexColor("#0f172a")),
        "Muted": ParagraphStyle("Muted", parent=base["BodyText"], fontSize=8,
                                 leading=11, textColor=colors.HexColor("#64748b")),
    }


def generate_cheatsheet_pdf(doc_id: str) -> bytes:
    doc, kind = _resolve(doc_id)
    if not doc:
        # Empty single-page PDF with an error message.
        buf = io.BytesIO()
        d = BaseDocTemplate(buf, pagesize=LETTER)
        d.addPageTemplates([PageTemplate(
            id="err",
            frames=[Frame(0.5*inch, 0.5*inch, 7.5*inch, 10*inch)],
        )])
        d.build([Paragraph(f"Unknown page: {doc_id}", getSampleStyleSheet()["Normal"])])
        return buf.getvalue()

    iocs, mitre = _extract_iocs_and_mitre(doc)
    styles = _styles()
    buf = io.BytesIO()

    tmpl = BaseDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=0.5*inch, rightMargin=0.5*inch,
        topMargin=0.5*inch, bottomMargin=0.5*inch,
        title=f"{doc.get('title', doc_id)} · Cheat Sheet",
    )
    frame = Frame(tmpl.leftMargin, tmpl.bottomMargin,
                   tmpl.width, tmpl.height, id="cs")
    tmpl.addPageTemplates([PageTemplate(id="cs", frames=[frame])])

    story: List[Any] = []
    story.append(Paragraph(f"<b>NIVXRAY · CHEAT SHEET</b> · {kind or ''}", styles["Kind"]))
    story.append(Paragraph(doc.get("title", doc_id), styles["H1"]))
    if doc.get("purpose"):
        story.append(Paragraph(doc["purpose"], styles["Purpose"]))

    # Screenshot (single)
    p = _SCREENSHOTS_DIR / doc_id / "step_1.png"
    if p.exists():
        try:
            img = RLImage(str(p))
            max_w = 7.5 * inch
            scale = max_w / max(1, img.imageWidth)
            img.drawWidth = max_w
            img.drawHeight = img.imageHeight * scale
            if img.drawHeight > 3.5 * inch:
                s2 = (3.5*inch) / img.drawHeight
                img.drawHeight *= s2
                img.drawWidth *= s2
            story.append(img)
            story.append(Spacer(1, 4))
        except Exception:
            pass

    def _section(label: str, items: List[str]):
        if not items:
            return
        story.append(Paragraph(label, styles["H2"]))
        for it in items:
            story.append(Paragraph(f"• {it}", styles["Body"]))

    if kind == "workflow":
        steps = doc.get("steps") or []
        if steps:
            story.append(Paragraph("Steps", styles["H2"]))
            for i, s in enumerate(steps, 1):
                story.append(Paragraph(
                    f"<b>{i}. {s.get('title','')}</b> — {s.get('action','')}",
                    styles["Body"]))
    _section("When to use", doc.get("when_to_use") or [])
    _section("Analyst tips", doc.get("tips") or [])
    if mitre:
        story.append(Paragraph("MITRE ATT&amp;CK", styles["H2"]))
        story.append(Paragraph(", ".join(mitre), styles["Body"]))
    if iocs:
        story.append(Paragraph("IOC signatures (extracted from YAML)", styles["H2"]))
        for i in iocs:
            story.append(Paragraph(f"<font face='Courier'>{i}</font>", styles["Body"]))
    _section("Common errors", doc.get("common_errors") or [])
    rel = doc.get("related") or doc.get("related_features") or []
    if rel:
        story.append(Paragraph("Related", styles["H2"]))
        story.append(Paragraph(", ".join(rel), styles["Body"]))

    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Auto-generated {datetime.now(timezone.utc).strftime('%Y-%m-%d')} · "
        f"NivXRay one-page cheat sheet · {doc_id}",
        styles["Muted"]))

    tmpl.build(story)
    return buf.getvalue()
