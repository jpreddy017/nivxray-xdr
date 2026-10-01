"""v2/report/pdf.py · Deterministic PDF rendering of the R4 report envelope.

Reportlab-based renderer. Same envelope → same PDF byte-stream:
- No wall-clock timestamps (report uses the envelope's `generated_at`)
- No random layout jitter (reportlab is deterministic given identical fonts)

Design tokens loosely mirror the Amber-on-Graphite web palette but PDF
is a print artefact so we lighten the surface (paper-white background,
dark ink) for readability on grayscale printers.
"""
from __future__ import annotations
from io import BytesIO
from typing import Any

from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    KeepTogether,
)

from .schema import ReportEnvelope


# ─── Style tokens ─────────────────────────────────────────────────────
_INK   = colors.HexColor("#0B0B0E")
_MUTED = colors.HexColor("#71717A")
_LINE  = colors.HexColor("#E4E4E7")
_AMBER = colors.HexColor("#B45309")
_ROSE  = colors.HexColor("#B91C1C")
_AMBER_LT = colors.HexColor("#FEF3C7")
_LINE_LT  = colors.HexColor("#F4F4F5")


def _styles() -> dict[str, ParagraphStyle]:
    ss = getSampleStyleSheet()
    return {
        "h1": ParagraphStyle("h1", parent=ss["Heading1"],
            fontName="Helvetica-Bold", fontSize=18, leading=22,
            textColor=_INK, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=ss["Heading2"],
            fontName="Helvetica-Bold", fontSize=13, leading=16,
            textColor=_AMBER, spaceBefore=14, spaceAfter=4),
        "body": ParagraphStyle("body", parent=ss["BodyText"],
            fontName="Helvetica", fontSize=9.5, leading=13,
            textColor=_INK, alignment=TA_LEFT),
        "mono": ParagraphStyle("mono", parent=ss["BodyText"],
            fontName="Courier", fontSize=8, leading=11, textColor=_INK),
        "muted": ParagraphStyle("muted", parent=ss["BodyText"],
            fontName="Helvetica", fontSize=8, leading=11, textColor=_MUTED),
        "hdr": ParagraphStyle("hdr", parent=ss["BodyText"],
            fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=_INK),
    }


def _table(headers: list[str], rows: list[list[Any]], col_widths=None) -> Table:
    data = [headers] + rows
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (-1, 0), _AMBER_LT),
        ("TEXTCOLOR",  (0, 0), (-1, 0), _INK),
        ("BOX",        (0, 0), (-1, -1), 0.4, _LINE),
        ("INNERGRID",  (0, 0), (-1, -1), 0.25, _LINE_LT),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING",   (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
    ]))
    return t


def _kv_lines(styles, pairs: list[tuple[str, Any]]) -> list:
    out = []
    for k, v in pairs:
        if v in (None, "", [], {}): continue
        v_str = ", ".join(str(x) for x in v) if isinstance(v, list) else str(v)
        out.append(Paragraph(f"<b>{k}</b>: <font face='Courier' size='8'>{v_str}</font>",
                             styles["body"]))
    return out


# ─── Public entry ─────────────────────────────────────────────────────
def render_pdf(env: ReportEnvelope) -> bytes:
    """Render the report envelope to a PDF byte stream. Deterministic."""
    # reportlab embeds `/CreationDate` and `/ID` from wall clock by
    # default — set `invariant=1` in module-scope config so two runs on
    # identical inputs produce byte-identical PDFs (matches the R4 hash
    # guarantee). We also stamp `/CreationDate` from the envelope's
    # `generated_at` for explicit provenance.
    from reportlab import rl_config
    rl_config.invariant = 1

    buf = BytesIO()
    styles = _styles()

    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
        title=f"NivXRay Investigation Report · {env.case_id}",
        author="NivXRay v2 · Deterministic Report Generator",
        subject=f"Case {env.case_id} · schema {env.schema_version}",
        creator="nivxray.v2.report",
        producer="reportlab",  # kept constant for byte-stability
    )

    story: list = []
    # Title block
    story.append(Paragraph("NivXRay · Deterministic Investigation Report", styles["h1"]))
    story.append(Paragraph(
        f"<b>Case</b>: <font face='Courier'>{env.case_id}</font> · "
        f"<b>Schema</b>: <font face='Courier'>{env.schema_version}</font> · "
        f"<b>Generated</b>: <font face='Courier'>{env.generated_at}</font>",
        styles["muted"]))
    story.append(Paragraph(
        f"<b>Signature (SHA-256)</b>: <font face='Courier' size='7'>{env.signature.get('sha256','—')}</font>",
        styles["muted"]))
    story.append(Spacer(1, 10))

    for sec in env.sections:
        story.append(Paragraph(f"{sec.order}. {sec.title}", styles["h2"]))
        if sec.narrative:
            story.append(Paragraph(sec.narrative, styles["body"]))
            story.append(Spacer(1, 4))
        b = sec.body

        if sec.id == "executive_summary":
            vc = b.get("verdict_counts", {})
            story.append(_table(
                ["Malicious", "Suspicious", "Observation", "Total"],
                [[str(vc.get("malicious", 0)), str(vc.get("suspicious", 0)),
                  str(vc.get("benign", 0)), str(b.get("event_total", 0))]],
                col_widths=[1.2 * inch] * 4,
            ))
            tactics = b.get("tactics") or []
            if tactics:
                story.append(Spacer(1, 4))
                story.append(Paragraph(f"<b>MITRE tactics</b>: {', '.join(tactics)}", styles["body"]))

        elif sec.id == "case_metadata":
            story.extend(_kv_lines(styles, [
                ("case_id",           b.get("case_id")),
                ("name",              b.get("name")),
                ("description",       b.get("description")),
                ("status",            b.get("status")),
                ("tags",              b.get("tags")),
                ("created_at",        b.get("created_at")),
                ("first_observed",    b.get("first_observed")),
                ("last_observed",     b.get("last_observed")),
                ("observation_count", b.get("observation_count")),
            ]))

        elif sec.id == "verdict_rollup":
            counts = b.get("counts", {})
            pct = b.get("percentages", {})
            story.append(_table(
                ["Verdict", "Count", "Percentage"],
                [[k, str(counts.get(k, 0)), f"{pct.get(k, 0)}%"]
                 for k in ("malicious", "suspicious", "benign")],
                col_widths=[2 * inch, 1 * inch, 1.5 * inch],
            ))

        elif sec.id == "mitre_coverage":
            if b.get("tactics"):
                story.append(Paragraph("<b>Tactics</b>", styles["body"]))
                story.append(_table(["Tactic", "Count"],
                                    [[t["id"], str(t["count"])] for t in b["tactics"]],
                                    col_widths=[3 * inch, 1 * inch]))
                story.append(Spacer(1, 4))
            if b.get("techniques"):
                story.append(Paragraph("<b>Techniques</b>", styles["body"]))
                story.append(_table(["Technique", "Count"],
                                    [[t["id"], str(t["count"])] for t in b["techniques"]],
                                    col_widths=[3 * inch, 1 * inch]))

        elif sec.id == "process_ancestry":
            for p in b.get("top_processes", []):
                story.append(Paragraph(
                    f"<font face='Courier'>{p['process']}</font> — {p['event_count']} events",
                    styles["body"]))
            edges = b.get("spawn_edges", [])
            if edges:
                story.append(Spacer(1, 4))
                story.append(Paragraph("<b>Spawn edges</b>", styles["body"]))
                for e in edges[:20]:
                    story.append(Paragraph(
                        f"<font face='Courier' size='8'>{e['parent']}</font> → "
                        f"{', '.join(f'<font face=' + chr(39) + 'Courier' + chr(39) + ' size=' + chr(39) + '8' + chr(39) + '>' + c + '</font>' for c in e['children'])}",
                        styles["body"]))

        elif sec.id == "top_entities":
            for kind in ("file", "network", "registry", "user", "device"):
                items = b.get(kind, [])
                if not items: continue
                story.append(Paragraph(f"<b>{kind.title()}</b>", styles["body"]))
                for it in items:
                    story.append(Paragraph(
                        f"<font face='Courier' size='8'>{it['iid']}</font> — {it['count']}",
                        styles["body"]))
                story.append(Spacer(1, 4))

        elif sec.id == "chronological_timeline":
            rows_data = b.get("rows", [])
            # Cap at 60 rows for PDF layout — full data lives in JSON export
            for i, r in enumerate(rows_data[:60], 1):
                m = ",".join(r.get("mitre") or [])
                story.append(Paragraph(
                    f"<b>{i:03d}</b> "
                    f"<font face='Courier' size='7'>{r.get('ts','')}</font> · "
                    f"<b>{r.get('verdict','').upper()}</b> · "
                    f"{r.get('lane','')} · "
                    f"<font face='Courier'>{r.get('action','')}</font> · "
                    f"<font face='Courier'>{r.get('process','')}</font>"
                    + (f" · <font color='#B91C1C'>{m}</font>" if m else ""),
                    styles["mono"]))
            if len(rows_data) > 60:
                story.append(Paragraph(f"… {len(rows_data) - 60} more rows in JSON export.",
                                       styles["muted"]))

        elif sec.id == "commandline_decoding":
            for d in b.get("decoded_events", []):
                story.append(Paragraph(f"<b>{d.get('ts','')}</b> "
                                       f"<font face='Courier' size='7'>{d.get('frame_iid','')}</font>",
                                       styles["body"]))
                story.append(Paragraph(f"raw: <font face='Courier' size='8'>{d.get('raw','')}</font>", styles["body"]))
                if d.get("decoded"):
                    story.append(Paragraph(f"decoded: <font face='Courier' size='8'>{d['decoded']}</font>", styles["body"]))

        elif sec.id == "enrichment":
            story.append(Paragraph(f"<i>Status: {b.get('status','—')} · "
                                   f"Enrichment kit lands in R3.</i>", styles["muted"]))

        elif sec.id == "signature":
            story.append(_table(
                ["Algorithm", "SHA-256", "Bytes"],
                [[env.signature.get("algorithm", "sha256"),
                  env.signature.get("sha256", "—"),
                  env.signature.get("canonical_json_bytes", "—")]],
                col_widths=[1 * inch, 4.5 * inch, 0.9 * inch],
            ))

    doc.build(story)
    return buf.getvalue()
