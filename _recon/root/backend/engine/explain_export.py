"""RC5 · Phase 9.5+ · Explainability Export.

Given the RC5 `/api/rc5/parse` response dict (or the individual components),
produce a self-contained, analyst-shareable artefact in one of:

  * JSON  — the raw structured bundle (Evidence Tree · Execution Graph ·
            Semantic IR · Behaviors · MITRE mappings · Verdict ·
            Confidence Breakdown · Why-NOT-Malicious)
  * HTML  — dark-themed, printable, self-contained (all CSS inlined)
  * PDF   — ReportLab flowables

Deterministic. No AI imports.
"""
from __future__ import annotations

import html
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def export_json(rc5: Dict[str, Any]) -> bytes:
    """Return a canonical JSON bundle. Deterministic (sorted keys)."""
    bundle = _bundle(rc5)
    return json.dumps(bundle, sort_keys=True, indent=2, default=str).encode("utf-8")


def _bundle(rc5: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "format": "nivxray.rc5.explain.v1",
        "input": rc5.get("input", ""),
        "language": rc5.get("language", ""),
        "verdict": rc5.get("verdict_v2"),
        "confidence": (rc5.get("explain") or {}).get("confidence_breakdown"),
        "why_not_malicious": (rc5.get("explain") or {}).get("why_not_malicious"),
        "evidence_tree": (rc5.get("explain") or {}).get("evidence_tree"),
        "behaviors": rc5.get("behaviors"),
        "mitre": rc5.get("mitre"),
        "mitre_navigator": rc5.get("mitre_navigator"),
        "mitre_stix": rc5.get("mitre_stix"),
        "lolbins_v2": rc5.get("lolbins_v2"),
        "exec_graph": rc5.get("exec_graph"),
        "semantic_ir": rc5.get("semantic_ir"),
        "reconstructed_commands": rc5.get("reconstructed_commands"),
        "decode_chain": rc5.get("decode_chain"),
        "warnings": rc5.get("warnings"),
        "unresolved_nodes": rc5.get("unresolved_nodes"),
        "processing_time_ms": rc5.get("processing_time_ms"),
    }


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
_HTML_CSS = """
:root{color-scheme:dark}
body{font:14px/1.5 -apple-system,'Segoe UI',Roboto,sans-serif;
     margin:0;padding:24px 32px;background:#0e1116;color:#dfe6ec}
h1{font-size:22px;margin:0 0 4px;color:#7dd3fc}
h2{font-size:16px;margin:24px 0 8px;color:#facc15;
   border-bottom:1px solid #1f2937;padding-bottom:4px}
h3{font-size:14px;margin:16px 0 6px;color:#94a3b8}
.tag{display:inline-block;padding:2px 8px;border-radius:9999px;
     font-size:12px;font-weight:600}
.tag.benign{background:#14532d;color:#bbf7d0}
.tag.suspicious{background:#78350f;color:#fed7aa}
.tag.malicious{background:#7f1d1d;color:#fecaca}
.tag.critical{background:#450a0a;color:#fecaca;border:1px solid #ef4444}
.mono{font-family:'SF Mono',Consolas,monospace;font-size:12px;
      background:#0b0f14;padding:8px 12px;border-radius:6px;
      white-space:pre-wrap;word-break:break-all;color:#e2e8f0}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:8px 0}
.card{background:#111827;border:1px solid #1f2937;border-radius:8px;
      padding:12px 14px}
.card b{color:#f1f5f9}
.small{color:#94a3b8;font-size:12px}
table{border-collapse:collapse;width:100%;font-size:12px;margin:8px 0}
th,td{border-bottom:1px solid #1f2937;padding:6px 10px;text-align:left;
      vertical-align:top}
th{color:#facc15;font-weight:600}
ul{margin:6px 0 6px 24px;padding:0}
li{margin:2px 0}
.evidence{background:#0b0f14;border-left:3px solid #38bdf8;padding:8px 12px;
          margin:6px 0;border-radius:0 6px 6px 0}
footer{margin-top:24px;color:#64748b;font-size:11px}
@media print{body{background:white;color:#111}
  .card{background:#fafafa;border-color:#e5e7eb}
  .mono{background:#f5f5f5;color:#111}
  h1{color:#0369a1}h2{color:#b45309}h3{color:#334155}}
"""


def _tier_class(tier: str) -> str:
    return (tier or "").lower()


def _fmt_json(obj: Any) -> str:
    return html.escape(json.dumps(obj, default=str, indent=2))


def export_html(rc5: Dict[str, Any]) -> bytes:
    b = _bundle(rc5)
    verdict = b.get("verdict") or {}
    tier = verdict.get("verdict") or "—"
    risk = verdict.get("risk", "—")
    scores = verdict.get("scores") or {}
    conf = b.get("confidence") or {}
    wnm = b.get("why_not_malicious") or {}
    tree = b.get("evidence_tree") or []
    mitre = b.get("mitre") or []
    lolbins = b.get("lolbins_v2") or []
    behaviors = b.get("behaviors") or []

    def _row(label: str, value: Any) -> str:
        return f"<div class='card'><div class='small'>{html.escape(label)}</div><b>{html.escape(str(value))}</b></div>"

    dims = "".join(_row(k, v) for k, v in scores.items())
    conf_rows = "".join(_row(k, v) for k, v in conf.items() if k != "weights")
    reasons = "".join(
        f"<div class='evidence'><b>{html.escape(r.get('reason',''))}</b>"
        f"<br><span class='small'>dim={html.escape(r.get('dimension',''))}"
        f" · contribution={r.get('contribution',0)}"
        f" · behavior={html.escape(r.get('behavior_id',''))}"
        f" · nodes={', '.join(r.get('exec_node_ids') or [])}</span></div>"
        for r in tree
    )
    wnm_signals = "".join(
        f"<li>{html.escape(s)}</li>" for s in (wnm.get("missing_signals") or [])
    )
    wnm_guards = "".join(
        f"<li>{html.escape(g)}</li>" for g in (wnm.get("guardrails_applied") or [])
    )
    mitre_rows = "".join(
        f"<tr><td>{html.escape(m.get('technique_id',''))}</td>"
        f"<td>{html.escape(m.get('sub_technique_id','') or '')}</td>"
        f"<td>{html.escape(m.get('technique_name',''))}</td>"
        f"<td>{html.escape(m.get('tactic_name',''))}</td>"
        f"<td>{m.get('confidence',0)}</td>"
        f"<td>{html.escape(m.get('rule_id',''))}</td></tr>"
        for m in mitre
    )
    lolbin_rows = "".join(
        f"<tr><td><b>{html.escape(l.get('display_name',''))}</b></td>"
        f"<td>{html.escape(l.get('state',''))}</td>"
        f"<td>{'yes' if l.get('enters_verdict') else 'no'}</td>"
        f"<td>{', '.join(l.get('purposes',[]))}</td>"
        f"<td>{', '.join(l.get('mitre',[]))}</td></tr>"
        for l in lolbins
    )
    behavior_rows = "".join(
        f"<tr><td>{html.escape(b.get('tactic',''))}</td>"
        f"<td>{html.escape(b.get('sub_kind','') or '')}</td>"
        f"<td>{b.get('confidence',0)}</td>"
        f"<td class='mono'>{html.escape(b.get('reconstructed','')[:200])}</td></tr>"
        for b in behaviors
    )

    body = f"""<!doctype html><html><head><meta charset='utf-8'>
<title>NivXRay · RC5 Explainability Report</title>
<style>{_HTML_CSS}</style></head><body>
<h1>NivXRay · RC5 Explainability Report</h1>
<div class='small'>Generated {html.escape(b.get('generated_at',''))} · language={html.escape(b.get('language',''))}</div>

<h2>Verdict</h2>
<div class='grid'>
  <div class='card'><div class='small'>Tier</div><b><span class='tag {_tier_class(tier)}'>{html.escape(str(tier))}</span></b></div>
  <div class='card'><div class='small'>Risk score</div><b>{html.escape(str(risk))}</b></div>
  <div class='card'><div class='small'>Raw risk</div><b>{html.escape(str(verdict.get('raw_risk','—')))}</b></div>
  <div class='card'><div class='small'>Cap</div><b>{html.escape(str(verdict.get('cap_applied','—') or '—'))}</b></div>
  <div class='card'><div class='small'>Floor</div><b>{html.escape(str(verdict.get('floor_applied','—') or '—'))}</b></div>
</div>

<h3>7-dimension scores</h3>
<div class='grid'>{dims}</div>

<h2>Confidence Breakdown</h2>
<div class='grid'>{conf_rows}</div>

<h2>Why NOT Malicious?</h2>
{'<div class="small">Applicable: <b>YES</b></div>' if wnm.get('applicable') else '<div class="small">Applicable: <b>NO</b> — verdict is Malicious/Critical.</div>'}
<p>{html.escape(wnm.get('summary',''))}</p>
{'<h3>Missing signals</h3><ul>' + wnm_signals + '</ul>' if wnm_signals else ''}
{'<h3>Guardrails applied</h3><ul>' + wnm_guards + '</ul>' if wnm_guards else ''}

<h2>Evidence Tree</h2>
{reasons or '<div class="small">No evidence links (verdict likely benign or empty).</div>'}

<h2>MITRE ATT&amp;CK Mappings</h2>
<table><thead><tr><th>Tid</th><th>Sub</th><th>Name</th><th>Tactic</th><th>Conf</th><th>Rule</th></tr></thead>
<tbody>{mitre_rows or '<tr><td colspan=6 class="small">No mappings emitted.</td></tr>'}</tbody></table>

<h2>LOLBIN Attribution (3-state)</h2>
<table><thead><tr><th>Binary</th><th>State</th><th>Enters verdict</th><th>Purposes</th><th>MITRE</th></tr></thead>
<tbody>{lolbin_rows or '<tr><td colspan=5 class="small">No LOLBIN observed.</td></tr>'}</tbody></table>

<h2>Behaviors</h2>
<table><thead><tr><th>Tactic</th><th>Sub-kind</th><th>Conf</th><th>Reconstructed</th></tr></thead>
<tbody>{behavior_rows or '<tr><td colspan=4 class="small">No behaviors extracted.</td></tr>'}</tbody></table>

<h2>Input</h2>
<div class='mono'>{html.escape(b.get('input',''))}</div>

<footer>
NivXRay RC5 · format nivxray.rc5.explain.v1 · deterministic bundle · no AI in decoded evidence.
</footer>
</body></html>"""
    return body.encode("utf-8")


# ---------------------------------------------------------------------------
# PDF (ReportLab)
# ---------------------------------------------------------------------------
def export_pdf(rc5: Dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    )

    b = _bundle(rc5)
    verdict = b.get("verdict") or {}
    tier = verdict.get("verdict") or "—"
    scores = verdict.get("scores") or {}
    conf = b.get("confidence") or {}
    wnm = b.get("why_not_malicious") or {}
    tree = b.get("evidence_tree") or []
    mitre = b.get("mitre") or []
    lolbins = b.get("lolbins_v2") or []
    behaviors = b.get("behaviors") or []

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            topMargin=0.6 * inch, bottomMargin=0.6 * inch,
                            leftMargin=0.6 * inch, rightMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=16,
                        textColor=colors.HexColor("#0369a1"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12,
                        textColor=colors.HexColor("#b45309"))
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8,
                           textColor=colors.HexColor("#64748b"))
    mono = ParagraphStyle("mono", parent=body, fontName="Courier",
                          fontSize=8, textColor=colors.HexColor("#111827"))

    story = []
    story.append(Paragraph("NivXRay · RC5 Explainability Report", h1))
    story.append(Paragraph(
        f"Generated {b.get('generated_at')} · language={b.get('language')}", small))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Verdict", h2))
    verdict_tbl = Table([
        ["Tier", str(tier)],
        ["Risk", str(verdict.get("risk", "—"))],
        ["Raw risk", str(verdict.get("raw_risk", "—"))],
        ["Cap applied", str(verdict.get("cap_applied") or "—")],
        ["Floor applied", str(verdict.get("floor_applied") or "—")],
    ], colWidths=[110, 380])
    verdict_tbl.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
    ]))
    story.append(verdict_tbl)
    story.append(Spacer(1, 6))

    story.append(Paragraph("7-Dimension Scores", h2))
    dim_tbl = Table([[k, str(v)] for k, v in scores.items()], colWidths=[180, 60])
    dim_tbl.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
    ]))
    story.append(dim_tbl)
    story.append(Spacer(1, 6))

    story.append(Paragraph("Confidence Breakdown", h2))
    conf_tbl = Table([[k, str(v)] for k, v in conf.items() if k != "weights"],
                     colWidths=[220, 60])
    conf_tbl.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
    ]))
    story.append(conf_tbl)
    story.append(Spacer(1, 6))

    story.append(Paragraph("Why NOT Malicious?", h2))
    if wnm.get("applicable"):
        story.append(Paragraph(str(wnm.get("summary") or ""), body))
        for s in (wnm.get("missing_signals") or []):
            story.append(Paragraph(f"• {s}", body))
    else:
        story.append(Paragraph("Not applicable — verdict is Malicious/Critical.", small))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Evidence Tree", h2))
    if tree:
        for r in tree:
            story.append(Paragraph(
                f"<b>{r.get('reason','')}</b> "
                f"<font size=7 color='#64748b'>· dim={r.get('dimension','')} · "
                f"contribution={r.get('contribution',0)}</font>", body))
            story.append(Paragraph(
                f"behavior={r.get('behavior_id','')} · nodes={', '.join(r.get('exec_node_ids') or [])}",
                small))
    else:
        story.append(Paragraph("No evidence links.", small))
    story.append(Spacer(1, 6))

    story.append(Paragraph("MITRE ATT&amp;CK Mappings", h2))
    if mitre:
        rows = [["Tid", "Sub", "Name", "Tactic", "Conf"]]
        for m in mitre:
            rows.append([m.get("technique_id", ""),
                         m.get("sub_technique_id") or "",
                         (m.get("technique_name") or "")[:48],
                         m.get("tactic_name", ""),
                         str(m.get("confidence", 0))])
        t = Table(rows, colWidths=[45, 55, 240, 90, 40])
        t.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fef3c7")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No mappings.", small))
    story.append(Spacer(1, 6))

    story.append(Paragraph("LOLBIN Attribution", h2))
    if lolbins:
        rows = [["Binary", "State", "→Verdict", "Purposes", "MITRE"]]
        for l in lolbins:
            rows.append([l.get("display_name", ""),
                         l.get("state", ""),
                         "yes" if l.get("enters_verdict") else "no",
                         ", ".join(l.get("purposes", [])),
                         ", ".join(l.get("mitre", []))])
        t = Table(rows, colWidths=[95, 55, 55, 145, 120])
        t.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fef3c7")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No LOLBIN observed.", small))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Input", h2))
    story.append(Paragraph(str(b.get("input", ""))[:2000], mono))

    doc.build(story)
    return buf.getvalue()


__all__ = ["export_json", "export_html", "export_pdf"]
