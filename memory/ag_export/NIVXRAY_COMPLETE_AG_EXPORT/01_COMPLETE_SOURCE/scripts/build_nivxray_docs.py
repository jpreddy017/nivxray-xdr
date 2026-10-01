#!/usr/bin/env python3
"""Build printable HTML views of the five baseline ADRs.

This is a documentation deliverable — it renders existing markdown into
self-contained HTML files served by the frontend at:

    ${REACT_APP_BACKEND_URL}/nivxray-docs/index.html

No backend route added. No React component touched. No shipping product
code affected. Files live under frontend/public/nivxray-docs/.

Run:
    python3 /app/scripts/build_nivxray_docs.py
"""
from __future__ import annotations
import os, re, html
from pathlib import Path
import markdown

ADR_DIR  = Path("/app/memory/adr")
OUT_DIR  = Path("/app/frontend/public/nivxray-docs")
OUT_DIR.mkdir(parents=True, exist_ok=True)

DOCS = [
    ("0010-nivxray-product-blueprint.md",     "product-blueprint.html",
     "NivXRay · Product & Architecture Blueprint",
     "1,815-line plain-language synthesis of what NivXRay actually is today. "
     "45 sections + 8 architecture diagrams + 15-minute owner narrative. Read §44 first."),
    ("0007-current-state-master-snapshot.md", "current-state-audit.html",
     "NivXRay · 360° Current-State Master Snapshot",
     "Evidence baseline — every claim traceable to a file, route, collection, "
     "flag, or test. Read this if you need to verify a claim in the Blueprint."),
    ("0008-execution-plan-from-audit.md",     "execution-plan.html",
     "NivXRay · Execution Plan from Audit (ADR-0008)",
     "The execution constitution: shadow ≠ dead, 5 shadow-subsystem promotion "
     "criteria, security gate, server-side file mode, do-NOT-build-yet list."),
    ("0009-route-classification.md",          "route-classification.html",
     "NivXRay · API Route Classification (ADR-0009)",
     "All 466 backend operations classified: ACTIVE-UI · ACTIVE-API · INTERNAL · "
     "EXPERIMENTAL · DEPRECATED · DUPLICATE · UNKNOWN. Evidence-backed."),
    ("0011-tweetfeed-evaluation.md",          "tweetfeed-evaluation.html",
     "NivXRay · TweetFeed Evaluation (ADR-0011)",
     "Read-only evaluation of tweetfeed.live as a potential 9th TI provider. "
     "Decision: BACKLOG (multi-use, high priority)."),
]

CSS = """
:root {
  --bg:#0f1218; --fg:#e6edf3; --muted:#8b96a5; --accent:#7ee787;
  --card:#161b22; --border:#30363d; --code-bg:#1c2128; --link:#79c0ff;
}
* { box-sizing:border-box; }
html,body { margin:0; padding:0; background:var(--bg); color:var(--fg);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,ui-sans-serif,system-ui,sans-serif;
  font-size:15px; line-height:1.6; -webkit-font-smoothing:antialiased; }
main { max-width:920px; margin:0 auto; padding:56px 40px 120px; }
nav.topbar { background:#0b0e13; border-bottom:1px solid var(--border);
  padding:14px 40px; display:flex; align-items:center; justify-content:space-between;
  position:sticky; top:0; z-index:10; }
nav.topbar a { color:var(--link); text-decoration:none; margin-right:16px; font-size:13px; }
nav.topbar a.brand { color:var(--accent); font-weight:600; }
nav.topbar a:hover { text-decoration:underline; }
h1 { font-size:32px; margin:32px 0 12px; letter-spacing:-.02em; }
h2 { font-size:24px; margin:44px 0 12px; padding-bottom:8px; border-bottom:1px solid var(--border); letter-spacing:-.01em; }
h3 { font-size:19px; margin:28px 0 10px; color:#c9d1d9; }
h4 { font-size:16px; margin:22px 0 8px; color:#c9d1d9; }
p, li { color:var(--fg); }
a { color:var(--link); }
strong { color:#ffdf5d; }
em { color:#c9d1d9; }
code { background:var(--code-bg); padding:2px 6px; border-radius:4px; font-size:13px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,"Cascadia Mono",monospace; color:#ffa657; }
pre { background:var(--code-bg); padding:16px 20px; border-radius:8px; overflow-x:auto;
  border:1px solid var(--border); }
pre code { background:transparent; padding:0; color:#c9d1d9; font-size:12.5px; line-height:1.55; }
blockquote { border-left:3px solid var(--accent); background:#141a20; padding:12px 20px;
  margin:16px 0; color:#c9d1d9; border-radius:4px; }
table { border-collapse:collapse; width:100%; margin:16px 0; font-size:13.5px; }
th, td { border:1px solid var(--border); padding:8px 12px; text-align:left; vertical-align:top; }
th { background:#141a20; color:#c9d1d9; font-weight:600; }
tr:nth-child(even) td { background:#131820; }
hr { border:none; border-top:1px solid var(--border); margin:32px 0; }
ul, ol { padding-left:24px; }
li { margin:4px 0; }
.meta { color:var(--muted); font-size:13px; margin-bottom:24px; }
.legend-live      { color:#7ee787; }
.legend-shadow    { color:#f0d05e; }
.legend-disc      { color:#ffa657; }
.legend-partial   { color:#79c0ff; }
.legend-exp       { color:#d2a8ff; }
.legend-planned   { color:#8b96a5; }
.legend-dead      { color:#ff7b72; }
@media print {
  nav.topbar { display:none; }
  main { max-width:none; padding:24px 32px; }
  body { background:#fff; color:#000; }
  h1,h2,h3,h4 { color:#000; }
  code, pre { background:#f4f4f4; color:#000; }
  pre { border:1px solid #ddd; }
  th { background:#eee; color:#000; }
  a { color:#0057aa; }
  blockquote { background:#f4f4f4; color:#333; }
}
""".strip()

NAV = """
<nav class="topbar">
  <div>
    <a class="brand" href="index.html">NivXRay Docs</a>
    <a href="product-blueprint.html">Blueprint</a>
    <a href="current-state-audit.html">Audit</a>
    <a href="execution-plan.html">Execution Plan</a>
    <a href="route-classification.html">Routes</a>
    <a href="tweetfeed-evaluation.html">TweetFeed</a>
  </div>
  <div style="color:#8b96a5;font-size:12px;">Session-9 baseline · read-only</div>
</nav>
""".strip()

TEMPLATE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{title}</title>
<style>{css}</style>
</head><body>
{nav}
<main>
<div class="meta">Source: <code>{source}</code></div>
{body}
</main>
</body></html>
"""

INDEX_TEMPLATE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>NivXRay · Documentation Index</title>
<style>{css}
.card {{ border:1px solid var(--border); background:var(--card); border-radius:10px;
  padding:22px 26px; margin:16px 0; transition:border-color .12s ease; }}
.card:hover {{ border-color:var(--accent); }}
.card a {{ display:block; text-decoration:none; }}
.card h3 {{ margin:0 0 8px; color:var(--accent); }}
.card p  {{ margin:0; color:var(--muted); font-size:14px; }}
.legend {{ font-size:12.5px; color:var(--muted); margin-top:32px; }}
.legend span {{ margin-right:14px; }}
</style>
</head><body>
{nav}
<main>
<h1>NivXRay · Documentation Baseline</h1>
<p class="meta">Five ADRs form the frozen Session-9 baseline. Read them in this order.
Every claim in the Blueprint is evidence-traceable to the Audit.</p>

{cards}

<hr/>
<h3>What to read first</h3>
<ul>
<li>New to NivXRay? &nbsp;→ &nbsp;<a href="product-blueprint.html">Product Blueprint</a> · jump to <em>§44 NivXRay in Plain English</em> and diagrams A-H.</li>
<li>Need proof of a claim? &nbsp;→ &nbsp;<a href="current-state-audit.html">360° Master Snapshot</a>.</li>
<li>Want to know what we're about to build? &nbsp;→ &nbsp;<a href="execution-plan.html">Execution Plan</a>.</li>
<li>Want to know what an API route does? &nbsp;→ &nbsp;<a href="route-classification.html">Route Classification</a>.</li>
</ul>

<div class="legend">
  <strong>Status legend used across the docs:</strong><br/>
  <span class="legend-live">🟢 LIVE</span>
  <span class="legend-shadow">🟡 SHADOW</span>
  <span class="legend-disc">🟠 DISCONNECTED</span>
  <span class="legend-partial">🔵 PARTIAL</span>
  <span class="legend-exp">🧪 EXPERIMENTAL</span>
  <span class="legend-planned">⚪ PLANNED</span>
  <span class="legend-dead">⚫ DEAD</span>
</div>

<p class="meta" style="margin-top:40px;">Locked next move: <strong>P0 Security Hardening Gate</strong>.
Discovery loop is closed — see PRD.md at the repo root for the sequenced roadmap.</p>
</main>
</body></html>
"""

md = markdown.Markdown(extensions=[
    "extra",         # tables, fenced_code, attr_list, def_list
    "sane_lists",
    "toc",
    "codehilite",
])

def render(src_path: Path) -> str:
    md.reset()
    text = src_path.read_text(encoding="utf-8")
    return md.convert(text)

def build_page(title: str, source: str, body_html: str) -> str:
    return TEMPLATE.format(title=html.escape(title), css=CSS, nav=NAV,
                           source=html.escape(source), body=body_html)

def build_index(cards_html: str) -> str:
    return INDEX_TEMPLATE.format(css=CSS, nav=NAV, cards=cards_html)

cards = []
for md_name, out_name, title, blurb in DOCS:
    src = ADR_DIR / md_name
    if not src.exists():
        print(f"SKIP (missing): {src}")
        continue
    html_body = render(src)
    page = build_page(title, str(src), html_body)
    (OUT_DIR / out_name).write_text(page, encoding="utf-8")
    print(f"WROTE {OUT_DIR / out_name}  ({len(page):,} bytes)")
    cards.append(
        f'<div class="card"><a href="{out_name}">'
        f'<h3>{html.escape(title)}</h3>'
        f'<p>{html.escape(blurb)}</p></a></div>'
    )

(OUT_DIR / "index.html").write_text(build_index("\n".join(cards)), encoding="utf-8")
print(f"WROTE {OUT_DIR / 'index.html'}")
print("\nOpen the docs at:")
print("  ${REACT_APP_BACKEND_URL}/nivxray-docs/index.html")
