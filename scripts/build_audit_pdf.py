"""Generate a downloadable PDF from the 360° audit markdown.

Read-only in intent — writes the PDF to /app/backend/exports/ so the
frontend's static-file mount serves it. No app code is modified.
"""
from __future__ import annotations
import os, sys
import markdown  # noqa
from xhtml2pdf import pisa

SRC = "/app/memory/adr/0012-workspace-360-audit.md"
OUT_DIR = "/app/backend/exports"
os.makedirs(OUT_DIR, exist_ok=True)
OUT = os.path.join(OUT_DIR, "NivXRay-Workspace-360-Audit.pdf")

with open(SRC, "r", encoding="utf-8") as fh:
    md_text = fh.read()

html_body = markdown.markdown(md_text, extensions=["tables", "fenced_code", "toc"])

CSS = """
<style>
  @page { size: A4 portrait; margin: 20mm 15mm 20mm 15mm; }
  body  { font-family: Helvetica, Arial, sans-serif; font-size: 9.5pt; color: #111; line-height: 1.35; }
  h1    { font-size: 16pt; color: #0b3d91; border-bottom: 1.5pt solid #0b3d91; padding-bottom: 3pt; margin-top: 14pt;}
  h2    { font-size: 12.5pt; color: #0b3d91; margin-top: 12pt; }
  h3    { font-size: 10.8pt; color: #333; margin-top: 8pt; }
  h4    { font-size: 10pt;   color: #444; margin-top: 6pt; }
  code, pre { font-family: "Courier New", monospace; font-size: 8.5pt; background: #f2f4f8; }
  pre   { padding: 6pt; border: 1px solid #d8dde5; white-space: pre-wrap; }
  table { border-collapse: collapse; width: 100%; margin: 4pt 0; font-size: 8.5pt; }
  th, td{ border: 0.5pt solid #b7bcc4; padding: 3pt 4pt; vertical-align: top; }
  th    { background: #e6ecf4; text-align: left; }
  ul, ol{ margin: 4pt 0 4pt 15pt; }
  hr    { border: none; border-top: 1pt solid #b7bcc4; margin: 10pt 0; }
  a     { color: #0b3d91; text-decoration: none; }
  blockquote { border-left: 3pt solid #b7bcc4; padding-left: 8pt; color: #444; }
</style>
"""

FOOTER = """
<div style="text-align:center; font-size: 8pt; color:#888; margin-top:12pt;">
  NivXRay — Workspace 360° Current-State Architecture & Functionality Audit — Session-20
</div>
"""

full_html = f"<html><head><meta charset='utf-8'>{CSS}</head><body>{html_body}{FOOTER}</body></html>"

with open(OUT, "wb") as fh:
    status = pisa.CreatePDF(src=full_html, dest=fh, encoding="utf-8")

if status.err:
    print(f"PDF generation FAILED with {status.err} errors", file=sys.stderr)
    sys.exit(1)

sz = os.path.getsize(OUT)
print(f"OK · {OUT} · {sz} bytes")
