#!/usr/bin/env python3
"""One-shot builder for /app/memory/NIVXRAY_XDR_SOURCE_EXPORT.html

Emits a single self-contained HTML that embeds every text source file
in the NivXRay XDR repository, with a navigation index and per-file
sections.  Excludes: node_modules, __pycache__, .git, generated locks,
secrets (.env, test_credentials.md), uploads, binaries, and files >2MB.
No application code is modified.
"""
from __future__ import annotations
import hashlib
import html
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/app")
OUT = Path("/app/memory/NIVXRAY_XDR_SOURCE_EXPORT.html")

INCLUDE_EXTS = {
    ".py", ".pyi",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
    ".md", ".txt", ".rst",
    ".html", ".css", ".scss", ".sass",
    ".sh", ".bash",
    ".sql", ".graphql", ".proto",
}
INCLUDE_FILENAMES = {
    "Dockerfile", "Makefile",
    ".gitignore", ".dockerignore",
    "requirements.txt", "package.json", "tsconfig.json",
    ".env.example",
}
EXCLUDE_DIRS = {
    "node_modules", "__pycache__", ".git",
    "dist", "build", ".next", ".turbo",
    "venv", ".venv", "env", "virtualenv",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".cache",
    "coverage", ".coverage",
    "uploads", "uploaded_cases", "downloads",
}
EXCLUDE_EXACT = {
    "yarn.lock", "package-lock.json", "pnpm-lock.yaml",
    "poetry.lock", "Pipfile.lock",
    ".env",
    "test_credentials.md",
}
MAX_FILE_BYTES = 2_000_000  # skip individual files > 2 MB (fixtures)


def is_includable(p: Path) -> bool:
    parts = set(p.parts)
    if parts & EXCLUDE_DIRS:
        return False
    if p.name in EXCLUDE_EXACT:
        return False
    if p.name in INCLUDE_FILENAMES:
        return True
    if p.name.startswith("Dockerfile"):
        return True
    return p.suffix in INCLUDE_EXTS


def gather() -> list[Path]:
    out = []
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file():
            continue
        if not is_includable(p):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        out.append(p)
    return out


def anchor(rel: str) -> str:
    h = hashlib.sha1(rel.encode("utf-8")).hexdigest()[:12]
    return f"f-{h}"


HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NivXRay XDR · Source Export (offline reference for Antigravity)</title>
<style>
:root {{ color-scheme: light dark; }}
html, body {{ margin: 0; padding: 0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; line-height: 1.45; }}
body {{ display: grid; grid-template-columns: 320px 1fr; min-height: 100vh; }}
aside {{ position: sticky; top: 0; height: 100vh; overflow-y: auto; padding: 12px 14px; border-right: 1px solid #ccc; background: #f8f9fb; font-size: 12.5px; }}
aside h1 {{ font-size: 14px; margin: 4px 0 8px; }}
aside details {{ margin: 4px 0; }}
aside details summary {{ cursor: pointer; font-weight: 600; padding: 2px 0; }}
aside ul {{ list-style: none; margin: 0; padding: 0 0 0 14px; }}
aside li {{ margin: 2px 0; }}
aside a {{ text-decoration: none; color: #0645ad; word-break: break-all; }}
aside a:hover {{ text-decoration: underline; }}
main {{ padding: 18px 22px 80px; max-width: none; overflow-x: hidden; }}
main header.top {{ padding-bottom: 12px; border-bottom: 2px solid #333; margin-bottom: 20px; }}
main h1 {{ font-size: 22px; margin: 0 0 6px; }}
main .meta {{ font-size: 12.5px; color: #444; }}
main .meta kbd {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: #eee; padding: 1px 4px; border-radius: 3px; }}
main .notice {{ background: #fff8dc; border-left: 4px solid #d4a017; padding: 8px 12px; margin: 10px 0; font-size: 13px; }}
main section.file {{ margin: 28px 0; }}
main section.file > h2 {{ font-size: 13.5px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: #eef1f6; padding: 8px 10px; margin: 0; border: 1px solid #ccd; border-radius: 4px 4px 0 0; display: flex; justify-content: space-between; gap: 12px; }}
main section.file > h2 .size {{ color: #666; font-weight: normal; font-size: 12px; }}
main pre {{ margin: 0; padding: 10px 12px; background: #fafbfd; border: 1px solid #ccd; border-top: 0; border-radius: 0 0 4px 4px; overflow-x: auto; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; line-height: 1.35; white-space: pre; }}
main a.backtotop {{ float: right; font-size: 11px; color: #888; text-decoration: none; }}
@media (max-width: 800px) {{ body {{ grid-template-columns: 1fr; }} aside {{ position: static; height: auto; max-height: 40vh; }} }}
</style>
</head>
<body>
"""


def render_nav(groups: dict[str, list[tuple[Path, str]]]) -> str:
    lines = ['<aside id="nav">']
    lines.append('<h1>NivXRay XDR · Source Index</h1>')
    lines.append('<div style="font-size:11.5px;color:#555;margin-bottom:8px;">Click a directory to expand its files.</div>')
    lines.append('<div style="font-size:11.5px;margin-bottom:10px;"><a href="#top">↑ back to top</a></div>')
    for top, entries in sorted(groups.items()):
        lines.append(f'<details><summary>{html.escape(top)} · {len(entries)} files</summary><ul>')
        for p, a in entries:
            rel = str(p.relative_to(ROOT))
            lines.append(f'<li><a href="#{a}">{html.escape(rel)}</a></li>')
        lines.append('</ul></details>')
    lines.append('</aside>')
    return "\n".join(lines)


def render_file_section(p: Path, a: str) -> str:
    rel = str(p.relative_to(ROOT))
    try:
        raw = p.read_bytes()
    except Exception as e:
        return f'<section class="file" id="{a}"><h2>{html.escape(rel)} <span class="size">READ ERROR: {html.escape(str(e))}</span></h2></section>'
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
    size = len(raw)
    lines = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
    esc = html.escape(text)
    return (
        f'<section class="file" id="{a}">'
        f'<h2><span>{html.escape(rel)}</span>'
        f'<span class="size">{size:,} B · {lines:,} lines <a class="backtotop" href="#nav">↑ index</a></span></h2>'
        f'<pre>{esc}</pre>'
        f'</section>'
    )


def main() -> int:
    t0 = time.time()
    files = gather()

    # Compute per-file anchors and group by top-level directory.
    groups: dict[str, list[tuple[Path, str]]] = {}
    for p in files:
        rel = str(p.relative_to(ROOT))
        top = rel.split("/", 1)[0] if "/" in rel else "(root)"
        groups.setdefault(top, []).append((p, anchor(rel)))

    total_bytes = 0
    total_lines = 0
    with OUT.open("w", encoding="utf-8") as f:
        f.write(HEAD)
        f.write('<a id="top"></a>')
        f.write(render_nav(groups))
        f.write('<main>')
        f.write('<header class="top">')
        f.write('<h1>NivXRay XDR · Source Export</h1>')
        gen_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        f.write(f'<div class="meta">Generated <kbd>{gen_at}</kbd> · single-file, self-contained, offline-readable · '
                f'{len(files):,} files · authoritative source of implementation truth for Antigravity Phase-0.</div>')
        f.write('<div class="notice"><b>Honest-state disclosures (what is intentionally excluded):</b><ul>'
                '<li><code>.env</code> files (contain secrets: <code>ADMIN_PASSWORD</code>, <code>JWT_SECRET</code>, <code>EMERGENT_LLM_KEY</code>, etc.). '
                '<code>.env.example</code> IS included where present.</li>'
                '<li><code>test_credentials.md</code> (contains live-pod test credentials per handoff).</li>'
                '<li>Generated / vendored trees: <code>node_modules</code>, <code>__pycache__</code>, <code>.git</code>, <code>dist</code>, <code>build</code>, <code>.next</code>, <code>venv</code>, <code>.pytest_cache</code>, <code>.mypy_cache</code>.</li>'
                '<li>Lockfiles (auto-generated & huge): <code>yarn.lock</code>, <code>package-lock.json</code>, <code>poetry.lock</code>.</li>'
                '<li>User data: <code>uploads/</code>, <code>uploaded_cases/</code>, <code>downloads/</code> (contains user artifacts, not source).</li>'
                '<li>Binary assets (images, PDFs, decks, fonts) and any single file &gt; 2 MB.</li>'
                '</ul>Everything else — Python, JS/TS/JSX/TSX, JSON/YAML/TOML configs, HTML/CSS, shell, Dockerfiles, Markdown, requirements.txt, package.json, tests, GitHub Actions — is included byte-for-byte.</div>')
        f.write('</header>')

        for i, p in enumerate(files, 1):
            rel = str(p.relative_to(ROOT))
            a = anchor(rel)
            try:
                size = p.stat().st_size
                total_bytes += size
                total_lines += sum(1 for _ in p.open("rb"))
            except OSError:
                pass
            f.write(render_file_section(p, a))
            if i % 500 == 0:
                sys.stderr.write(f"[{i}/{len(files)}] {rel}\n"); sys.stderr.flush()

        elapsed = time.time() - t0
        f.write(f'<footer style="margin-top:40px;padding-top:14px;border-top:2px solid #333;font-size:13px;color:#444;">')
        f.write(f'<div><b>Export complete.</b></div>')
        f.write(f'<div>Total files: <b>{len(files):,}</b></div>')
        f.write(f'<div>Total source bytes: <b>{total_bytes:,}</b> ({total_bytes/1024/1024:.2f} MB)</div>')
        f.write(f'<div>Total source lines: <b>{total_lines:,}</b></div>')
        f.write(f'<div>Elapsed: <b>{elapsed:.1f}s</b></div>')
        f.write(f'<div>Output: <kbd>{OUT}</kbd></div>')
        f.write(f'<div>Groups: {", ".join(sorted(groups))}</div>')
        f.write('</footer>')
        f.write('</main></body></html>')

    print(f"OK · files={len(files)} · bytes={total_bytes} · lines={total_lines} · elapsed={elapsed:.1f}s · out={OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
