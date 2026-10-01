#!/usr/bin/env python3
"""Nx contrast convergence · replace hard-coded dark literals with tokens.

WHY THIS EXISTS
The owner reported unreadable surfaces in LIGHT mode (e.g.
`/xdr/admin/edr-response`: a near-black slab with dark text on it). The
cause is not the theme — `xdr-console.css` already maps the legacy
`--text` / `--faint` / `--cyan` vars onto the nx tokens, so FOREGROUND
colour follows the theme correctly. It is that ~136 dark hex literals are
baked into JSX inline styles and page CSS as BACKGROUNDS and BORDERS, so
in light mode theme-aware dark text lands on a hard-coded dark slab.

A literal cannot theme. Every dark literal is therefore rewritten to the
token that carries the same MEANING:

    background / backgroundColor   → var(--nx-surf-inset)
    border* / outline              → var(--nx-bd-quiet)
    color                          → var(--nx-text-dim)

Only literals darker than `--luma` are touched (default 0.30), only inside
`src/xdr/` (the NivXForge EDR console has its own dark product theme and is
out of scope), and anything whose owning CSS property cannot be identified
is REPORTED, never guessed.

    python3 scripts/nx_contrast_purge.py            # report only
    python3 scripts/nx_contrast_purge.py --apply    # rewrite
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path("/app/apps/nivxray-xdr/src/xdr")
HEX = re.compile(r"#([0-9A-Fa-f]{6})\b")

PROP = re.compile(
    r"(background(?:Color)?|border(?:Top|Right|Bottom|Left)?(?:Color)?|"
    r"outline(?:Color)?|color|fill|stroke|boxShadow|"
    r"background-color|border-color|border-top|border-bottom|border-left|"
    r"border-right|border|outline)\s*[:=]\s*[^;,\n]*$")

TOKEN = {
    "background": "var(--nx-surf-inset)",
    "backgroundColor": "var(--nx-surf-inset)",
    "background-color": "var(--nx-surf-inset)",
    "color": "var(--nx-text-dim)",
    "fill": "var(--nx-surf-inset)",
    "stroke": "var(--nx-bd-strong)",
}
BORDERISH = "var(--nx-bd-quiet)"


def luma(h: str) -> float:
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    f = lambda c: c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def token_for(prop: str, head: str = "") -> str:
    if prop.startswith("border") or prop.startswith("outline"):
        return BORDERISH
    if prop == "fill":
        # An SVG <text fill=…> is FOREGROUND, not a surface.
        tag = head.rsplit("<", 1)[-1].split()[0] if "<" in head else ""
        if tag.startswith("text") or tag.startswith("tspan"):
            return "var(--nx-text)"
    return TOKEN.get(prop, "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--luma", type=float, default=0.30)
    args = ap.parse_args()

    changed = unresolved = 0
    files = sorted([*ROOT.rglob("*.jsx"), *ROOT.rglob("*.css"),
                    *ROOT.rglob("*.js")])
    for f in files:
        src = f.read_text(encoding="utf8")
        out, cursor, hits = [], 0, 0
        for m in HEX.finditer(src):
            if luma(m.group(1)) >= args.luma:
                continue
            head = src[max(0, m.start() - 160):m.start()]
            pm = PROP.search(head)
            if not pm:
                unresolved += 1
                print(f"UNRESOLVED {f.relative_to(ROOT)}:"
                      f"{src.count(chr(10), 0, m.start()) + 1} #{m.group(1)}")
                continue
            tok = token_for(pm.group(1), head)
            if not tok:
                unresolved += 1
                continue
            out.append(src[cursor:m.start()])
            out.append(tok)
            cursor = m.end()
            hits += 1
        if hits:
            changed += hits
            print(f"{'REWROTE' if args.apply else 'WOULD REWRITE'} "
                  f"{hits:>3}  {f.relative_to(ROOT)}")
            if args.apply:
                out.append(src[cursor:])
                f.write_text("".join(out), encoding="utf8")

    print(f"\n{changed} dark literals tokenised · {unresolved} unresolved "
          f"(left untouched, reported above)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
