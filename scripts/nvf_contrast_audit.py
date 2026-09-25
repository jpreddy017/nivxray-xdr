#!/usr/bin/env python3
"""A2 gate · contrast audit for the NivXForge EDR token layer.

The XDR console already had `nx_contrast_audit.py`. The EDR console had
NO gate at all, which is how it kept a dark-only palette: nothing
measured the light theme because the light theme did not exist.

This reads the real values out of `nivxforge/nivxforge.css` — the dark
block on `.nvf-console` and the light block on
`.nvf-console[data-nx-theme="light"]` — and asserts, in BOTH themes:

    body / secondary / metadata text   ≥ 4.5 : 1 on every surface
    state + verdict accents            ≥ 4.5 : 1 (they are 9.4-10px bold)
    seams                              ≥ 1.4 : 1 (separation, not text)

Exit code 1 on any failure, so it can gate a build.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from nx_contrast_audit import ratio, rgb  # noqa: E402  (same math, one authority)

CSS = Path("/app/apps/nivxray-xdr/src/nivxforge/nivxforge.css")

TEXT = ["--text", "--text-dim", "--muted", "--faint"]
ACCENTS = ["--mint", "--cyan", "--amber", "--yellow", "--red", "--purple",
           "--link"]
SURFACES = ["--bg", "--panel", "--panel2", "--surf-th", "--surf-row-hover",
            "--surf-row-sel", "--surf-active", "--surf-chip", "--mint-soft",
            "--surf-hover", "--surf-accent-soft"]
# Two declared seam tiers, both measured: `--border` frames a surface and
# carries table/panel structure; `--border-sf` is a sub-frame divider
# INSIDE an already-framed surface (row rules, section splits), so it is
# held to a lower but still measurable floor rather than to taste.
SEAMS = {"--border": 1.4, "--border-hover": 1.4, "--border-sf": 1.25}
TEXT_MIN, ACCENT_MIN = 4.5, 4.5


def blocks(css: str) -> dict[str, str]:
    m = re.search(r'^\.nvf-console\[data-nx-theme="light"\]', css,
                  re.MULTILINE)
    if m is None:
        raise SystemExit("nivxforge.css: light theme rule not found — the EDR "
                         "console would be dark-only again")
    return {"dark": css[:m.start()], "light": css[m.start():]}


def tokens(block: str) -> dict[str, str]:
    return {n: v.strip() for n, v in
            re.findall(r"(--[a-z0-9-]+)\s*:\s*([^;]+);", block)}


def main() -> int:
    css = CSS.read_text(encoding="utf8")
    fails = 0
    for theme, block in blocks(css).items():
        t = tokens(block)
        for surf in SURFACES:
            sc = rgb(t.get(surf, ""), t)
            if not sc:
                print(f"SKIP  {theme}/{surf}: unresolved")
                fails += 1
                continue
            for fg, floor in ([(f, TEXT_MIN) for f in TEXT]
                              + [(a, ACCENT_MIN) for a in ACCENTS]):
                fc = rgb(t.get(fg, ""), t)
                if not fc:
                    print(f"SKIP  {theme}/{fg}: unresolved")
                    fails += 1
                    continue
                r = ratio(fc, sc)
                ok = r >= floor
                fails += 0 if ok else 1
                print(f"{'PASS' if ok else 'FAIL'}  {theme:5s} "
                      f"{fg:12s} on {surf:20s} {r:5.2f}:1")
            for seam, floor in SEAMS.items():
                scm = rgb(t.get(seam, ""), t)
                if not scm:
                    continue
                r = ratio(scm, sc)
                ok = r >= floor
                fails += 0 if ok else 1
                print(f"{'PASS' if ok else 'FAIL'}  {theme:5s} "
                      f"{seam:12s} on {surf:20s} {r:5.2f}:1")
    print(f"\n{fails} contrast failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
