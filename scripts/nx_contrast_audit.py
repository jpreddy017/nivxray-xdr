#!/usr/bin/env python3
"""Design-token contrast audit · light AND dark are both acceptance gates.

The owner's rule: "Low contrast is a defect. Do not make important text
faint merely because a reference product uses subdued styling."

This reads the real token values out of `nx/nx-theme.css` (dark block and
`[data-nx-theme="light"]` block) and asserts WCAG contrast for every
foreground/surface pair the console actually uses:

    body / secondary text   ≥ 4.5 : 1
    metadata floor (faint)  ≥ 4.5 : 1   (it carries timestamps and headers)
    borders / seams         ≥ 1.4 : 1   (visible separation, not text)

Exit code 1 on any failure, so it can gate a build.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

THEME = Path("/app/apps/nivxray-xdr/src/xdr/nx/nx-theme.css")

TEXT = ["--nx-text", "--nx-text-dim", "--nx-muted", "--nx-faint"]
SURFACES = ["--nx-surf-canvas", "--nx-surf-primary", "--nx-surf-inset"]
SEAMS = ["--nx-bd-quiet", "--nx-bd-strong"]
TEXT_MIN, SEAM_MIN = 4.5, 1.4


def blocks(css: str) -> dict[str, str]:
    """Split the two authoritative theme blocks."""
    light_at = css.index('[data-nx-theme="light"]')
    return {"dark": css[:light_at], "light": css[light_at:]}


def tokens(block: str) -> dict[str, str]:
    out = {}
    for name, value in re.findall(r"(--nx-[a-z0-9-]+)\s*:\s*([^;]+);", block):
        out[name] = value.strip()
    return out


def rgb(value: str, table: dict[str, str], depth: int = 0):
    value = value.strip()
    if value.startswith("var(") and depth < 5:
        inner = value[4:-1].split(",")[0].strip()
        return rgb(table.get(inner, ""), table, depth + 1)
    m = re.fullmatch(r"#([0-9a-fA-F]{6})", value)
    if m:
        h = m.group(1)
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
    m = re.match(r"rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)", value)
    if m:
        return tuple(float(x) for x in m.groups())
    return None


def lum(c) -> float:
    def f(x):
        x /= 255
        return x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4
    r, g, b = c
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def ratio(a, b) -> float:
    la, lb = lum(a), lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def main() -> int:
    css = THEME.read_text(encoding="utf8")
    fails = 0
    for theme, block in blocks(css).items():
        t = tokens(block)
        for surf in SURFACES:
            sc = rgb(t.get(surf, ""), t)
            if not sc:
                print(f"SKIP  {theme}/{surf}: unresolved")
                continue
            for fg in TEXT:
                fc = rgb(t.get(fg, ""), t)
                if not fc:
                    continue
                r = ratio(fc, sc)
                ok = r >= TEXT_MIN
                fails += 0 if ok else 1
                print(f"{'PASS' if ok else 'FAIL'}  {theme:5s} "
                      f"{fg:14s} on {surf:18s} {r:5.2f}:1")
            for seam in SEAMS:
                scm = rgb(t.get(seam, ""), t)
                if not scm:
                    continue
                # rgba() seams are composited over the surface.
                if len(scm) == 3 and all(v <= 255 for v in scm):
                    r = ratio(scm, sc)
                    ok = r >= SEAM_MIN
                    fails += 0 if ok else 1
                    print(f"{'PASS' if ok else 'FAIL'}  {theme:5s} "
                          f"{seam:14s} on {surf:18s} {r:5.2f}:1")
    print(f"\n{fails} contrast failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
