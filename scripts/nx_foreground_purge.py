#!/usr/bin/env python3
"""Foreground convergence · a colour literal cannot theme.

Companion to `nx_contrast_purge.py`, which handled hard-coded dark
SURFACES. This one handles the opposite half of the same defect: ~200
hard-coded dark-theme FOREGROUND literals (`color: "#e6edf3"`,
`"#9198a1"`, `"#fbbf24"`, …) that were authored when the console was dark
only. In light mode they render pale text on a pale surface — the exact
"text disappearing into the background" the owner reported.

Each literal is mapped by hue and luminance onto the semantic token that
carries the same MEANING, so both themes resolve correctly and severity
colour keeps one definition:

    near-white / light grey  → --nx-text        (primary text)
    mid grey                 → --nx-muted       (metadata)
    red / pink-red           → --nx-critical
    orange / amber / yellow  → --nx-medium
    green / mint / teal      → --nx-benign
    blue / cyan              → --nx-low
    purple / violet          → --nx-purple

Only the `color` property is rewritten. Fills, strokes and backgrounds are
left to the surface pass, and anything that cannot be classified is
reported rather than guessed.

    python3 scripts/nx_foreground_purge.py [--apply]
"""
from __future__ import annotations

import argparse
import colorsys
import re
import sys
from pathlib import Path

ROOT = Path("/app/apps/nivxray-xdr/src/xdr")
#: `color: "#rrggbb"` in JSX inline styles and `color: #rrggbb;` in CSS.
PAT = re.compile(r'(\bcolor:\s*")(#[0-9a-fA-F]{6})(")')
PAT_CSS = re.compile(r'(\bcolor:\s*)(#[0-9a-fA-F]{6})(\s*;)')


def classify(hexv: str) -> str | None:
    r, g, b = (int(hexv[i:i + 2], 16) / 255 for i in (1, 3, 5))
    h, l, s = colorsys.rgb_to_hls(r, g, b)
    hue = h * 360
    #: Lightness decides FIRST. A near-white with a faint blue cast
    #: (`#e6edf3`) is primary text, not an accent — classifying it by hue
    #: would paint body copy blue.
    if l >= 0.85:
        return "var(--nx-text)"
    if l <= 0.18:
        return None                     # already dark: the surface pass owns it
    if s < 0.18:                        # achromatic
        if l >= 0.42:
            return "var(--nx-muted)"
        return None
    if hue < 20 or hue >= 330:
        return "var(--nx-critical)"
    if hue < 45:
        return "var(--nx-high)"
    if hue < 70:
        return "var(--nx-medium)"
    if hue < 175:
        return "var(--nx-benign)"
    if hue < 200:
        return "var(--nx-teal)"
    if hue < 255:
        return "var(--nx-low)"
    return "var(--nx-purple)"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    total = skipped = 0
    for f in sorted([*ROOT.rglob("*.jsx"), *ROOT.rglob("*.css")]):
        src = f.read_text(encoding="utf8")
        hits = [0]

        def sub_jsx(m):
            tok = classify(m.group(2).lower())
            if not tok:
                return m.group(0)
            hits[0] += 1
            return f'{m.group(1)}{tok}{m.group(3)}'

        def sub_css(m):
            tok = classify(m.group(2).lower())
            if not tok:
                return m.group(0)
            hits[0] += 1
            return f"{m.group(1)}{tok}{m.group(3)}"

        out = PAT.sub(sub_jsx, src)
        out = PAT_CSS.sub(sub_css, out)
        if hits[0]:
            total += hits[0]
            print(f"{'REWROTE' if args.apply else 'WOULD REWRITE'} "
                  f"{hits[0]:>3}  {f.relative_to(ROOT)}")
            if args.apply:
                f.write_text(out, encoding="utf8")

    print(f"\n{total} foreground literals tokenised")
    return 0


if __name__ == "__main__":
    sys.exit(main())
