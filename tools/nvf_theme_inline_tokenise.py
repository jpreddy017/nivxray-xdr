"""A2 · the same repair for inline literals inside the EDR surfaces.

Several EDR pages passed literal hex to `style={{}}` / `color=` props.
Those bypass the token layer entirely, so they survived the theme
toggle and rendered dark-on-light (or invisible) in the light console.
Each literal is replaced by the SEMANTIC token it was standing in for —
no new colours are introduced, and severity/verdict meaning is
preserved (red = refusal/malicious, amber = attention, green =
verified-healthy, blue = pivot/link).

Run once; idempotent.
"""
from pathlib import Path

SRC = Path("/app/apps/nivxray-xdr/src/nivxforge")

SUBS = {
    # severity / verdict accents
    "#ff9494": "var(--red)", "#ff6b6b": "var(--red)", "#FF6B6B": "var(--red)",
    "#ff8a8a": "var(--red)", "#FF8A8A": "var(--red)",
    "#ffb454": "var(--amber)", "#FFB454": "var(--amber)",
    "#5FD4A0": "var(--mint)", "#5fd4a0": "var(--mint)",
    "#22B8CF": "var(--cyan)",
    "#7FB3FF": "var(--link)",
    "#8A93A0": "var(--muted)",
    "#8C7A5A": "var(--yellow)",
    # surfaces / seams
    "#2A3540": "var(--border)",
    "#141C24": "var(--panel)",
    "#17202A": "var(--panel2)",
    "#080C10": "var(--bg)",
    "#101a24": "var(--surf-active)",
}

total = 0
for path in sorted(SRC.rglob("*.jsx")):
    if "trajectory" in path.parts:      # own two-theme palette (ampModel)
        continue
    text = path.read_text()
    n = 0
    for literal, token in SUBS.items():
        if literal in text:
            n += text.count(literal)
            text = text.replace(literal, token)
    if n:
        path.write_text(text)
        total += n
        print(f"{path.relative_to(SRC)}: {n}")
print(f"total: {total}")
