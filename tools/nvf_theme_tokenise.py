"""A2 · tokenise the NivXForge EDR surface so ONE theme authority drives it.

The EDR console declared its palette ONCE, unconditionally dark, on
`.nvf-console`, and several surfaces painted literal hex on top of it.
The platform toggle therefore changed `data-nx-theme` and nothing moved.
This script does the mechanical part of the repair — every literal that
encoded a surface, seam, tint or ring becomes a semantic token — so the
light block added afterwards can actually reach those surfaces.

Run once; it is idempotent (a second run reports 0 replacements).
"""
from pathlib import Path

SRC = Path("/app/apps/nivxray-xdr/src/nivxforge")

# literal -> token.  Ordered longest-first so rgba() never partially matches.
SUBS = [
    # surfaces
    ("#1a2028", "var(--surf-chip)"),
    ("#101a24", "var(--surf-active)"),
    ("#141a24", "var(--surf-hover)"),
    ("#0f1f1a", "var(--mint-soft)"),
    ("#0e1a24", "var(--surf-accent-soft)"),
    ("#131926", "var(--surf-row-hover)"),
    ("#111a24", "var(--surf-row-sel)"),
    ("#0c0f15", "var(--surf-th)"),
    ("#2c3547", "var(--border-hover)"),
    ("#12161f", "var(--sk-a)"),
    ("#1a202c", "var(--sk-b)"),
    # accent tints
    ("rgba(63,193,232,.12)", "var(--ring-cyan)"),
    ("rgba(63,193,232,.45)", "var(--info-bd)"),
    ("rgba(63,193,232,.35)", "var(--info-bd)"),
    ("rgba(63,193,232,.07)", "var(--info-bg)"),
    ("rgba(63,193,232,.06)", "var(--info-bg)"),
    ("rgba(60,232,184,.45)", "var(--ok-bd)"),
    ("rgba(60,232,184,.4)", "var(--ok-bd)"),
    ("rgba(60,232,184,.07)", "var(--ok-bg)"),
    ("rgba(245,166,35,.45)", "var(--warn-bd)"),
    ("rgba(245,166,35,.4)", "var(--warn-bd)"),
    ("rgba(245,166,35,.07)", "var(--warn-bg)"),
    ("rgba(245,166,35,.06)", "var(--warn-bg)"),
    ("rgba(239,91,91,.45)", "var(--bad-bd)"),
    ("rgba(239,91,91,.07)", "var(--bad-bg)"),
    ("rgba(239,91,91,.06)", "var(--bad-bg)"),
    ("rgba(155,123,240,.5)", "var(--att-bd)"),
    ("rgba(155,123,240,.45)", "var(--att-bd)"),
    ("rgba(155,123,240,.10)", "var(--att-bg)"),
    ("rgba(155,123,240,.06)", "var(--att-bg)"),
    # brand mark text sits ON the accent, so it is a token too
    ("color: #0A0C11;", "color: var(--on-accent);"),
]

total = 0
for name in ("nivxforge.css", "nvf-ops.css"):
    p = SRC / name
    text = p.read_text()
    n = 0
    for literal, token in SUBS:
        if literal in text:
            n += text.count(literal)
            text = text.replace(literal, token)
    p.write_text(text)
    total += n
    print(f"{name}: {n} literals tokenised")
print(f"total: {total}")
