#!/usr/bin/env python3
"""Build the NivXRay XDR UI migration register.

The owner's migration-control rule: every route is accounted for, with its
current design system, its page-local CSS, the nx primitives it must adopt
and its migration state. Nothing is declared finished because it merely
looks nicer — a page is `MIGRATED` only when it composes `nx/` and carries
no parallel visual system.

    python3 scripts/build_ui_migration_register.py

Writes `/app/memory/UI_MIGRATION_REGISTER.md`. Re-run it after every wave:
the register is generated from the code, so it cannot drift into fiction.
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path("/app/apps/nivxray-xdr/src")
APP = SRC / "App.jsx"
OUT = Path("/app/memory/UI_MIGRATION_REGISTER.md")

#: The element is usually wrapped (`<Protected>`, `<ProductScopeGuard>`,
#: `<Suspense>`), so take the LAST component named inside the element prop.
ROUTE = re.compile(r'<Route\s+path="([^"]+)"[^>]*?element=\{(.*?)\}\s*/>',
                   re.S)
COMPONENT = re.compile(r"<(\w+)")
LAZY = re.compile(r'const\s+(\w+)\s*=\s*lazy\(\s*\(\)\s*=>\s*import\(\s*"([^"]+)"')
DIRECT = re.compile(r'^import\s+(\w+)\s+from\s+"([^"]+)"', re.M)

NX = re.compile(r"\bNx[A-Z]\w+")
AD_HOC = {
    "hand-built <table>": re.compile(r"<table\b"),
    "page-local class system": re.compile(
        r'className="(?:wx|rl|ux0|intel|cx|edr)-'),
    "inline dark literal": re.compile(
        r"#(?:0[0-9a-fA-F]{5}|1[0-9a-fA-F]{5})"),
    "ad-hoc <details>": re.compile(r"<details\b"),
}
CSS_IMPORT = re.compile(r'import\s+"([^"]+\.css)"')


def component_map(app: str) -> dict[str, str]:
    m = {}
    for name, path in LAZY.findall(app):
        m[name] = path
    for name, path in DIRECT.findall(app):
        if path.startswith("@/") or path.startswith("./"):
            m.setdefault(name, path)
    return m


def resolve(path: str) -> Path | None:
    p = path.replace("@/", "")
    for cand in (SRC / f"{p}.jsx", SRC / f"{p}.js", SRC / p):
        if cand.exists():
            return cand
    return None


def main() -> None:
    app = APP.read_text(encoding="utf8")
    comps = component_map(app)
    rows, seen = [], set()

    for route, element in ROUTE.findall(app):
        names = [n for n in COMPONENT.findall(element) if n in comps]
        if not names and "Navigate" in element:
            continue  # a redirect has no presentation of its own
        comp = names[-1] if names else COMPONENT.findall(element)[-1]
        target = comps.get(comp)
        f = resolve(target) if target else None
        if not f:
            rows.append((route, comp, "—", "—", "—", "UNRESOLVED"))
            continue
        src = f.read_text(encoding="utf8")
        nx = sorted(set(NX.findall(src)))
        css = [c for c in CSS_IMPORT.findall(src) if "/nx/" not in c]
        debt = [k for k, rx in AD_HOC.items() if rx.search(src)]
        state = ("MIGRATED" if nx and not debt
                 else "IN_PROGRESS" if nx else "NOT_STARTED")
        rows.append((route, f.relative_to(SRC).as_posix(),
                     f"{len(nx)} nx primitives" if nx else "none",
                     ", ".join(css) or "—",
                     "; ".join(debt) or "—", state))
        seen.add(f)

    counts = {}
    for r in rows:
        counts[r[5]] = counts.get(r[5], 0) + 1

    lines = [
        "# NivXRay XDR · UI migration register",
        "",
        "GENERATED — do not hand-edit. Rebuild with",
        "`python3 scripts/build_ui_migration_register.py`.",
        "",
        "One design language, appropriate primitives. `MIGRATED` does NOT",
        "mean \"turned into a table\": an Attack Story, an entity graph, a",
        "timeline, a response lifecycle and an event table are different",
        "representations of the SAME nx design language. It means the page",
        "composes `xdr/nx/` and carries no parallel visual system.",
        "",
        "Automatic states: `NOT_STARTED` (no nx primitive), `IN_PROGRESS`",
        "(nx + residual ad-hoc debt), `MIGRATED` (nx, no detected debt).",
        "`VERIFIED_PROGRAMMATICALLY` and `OWNER_VISUALLY_ACCEPTED` are",
        "recorded by the wave notes below, not inferred from code.",
        "",
        "| State | Routes |",
        "| --- | --- |",
    ]
    for k in ("MIGRATED", "IN_PROGRESS", "NOT_STARTED", "UNRESOLVED"):
        if k in counts:
            lines.append(f"| {k} | {counts[k]} |")
    lines += [
        "",
        "| Route | Page | nx adoption | Page-local CSS | Residual debt | State |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    order = {"NOT_STARTED": 0, "IN_PROGRESS": 1, "UNRESOLVED": 2,
             "MIGRATED": 3}
    for r in sorted(rows, key=lambda r: (order.get(r[5], 9), r[0])):
        lines.append("| " + " | ".join(str(c) for c in r) + " |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf8")
    print(f"{len(rows)} routes · " +
          " · ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print(f"→ {OUT}")


if __name__ == "__main__":
    main()
