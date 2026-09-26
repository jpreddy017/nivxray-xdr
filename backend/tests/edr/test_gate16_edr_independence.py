"""GATE 16 · NivXForge EDR INDEPENDENCE.

Owner architecture lock: *"When an analyst enters NivXForge EDR, every
EDR navigation item, tab, button, entity pivot, investigation link,
search result and operational action must remain inside the NivXForge
EDR product unless the analyst explicitly chooses an action labelled as
opening NivXRay XDR."*

This is a STATIC gate over the EDR frontend bundle. It is deliberately
static rather than a crawl, because it must fail in CI the moment a
developer writes `to="/xdr/..."` inside `src/nivxforge/`, not only when
someone happens to click that control.

Three rules:

1. **Navigation** — any `/xdr` navigation target inside the EDR bundle
   must be declared in `ALLOWED_XDR_PIVOTS` with the visible label that
   tells the analyst they are leaving the product. An undeclared one is
   an `ILLEGAL_EDR_TO_XDR_DEPENDENCY`.
2. **Components** — the EDR bundle may import XDR *libraries* (shared
   design system, api-error helper, pivot builders). It may NOT import an
   XDR *page* or *route* component: shared library ≠ product coupling.
3. **Routes** — every EDR capability in the product's own navigation must
   resolve to an `/edr/*` route (or be declared NOT_IMPLEMENTED); it may
   never be satisfied by pointing at an `/xdr/*` route.
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path("/app/apps/nivxray-xdr/src")
EDR = SRC / "nivxforge"
APP = SRC / "App.jsx"

# ── the ONLY sanctioned cross-product transitions ────────────────────────
# testid -> (file, visible label the analyst sees before navigating)
ALLOWED_XDR_PIVOTS = {
    "edr-return-to-incident": (
        "NivXForgeConsole.jsx",
        "Return to NivXRay XDR incident ↗"),
    "nvf-open-in-xdr": (
        "NivXForgeConsole.jsx",
        "Investigate in NivXRay XDR ↗"),
}

# A navigation target is what actually moves the analyst: a router `to=`,
# `navigate(...)`, an anchor `href=`, or a location assignment.
NAV = re.compile(
    r"""(?:\bto=\{?["'`]|\bnavigate\(\s*["'`]|\bhref=\{?["'`]|"""
    r"""location\.(?:assign|replace|href\s*=)\s*\(?\s*["'`])\s*(/xdr[^"'`]*)""",
    re.VERBOSE)
# `productHref("xdr", "/xdr...")` is the declared cross-origin builder —
# it is only ever used by the sanctioned pivots, which are checked below.
NAV_BUILDER = re.compile(r"productHref\(\s*[\"']xdr[\"']")


def _edr_sources():
    for p in sorted(EDR.rglob("*.js*")):
        yield p, p.read_text(encoding="utf8")
    # A leak can hide in a SHARED component that the EDR bundle renders:
    # `XdrContextBar` rooted every EDR breadcrumb at "NivXRay XDR → /xdr".
    # Shared components the EDR console actually mounts are therefore in
    # scope for the navigation rule too.
    for rel in SHARED_COMPONENTS_MOUNTED_BY_EDR:
        p = SRC / rel
        yield p, p.read_text(encoding="utf8")


SHARED_COMPONENTS_MOUNTED_BY_EDR = ["xdr/components/XdrContextBar.jsx"]


def test_no_undeclared_edr_to_xdr_navigation():
    offences = []
    for path, text in _edr_sources():
        lines = text.splitlines()
        for i, line in enumerate(lines, start=1):
            if not (NAV.search(line) or NAV_BUILDER.search(line)):
                continue
            # the sanctioned pivots carry their testid within a few lines
            window = "\n".join(lines[max(0, i - 22): i + 22])
            if any(tid in window for tid in ALLOWED_XDR_PIVOTS):
                continue
            # A SHARED component may contain XDR navigation for the XDR
            # console, provided the site is plane-guarded so it cannot
            # render inside the EDR product.
            if str(path).endswith(tuple(SHARED_COMPONENTS_MOUNTED_BY_EDR)) \
                    and 'plane === "NIVXFORGE_EDR"' in \
                    "\n".join(lines[max(0, i - 14): i + 3]):
                continue
            offences.append(f"{path.relative_to(SRC)}:{i}: {line.strip()}")
    assert not offences, (
        "ILLEGAL_EDR_TO_XDR_DEPENDENCY — ordinary EDR navigation may not "
        "enter NivXRay XDR:\n  " + "\n  ".join(offences))


def test_every_sanctioned_pivot_is_visibly_labelled():
    """An explicit pivot is only explicit if the analyst can SEE it is
    leaving the product before they click."""
    for testid, (filename, label) in ALLOWED_XDR_PIVOTS.items():
        text = (EDR / filename).read_text(encoding="utf8")
        assert testid in text, f"{testid} no longer exists in {filename}"
        assert label in text, (
            f"{testid} must remain visibly labelled as leaving the "
            f"product — expected the label {label!r} in {filename}")
        assert "↗" in label


def test_the_edr_bundle_imports_no_xdr_page_or_route_component():
    illegal = []
    for path, text in _edr_sources():
        for m in re.finditer(r"""from\s+["'](@/xdr/[^"']+)["']""", text):
            target = m.group(1)
            # libraries and the shared design system are SHARED_*_SAFE
            if re.search(r"@/xdr/(lib|nx|components|hooks|util)", target):
                continue
            illegal.append(f"{path.relative_to(SRC)}: {target}")
    assert not illegal, (
        "the EDR bundle may share XDR LIBRARIES but must not depend on an "
        "XDR page/route component:\n  " + "\n  ".join(illegal))


def test_every_edr_navigation_item_resolves_to_an_edr_route():
    """The product's own navigation may only address `/edr/*`."""
    console = (EDR / "NivXForgeConsole.jsx").read_text(encoding="utf8")
    nav = console[console.index("const NAV"):console.index("const NAV") + 6000]
    hrefs = re.findall(r"""to:\s*["'`]([^"'`]+)""", nav) + \
        re.findall(r"""path:\s*["'`]([^"'`]+)""", nav)
    bad = [h for h in hrefs if h.startswith("/") and
           not h.startswith("/edr")]
    assert not bad, (
        "an EDR navigation item addresses a non-EDR route: " + repr(bad))


def test_the_edr_product_has_its_own_login_and_entry_route():
    """Independence starts at the door: the product must be enterable
    without the XDR application."""
    app = APP.read_text(encoding="utf8")
    assert '"/edr/login"' in app or "'/edr/login'" in app
    assert re.search(r"""path="/edr"\s""", app), \
        "the EDR product has no root route of its own"
