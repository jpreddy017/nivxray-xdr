"""ADR-0006 · Phase 1 · Parity contract test.

Structural (not behavioural) assertion that NivXForge and Workspace call
the SAME backend endpoints for analyst work. If either surface points at
a different route, this test fails — catching divergence at PR time.

Backend isolation invariant preserved: this test parses source files as
text; it does NOT import Workspace modules from the nivxforge package.

Contracts pinned:
    Workspace                → /api/decode/smart
    NivXForge Investigate    → /api/decode/smart

    Workspace AutoInvestigate → /api/v2/auto-investigate
    NivXForge Investigate     → /api/v2/auto-investigate

Explicit non-goal: this test does NOT verify that both surfaces render
the same UI. UI parity is not required by ADR-0006 §2. Backend contract
parity IS required.
"""
from __future__ import annotations

import pathlib
import re


_ROOT = pathlib.Path("/app/frontend/src")

# Paths must resolve; if a file was renamed or removed, we want to know.
_WORKSPACE_DECODE   = _ROOT / "pages" / "WorkspacePage.jsx"
_WORKSPACE_AUTO     = _ROOT / "pages" / "AutoInvestigatePage.jsx"
_NIVXFORGE_INVEST   = _ROOT / "nivxforge" / "pages" / "InvestigatePage.jsx"


def _read(p: pathlib.Path) -> str:
    assert p.is_file(), f"Missing frontend source file: {p}"
    return p.read_text(encoding="utf-8")


def _endpoints_called(text: str) -> set[str]:
    """Return every api.get/post path literal appearing in `text`."""
    return set(re.findall(r'api\.(?:get|post)\(\s*[\'"]([^\'"]+)[\'"]', text))


# ── 1) /api/decode/smart is the shared decode endpoint ─────────────────
def test_decode_smart_endpoint_is_shared_by_workspace_and_nivxforge():
    workspace_eps = _endpoints_called(_read(_WORKSPACE_DECODE))
    nvx_eps       = _endpoints_called(_read(_NIVXFORGE_INVEST))
    assert "/decode/smart" in workspace_eps, (
        "Workspace no longer calls /api/decode/smart — the shared decode "
        "contract is broken. NivXForge parity assumption is void."
    )
    assert "/decode/smart" in nvx_eps, (
        "NivXForge InvestigatePage does not call /api/decode/smart — "
        "ADR-0006 §2.1 requires the same endpoint as Workspace."
    )


# ── 2) /api/v2/auto-investigate is the shared auto endpoint ────────────
def test_auto_investigate_endpoint_is_shared_by_workspace_and_nivxforge():
    workspace_eps = _endpoints_called(_read(_WORKSPACE_AUTO))
    nvx_eps       = _endpoints_called(_read(_NIVXFORGE_INVEST))
    ws_auto = {ep for ep in workspace_eps if ep.startswith("/v2/auto-investigate")}
    nvx_auto = {ep for ep in nvx_eps if ep.startswith("/v2/auto-investigate")}
    assert ws_auto, (
        "Workspace AutoInvestigate page no longer calls /api/v2/auto-investigate. "
        "The shared auto-investigate contract is broken."
    )
    assert nvx_auto, (
        "NivXForge InvestigatePage does not call /api/v2/auto-investigate — "
        "ADR-0006 §2.1 requires the same endpoint as Workspace."
    )


# ── 3) NivXForge introduces NO new backend routes for analytical work ──
def test_nivxforge_introduces_no_new_analytical_backend_routes():
    """Every endpoint called from NivXForge InvestigatePage must be an
    endpoint that Workspace already uses (either the decode or the auto
    page). Otherwise NivXForge has introduced its own analytical
    contract — a violation of ADR-0006 §2 invariant 1."""
    nvx_eps = _endpoints_called(_read(_NIVXFORGE_INVEST))
    workspace_eps = (
        _endpoints_called(_read(_WORKSPACE_DECODE))
        | _endpoints_called(_read(_WORKSPACE_AUTO))
    )
    # /nivxforge/preview/* is the governance surface; it's read-only and
    # explicitly permitted by ADR-0005.
    governance_ok = {ep for ep in nvx_eps if ep.startswith("/nivxforge/preview/")}
    leaked = nvx_eps - workspace_eps - governance_ok
    assert not leaked, (
        "NivXForge InvestigatePage calls endpoints not shared with Workspace: "
        f"{sorted(leaked)}. ADR-0006 §2 invariant 1 forbids analytical route "
        "duplication or NivXForge-owned analytical endpoints."
    )
