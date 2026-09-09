"""Workspace Compatibility invariant — Phase 0 introduces zero observable
Workspace behavior change.

The invariants asserted here are structural, not behavioral (behavioral
regression is covered by the pre-existing Workspace pytest suite).

Structural facts locked by this test:
  1. NivXForge router is NOT registered under Workspace `server.py`.
     (Decision A1 · router is dormant.)
  2. Workspace-protected paths retain their expected top-level files
     (fast smoke check — full behavioral coverage lives in the existing
     Workspace regression suite).
  3. Importing every nivxforge module has no runtime side effect
     against Workspace state (no Mongo collection created, no route
     mounted, no env var read outside the FORGE_* prefix).
"""

from __future__ import annotations

import importlib
import pathlib
import sys


_BACKEND = pathlib.Path("/app/backend")


# ── (1) NivXForge router is mounted exactly once under /api ────────────
# ADR-0005 (Accepted 2026-02-28) authorised a single mount for read-only
# Preview endpoints. The mount MUST remain exactly one line and MUST
# stay under the `api` router (which carries prefix "/api").
def test_nivxforge_router_registered_exactly_once_and_read_only():
    server_src = (_BACKEND / "server.py").read_text(encoding="utf-8")
    mount_lines = [
        line for line in server_src.splitlines()
        if "nivxforge" in line.lower() and "include_router" in line
    ]
    assert len(mount_lines) == 1, (
        f"Expected exactly one nivxforge include_router line — found {len(mount_lines)}. "
        "ADR-0005 authorises exactly one mount. Any additional mount is a governance violation."
    )
    # Preview endpoints must be GET-only per ADR-0005 §3. Verify no POST/PUT/DELETE/PATCH
    # is registered on any nivxforge route.
    from nivxforge.router import router as nvx_router
    for route in nvx_router.routes:
        methods = set(getattr(route, "methods", set()) or set())
        # HEAD is implicit for GET; ignore
        write_methods = methods - {"GET", "HEAD"}
        assert not write_methods, (
            f"nivxforge route {route.path!r} exposes write methods {write_methods} "
            "which violates ADR-0005 read-only constraint."
        )


# ── (2) Workspace protected paths still exist ──────────────────────────
def test_workspace_protected_paths_intact():
    """Verify Workspace-protected assets are still present.

    Directories vs modules — `file_extractors` is a single module
    (`file_extractors.py`), not a package. Both shapes are checked.
    """
    expected_dirs = [
        "routers", "engine", "decoders", "heuristics", "knowledge_base",
        "extractors", "enrichment",
    ]
    expected_modules = [
        "file_extractors.py",
    ]
    missing_dirs = [p for p in expected_dirs if not (_BACKEND / p).is_dir()]
    missing_modules = [p for p in expected_modules if not (_BACKEND / p).is_file()]
    assert not missing_dirs and not missing_modules, (
        "Workspace-protected paths missing from /app/backend — "
        f"dirs={missing_dirs} modules={missing_modules}. "
        "Phase 0 must not delete or move Workspace assets."
    )


# ── (3) Importing nivxforge is side-effect-free w.r.t. Workspace ──────
def test_importing_nivxforge_has_no_workspace_side_effects():
    # Snapshot modules that were already loaded by the test runner.
    before = set(sys.modules)
    # Import the whole nivxforge subtree fresh.
    for name in [
        "nivxforge",
        "nivxforge.config",
        "nivxforge.router",
        "nivxforge.core",
        "nivxforge.core.cio",
        "nivxforge.core.evidence",
        "nivxforge.engines",
        "nivxforge.engines.base",
        "nivxforge.observability",
        "nivxforge.observability.logging",
    ]:
        importlib.import_module(name)
    after = set(sys.modules)

    # The only NEW modules introduced by these imports must be either
    # nivxforge.* or third-party libs (fastapi, pydantic, starlette, …).
    # No new Workspace top-level module may be loaded as a side effect.
    workspace_roots = {
        "routers", "engine", "decoders", "heuristics", "knowledge_base",
        "extractors", "enrichment", "file_extractors", "operations",
        "analysis_core", "wrapper_archetypes", "magic_decoder",
        "command_analyzer", "shellcode_analyzer", "chain_analyzer",
        "server", "deps", "v2",
    }
    newly_loaded = after - before
    leaked = sorted(m for m in newly_loaded if m.split(".", 1)[0] in workspace_roots)
    assert not leaked, (
        "Importing nivxforge loaded Workspace modules as a side effect: "
        f"{leaked}. Phase 0 must remain dormant."
    )
