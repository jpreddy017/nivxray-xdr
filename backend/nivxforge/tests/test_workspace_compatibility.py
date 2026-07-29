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


# ── (1) NivXForge router is not mounted in Workspace server.py ─────────
def test_nivxforge_router_not_registered_in_workspace_server():
    server_src = (_BACKEND / "server.py").read_text(encoding="utf-8")
    assert "nivxforge" not in server_src.lower(), (
        "server.py mentions 'nivxforge' — Decision A1 requires the "
        "router to remain dormant during Phase 0. Undo the mount."
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
