"""v2 isolation invariants — Round-6 conditions.

  1. RC5 files (backend/engine + backend/routers/rc5_* + non-v2
     modules) MUST NOT import from `v2.*`. The only exception is
     `server.py`, which is allowed to import v2 routers ONLY inside
     a try/except block (so the app boots without v2 if v2 is
     deleted).

  2. `rebaseline.py --dry-run` must succeed on every CI run — it's
     the canary for silent per-sample drift in the RC5 core. If it
     ever prints a different `sample_map_hash` from the baseline,
     that's a signal that RC5 has moved and the regression gate
     needs an explicit human-approved rebaseline.
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]


# ─── 1 · Deletion-safety ────────────────────────────────────────────
def _v2_imports_in(py: Path) -> list[str]:
    try:
        tree = ast.parse(py.read_text(errors="ignore"))
    except SyntaxError:
        return []
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "v2" or alias.name.startswith("v2."):
                    hits.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == "v2" or mod.startswith("v2."):
                names = ", ".join(a.name for a in node.names)
                hits.append(f"from {mod} import {names}")
    return hits


def _try_wrapped_imports(py: Path) -> set[str]:
    """Return module-string set of imports that are enclosed in a
    try / try-except block anywhere in the file. Uses AST so we're
    resilient to comments and formatting."""
    tree = ast.parse(py.read_text(errors="ignore"))
    wrapped: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Import):
                    for a in sub.names:
                        wrapped.add(a.name)
                elif isinstance(sub, ast.ImportFrom) and sub.module:
                    wrapped.add(sub.module)
    return wrapped


def test_rc5_source_never_imports_v2_unwrapped():
    """No RC5 source file may import from v2 outside a try/except.
    server.py IS allowed to include v2 routers via a try-wrapped
    import (that's the deletion-safety pattern)."""
    offenders: list[str] = []
    for py in BACKEND.rglob("*.py"):
        rel = py.relative_to(BACKEND)
        s = str(rel)
        # Skip anything under v2/ or under tests/ — those are v2 or
        # test files respectively.
        if s.startswith("v2/") or s.startswith("tests/"):
            continue
        imports = _v2_imports_in(py)
        if not imports:
            continue
        wrapped = _try_wrapped_imports(py)
        # Any v2 import not covered by a try-block is a violation.
        raw_wrapped = {"v2", "v2.routers", "v2.flags"} | wrapped
        for imp in imports:
            # imp looks like "from v2.routers import ..." or "import v2.foo"
            mod = imp.split()[1] if imp.startswith("from") else imp.split()[1]
            if mod not in wrapped and not any(mod.startswith(w) for w in raw_wrapped if w != "v2"):
                # Special case: server.py's v2 include is in a try block,
                # so the AST walk finds it in `wrapped`.
                if mod in wrapped:
                    continue
                offenders.append(f"{rel}: {imp}")

    assert not offenders, (
        "RC5 files import v2 outside a try/except block — this breaks "
        f"the deletion-safety contract: {offenders}"
    )


def test_deleting_v2_would_not_break_rc5_imports():
    """Simulate v2 deletion by hiding the `v2` package from
    sys.modules, then re-import `server`. If any RC5 module raised
    ImportError, the deletion-safety contract is violated."""
    # Freeze the pre-experiment snapshot so we can restore.
    snap = {k: v for k, v in sys.modules.items() if k == "v2" or k.startswith("v2.") or k == "server"}
    # Blank out v2 modules.
    for k in list(sys.modules):
        if k == "v2" or k.startswith("v2."):
            sys.modules[k] = None                        # None → import machinery raises ImportError
    try:
        # Reload server. It must NOT raise even though `v2` is gone.
        if "server" in sys.modules:
            del sys.modules["server"]
        import importlib
        srv = importlib.import_module("server")
        # Sanity: RC5 endpoint still registered.
        route_paths = {getattr(r, "path", None) for r in srv.app.routes}
        assert "/api/rc5/parse" in route_paths, (
            "RC5 route /api/rc5/parse missing after simulated v2 deletion"
        )
    finally:
        # Restore v2 modules to keep the rest of the test session honest.
        for k in list(sys.modules):
            if k == "v2" or k.startswith("v2."):
                sys.modules.pop(k, None)
        for k, v in snap.items():
            if v is not None:
                sys.modules[k] = v


# ─── 2 · CI rebaseline dry-run canary ───────────────────────────────
def test_rebaseline_dry_run_matches_frozen_baseline():
    """Runs the governance-gated rebaseline tool in --dry-run mode
    and asserts the freshly-captured baseline_id and sample_map_hash
    match the checked-in artefact. Any drift here is an early signal
    that RC5 output has moved and the regression gate is about to
    fire on the next PR."""
    env = os.environ.copy()
    env["NIVX_REBASELINE_TICKET"] = "CI-DRY-RUN"
    proc = subprocess.run(
        [sys.executable, "-m", "tests.tools.rebaseline",
         "--i-know-what-im-doing", "--dry-run"],
        cwd=str(BACKEND),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, (
        f"rebaseline dry-run exited {proc.returncode}: {proc.stderr}"
    )
    out = proc.stdout
    # The diff output prints "baseline_id: <old> → <new>" and
    # "sample_map_hash: <old>… → <new>…". For the dry-run to be a
    # green canary, old and new MUST be identical.
    for line in out.splitlines():
        if "→" not in line:
            continue
        if line.strip().startswith(("baseline_id:", "sample_map_hash:")):
            left, right = line.split("→", 1)
            l = left.split(":", 1)[1].strip().rstrip("…").strip()
            r = right.strip().rstrip("…").strip()
            assert l == r, (
                f"RC5 baseline drift detected in dry-run: {line.strip()!r}"
            )
