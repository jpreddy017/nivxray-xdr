"""Workspace Isolation invariant — nivxforge/ must not import from Workspace.

Static AST scan of every .py file under /app/backend/nivxforge/. If any
`import X` or `from X import ...` references a Workspace module root,
the test fails. This is the structural enforcement of North Star §7.

Allowed imports:
  - Python stdlib
  - Third-party packages (fastapi, pydantic, etc.)
  - Anything under `nivxforge.*`

Forbidden top-level modules (all Workspace):
"""

from __future__ import annotations

import ast
import pathlib


_NIVXFORGE_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Every top-level Workspace module discovered under /app/backend/.
# Any import whose root name matches one of these is a boundary violation.
_WORKSPACE_MODULES = frozenset({
    "routers",
    "engine",
    "decoders",
    "heuristics",
    "knowledge_base",
    "extractors",
    "enrichment",
    "file_extractors",
    "operations",
    "analysis_core",
    "wrapper_archetypes",
    "magic_decoder",
    "command_analyzer",
    "commandline_miner",
    "shellcode_analyzer",
    "chain_analyzer",
    "signatures",
    "sample_library",
    "payload_sanitizer",
    "amsi_detector",
    "corrupt_payload_detector",
    "crypto_hints",
    "layer_360",
    "layer_validator",
    "learner_engine",
    "learning",
    "evidence_extractor",
    "investigation_report",
    "docs",
    "baselines",
    "corpus_refresh",
    "feeds",
    "finetune",
    "server",
    "deps",
    "v2",
})


def _iter_py_files(root: pathlib.Path):
    for p in root.rglob("*.py"):
        # skip __pycache__ / caches
        if any(part.startswith("__pycache__") for part in p.parts):
            continue
        yield p


def _root_of(module_name: str) -> str:
    return module_name.split(".", 1)[0]


def test_no_nivxforge_module_imports_from_workspace():
    violations = []
    for py in _iter_py_files(_NIVXFORGE_ROOT):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError as e:  # pragma: no cover — should never happen
            violations.append(f"{py}: unparsable ({e})")
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = _root_of(alias.name)
                    if root in _WORKSPACE_MODULES:
                        violations.append(f"{py}:{node.lineno}  import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                # ignore relative imports (level > 0) — they cannot reach Workspace
                if node.level and node.level > 0:
                    continue
                mod = node.module or ""
                root = _root_of(mod) if mod else ""
                if root in _WORKSPACE_MODULES:
                    names = ", ".join(a.name for a in node.names)
                    violations.append(f"{py}:{node.lineno}  from {mod} import {names}")

    assert not violations, (
        "Workspace isolation violated — nivxforge/ modules imported from "
        "Workspace paths (NORTH_STAR §7):\n  " + "\n  ".join(violations)
    )
