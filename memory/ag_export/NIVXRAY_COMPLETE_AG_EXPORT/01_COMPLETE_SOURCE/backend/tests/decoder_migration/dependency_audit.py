"""Gate 2D-B3.3 · Dependency audit toolkit.

Static + runtime dependency graph analysis proving that
`services/decoder/` and `services/analyzers/` — the authoritative
production runtime after B3.1 + B3.2 — have NO production
dependency on any legacy decoder/analyzer implementation surface.

Key invariant (owner-locked):

    LEGACY / COMPATIBILITY SHIMS
            ↓
    AUTHORITATIVE NEW IMPLEMENTATIONS       ← allowed

    AUTHORITATIVE NEW IMPLEMENTATIONS
            ↓
    LEGACY IMPLEMENTATIONS                  ← FORBIDDEN

This module is pure-analysis: it never imports the modules it
audits at test time, so it cannot introduce false dependencies of
its own.  It parses source AST for `import` / `from ... import`
statements.

Static-only.  Deterministic.  Bounded.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Iterable

# ── Repository roots ─────────────────────────────────────────────
BACKEND_ROOT = Path(__file__).resolve().parents[2]     # /app/backend


# ── Module role classification ───────────────────────────────────
# Authoritative production packages — the desired end-state
# authoritative runtime.  Every module under these prefixes is
# subject to the "no legacy dependency" invariant.
AUTHORITATIVE_PREFIXES: tuple[str, ...] = (
    "services.decoder.",         # base/, orchestrator, cmd, powershell, engine, types, registry
    "services.decoder",          # top-level services.decoder
    "services.analyzers.",
    "services.analyzers",
)

# Legacy implementation surfaces that must NOT be transitively
# depended on by any authoritative module.
LEGACY_MODULES: tuple[str, ...] = (
    "services.die.preprocessor.recursive_decoder",
    "decoders.crypto_symmetric",
    "decoders.xor_brute",
    "services.pe_analyzer",
    "shellcode_analyzer",
)


def is_authoritative(module: str) -> bool:
    return any(module == p.rstrip(".") or module.startswith(p)
               for p in AUTHORITATIVE_PREFIXES)


def is_legacy(module: str) -> bool:
    return module in LEGACY_MODULES


# ── Path ↔ dotted-module resolution ──────────────────────────────
def module_of_path(path: Path) -> str | None:
    """Return the dotted-module name for a python file under
    /app/backend, or None if the path is not a .py file."""
    try:
        rel = path.resolve().relative_to(BACKEND_ROOT)
    except ValueError:
        return None
    if rel.suffix != ".py":
        return None
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else None


def path_of_module(module: str) -> Path | None:
    """Reverse map — dotted module → file path under /app/backend."""
    p = BACKEND_ROOT / (module.replace(".", "/") + ".py")
    if p.exists():
        return p
    pkg = BACKEND_ROOT / module.replace(".", "/") / "__init__.py"
    if pkg.exists():
        return pkg
    return None


# ── AST-based import extraction ──────────────────────────────────
def imports_of_file(path: Path) -> list[str]:
    """Return every module imported by `path` as a dotted string.

    Handles both `import a.b.c` and `from a.b import c` forms.
    Relative imports are resolved against the file's package.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError):
        return []
    file_mod = module_of_path(path) or ""
    pkg_parts = file_mod.split(".")[:-1] if file_mod else []
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            base: list[str]
            if node.level and node.level > 0:
                # relative import — resolve against current package
                if len(pkg_parts) < node.level:
                    continue
                base = pkg_parts[: len(pkg_parts) - node.level + 1]
            else:
                base = []
            module = node.module or ""
            full = ".".join([*base, module]).strip(".")
            if not full:
                # `from . import x` — each name is a sub-module
                for alias in node.names:
                    submod = ".".join([*base, alias.name]).strip(".")
                    if submod:
                        out.append(submod)
                continue
            out.append(full)
            # Also record `from X import Y` where Y is itself a module
            # (best-effort; direct-package heuristic).
            for alias in node.names:
                sub = f"{full}.{alias.name}"
                out.append(sub)
    # Dedupe while preserving order.
    seen: set[str] = set()
    ordered: list[str] = []
    for m in out:
        if m and m not in seen:
            seen.add(m)
            ordered.append(m)
    return ordered


# ── Static transitive graph ──────────────────────────────────────
def collect_authoritative_files() -> list[Path]:
    """Enumerate .py files under authoritative package roots."""
    files: list[Path] = []
    for prefix in {"services/decoder", "services/analyzers"}:
        root = BACKEND_ROOT / prefix
        if not root.exists():
            continue
        files.extend(sorted(root.rglob("*.py")))
    return files


def transitive_imports(seed_modules: Iterable[str],
                       max_depth: int = 12) -> dict[str, set[str]]:
    """Return `{module: {direct_imports}}` reachable transitively
    from any seed module.  Only follows imports whose target file
    lives INSIDE /app/backend (external packages are recorded but
    not descended into)."""
    graph: dict[str, set[str]] = {}
    frontier: set[str] = set(seed_modules)
    depth = 0
    while frontier and depth < max_depth:
        new_frontier: set[str] = set()
        for mod in frontier:
            if mod in graph:
                continue
            p = path_of_module(mod)
            if p is None:
                graph[mod] = set()
                continue
            imports = imports_of_file(p)
            graph[mod] = set(imports)
            for imp in imports:
                # Descend only if the import maps to a repo file.
                if imp not in graph and path_of_module(imp) is not None:
                    new_frontier.add(imp)
        frontier = new_frontier
        depth += 1
    return graph


def find_forbidden_paths(graph: dict[str, set[str]]) -> list[tuple[str, list[str]]]:
    """Enumerate every authoritative → legacy dependency path.

    Returns a list of (authoritative_root, path_chain) — the chain
    is the sequence of modules from the authoritative root down
    to the legacy target."""
    forbidden: list[tuple[str, list[str]]] = []
    for root in graph:
        if not is_authoritative(root):
            continue
        # BFS to find any legacy reachable from root.
        seen: set[str] = {root}
        stack: list[tuple[str, list[str]]] = [(root, [root])]
        while stack:
            node, chain = stack.pop()
            for tgt in graph.get(node, ()):
                if tgt in seen:
                    continue
                seen.add(tgt)
                new_chain = chain + [tgt]
                if is_legacy(tgt):
                    forbidden.append((root, new_chain))
                    continue
                if tgt in graph:
                    stack.append((tgt, new_chain))
    # Dedupe on chain identity.
    seen_chains: set[tuple[str, ...]] = set()
    out: list[tuple[str, list[str]]] = []
    for root, chain in forbidden:
        key = tuple(chain)
        if key in seen_chains:
            continue
        seen_chains.add(key)
        out.append((root, chain))
    return out


# ── Runtime audit (subprocess) ───────────────────────────────────
def runtime_audit_snippet() -> str:
    """Python source that imports the authoritative production path
    and prints the loaded legacy-module names to stdout.  Meant to
    be executed in a *fresh* subprocess so no test/shim modules
    are pre-loaded."""
    return r"""
import sys, json
# Import the production authoritative surface.
import services.decoder                        # noqa: F401
import services.decoder.orchestrator           # noqa: F401
import services.decoder.base                   # noqa: F401
import services.decoder.base.compression       # noqa: F401
import services.decoder.base.transform         # noqa: F401
import services.decoder.base.crypto            # noqa: F401
import services.decoder.base.xor_brute         # noqa: F401
import services.decoder.base.powershell_encoded_command  # noqa: F401
import services.decoder.base._ddo_adapter      # noqa: F401
import services.analyzers                      # noqa: F401
import services.analyzers.pe                   # noqa: F401
import services.analyzers.shellcode            # noqa: F401
# Exercise the DDO once so its lazy paths execute.
from services.decoder.orchestrator import orchestrate
orchestrate('powershell -enc SQBFAFgAIABbAG4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAXQA=')
LEGACY = {
    'services.die.preprocessor.recursive_decoder',
    'decoders.crypto_symmetric',
    'decoders.xor_brute',
    'services.pe_analyzer',
    'shellcode_analyzer',
}
loaded_legacy = sorted(LEGACY & set(sys.modules.keys()))
print(json.dumps({'loaded_legacy_modules': loaded_legacy}))
"""


__all__ = [
    "AUTHORITATIVE_PREFIXES",
    "LEGACY_MODULES",
    "is_authoritative",
    "is_legacy",
    "module_of_path",
    "path_of_module",
    "imports_of_file",
    "collect_authoritative_files",
    "transitive_imports",
    "find_forbidden_paths",
    "runtime_audit_snippet",
]
