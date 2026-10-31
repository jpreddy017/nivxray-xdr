"""
Engine discovery + role classification — Phase-1 for the P0.2
Engine Fabric slice.

Walks the actual code at import-time paths and classifies every
discovered implementation by its role.  Role assignment is
deterministic and driven by:

    1. Module path / directory context
    2. Class / function surface (importlib inspection)
    3. Known NivXRay canonical namespaces (canonical/, services/,
       engine/, decoders/, engine/parsers/, engine/interpreters/,
       engine/normalizers_ps/)

If a module cannot be classified from its code surface, its
role is honestly `OTHER` — never `DETECTION_ENGINE` by default.
"""
from __future__ import annotations
import importlib
import inspect
import pkgutil
import re
from datetime import datetime, timezone
from pathlib import Path

from .engine_registry import COLLECTION, EngineRole, EngineState


# ── Rule-based classifier ─────────────────────────────────────────
# Order matters — first match wins.
_RULES: list[tuple[re.Pattern, EngineRole]] = [
    # Parsers / interpreters / normalizers first (path-driven)
    (re.compile(r"(^|/)parsers?/"),          EngineRole.PARSER),
    (re.compile(r"(^|/)interpreters?/"),     EngineRole.INTERPRETER),
    (re.compile(r"(^|/)normalizers?"),       EngineRole.NORMALIZER),
    (re.compile(r"(^|/)decoders?"),          EngineRole.DECODER),
    # Orchestrators / planners
    (re.compile(r"orchestrat"),              EngineRole.ORCHESTRATOR),
    (re.compile(r"planner|recipe_planner"),  EngineRole.PLANNER),
    # Graphs
    (re.compile(r"evidence_graph|exec_graph|process_tree"), EngineRole.GRAPH_ENGINE),
    # Verdict / correlation / evidence
    (re.compile(r"verdict"),                 EngineRole.VERDICT_ENGINE),
    (re.compile(r"correlat"),                EngineRole.CORRELATION_ENGINE),
    (re.compile(r"evidence_(builder|extractor|driven)"), EngineRole.EVIDENCE_ENGINE),
    # Analyzers / detectors
    (re.compile(r"analyzer|detector|behavior_extractor"), EngineRole.ANALYZER),
    # Intelligence
    (re.compile(r"mitre|lolbas|kb|attack|technique|fingerprint|behavioral|ioc|artifact_intel"),
                                                        EngineRole.INTELLIGENCE_ENGINE),
    # Protocols
    (re.compile(r"protocol|plugin_api|models"),         EngineRole.PROTOCOL),
]


def _classify_path(path: str) -> EngineRole:
    p = path.lower()
    for pat, role in _RULES:
        if pat.search(p):
            return role
    return EngineRole.OTHER


# ── Discovery scope ───────────────────────────────────────────────
# Roots relative to /app/backend that we walk for discovery.
DISCOVERY_ROOTS = [
    "canonical",     # IUE + evidence
    "services",      # DIE, UAIE, IUE, mitigation, etc.
    "engine",        # correlation engine, graphs, planners, detectors
    "decoders",
    "workspace",
    "detection_content",  # P0.2e — native detection engines live here
]

# Files to skip
_SKIP_SUFFIXES = ("_test.py", "test_", "__init__.py", "conftest.py")
_SKIP_DIRS     = {"tests", "test", "__pycache__", "fixtures"}


def _iter_modules(root: Path):
    for py in sorted(root.rglob("*.py")):
        parts = py.parts
        if any(seg in _SKIP_DIRS for seg in parts):
            continue
        name = py.name
        if (name.startswith("test_") or
                name.endswith("_test.py") or
                name == "conftest.py" or
                name == "__init__.py"):
            continue
        yield py


def discover_engines(backend_dir: str = "/app/backend") -> list[dict]:
    """
    Walk the codebase and return one document per discovered
    implementation with its actual classified role.
    """
    root = Path(backend_dir)
    docs: list[dict] = []
    now = datetime.now(timezone.utc).isoformat()

    for scope in DISCOVERY_ROOTS:
        sroot = root / scope
        if not sroot.exists(): continue
        for py in _iter_modules(sroot):
            rel = str(py.relative_to(root))
            role = _classify_path(rel)
            # Try to import and grab a version/name if available.
            mod_name = str(py.relative_to(root)).replace("/", ".").removesuffix(".py")
            title = mod_name.split(".")[-1]
            version = None
            has_execute = False
            classes = []
            try:
                mod = importlib.import_module(mod_name)
                version = getattr(mod, "__version__", None)
                has_execute = any(callable(getattr(mod, n, None))
                                        for n in ("execute", "run", "analyze",
                                                     "detect", "process"))
                classes = [k for k, v in vars(mod).items()
                              if inspect.isclass(v) and v.__module__ == mod_name][:8]
            except Exception:
                pass

            engine_id = f"nivxray::{scope}::{title}"
            docs.append({
                "engine_id":         engine_id,
                "canonical_name":    title,
                "role":              role.value,
                "module":            mod_name,
                "path":              rel,
                "scope":             scope,
                "version":           version,
                "has_execute_surface": has_execute,
                "class_surface":     classes,
                "state":             EngineState.DISCOVERED.value,
                "state_history":     [EngineState.DISCOVERED.value],
                "discovered_at":     now,
                # These MUST NOT be promoted here — that requires
                # dependency resolution + readiness check + real
                # runtime invocation in a subsequent slice.
                "ready_at":          None,
                "connected_at":      None,
                "execution_count":   0,
                "failure_count":     0,
                "last_execution_at": None,
                "last_error":        None,
                "capabilities":      [],
                "dependencies":      [],
                "provenance": {
                    "discovered_by": "detection_content.engine_classifier",
                    "discovered_at": now,
                },
            })
    return docs


def role_distribution(docs: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for d in docs:
        out[d["role"]] = out.get(d["role"], 0) + 1
    return out


def upsert_engines(docs: list[dict], mongo_db) -> int:
    coll = mongo_db[COLLECTION]
    n = 0
    for d in docs:
        r = coll.update_one(
            {"engine_id": d["engine_id"]},
            {"$set":        {k: v for k, v in d.items()
                                if k not in ("state_history",)},
             "$addToSet":   {"state_history": {"$each": d["state_history"]}}},
            upsert=True,
        )
        if r.upserted_id or r.modified_count:
            n += 1
    return n
