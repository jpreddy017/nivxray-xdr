"""P0.6 · Track B · SSOT projector consumes Behaviors (never synthesizes).

Locks the "projector projects, never interprets" contract for the
UAIE SSOT projector.  Also adds the CI invariant preventing any
downstream module from re-implementing the Evidence → MITRE /
Recommendations edge outside the projection layer.
"""
from __future__ import annotations

import ast
import pathlib
from typing import List, Tuple

from services.ida.behaviors import Behavior
from services.ida.projections.mitre       import BEHAVIOR_TO_MITRE
from services.ida.projections.kill_chain  import BEHAVIOR_TO_KILL_CHAIN
from services.ida.projections.impact      import BEHAVIOR_TO_IMPACTS
from services.uaie import plugins as _p                              # noqa: F401
from services.uaie.orchestrator import Orchestrator
from services.uaie.ssot_projector import project as uaie_project


# ══════════════════════════════════════════════════════════════════
# Track B contract · projector consumes Behaviors, never synthesizes
# ══════════════════════════════════════════════════════════════════
def _run_orch(payload: bytes):
    orch = Orchestrator(recognizers=_p.all_recognizers(),
                         max_artifacts=64, max_depth=8)
    return orch.run(payload, filename="test.txt")


def test_projector_without_behaviors_emits_empty_behavior_and_impact_fields():
    """When no behaviors are pre-computed, projector emits [] for
    the SSOT ``behaviors`` and ``impacts`` fields — it does NOT
    invent them from evidence."""
    r = _run_orch(b"vssadmin delete shadows /all /quiet")
    ssot = uaie_project(r, root_input="vssadmin delete shadows /all /quiet")
    assert ssot["behaviors"]      == []
    assert ssot["impacts"]        == []
    assert ssot["behaviors_full"] == []


def test_projector_with_precomputed_behaviors_projects_them():
    """When the caller supplies Behaviors, the projector projects
    them into the SSOT kill-chain and impact fields."""
    r = _run_orch(b"vssadmin delete shadows /all /quiet")
    behaviors = [
        Behavior(behavior_type = "shadow_copy_deletion",
                   label         = "Shadow copy deletion",
                   source        = "command_classifier",
                   source_ref    = "body.line.1",
                   provenance    = "command_execution",
                   evidence      = {"command": "vssadmin delete shadows"}),
        Behavior(behavior_type = "data_encryption_for_impact",
                   label         = "Ransomware family: Medusa",
                   source        = "malware_lookup",
                   source_ref    = "malware:Medusa",
                   provenance    = "malware_reference",
                   evidence      = {"malware_family": "Medusa"}),
    ]
    ssot = uaie_project(r, root_input="vssadmin delete shadows",
                            behaviors=behaviors)
    assert "impact" in ssot["behaviors"]
    assert "recovery_inhibited" in ssot["impacts"]
    assert "data_encrypted"     in ssot["impacts"]
    assert len(ssot["behaviors_full"]) == 2
    # Provenance preserved.
    for bf in ssot["behaviors_full"]:
        assert bf["provenance"] in (
            "command_execution", "malware_reference")


def test_projector_does_not_call_behavior_generator():
    """Static AST assertion — the ssot_projector module must not
    IMPORT or CALL ``generate_behaviors``.  (A docstring reference
    is fine — it's the runtime linkage that would prove synthesis.)"""
    src = pathlib.Path(
        "services/uaie/ssot_projector.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    violations: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in getattr(node, "names", [])]
            if "generate_behaviors" in names:
                violations.append(f"import at line {node.lineno}")
        elif isinstance(node, ast.Call):
            fn = node.func
            name = (getattr(fn, "id", None) or getattr(fn, "attr", None))
            if name == "generate_behaviors":
                violations.append(f"call at line {node.lineno}")
    assert not violations, (
        "ssot_projector links generate_behaviors at runtime — "
        "the projector must NOT synthesize behaviors · "
        f"violations: {violations}")


def test_projector_preserves_observed_at_provenance():
    r = _run_orch(b"some payload")
    b = Behavior(behavior_type = "shadow_copy_deletion",
                   label = "Shadow copy deletion",
                   source = "command_classifier",
                   source_ref = "body.line.42",
                   provenance = "command_execution",
                   evidence = {"command": "vssadmin delete shadows"},
                   observed_at = {"artifact_id": "art-abc-123",
                                     "evidence_index": 7,
                                     "line": 42})
    ssot = uaie_project(r, behaviors=[b])
    bf = ssot["behaviors_full"][0]
    assert bf["observed_at"] == {
        "artifact_id": "art-abc-123",
        "evidence_index": 7,
        "line": 42,
    }


# ══════════════════════════════════════════════════════════════════
# CI Invariant · Evidence must flow through Behavior before any
# framework projection.  No downstream module may import a framework
# map directly and derive from Evidence — projection must go via
# the ``project_to_*`` public functions.
# ══════════════════════════════════════════════════════════════════
_ALLOWED_MAP_IMPORTS: Tuple[str, ...] = (
    # The projection modules themselves define the maps.
    "services/ida/projections/mitre.py",
    "services/ida/projections/kill_chain.py",
    "services/ida/projections/impact.py",
    # The Behavior generator + aggregator legitimately reference
    # the maps because they emit Behaviors from Evidence — the ONE
    # place where the Evidence → Behavior edge exists.
    "services/ida/behaviors.py",
    "services/ida/projections/__init__.py",
    # Regression tests exercise the maps.
    "tests/test_ida_behavior_generation.py",
    "tests/test_ida_behavior_projections.py",
    "tests/test_track_b_projector_and_ci_invariants.py",
)

_BANNED_MAP_NAMES: Tuple[str, ...] = (
    "BEHAVIOR_TO_MITRE",
    "BEHAVIOR_TO_KILL_CHAIN",
    "BEHAVIOR_TO_IMPACTS",
)


def _scan_python_files(root: pathlib.Path) -> List[pathlib.Path]:
    """Yield every .py file under root, skipping caches / venvs."""
    ok: List[pathlib.Path] = []
    for p in root.rglob("*.py"):
        s = str(p).replace("\\", "/")
        if any(seg in s for seg in ("__pycache__", ".venv", "site-packages")):
            continue
        ok.append(p)
    return ok


def test_ci_invariant_no_framework_map_imports_outside_projections():
    """Enforce the architectural rule the user set on 2026-02-05:

        "No downstream component may derive semantic behavior
        directly from Evidence.  Everything else consumes
        Behavior via the projection layer."

    The concrete check: no source file OUTSIDE the projection
    layer, the Behavior generator, or its regression tests may
    import ``BEHAVIOR_TO_MITRE`` / ``BEHAVIOR_TO_KILL_CHAIN`` /
    ``BEHAVIOR_TO_IMPACTS``.  All consumers must go through the
    ``project_to_*`` functions.
    """
    root = pathlib.Path(".")
    violations: List[str] = []
    for p in _scan_python_files(root):
        rel = str(p).replace("\\", "/").lstrip("./")
        if rel in _ALLOWED_MAP_IMPORTS:
            continue
        try:
            src = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for banned in _BANNED_MAP_NAMES:
            if banned in src:
                violations.append(f"{rel} :: imports {banned}")
    assert not violations, (
        "CI invariant violation — framework maps referenced outside "
        "projection layer:\n  " + "\n  ".join(violations))
