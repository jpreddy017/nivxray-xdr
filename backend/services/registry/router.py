"""M0d · Thin execution router (ADR-0014).

Reads a plan of `ExecutionStep`s, resolves each step's `entry_id` via the
M0b registry (`ADAPTER_REGISTRY` / `ANALYZER_REGISTRY`), invokes the
resolved implementation, and returns a deterministic list of `StepOutcome`s.

RULES (owner directive · M0d, 2026-02-15):

  • The router is a DISPATCHER.  It is NOT a classifier, not an IUE,
    not a content detector, not an analyzer, not an adapter.
  • Resolution SSOT is the M0b registry — there is no hard-coded
    dispatch table, and there is no silent fallback to another
    implementation on miss.
  • Unknown `entry_id`   →  `StepStatus.UNKNOWN_IMPLEMENTATION`.
  • Failed dependency    →  `StepStatus.DEPENDENCY_FAILED`
                             (dependent skipped unless
                              `failure_policy == "continue"`).
  • Missing dependency in the plan → also `DEPENDENCY_FAILED`.
  • Exceptions surface as `StepStatus.EXECUTION_FAILED` with `error` +
    `error_type` populated.  Exceptions are NEVER swallowed silently
    and NEVER converted into apparently-successful empty results.
  • Deterministic ordering: topological by `depends_on`, ties broken by
    original input index.
  • The router MUST NOT read `step.inputs` to decide what to run; it
    MUST NOT modify inputs; it MUST NOT attach M0c provenance to
    outcomes (that is the producer's responsibility, not the router's).
"""
from __future__ import annotations

import bisect
import importlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence

from . import ADAPTER_REGISTRY, ANALYZER_REGISTRY, RegistryEntry, RegistryError


# ─── Public enums ──────────────────────────────────────────────────────────
class StepStatus(str, Enum):
    SUCCESS                = "success"
    SKIPPED                = "skipped"
    NOT_APPLICABLE         = "not_applicable"
    DEPENDENCY_FAILED      = "dependency_failed"
    UNKNOWN_IMPLEMENTATION = "unknown_implementation"
    EXECUTION_FAILED       = "execution_failed"


class FailurePolicy(str, Enum):
    HALT     = "halt"        # dependents get DEPENDENCY_FAILED  (default)
    CONTINUE = "continue"    # dependents run regardless of dep outcome


class RouterError(RuntimeError):
    """Structural router error — bad plan shape, cyclic dependency, etc."""


# ─── Plan and outcome dataclasses ──────────────────────────────────────────
@dataclass(frozen=True)
class ExecutionStep:
    """One unit of work the caller wants the router to dispatch.

    Populated by the IUE (in a future migration) OR by tests today.
    The router does not construct these itself.
    """
    step_id:         str
    entry_id:        str
    inputs:          Mapping[str, Any] = field(default_factory=dict)
    depends_on:      FrozenSet[str]    = field(default_factory=frozenset)
    failure_policy:  str               = FailurePolicy.HALT.value
    # Optional mechanical accepts_formats check. Callers who want it
    # supply the format label; the router only verifies set membership.
    # This is NOT classification — the caller declares the format.
    input_format:    Optional[str]     = None


@dataclass(frozen=True)
class StepOutcome:
    """Full record of one step's dispatch, including provenance-adjacent
    metadata (step_id, entry_id, implementation).  StepOutcome is an
    EXECUTION artefact, not an evidence record — the M0c provenance
    block is intentionally NOT attached here (see ADR-0014a)."""
    step_id:            str
    entry_id:           str
    status:             StepStatus
    result:             Any             = None
    error:              Optional[str]   = None
    error_type:         Optional[str]   = None
    failed_dependency:  Optional[str]   = None
    implementation:     Optional[str]   = None


# ─── Registry lookup (M0b is the SSOT) ─────────────────────────────────────
def _lookup_entry(entry_id: str) -> Optional[RegistryEntry]:
    """Resolve `entry_id` against ADAPTER_REGISTRY, then ANALYZER_REGISTRY.

    Returns None if not found in either.  No silent fallback, no
    hard-coded dispatch table — the registry is the only source.
    """
    for reg in (ADAPTER_REGISTRY, ANALYZER_REGISTRY):
        try:
            return reg.get(entry_id)
        except RegistryError:
            continue
    return None


def _resolve_callable(entry: RegistryEntry) -> Callable[..., Any]:
    mod_name, _, attr = entry.implementation_path.partition(":")
    module = importlib.import_module(mod_name)
    if not attr:
        if not callable(module):
            raise RouterError(
                f"registry entry {entry.entry_id!r} has no callable attr and "
                f"module {mod_name!r} is not itself callable")
        return module   # type: ignore[return-value]
    if not hasattr(module, attr):
        raise RouterError(
            f"registry entry {entry.entry_id!r} points at missing attribute "
            f"{entry.implementation_path!r}")
    fn = getattr(module, attr)
    if not callable(fn):
        raise RouterError(
            f"registry entry {entry.entry_id!r} resolves to a non-callable "
            f"({type(fn).__name__}) at {entry.implementation_path!r}")
    return fn


# ─── Deterministic topological order ───────────────────────────────────────
def _topological_order(steps: Sequence[ExecutionStep]) -> List[int]:
    """Return step indices in topological order.

    Ties broken by original input index (deterministic).  Missing
    dependencies do NOT cause a topo error — the runtime step handler
    converts them into `DEPENDENCY_FAILED` outcomes.
    """
    id_to_idx = {s.step_id: i for i, s in enumerate(steps)}
    graph: Dict[int, set] = {i: set() for i in range(len(steps))}
    in_deg: Dict[int, int] = {i: 0 for i in range(len(steps))}
    for i, s in enumerate(steps):
        present_deps = [id_to_idx[d] for d in s.depends_on if d in id_to_idx]
        in_deg[i] = len(present_deps)
        for d in present_deps:
            graph[d].add(i)
    ready: List[int] = sorted(i for i, deg in in_deg.items() if deg == 0)
    ordered: List[int] = []
    while ready:
        node = ready.pop(0)          # smallest index first
        ordered.append(node)
        for child in sorted(graph[node]):
            in_deg[child] -= 1
            if in_deg[child] == 0:
                bisect.insort(ready, child)
    if len(ordered) != len(steps):
        raise RouterError("cyclic dependency in plan")
    return ordered


# ─── Plan validation ───────────────────────────────────────────────────────
def _validate_plan(steps: Sequence[ExecutionStep]) -> None:
    seen: set = set()
    valid_policies = {FailurePolicy.HALT.value, FailurePolicy.CONTINUE.value}
    for s in steps:
        if not isinstance(s, ExecutionStep):
            raise RouterError(f"plan contains non-ExecutionStep object: {type(s).__name__}")
        if not isinstance(s.step_id, str) or not s.step_id:
            raise RouterError(f"invalid step_id: {s.step_id!r}")
        if s.step_id in seen:
            raise RouterError(f"duplicate step_id in plan: {s.step_id!r}")
        seen.add(s.step_id)
        if not isinstance(s.entry_id, str) or not s.entry_id:
            raise RouterError(f"step {s.step_id!r} has invalid entry_id: {s.entry_id!r}")
        if s.failure_policy not in valid_policies:
            raise RouterError(
                f"step {s.step_id!r} has invalid failure_policy: {s.failure_policy!r}")


# ─── Single-step execution ─────────────────────────────────────────────────
def _execute_one(step: ExecutionStep,
                  outcomes_by_id: Mapping[str, StepOutcome],
                  id_to_idx: Mapping[str, int]) -> StepOutcome:
    # 1. dependency check — sorted for deterministic error report
    for dep_id in sorted(step.depends_on):
        if dep_id not in id_to_idx:
            return StepOutcome(
                step_id=step.step_id, entry_id=step.entry_id,
                status=StepStatus.DEPENDENCY_FAILED,
                failed_dependency=dep_id,
                error=f"declared dependency {dep_id!r} not present in plan")
        dep = outcomes_by_id.get(dep_id)
        if dep is None:
            # topo sort guarantees deps ran; safety net only.
            return StepOutcome(
                step_id=step.step_id, entry_id=step.entry_id,
                status=StepStatus.DEPENDENCY_FAILED,
                failed_dependency=dep_id,
                error=f"dependency {dep_id!r} not executed before this step")
        if dep.status != StepStatus.SUCCESS:
            if step.failure_policy == FailurePolicy.CONTINUE.value:
                continue
            return StepOutcome(
                step_id=step.step_id, entry_id=step.entry_id,
                status=StepStatus.DEPENDENCY_FAILED,
                failed_dependency=dep_id,
                error=(f"dependency {dep_id!r} finished with status "
                        f"{dep.status.value!r}"))

    # 2. registry resolution (M0b SSOT, no fallback)
    entry = _lookup_entry(step.entry_id)
    if entry is None:
        return StepOutcome(
            step_id=step.step_id, entry_id=step.entry_id,
            status=StepStatus.UNKNOWN_IMPLEMENTATION,
            error=(f"entry_id {step.entry_id!r} is not registered in "
                    "ADAPTER_REGISTRY or ANALYZER_REGISTRY"))

    # 3. optional mechanical format check (set membership on caller-declared format)
    if step.input_format is not None and step.input_format not in entry.accepts_formats:
        return StepOutcome(
            step_id=step.step_id, entry_id=step.entry_id,
            status=StepStatus.NOT_APPLICABLE,
            implementation=entry.implementation_path,
            error=(f"declared input_format {step.input_format!r} not in "
                    f"accepts_formats {sorted(entry.accepts_formats)}"))

    # 4. resolve callable
    try:
        fn = _resolve_callable(entry)
    except RouterError as ex:
        return StepOutcome(
            step_id=step.step_id, entry_id=step.entry_id,
            status=StepStatus.UNKNOWN_IMPLEMENTATION,
            implementation=entry.implementation_path,
            error=str(ex), error_type=type(ex).__name__)

    # 5. invoke — capture Exception (not BaseException — never swallow SIGINT)
    try:
        result = fn(**dict(step.inputs)) if step.inputs else fn()
    except Exception as ex:                                     # noqa: BLE001
        return StepOutcome(
            step_id=step.step_id, entry_id=step.entry_id,
            status=StepStatus.EXECUTION_FAILED,
            implementation=entry.implementation_path,
            error=str(ex), error_type=type(ex).__name__)

    return StepOutcome(
        step_id=step.step_id, entry_id=step.entry_id,
        status=StepStatus.SUCCESS,
        result=result,
        implementation=entry.implementation_path)


# ─── Public entry-point ────────────────────────────────────────────────────
def execute_plan(steps: Sequence[ExecutionStep]) -> List[StepOutcome]:
    """Execute a plan of `ExecutionStep`s.

    Execution order is a deterministic topological sort of `depends_on`.
    Return order matches the ORIGINAL step ordering (analyst-friendly).
    Every step yields exactly one `StepOutcome`.
    """
    _validate_plan(steps)
    exec_order = _topological_order(steps)
    outcomes_by_id: Dict[str, StepOutcome] = {}
    results: List[Optional[StepOutcome]] = [None] * len(steps)
    id_to_idx = {s.step_id: i for i, s in enumerate(steps)}

    for idx in exec_order:
        step = steps[idx]
        outcome = _execute_one(step, outcomes_by_id, id_to_idx)
        outcomes_by_id[step.step_id] = outcome
        results[idx] = outcome

    return [o for o in results if o is not None]


__all__ = [
    "ExecutionStep",
    "StepOutcome",
    "StepStatus",
    "FailurePolicy",
    "RouterError",
    "execute_plan",
]
