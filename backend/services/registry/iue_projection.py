"""M0e · IUE-v3 execution-plan projection (ADR-0014).

Pure function that projects an existing (unmodified) `InputUnderstanding`
into an `ExecutionPlanProjection` — the machine-readable contract the
M0d router understands.

RULES (owner directive · M0e, 2026-02-15):
  • The existing IUE is NOT modified.  This module reads it, never
    writes to it.  The 18 M0a-frozen fields keep their exact values.
  • The projection is a name-mapping, NOT a classifier.  The IUE has
    already decided WHAT to run (via `engines_selected`); the
    projection only translates each friendly name into its M0b
    registry `entry_id`.
  • Legacy engines with no M0b registry entry today are NOT silently
    dropped.  They surface in `ExecutionPlanProjection.unmapped_engines`
    for analyst visibility.  Fixing that gap belongs to a future
    migration (registering more capabilities), not to M0e.
  • Every emitted `ExecutionStep.entry_id` is verified against
    `ADAPTER_REGISTRY.ids() ∪ ANALYZER_REGISTRY.ids()` at import time,
    so a stale mapping cannot ship silently.
  • Dependencies preserve the linear ordering of `engines_selected`:
    each mapped step depends on the previous mapped step.  Deterministic.
  • The M0d router remains the ONLY execution dispatcher.  This module
    imports nothing that could execute a step.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from . import ADAPTER_REGISTRY, ANALYZER_REGISTRY
from .router import ExecutionStep, FailurePolicy


# ─── Name-mapping table  ────────────────────────────────────────────────────
# Keys are the AUTHORITATIVE friendly names surfaced by the current IUE in
# `engines_selected`.  Values are the M0b registry entry_ids that ALREADY
# EXIST.  Unmapped friendly names are legitimate — they correspond to
# legacy pipeline stages that don't have a standalone M0b capability yet.
_LEGACY_ENGINE_TO_ENTRY_ID: Dict[str, str] = {
    "DIE (Semantic AST)": "die.command.v1",
    "Decoder":            "die.recursive.v1",
    "IOC Enrichment":     "ioc_enrichment.v1",
    "URL Acquisition":    "url.acquire.v1",
}


class ProjectionError(RuntimeError):
    """Raised at IMPORT TIME if a mapping value points at a non-existent
    registry id — never at projection time.  This guarantees that a
    stale table cannot ship silently."""


def _validate_mapping_at_import() -> None:
    valid = set(ADAPTER_REGISTRY.ids()) | set(ANALYZER_REGISTRY.ids())
    bad = {k: v for k, v in _LEGACY_ENGINE_TO_ENTRY_ID.items() if v not in valid}
    if bad:
        raise ProjectionError(
            f"legacy→registry mapping references unknown ids: {bad}. "
            f"Fix the table or update the M0b registry.")


_validate_mapping_at_import()


# ─── Projection dataclass ──────────────────────────────────────────────────
@dataclass(frozen=True)
class ExecutionPlanProjection:
    """The M0e contract handed to the M0d router.

    Three lists, all deterministic:
      • `steps`            → router-executable ExecutionSteps
      • `unmapped_engines` → legacy engines with no M0b capability today
      • `legacy_plan`      → the IUE's original plan[] preserved verbatim
    """
    steps:            List[ExecutionStep]
    unmapped_engines: List[str]
    legacy_plan:      List[dict] = field(default_factory=list)


# ─── Projection function ───────────────────────────────────────────────────
def plan_to_execution_steps(iue_output) -> ExecutionPlanProjection:
    """Project an `InputUnderstanding` (or its `asdict()` form) into the
    M0e contract.  Pure function.  Deterministic.  Non-mutating.

    The IUE's `engines_selected` is authoritative — the projection walks
    it in order and maps each friendly name to a registry `entry_id`.
    """
    # Accept either the dataclass or its asdict() form — no coupling to
    # the concrete InputUnderstanding class.
    if hasattr(iue_output, "engines_selected"):
        engines_selected = list(iue_output.engines_selected)
        legacy_plan_src  = list(iue_output.plan)
    elif isinstance(iue_output, dict):
        engines_selected = list(iue_output.get("engines_selected", []))
        legacy_plan_src  = list(iue_output.get("plan", []))
    else:
        raise TypeError(
            f"plan_to_execution_steps expects InputUnderstanding or dict, "
            f"got {type(iue_output).__name__}")

    steps:    List[ExecutionStep] = []
    unmapped: List[str]           = []
    prev_step_id: str | None      = None

    for order_idx, friendly_name in enumerate(engines_selected):
        entry_id = _LEGACY_ENGINE_TO_ENTRY_ID.get(friendly_name)
        if entry_id is None:
            unmapped.append(friendly_name)
            continue

        # Deterministic step_id — friendly-name-derived, not order-derived,
        # so re-runs of the same input give byte-identical projections.
        step_id = f"s{order_idx:02d}_{entry_id.replace('.', '_')}"

        depends_on = frozenset({prev_step_id}) if prev_step_id else frozenset()
        steps.append(ExecutionStep(
            step_id       = step_id,
            entry_id      = entry_id,
            inputs        = {},                          # populated by caller
            depends_on    = depends_on,
            failure_policy = FailurePolicy.HALT.value,
            input_format  = None,
        ))
        prev_step_id = step_id

    # Preserve the original plan[] verbatim as a plain-list of dicts.
    # Each element is already a dict per the IUE's contract.
    legacy_plan = [dict(s) if isinstance(s, dict) else dict(s.__dict__)
                    for s in legacy_plan_src]

    return ExecutionPlanProjection(
        steps            = steps,
        unmapped_engines = unmapped,
        legacy_plan      = legacy_plan,
    )


__all__ = [
    "ExecutionPlanProjection",
    "ProjectionError",
    "plan_to_execution_steps",
]
