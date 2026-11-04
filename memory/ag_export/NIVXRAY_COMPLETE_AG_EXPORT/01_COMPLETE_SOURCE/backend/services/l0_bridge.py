"""L0 Read-Only Transformation Bridge  · ARB PR-2.2 Phase A.

Exposes the *real* per-stage deterministic output of every L0
convergence transformation so the analyst trace UI can show:

    Input → transformation → Output → Evidence → Why

for each stage the L0 engine actually executed on the winning chain.

Contract
--------
- **Read-only**: this bridge NEVER modifies the L0 engine, its
  registry, or its transformation functions. It looks up the callable
  attached to the frozen ``Transformation.apply`` descriptor and
  invokes it against the running buffer. Nothing else.
- **No self-healing**: this module implements observability, not
  intelligence. There are no quality gates, no entropy checks, no
  alternate paths, no repair logic. If a transformation returns
  ``(new, 0)`` (it didn't fire), the buffer passes through unchanged
  — same behaviour as the L0 engine.
- **No side effects**: does not import anything from the router-side
  ``operations.py`` registry. L0 transformations are pure functions
  by contract (see ``workspace/convergence/transformation.py``).
- **Deterministic**: same buffer + same op_id → same output. Backed
  by the FROZEN L0 registry.

Coverage
--------
Concatenates the transformation tuples from all four L0 pass modules
(``structural`` / ``content`` / ``decoder`` / ``semantic``) into a
single name→callable lookup table. The lookup table is built lazily
on first use and cached for the process lifetime — the L0 registry
is immutable at import time.

Consumer path
-------------
``backend/routers/ops.py`` `/api/decode/smart` builds the per-layer
trace by iterating ``det["steps"]`` (the L0 canonical chain). For
each step where the router's local ``OPERATIONS`` dict does NOT own
the op but the L0 registry DOES, the trace-builder invokes
``execute_l0_transformation(op_id, buffer)`` and records the real
output preview + fire count in the trace entry.

This is the Phase A analyst-observability improvement approved by
the ARB (Aug 2026). Phase B (stage-quality gates) and Phase C
(self-healing alternates) are explicitly deferred until an expanded
evidence corpus is available.
"""
from __future__ import annotations

import logging
from typing import Callable, Dict, Optional, Tuple

log = logging.getLogger("nivx.services.l0_bridge")


_L0_APPLY_TABLE: Optional[Dict[str, Callable[[str], Tuple[str, int]]]] = None


def _build_apply_table() -> Dict[str, Callable[[str], Tuple[str, int]]]:
    """Concatenate L0 transformation tuples into a name→apply lookup."""
    table: Dict[str, Callable[[str], Tuple[str, int]]] = {}
    for mod_name in ("structural", "content", "decoder", "semantic"):
        try:
            mod = __import__(f"workspace.convergence.{mod_name}",
                             fromlist=["TRANSFORMATIONS"])
        except Exception as e:
            log.warning("l0_bridge: could not import workspace.convergence.%s: %s",
                        mod_name, e)
            continue
        transforms = getattr(mod, "TRANSFORMATIONS", None)
        if not transforms:
            continue
        for t in transforms:
            fn = getattr(t, "apply", None)
            if fn is None:
                continue
            table[t.name] = fn
    return table


def _table() -> Dict[str, Callable[[str], Tuple[str, int]]]:
    global _L0_APPLY_TABLE
    if _L0_APPLY_TABLE is None:
        _L0_APPLY_TABLE = _build_apply_table()
    return _L0_APPLY_TABLE


def is_l0_transformation(op_id: str) -> bool:
    """Return True iff ``op_id`` names a registered L0 transformation
    whose ``apply`` callable is invocable via this bridge."""
    return op_id in _table()


def execute_l0_transformation(op_id: str, buffer: str) -> Tuple[str, int, Optional[str]]:
    """Execute the L0 transformation ``op_id`` against ``buffer``.

    Returns ``(new_buffer, fire_count, error)`` where:
      • ``new_buffer`` — buffer AFTER the transformation. Equals
        ``buffer`` when the transformation did not fire.
      • ``fire_count`` — number of times the transformation fired
        (0 means the buffer was unchanged).
      • ``error`` — ``None`` on success, human-readable string on
        failure. Consumers should surface this as an analyst-visible
        note but must NOT hide it from the trace.

    This function is READ-ONLY with respect to the L0 engine. It does
    not mutate any registry, cache, or shared state.
    """
    table = _table()
    fn = table.get(op_id)
    if fn is None:
        return (buffer, 0, f"L0 transformation {op_id!r} not registered")
    try:
        result = fn(buffer)
    except Exception as e:
        # Never raise — trace UI must remain populated. Surface as an
        # error string so analysts see WHY the stage produced no
        # change. Does NOT trigger self-healing (deferred to PR-2.2 B/C).
        return (buffer, 0, f"{type(e).__name__}: {e}")
    # L0 contract: apply returns (str, int) — but be forgiving in case
    # of unexpected shapes.
    if isinstance(result, tuple) and len(result) == 2:
        new_buf, fired = result
        if not isinstance(new_buf, str):
            new_buf = str(new_buf)
        try:
            fired = int(fired)
        except Exception:
            fired = 0
        return (new_buf, fired, None)
    if isinstance(result, str):
        return (result, (1 if result != buffer else 0), None)
    return (buffer, 0, f"L0 transformation returned unexpected shape: {type(result).__name__}")


__all__ = ["is_l0_transformation", "execute_l0_transformation"]
