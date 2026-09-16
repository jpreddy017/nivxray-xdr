"""Canonical Executor.

Given an IUEDecision + RawInput + optional SSOT store, run the plan,
invoke capability plug-ins, and produce a populated AuthoritativeSSOT.

INV-1: capability plug-ins ARE NOT SSOTs. They write to the SSOT via
`.append(...)`. Executor validates plug-in role classification.
INV-2: with `enrichers_enabled=False`, Enricher plug-ins are skipped.
INV-3: every append carries mandatory Provenance (SSOT enforces).
INV-4: projections remain empty (asserted post-run).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..iue.models import Capability, DispatchPolicy, IUEDecision, RawInput
from ..ssot import (
    AuthoritativeSSOT,
    ExecutionStep,
    InMemorySSOTStore,
    Provenance,
    Source,
)
from .budget import ExecutorBudget
from .registry import CAPABILITY_REGISTRY, CapabilityRole


@dataclass
class ExecutorResult:
    ssot: AuthoritativeSSOT
    ssot_ref: str
    executed_capabilities: List[str] = field(default_factory=list)
    skipped_capabilities: List[str] = field(default_factory=list)
    child_refs: List[str] = field(default_factory=list)
    depth: int = 0


class Executor:
    """Canonical Executor (D4-3)."""

    VERSION = "1.0.0-phase3"

    def __init__(self, store: Optional[InMemorySSOTStore] = None,
                 budget: Optional[ExecutorBudget] = None) -> None:
        self.store = store or InMemorySSOTStore()
        self.budget = budget or ExecutorBudget()

    def _prov(self, engine_suffix: str) -> Provenance:
        return Provenance(engine=f"canonical.executor.{engine_suffix}",
                          version=self.VERSION, at="phase3")

    def run(
        self,
        iue: IUEDecision,
        raw: RawInput,
        source: Optional[Source] = None,
        depth: int = 0,
    ) -> ExecutorResult:
        """Execute IUE plan; populate + return the authoritative SSOT."""
        import hashlib as _hashlib
        # Deterministic id: sha256(iue_hash || raw_bytes[:64] || depth).
        raw_head = raw.as_bytes()[:64].hex() if raw.as_bytes() else ""
        det_seed = f"{iue.determinism_hash}|{raw_head}|{depth}"
        det_id = _hashlib.sha256(det_seed.encode()).hexdigest()[:32]

        ssot = AuthoritativeSSOT(
            id=det_id,
            source=source or Source(surface="canonical", endpoint="/executor",
                                    correlation_id=f"depth-{depth}",
                                    channel="executor_direct"),
            input_raw=raw.payload,
            input_profile=iue.to_dict()["input_profile"],
            input_health=iue.to_dict()["input_health"],
            iue_decision=iue.to_dict(),
            plan=iue.to_dict()["plan"],
            provenance=self._prov("run"),
        )

        executed: List[str] = []
        skipped: List[str] = []

        # Strict-ordered execution (D4-3 policy per Phase 1 spec §6).
        # Determinism-preserving parallel handling for parallel_where_safe:
        # execute in plan order, since plug-ins are pure functions of
        # (raw, ssot at plan[i] start) — see T3.3.
        for step in iue.plan:
            cap = step.capability
            entry = CAPABILITY_REGISTRY.get(cap)
            step_ctx: Dict[str, Any] = {"depth": depth,
                                        "budget": self.budget,
                                        "store": self.store}
            trace = ExecutionStep(
                step_id=f"exec.{cap.value.lower()}",
                capability=cap.value,
                engine=entry["fn"].__module__ if entry else "unregistered",
                status="planned",
                notes=step.reason,
            )
            if not entry:
                trace.status = "skipped"
                trace.notes = f"no plug-in registered for {cap.value}"
                ssot.append("execution_trace", trace,
                            provenance=self._prov("skip"))
                skipped.append(cap.value)
                continue

            role: CapabilityRole = entry["role"]
            if role is CapabilityRole.ENRICHER and not self.budget.enrichers_enabled:
                trace.status = "skipped"
                trace.notes = "enrichers disabled (INV-2)"
                ssot.append("execution_trace", trace,
                            provenance=self._prov("enricher.disabled"))
                skipped.append(cap.value)
                continue

            try:
                entry["fn"](ssot, raw, step_ctx)
                trace.status = "executed"
            except Exception as exc:                                # noqa: BLE001
                trace.status = "error"
                trace.notes = f"{type(exc).__name__}: {exc}"
            ssot.append("execution_trace", trace,
                        provenance=self._prov(f"{cap.value.lower()}.trace"))
            executed.append(cap.value)

        # Post-execution invariant.
        ssot.assert_projections_empty()

        # RECURSIVE_DISCOVERY sub-run (D6-r): if the recursive_discovery
        # capability queued children on the ssot's metadata, the executor
        # kicks off nested runs BEFORE freezing.
        child_refs: List[str] = list(
            ssot.metadata.get("_recursive_queue", []) or []
        )
        ssot.metadata.pop("_recursive_queue", None)
        emitted_child_refs: List[str] = []

        if depth < self.budget.max_depth and child_refs:
            # Executor emits nothing here — recursive_discovery's plug-in
            # already stored + queued children. Just record the refs.
            emitted_child_refs.extend(child_refs[:self.budget.max_children])
            if len(child_refs) > self.budget.max_children:
                ssot.append("execution_trace", ExecutionStep(
                    step_id="exec.budget",
                    capability=Capability.RECURSIVE_DISCOVERY.value,
                    engine="canonical.executor.budget",
                    status="budget_exhausted",
                    notes=(f"queued={len(child_refs)} "
                           f"max_children={self.budget.max_children}"),
                ), provenance=self._prov("budget"))

        ssot.freeze()
        ref = self.store.put(ssot)
        return ExecutorResult(
            ssot=ssot, ssot_ref=ref,
            executed_capabilities=executed,
            skipped_capabilities=skipped,
            child_refs=emitted_child_refs,
            depth=depth,
        )
