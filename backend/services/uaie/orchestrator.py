"""UAIE Contract #6 · Orchestrator (Rule R25)

Work-queue engine.  Owns the ledger.  Dispatches Recognizers →
Capabilities → Evidence + Child Artifacts.

Loop:
    while queue and budget:
        art       = planner.pick(queue)
        matches   = registry.recognize(art)
        for cap in registry.for_type(matches.best.artifact_type):
            r = cap.execute(art)
            ledger.append(...)
            evidence += r.evidence
            queue    += r.child_artifacts
Stop when no new artifacts and no new evidence.

Phase 1: sequential, deterministic, no plugin dependencies yet.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing      import Callable, Dict, List, Optional

from .artifact   import Artifact, make_artifact
from .capability import Capability, for_type as _caps_for_type
from .evidence   import Evidence
from .ledger     import (ACTION_COMPLETE, ACTION_EMIT_EVIDENCE, ACTION_ENQUEUE,
                          ACTION_EXECUTE, ACTION_RECOGNIZE, ACTION_SCHEDULE_SKIP,
                          Ledger)
from .recognizer import Recognition, Recognizer


@dataclass
class OrchestratorResult:
    artifacts:   Dict[str, Artifact] = field(default_factory=dict)
    evidence:    List[Evidence]      = field(default_factory=list)
    ledger:      Ledger              = field(default_factory=Ledger)
    warnings:    List[str]           = field(default_factory=list)
    total_ms:    float = 0.0


def _default_planner(queue: deque) -> Artifact:
    """FIFO planner (Phase 1 default).  Later phases replace with
    a score-based planner using ``confidence · severity · depth``."""
    return queue.popleft()


class Orchestrator:
    def __init__(self,
                  recognizers: Optional[List[Recognizer]] = None,
                  *,
                  planner: Optional[Callable[[deque], Artifact]] = None,
                  max_artifacts: int = 256,
                  max_depth:     int = 12) -> None:
        self.recognizers    = list(recognizers or [])
        self.planner        = planner or _default_planner
        self.max_artifacts  = max_artifacts
        self.max_depth      = max_depth

    def run(self, root_payload: bytes,
              *,
              root_type: str = "unknown") -> OrchestratorResult:
        t0 = time.perf_counter()
        root = make_artifact(root_payload, root_type,
                              discovered_by="orchestrator.root")
        result = OrchestratorResult()
        result.artifacts[root.uri] = root
        queue: deque = deque([root])
        seen_uris = {root.uri}

        while queue:
            if len(result.artifacts) >= self.max_artifacts:
                result.warnings.append(f"max_artifacts cap {self.max_artifacts} hit")
                break
            art: Artifact = self.planner(queue)

            # ── 1. Recognize ──
            best: Optional[Recognition] = None
            for rec in self.recognizers:
                try:
                    matches = rec.recognize(art)
                except Exception as e:  # pragma: no cover — never crash
                    result.warnings.append(f"recognizer {rec.name} raised {type(e).__name__}: {e}")
                    continue
                for m in matches or []:
                    m = m if isinstance(m, Recognition) else None
                    if not m:
                        continue
                    if best is None or m.confidence > best.confidence:
                        best = m
                result.ledger.append(
                    artifact_uri=art.uri,
                    action=ACTION_RECOGNIZE,
                    actor=rec.name,
                    input_summary=f"{art.size}B · type={art.artifact_type}",
                    output_summary=(best.artifact_type if best else "(no match)"),
                    confidence=(best.confidence if best else None),
                    reasons=(best.reasons if best else []),
                )
            if best is None:
                result.ledger.append(artifact_uri=art.uri,
                                       action=ACTION_SCHEDULE_SKIP,
                                       actor="orchestrator",
                                       output_summary="no recognizer match")
                continue

            # ── 2. Execute all capabilities registered for that type ──
            # ── Priority 3 · Deterministic Planner (2026-02) ──
            # Sort the capability list by artifact-type dependency graph
            # so analyzers always run BEFORE family emitters and family
            # emitters ALWAYS observe complete analyzer output.  This is
            # a pure, deterministic reordering — never drops capabilities.
            from .planner import plan as _plan_caps
            caps = _plan_caps(_caps_for_type(best.artifact_type))
            for cap in caps:
                # Dependency check — evidence prerequisites
                if cap.requires_evidence:
                    have = {ev.kind for ev in result.evidence}
                    if not all(r in have for r in cap.requires_evidence):
                        result.ledger.append(
                            artifact_uri=art.uri, action=ACTION_SCHEDULE_SKIP,
                            actor=cap.name,
                            output_summary=f"missing evidence deps {cap.requires_evidence}")
                        continue
                _t0 = time.perf_counter()
                try:
                    cr = cap.execute(art)
                except Exception as e:  # pragma: no cover
                    result.warnings.append(f"capability {cap.name} raised {type(e).__name__}")
                    result.ledger.append(artifact_uri=art.uri,
                                           action=ACTION_EXECUTE,
                                           actor=cap.name,
                                           output_summary=f"error: {type(e).__name__}",
                                           elapsed_ms=(time.perf_counter() - _t0) * 1000.0)
                    continue
                elapsed_ms = (time.perf_counter() - _t0) * 1000.0
                result.ledger.append(
                    artifact_uri=art.uri, action=ACTION_EXECUTE, actor=cap.name,
                    input_summary=f"type={best.artifact_type}",
                    output_summary=f"evidence={len(cr.evidence)} children={len(cr.child_artifacts)}",
                    evidence_ids=[e.id for e in cr.evidence],
                    children_uris=[c.uri for c in cr.child_artifacts],
                    elapsed_ms=elapsed_ms,
                )
                for ev in cr.evidence:
                    result.evidence.append(ev)
                    result.ledger.append(
                        artifact_uri=art.uri, action=ACTION_EMIT_EVIDENCE, actor=cap.name,
                        output_summary=f"{ev.kind}={ev.value}",
                        evidence_ids=[ev.id], confidence=ev.confidence)
                for child in cr.child_artifacts:
                    if child.uri in seen_uris:
                        continue
                    if child.depth > self.max_depth:
                        result.warnings.append(f"max_depth cap {self.max_depth} hit at {child.uri}")
                        continue
                    seen_uris.add(child.uri)
                    result.artifacts[child.uri] = child
                    queue.append(child)
                    result.ledger.append(artifact_uri=child.uri,
                                           action=ACTION_ENQUEUE, actor=cap.name,
                                           input_summary=f"parent={art.uri}",
                                           output_summary=f"type={child.artifact_type} depth={child.depth}")

        result.total_ms = (time.perf_counter() - t0) * 1000.0
        result.ledger.append(artifact_uri=root.uri, action=ACTION_COMPLETE,
                               actor="orchestrator",
                               output_summary=f"artifacts={len(result.artifacts)} "
                                                f"evidence={len(result.evidence)} "
                                                f"ledger={len(result.ledger)}",
                               elapsed_ms=result.total_ms)
        return result
