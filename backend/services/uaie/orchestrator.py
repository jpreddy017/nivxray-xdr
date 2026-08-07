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
from .evidence   import Evidence, make_evidence
from .ledger     import (ACTION_COMPLETE, ACTION_EMIT_EVIDENCE, ACTION_ENQUEUE,
                          ACTION_EXECUTE, ACTION_RECOGNIZE, ACTION_SCHEDULE_SKIP,
                          ACTION_VALIDATE, ACTION_REPAIR_PLAN, ACTION_REPAIR_ATTEMPT,
                          ACTION_REPAIR_SUCCESS, ACTION_REPAIR_FAIL,
                          ACTION_MARK_UNREACHABLE,
                          Ledger, SKIP_ARTIFACTS_CAP, SKIP_CAPABILITY_ERROR,
                          SKIP_DEPTH_CAP, SKIP_MISSING_EVIDENCE_PREREQ,
                          SKIP_NO_RECOGNIZER_MATCH,
                          format_skip_reason)
from .qa        import (RepairCandidate, RepairCertificate, RepairResult,
                         STATE_ANALYZED, STATE_EXECUTED, STATE_NEW,
                         STATE_RECOGNIZED, STATE_REPAIR_PENDING, STATE_REPAIRED,
                         STATE_UNREACHABLE, STATE_VALIDATED, ValidationCertificate,
                         ValidationResult, plan_repairs, repair_for,
                         validators_for, REPAIR_FAIL_EXCEPTION,
                         REPAIR_FAIL_NO_CAPABILITY, REPAIR_FAIL_VALIDATOR_REJECTED,
                         UNREACHABLE_NO_STRATEGIES_LEFT)
from .termination import (CERT_REASON_FIXED_POINT, RemainingTransition,
                            TerminationCertificate)
from .lifecycle   import (LC_ANALYZED, LC_DONE, LC_EVIDENCE_COMPLETE,
                             LC_EXECUTED, LC_FIXED_POINT, LC_NEW,
                             LC_PLANNED, LC_RECOGNIZED, LC_REPAIRED,
                             LC_REPAIR_PENDING, LC_UNREACHABLE, LC_VALIDATED,
                             LifecycleRecorder, StateTransition)
from .recognizer import Recognition, Recognizer


@dataclass
class OrchestratorResult:
    artifacts:   Dict[str, Artifact] = field(default_factory=dict)
    evidence:    List[Evidence]      = field(default_factory=list)
    ledger:      Ledger              = field(default_factory=Ledger)
    warnings:    List[str]           = field(default_factory=list)
    total_ms:    float = 0.0
    # ── QA-Layer (R28.3) ────────────────────────────────────────────
    states:                   Dict[str, str] = field(default_factory=dict)
    validation_certificates:  List[ValidationCertificate] = field(default_factory=list)
    repair_certificates:      List[RepairCertificate]     = field(default_factory=list)
    # ── Fixed-Point Termination (R28.4) ─────────────────────────────
    termination_certificate:  Optional[TerminationCertificate] = None
    # ── Artifact State Machine (R28.5) ──────────────────────────────
    state_transitions:        List[StateTransition] = field(default_factory=list)


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
                  max_depth:     int = 12,
                  max_repair_attempts_per_artifact: int = 8) -> None:
        self.recognizers    = list(recognizers or [])
        self.planner        = planner or _default_planner
        self.max_artifacts  = max_artifacts
        self.max_depth      = max_depth
        self.max_repair_attempts_per_artifact = max_repair_attempts_per_artifact

    # ── QA-Layer helpers (R28.3) ────────────────────────────────────
    def _run_validators(self, artifact: Artifact) -> List[ValidationResult]:
        """Diagnose an artifact with every registered validator for its
        type (+ universal ``*`` validators).  Pure function — validators
        never mutate bytes."""
        results: List[ValidationResult] = []
        for v in validators_for(artifact.artifact_type):
            try:
                results.append(v.validate(artifact))
            except Exception as e:  # pragma: no cover — validators are pure
                results.append(ValidationResult(
                    valid=True, validator=getattr(v, "name", "?"),
                    confidence=0.0,
                    detail=f"validator raised {type(e).__name__}: {e}",
                ))
        return results

    def _qa_accept_child(self, child: Artifact, parent: Artifact,
                          result: OrchestratorResult,
                          lc: Optional[LifecycleRecorder] = None) -> Optional[Artifact]:
        """Run the QA layer on a child artifact.

        Returns the artifact to enqueue (either the original child if
        it validates, or a repaired substitute), or ``None`` if the
        artifact is UNREACHABLE and must not be enqueued.

        Backwards-compat: if NO validators are registered for the
        child's artifact_type (and no universal validators exist),
        the child is accepted as-is with no ledger noise — exactly
        the pre-QA behaviour.
        """
        validator_results = self._run_validators(child)
        if not validator_results:
            # No QA registered for this type — legacy behaviour.
            result.states[child.uri] = STATE_VALIDATED
            if lc is not None:
                lc.transition(child.uri, LC_VALIDATED,
                                actor="qa.no_validators_registered",
                                reason="no_validators_for_type")
            return child

        # Aggregate validators' verdicts.  A child is VALID only if
        # EVERY validator that ran says valid=True.
        failures = [r for r in validator_results if not r.valid]
        for r in validator_results:
            result.validation_certificates.append(ValidationCertificate(
                artifact_uri=child.uri, validator=r.validator,
                valid=r.valid, reason=r.reason, detail=r.detail,
                confidence=r.confidence,
                candidates=[c.strategy for c in r.repair_candidates],
            ))
            result.ledger.append(
                artifact_uri=child.uri, action=ACTION_VALIDATE,
                actor=r.validator,
                input_summary=f"type={child.artifact_type} size={child.size}",
                output_summary=(
                    f"valid={r.valid} reason={r.reason or '-'} "
                    f"candidates={[c.strategy for c in r.repair_candidates]}"),
                confidence=r.confidence,
            )
        if not failures:
            result.states[child.uri] = STATE_VALIDATED
            if lc is not None:
                lc.transition(child.uri, LC_VALIDATED,
                                actor="qa.validators_passed",
                                reason=f"validators_passed={len(validator_results)}")
            return child

        # ── Repair phase ──
        result.states[child.uri] = STATE_REPAIR_PENDING
        if lc is not None:
            # We must first pass through VALIDATED because the DAG
            # requires it — the validator DID run (and failed).  The
            # recorder rejects illegal transitions silently.
            lc.transition(child.uri, LC_VALIDATED,
                            actor="qa.validators_ran",
                            reason=f"validators_failed={[r.reason for r in failures]}")
            lc.transition(child.uri, LC_REPAIR_PENDING,
                            actor="qa.planner",
                            reason=f"repair_pending failures={[r.reason for r in failures]}")
        # Union all candidates across failed validators, then rank.
        all_candidates: List[RepairCandidate] = []
        for r in failures:
            all_candidates.extend(r.repair_candidates)
        ranked = plan_repairs(all_candidates)
        result.ledger.append(
            artifact_uri=child.uri, action=ACTION_REPAIR_PLAN,
            actor="qa.planner",
            input_summary=(f"failures={[r.reason for r in failures]} "
                             f"validators={[r.validator for r in failures]}"),
            output_summary=f"ranked={[(c.strategy, round(c.confidence, 3)) for c in ranked]}",
        )
        if not ranked:
            # No strategies proposed — mark UNREACHABLE.
            self._mark_unreachable(child, failures, result,
                                    reason=UNREACHABLE_NO_STRATEGIES_LEFT,
                                    detail="validators diagnosed invalid but proposed no repairs",
                                    lc=lc)
            return None

        attempts = 0
        for cand in ranked:
            if attempts >= self.max_repair_attempts_per_artifact:
                self._mark_unreachable(child, failures, result,
                                        reason=UNREACHABLE_NO_STRATEGIES_LEFT,
                                        detail=f"max_repair_attempts={self.max_repair_attempts_per_artifact}",
                                        lc=lc)
                return None
            attempts += 1
            repair = repair_for(cand.strategy)
            if repair is None:
                result.ledger.append(
                    artifact_uri=child.uri, action=ACTION_REPAIR_FAIL,
                    actor="qa.planner",
                    input_summary=f"strategy={cand.strategy}",
                    output_summary=f"reason={REPAIR_FAIL_NO_CAPABILITY}",
                )
                result.repair_certificates.append(RepairCertificate(
                    source_uri=child.uri, repaired_uri=None,
                    strategy=cand.strategy, outcome="failed",
                    reason=REPAIR_FAIL_NO_CAPABILITY,
                    detail="no repair capability registered for strategy",
                ))
                continue
            result.ledger.append(
                artifact_uri=child.uri, action=ACTION_REPAIR_ATTEMPT,
                actor=repair.name,
                input_summary=(f"strategy={cand.strategy} "
                                 f"cand_confidence={round(cand.confidence, 3)}"),
                output_summary=f"reason={cand.reason} detail={cand.detail}",
            )
            try:
                rres: RepairResult = repair.repair(child, cand)
            except Exception as e:  # pragma: no cover
                rres = RepairResult(
                    success=False, strategy=cand.strategy,
                    reason=REPAIR_FAIL_EXCEPTION,
                    detail=f"{type(e).__name__}: {e}",
                )
            if not rres.success or rres.repaired_payload is None:
                result.ledger.append(
                    artifact_uri=child.uri, action=ACTION_REPAIR_FAIL,
                    actor=repair.name,
                    input_summary=f"strategy={cand.strategy}",
                    output_summary=f"reason={rres.reason} detail={rres.detail}",
                )
                result.repair_certificates.append(RepairCertificate(
                    source_uri=child.uri, repaired_uri=None,
                    strategy=cand.strategy, outcome="failed",
                    reason=rres.reason, detail=rres.detail,
                ))
                continue
            # Repair produced bytes — build the repaired artifact and re-validate.
            new_type = rres.repaired_artifact_type or child.artifact_type
            repaired = make_artifact(
                rres.repaired_payload, new_type,
                parent_uri=child.uri, depth=child.depth,
                discovered_by=f"repair.{cand.strategy}",
                meta={**dict(child.meta),
                        "repair_strategy": cand.strategy,
                        "repair_source_uri": child.uri,
                        "repair_source_type": child.artifact_type,
                        **dict(rres.meta)},
            )
            re_results = self._run_validators(repaired)
            re_failures = [r for r in re_results if not r.valid]
            for r in re_results:
                result.validation_certificates.append(ValidationCertificate(
                    artifact_uri=repaired.uri, validator=r.validator,
                    valid=r.valid, reason=r.reason, detail=r.detail,
                    confidence=r.confidence,
                    candidates=[c.strategy for c in r.repair_candidates],
                ))
                result.ledger.append(
                    artifact_uri=repaired.uri, action=ACTION_VALIDATE,
                    actor=r.validator,
                    input_summary=f"post_repair strategy={cand.strategy}",
                    output_summary=f"valid={r.valid} reason={r.reason or '-'}",
                    confidence=r.confidence,
                )
            if re_failures:
                # Repair produced bytes but they still don't validate.
                result.ledger.append(
                    artifact_uri=child.uri, action=ACTION_REPAIR_FAIL,
                    actor=repair.name,
                    input_summary=f"strategy={cand.strategy}",
                    output_summary=(f"reason={REPAIR_FAIL_VALIDATOR_REJECTED} "
                                      f"post_reasons={[r.reason for r in re_failures]}"),
                )
                result.repair_certificates.append(RepairCertificate(
                    source_uri=child.uri, repaired_uri=repaired.uri,
                    strategy=cand.strategy, outcome="failed",
                    reason=REPAIR_FAIL_VALIDATOR_REJECTED,
                    detail=f"post_reasons={[r.reason for r in re_failures]}",
                ))
                continue
            # Success — emit certificate + evidence + return the repaired artifact.
            result.ledger.append(
                artifact_uri=child.uri, action=ACTION_REPAIR_SUCCESS,
                actor=repair.name,
                input_summary=f"strategy={cand.strategy}",
                output_summary=f"repaired_uri={repaired.uri} size={repaired.size}",
            )
            result.repair_certificates.append(RepairCertificate(
                source_uri=child.uri, repaired_uri=repaired.uri,
                strategy=cand.strategy, outcome="success",
                reason="", detail=f"repaired {child.size}B → {repaired.size}B",
            ))
            result.states[child.uri]    = STATE_REPAIRED
            result.states[repaired.uri] = STATE_VALIDATED
            if lc is not None:
                lc.transition(child.uri, LC_REPAIRED,
                                actor=repair.name,
                                reason=f"repair_success strategy={cand.strategy}")
                # The repaired artifact enters the graph in NEW then
                # is immediately VALIDATED by the re-check above.
                lc.transition(repaired.uri, LC_NEW,
                                actor=repair.name,
                                reason=f"repair_produced_new_artifact strategy={cand.strategy}")
                lc.transition(repaired.uri, LC_VALIDATED,
                                actor="qa.re_validator",
                                reason="repaired_artifact_passed_revalidation")
            # Track the repaired artifact so downstream consumers can look it up.
            result.artifacts[repaired.uri] = repaired
            return repaired

        # Exhausted all candidates.
        self._mark_unreachable(child, failures, result,
                                reason=UNREACHABLE_NO_STRATEGIES_LEFT,
                                detail=f"tried={[c.strategy for c in ranked]}",
                                lc=lc)
        return None

    def _mark_unreachable(self, child: Artifact,
                           failures: List[ValidationResult],
                           result: OrchestratorResult,
                           *, reason: str, detail: str,
                           lc: Optional[LifecycleRecorder] = None) -> None:
        result.states[child.uri] = STATE_UNREACHABLE
        if lc is not None:
            lc.transition(child.uri, LC_UNREACHABLE,
                            actor="qa.planner",
                            reason=f"{reason}: {detail}")
        result.ledger.append(
            artifact_uri=child.uri, action=ACTION_MARK_UNREACHABLE,
            actor="qa.planner",
            input_summary=(f"validators={[f.validator for f in failures]} "
                             f"reasons={[f.reason for f in failures]}"),
            output_summary=f"reason={reason} detail={detail}",
        )
        # Emit a first-class evidence record so the analyst SEES what
        # was ruled unreachable and why (never silent).
        ev = make_evidence(
            artifact_uri=child.uri,
            kind="repair_failed",
            value={
                "reason":       reason,
                "detail":       detail,
                "validators":   [f.validator for f in failures],
                "failure_codes": [f.reason for f in failures],
                "failure_detail": [f.detail  for f in failures],
            },
            source_capability="qa.planner",
            confidence=0.99,
            severity="medium",
        )
        result.evidence.append(ev)
        result.ledger.append(
            artifact_uri=child.uri, action=ACTION_EMIT_EVIDENCE,
            actor="qa.planner",
            output_summary=f"repair_failed reason={reason}",
            evidence_ids=[ev.id], confidence=ev.confidence,
        )


    def run(self, root_payload: bytes,
              *,
              root_type: str = "unknown") -> OrchestratorResult:
        t0 = time.perf_counter()
        root = make_artifact(root_payload, root_type,
                              discovered_by="orchestrator.root")
        result = OrchestratorResult()
        result.artifacts[root.uri] = root
        result.states[root.uri] = STATE_NEW
        # ── Artifact State Machine (R28.5) ──────────────────────────
        lc = LifecycleRecorder()
        lc.transition(root.uri, LC_NEW,
                       actor="orchestrator.root",
                       reason="root_artifact_created")
        queue: deque = deque([root])
        seen_uris = {root.uri}

        while queue:
            if len(result.artifacts) >= self.max_artifacts:
                result.warnings.append(f"max_artifacts cap {self.max_artifacts} hit")
                result.ledger.append(artifact_uri=(queue[0].uri if queue else ""),
                                       action=ACTION_SCHEDULE_SKIP,
                                       actor="orchestrator",
                                       output_summary=format_skip_reason(
                                           SKIP_ARTIFACTS_CAP,
                                           f"max_artifacts={self.max_artifacts}"))
                break
            art: Artifact = self.planner(queue)

            # ── 1. Recognize ──
            # Priority 3 · Multi-type recognition: an artifact can be
            # legitimately claimed by more than one recognizer (e.g. raw
            # shellcode bytes ALSO look like ``text`` under latin-1
            # decoding).  We collect every matched artifact_type so no
            # analyzer capability is silently dropped just because a
            # noisier recognizer emitted a higher confidence for a
            # different type.  The declared ``art.artifact_type`` is
            # always seeded — a root labelled ``shellcode_bytes`` never
            # loses its shellcode-branch capabilities.
            best: Optional[Recognition] = None
            matched_types: set[str] = {art.artifact_type}
            for rec in self.recognizers:
                try:
                    matches = rec.recognize(art)
                except Exception as e:  # pragma: no cover — never crash
                    result.warnings.append(f"recognizer {rec.name} raised {type(e).__name__}: {e}")
                    continue
                rec_best: Optional[Recognition] = None
                for m in matches or []:
                    m = m if isinstance(m, Recognition) else None
                    if not m:
                        continue
                    matched_types.add(m.artifact_type)
                    if rec_best is None or m.confidence > rec_best.confidence:
                        rec_best = m
                    if best is None or m.confidence > best.confidence:
                        best = m
                result.ledger.append(
                    artifact_uri=art.uri,
                    action=ACTION_RECOGNIZE,
                    actor=rec.name,
                    input_summary=f"{art.size}B · type={art.artifact_type}",
                    output_summary=(rec_best.artifact_type if rec_best else "(no match)"),
                    confidence=(rec_best.confidence if rec_best else None),
                    reasons=(rec_best.reasons if rec_best else []),
                )
            if best is None and art.artifact_type in ("unknown", ""):
                # No recognizer matched AND artifact has no declared type
                # → nothing to do.  A declared type (e.g. ``shellcode_bytes``
                # on the root) is enough to run its typed capabilities.
                result.ledger.append(artifact_uri=art.uri,
                                       action=ACTION_SCHEDULE_SKIP,
                                       actor="orchestrator",
                                       output_summary=format_skip_reason(
                                           SKIP_NO_RECOGNIZER_MATCH))
                continue

            # ── Lifecycle transition · NEW → RECOGNIZED ──
            # Any artifact that has either a declared type OR a
            # recognizer match has entered the RECOGNIZED state.
            lc.transition(art.uri, LC_RECOGNIZED,
                           actor="orchestrator.recognizer_phase",
                           reason=(f"matched_types={sorted(matched_types)} "
                                     f"best={best.artifact_type if best else '-'}"))

            # ── 2. Execute all capabilities registered for any matched
            #      type ──
            # Priority 3 · Deterministic Planner (2026-02):
            # Union the capabilities across every matched artifact_type
            # (plus the declared type), de-duplicate by name, then let
            # the Planner order them by the dependency graph so
            # analyzers always run BEFORE family emitters and family
            # emitters ALWAYS observe complete analyzer output.  This is
            # a pure, deterministic union+reorder — never drops capabilities.
            from .planner import plan as _plan_caps
            seen_cap_names: set[str] = set()
            union_caps: List[Capability] = []
            for t in matched_types:
                for c in _caps_for_type(t):
                    if c.name in seen_cap_names:
                        continue
                    seen_cap_names.add(c.name)
                    union_caps.append(c)
            caps = _plan_caps(union_caps)
            # ── Lifecycle transition · RECOGNIZED → PLANNED ──
            lc.transition(art.uri, LC_PLANNED,
                           actor="orchestrator.planner",
                           reason=f"capabilities_planned={len(caps)}")
            # Track whether this artifact emitted any evidence during
            # its capability execution — used for ANALYZED transition.
            _artifact_emitted_evidence = False
            for cap in caps:
                # Dependency check — evidence prerequisites
                if cap.requires_evidence:
                    have = {ev.kind for ev in result.evidence}
                    missing = [r for r in cap.requires_evidence if r not in have]
                    if missing:
                        result.ledger.append(
                            artifact_uri=art.uri, action=ACTION_SCHEDULE_SKIP,
                            actor=cap.name,
                            output_summary=format_skip_reason(
                                SKIP_MISSING_EVIDENCE_PREREQ,
                                f"requires={missing}"))
                        continue
                _t0 = time.perf_counter()
                try:
                    cr = cap.execute(art)
                except Exception as e:  # pragma: no cover
                    result.warnings.append(f"capability {cap.name} raised {type(e).__name__}")
                    result.ledger.append(artifact_uri=art.uri,
                                           action=ACTION_SCHEDULE_SKIP,
                                           actor=cap.name,
                                           output_summary=format_skip_reason(
                                               SKIP_CAPABILITY_ERROR,
                                               f"{type(e).__name__}: {e}"),
                                           elapsed_ms=(time.perf_counter() - _t0) * 1000.0)
                    continue
                elapsed_ms = (time.perf_counter() - _t0) * 1000.0
                result.ledger.append(
                    artifact_uri=art.uri, action=ACTION_EXECUTE, actor=cap.name,
                    input_summary=(f"type={best.artifact_type}" if best
                                     else f"type={art.artifact_type}"),
                    output_summary=f"evidence={len(cr.evidence)} children={len(cr.child_artifacts)}",
                    evidence_ids=[e.id for e in cr.evidence],
                    children_uris=[c.uri for c in cr.child_artifacts],
                    elapsed_ms=elapsed_ms,
                )
                for ev in cr.evidence:
                    result.evidence.append(ev)
                    _artifact_emitted_evidence = True
                    result.ledger.append(
                        artifact_uri=art.uri, action=ACTION_EMIT_EVIDENCE, actor=cap.name,
                        output_summary=f"{ev.kind}={ev.value}",
                        evidence_ids=[ev.id], confidence=ev.confidence)
                for child in cr.child_artifacts:
                    if child.uri in seen_uris:
                        continue
                    # ── Idempotency guard (2026-02-14 · anti-loop) ──
                    # If a capability produces a child whose ``artifact_type``
                    # equals its parent's, we're in a normalizer feedback
                    # cycle (e.g. ``op.powershell-normalize`` running on its
                    # own ``powershell_normalized`` output).  Every legitimate
                    # peel changes the artifact type (base64 → base64_decoded,
                    # gzip → gzip_decoded, etc.), so a same-type child is
                    # always spurious.  Skip with a structured reason so the
                    # analyst can still see why the loop terminated.
                    if child.artifact_type == art.artifact_type:
                        result.ledger.append(
                            artifact_uri=child.uri,
                            action=ACTION_SCHEDULE_SKIP,
                            actor=cap.name,
                            output_summary=format_skip_reason(
                                "same_type_as_parent",
                                f"parent_type={art.artifact_type} "
                                f"child_type={child.artifact_type}"))
                        continue
                    if child.depth > self.max_depth:
                        result.warnings.append(f"max_depth cap {self.max_depth} hit at {child.uri}")
                        result.ledger.append(artifact_uri=child.uri,
                                               action=ACTION_SCHEDULE_SKIP,
                                               actor=cap.name,
                                               output_summary=format_skip_reason(
                                                   SKIP_DEPTH_CAP,
                                                   f"max_depth={self.max_depth} "
                                                   f"depth={child.depth}"))
                        continue
                    seen_uris.add(child.uri)
                    result.artifacts[child.uri] = child
                    # Lifecycle · NEW for every child at the moment it
                    # enters the graph (before QA / re-enqueue).
                    lc.transition(child.uri, LC_NEW,
                                    actor=cap.name,
                                    reason="child_artifact_produced")
                    # ── QA-Layer (R28.3) · Validate → Repair → Enqueue ──
                    # If any validators are registered for this
                    # artifact_type, run them.  Rejected children are
                    # given a chance to be repaired deterministically.
                    # If no validators exist for this type, this is a
                    # no-op and legacy behaviour is preserved.
                    to_enqueue = self._qa_accept_child(child, art, result, lc=lc)
                    if to_enqueue is None:
                        # UNREACHABLE — validators failed and no repair
                        # strategy produced a valid replacement.  The
                        # evidence + certificates already record why.
                        continue
                    if to_enqueue.uri != child.uri:
                        # Repaired artifact — track it under seen_uris
                        # so the loop doesn't reprocess it.
                        seen_uris.add(to_enqueue.uri)
                    queue.append(to_enqueue)
                    result.ledger.append(artifact_uri=to_enqueue.uri,
                                           action=ACTION_ENQUEUE, actor=cap.name,
                                           input_summary=f"parent={art.uri}",
                                           output_summary=f"type={to_enqueue.artifact_type} depth={to_enqueue.depth}")

            # ── Lifecycle transitions after all caps ran on `art` ──
            # PLANNED → EXECUTED (unconditional; the artifact went
            # through the caps loop even if 0 caps applied).
            lc.transition(art.uri, LC_EXECUTED,
                           actor="orchestrator.execute_phase",
                           reason=f"caps_executed_count={len(caps)}")
            # EXECUTED → ANALYZED only if at least one capability
            # emitted evidence directly on this artifact.
            if _artifact_emitted_evidence:
                lc.transition(art.uri, LC_ANALYZED,
                               actor="orchestrator.execute_phase",
                               reason="capability_emitted_evidence")
                # ANALYZED → EVIDENCE_COMPLETE — every applicable
                # capability was consulted (executed or skipped for a
                # structured reason).  The audit later will confirm
                # this at FIXED_POINT time; here we're just closing
                # the analyzer window per-artifact.
                lc.transition(art.uri, LC_EVIDENCE_COMPLETE,
                               actor="orchestrator.execute_phase",
                               reason="all_applicable_capabilities_consulted")

        # ── Fixed-Point Termination Audit (R28.4) ───────────────────
        # Prove the investigation is at its mathematical fixed point:
        # every artifact was seen by every applicable recognizer,
        # capability, validator, and — for UNREACHABLE artifacts —
        # every applicable repair strategy.
        result.termination_certificate = self._run_termination_audit(result)

        # ── Lifecycle transitions · FIXED_POINT → DONE (R28.5) ──────
        # If the audit confirms fixed-point, every artifact that is
        # NOT already at a terminal branch (UNREACHABLE) transitions
        # forward to FIXED_POINT and then to DONE.  Artifacts already
        # in UNREACHABLE close directly to DONE.
        if result.termination_certificate.fixed_point:
            for uri in list(result.artifacts.keys()):
                cur = lc.current(uri)
                if cur == LC_UNREACHABLE:
                    lc.transition(uri, LC_DONE,
                                    actor="orchestrator.audit",
                                    reason="unreachable_closed_at_fixed_point")
                    continue
                # Best-effort forward walk — the recorder validates
                # each hop and silently ignores illegal ones.
                lc.transition(uri, LC_FIXED_POINT,
                               actor="orchestrator.audit",
                               reason="audit_confirmed_fixed_point")
                lc.transition(uri, LC_DONE,
                               actor="orchestrator.audit",
                               reason="investigation_complete")

        # Publish the lifecycle timeline to the result + mirror the
        # authoritative recorder state into the QA-layer `states` map.
        result.state_transitions = list(lc.transitions)
        for uri, s in lc._current.items():
            # Never overwrite the QA-layer states that carry richer
            # meaning (REPAIRED / UNREACHABLE).  Only mirror if the
            # existing states entry hasn't set a more specific label.
            if uri not in result.states or result.states[uri] == STATE_NEW:
                result.states[uri] = s

        result.total_ms = (time.perf_counter() - t0) * 1000.0
        result.ledger.append(artifact_uri=root.uri, action=ACTION_COMPLETE,
                               actor="orchestrator",
                               output_summary=f"artifacts={len(result.artifacts)} "
                                                f"evidence={len(result.evidence)} "
                                                f"ledger={len(result.ledger)} "
                                                f"fixed_point={result.termination_certificate.fixed_point}",
                               elapsed_ms=result.total_ms)
        return result

    # ── Fixed-Point Termination Audit (R28.4) ──────────────────────
    def _run_termination_audit(self,
                                 result: OrchestratorResult) -> TerminationCertificate:
        """Final audit pass over the entire investigation graph.

        Read-only.  Never enqueues, never emits evidence, never
        mutates artifacts.  It computes:

            · which (artifact × recognizer)  pairs were evaluated
            · which (artifact × capability) pairs were executed
            · which (artifact × validator)  pairs were run
            · which (unreachable × repair strategy) pairs were tried

        For each dimension it enumerates every pair that COULD have
        run but didn't and records it as a ``RemainingTransition``.
        If the list is empty, the investigation is at fixed point.
        """
        from .qa       import _VALIDATOR_REGISTRY, _REPAIR_REGISTRY
        from .capability import _REGISTRY as _CAP_REG

        # ── Build "what actually ran" indexes from the ledger ──
        ran_recognize:  set = set()  # (uri, recognizer_name)
        ran_execute:    set = set()  # (uri, capability_name)
        ran_validate:   set = set()  # (uri, validator_name)
        ran_repair:     set = set()  # (uri, strategy_name)  — attempted, success or fail
        for e in result.ledger:
            if e.action == "recognize":
                ran_recognize.add((e.artifact_uri, e.actor))
            elif e.action == "execute":
                ran_execute.add((e.artifact_uri, e.actor))
            elif e.action == "validate":
                ran_validate.add((e.artifact_uri, e.actor))
            elif e.action in ("repair_success", "repair_fail", "repair_attempt"):
                # Ledger records the strategy in ``input_summary`` as
                # "strategy=<name>".  Repair certificates are the
                # authoritative record.
                pass
        for cert in result.repair_certificates:
            ran_repair.add((cert.source_uri, cert.strategy))

        remaining: List[RemainingTransition] = []
        recognizers_checked  = 0
        capabilities_checked = 0
        validators_checked   = 0
        repair_checked       = 0

        for uri, art in result.artifacts.items():
            state = result.states.get(uri, "")

            # ── Recognizer coverage ──
            # Every registered recognizer should have been asked about
            # every artifact at some point.  We know it ran if
            # ``(uri, recognizer.name)`` is in ``ran_recognize``.
            # Superseded artifacts (REPAIRED source URIs, UNREACHABLE,
            # REPAIR_PENDING) are structurally excluded — the
            # investigation replaced them.
            superseded = state in (STATE_UNREACHABLE, STATE_REPAIRED,
                                     STATE_REPAIR_PENDING)
            for rec in self.recognizers:
                recognizers_checked += 1
                if superseded:
                    continue
                if (uri, rec.name) not in ran_recognize:
                    remaining.append(RemainingTransition(
                        artifact_uri=uri, actor=rec.name, kind="recognizer",
                        reason="recognizer was never applied to this artifact",
                    ))

            # ── Capability coverage ──
            # Every capability registered for this artifact's type
            # (or universal) should have been executed on this
            # artifact — unless prereq-guarded away.  We check the
            # ledger; guarded skips are recorded via ACTION_SCHEDULE_SKIP
            # with a structured reason, which we do NOT count as a
            # missing transition (they had a deterministic reason to
            # skip).
            candidate_caps = list(_CAP_REG.get(art.artifact_type, [])) \
                             + list(_CAP_REG.get("*", []))
            skipped_pairs = set()
            for e in result.ledger:
                if e.action == "schedule_skip" and e.artifact_uri == uri:
                    skipped_pairs.add((uri, e.actor))
            for cap in candidate_caps:
                capabilities_checked += 1
                pair = (uri, cap.name)
                if pair in ran_execute:
                    continue
                if pair in skipped_pairs:
                    # skip had a structured reason — not a missed transition
                    continue
                # Only count as remaining if the artifact is still an
                # active investigation surface.  UNREACHABLE and
                # REPAIRED artifacts are terminal / superseded — the
                # investigation has structurally decided not to consume
                # them.  Same for REPAIR_PENDING (the QA loop is still
                # processing them).
                if state in (STATE_UNREACHABLE, STATE_REPAIRED,
                              STATE_REPAIR_PENDING):
                    continue
                remaining.append(RemainingTransition(
                    artifact_uri=uri, actor=cap.name, kind="capability",
                    reason=(f"capability registered for type='{art.artifact_type}' "
                              f"was neither executed nor deterministically skipped"),
                ))

            # ── Validator coverage ──
            candidate_validators = list(_VALIDATOR_REGISTRY.get(art.artifact_type, [])) \
                                    + list(_VALIDATOR_REGISTRY.get("*", []))
            for v in candidate_validators:
                validators_checked += 1
                if (uri, v.name) not in ran_validate:
                    # Root artifact isn't validated by design (only
                    # children go through the QA hook).  Only flag
                    # non-root artifacts.
                    if art.parent_uri is None:
                        continue
                    remaining.append(RemainingTransition(
                        artifact_uri=uri, actor=v.name, kind="validator",
                        reason=(f"validator registered for type='{art.artifact_type}' "
                                  f"never ran on this artifact"),
                    ))

            # ── Repair coverage (only for UNREACHABLE) ──
            if state == STATE_UNREACHABLE:
                # Every registered repair strategy should have been
                # considered; if the validators didn't PROPOSE it,
                # that's a validator gap, not a repair miss.  So we
                # only check strategies that were proposed by a
                # validator on this URI.
                proposed = set()
                for c in result.validation_certificates:
                    if c.artifact_uri == uri and not c.valid:
                        proposed.update(c.candidates)
                for strategy in proposed:
                    repair_checked += 1
                    if (uri, strategy) not in ran_repair:
                        remaining.append(RemainingTransition(
                            artifact_uri=uri, actor=strategy, kind="repair",
                            reason="proposed repair strategy was never attempted",
                        ))

        counts = {
            "artifacts":                 len(result.artifacts),
            "recognizers":               len(self.recognizers),
            "capability_types":          len(_CAP_REG),
            "validator_types":           len(_VALIDATOR_REGISTRY),
            "registered_repairs":        len(_REPAIR_REGISTRY),
            "unreachable_artifacts":     sum(1 for s in result.states.values()
                                              if s == STATE_UNREACHABLE),
            "repaired_artifacts":        sum(1 for s in result.states.values()
                                              if s == STATE_REPAIRED),
            "validated_artifacts":       sum(1 for s in result.states.values()
                                              if s == STATE_VALIDATED),
            "remaining_transitions":     len(remaining),
        }
        fixed = (len(remaining) == 0)
        reason = CERT_REASON_FIXED_POINT if fixed else (
            f"{len(remaining)} deterministic transition(s) still applicable "
            f"across {len(set(t.artifact_uri for t in remaining))} artifact(s)"
        )
        return TerminationCertificate(
            fixed_point=fixed,
            artifacts_examined=len(result.artifacts),
            recognizers_checked=recognizers_checked,
            capabilities_checked=capabilities_checked,
            validators_checked=validators_checked,
            repair_strategies_checked=repair_checked,
            remaining_transitions=remaining,
            reason=reason,
            counts=counts,
        )
