"""SequenceEngine: one code path for live and retrospective evaluation."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import ML_ONLY_REASON
from . import predicates as P
from .contracts import (MODE_LIVE, OUTCOME_BUDGET, OUTCOME_INSUFFICIENT,
                        OUTCOME_MATCH, OUTCOME_NO_MATCH, OUTCOME_SUPPRESSED,
                        FALSE, EvaluationResult, EvidenceRecord)
from .detection import build, material, merge
from .matcher import DEFAULT_BUDGET, evaluate_rule, stage_value
from .normalize import is_ml_evidence
from .provider import EnrichmentProvider, EvidenceProvider, NullEnrichmentProvider, dedupe
from .rules import RuleRegistry, SequenceRule
from .store import ConcurrencyConflict, DetectionStore
from .suppression import SuppressionPolicy, adjustments, decide
from .metrics import Metrics

MAX_WINDOW_EVENTS = 5000
MAX_PUT_RETRIES = 3


class SequenceEngine:
    def __init__(self, registry: RuleRegistry, provider: EvidenceProvider, store: DetectionStore, *,
                 enrichment: Optional[EnrichmentProvider] = None,
                 suppression: Optional[SuppressionPolicy] = None,
                 metrics: Optional[Metrics] = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 max_window_events: int = MAX_WINDOW_EVENTS, budget: int = DEFAULT_BUDGET) -> None:
        self.registry, self.provider, self.store = registry, provider, store
        self.enrichment = enrichment or NullEnrichmentProvider()
        self.suppression = suppression
        self.metrics = metrics or Metrics()
        self.clock = clock
        self.max_window_events, self.budget = max_window_events, budget

    def candidate_rules(self, rec: EvidenceRecord, rules: Sequence[SequenceRule]) -> List[SequenceRule]:
        """Pre-filter: only rules with a stage the record could satisfy (TRUE or UNKNOWN)."""
        out = []
        for r in rules:
            if rec.kind not in r.kinds():
                continue
            if any(rec.kind in s.kinds and (s.predicate is None or P.evaluate(rec, s.predicate) != FALSE)
                   for s in r.stages):
                out.append(r)
        return out

    async def process(self, rec: EvidenceRecord, *, mode: str = MODE_LIVE,
                      trigger: Optional[Dict[str, Any]] = None,
                      rules: Optional[Sequence[SequenceRule]] = None) -> List[EvaluationResult]:
        t0 = time.perf_counter()
        if not rec.tenant_id or not rec.endpoint_id or rec.ref.tenant_id != rec.tenant_id:
            self.metrics.inc("events_rejected_malformed")
            return []
        self.metrics.inc("events_evaluated")
        rules = list(rules) if rules is not None else self.registry.live_rules()
        cands = self.candidate_rules(rec, rules)
        self.metrics.inc("candidate_rules", len(cands))
        results: List[EvaluationResult] = []
        for rule in cands:
            try:
                results.append(await self._evaluate(rule, rec, mode, trigger))
            except (ValueError, KeyError, TypeError):
                self.metrics.inc("rule_errors")
                self.metrics.rule_outcome(rule.rule_id, rule.version, "RULE_ERROR")
        self.metrics.latency((time.perf_counter() - t0) * 1000.0)
        return results

    async def _window(self, rule: SequenceRule, rec: EvidenceRecord) -> Optional[List[EvidenceRecord]]:
        w = timedelta(seconds=rule.time_window_seconds)
        got = await self.provider.window(tenant_id=rec.tenant_id, endpoint_id=rec.endpoint_id,
                                         start=rec.event_time - w, end=rec.event_time + w,
                                         kinds=rule.kinds(), limit=self.max_window_events + 1)
        clean = []
        for e in got:
            if e.tenant_id != rec.tenant_id or e.endpoint_id != rec.endpoint_id \
                    or e.ref.tenant_id != rec.tenant_id:
                self.metrics.inc("tenant_isolation_rejections")
                continue
            clean.append(e)
        events = dedupe(clean + [rec])
        self.metrics.state(len(events))
        if len(events) > self.max_window_events:
            self.metrics.inc("window_truncated")
            return None
        return events

    async def _intel(self, rule: SequenceRule, events: List[EvidenceRecord]):
        intel = {}
        for s in rule.stages:
            if not s.intel:
                continue
            for e in events:
                if e.kind not in s.kinds:
                    continue
                obs = P.get_field(e, s.intel["observable_field"])
                if obs is None or isinstance(obs, list):
                    continue
                k = (e.tenant_id, str(obs).lower())
                if k not in intel:
                    intel[k] = await self.enrichment.lookup(tenant_id=e.tenant_id, observable=str(obs),
                                                            observable_type=s.intel["observable_type"])
        return intel

    async def _evaluate(self, rule: SequenceRule, rec: EvidenceRecord, mode: str,
                        trigger: Optional[Dict[str, Any]]) -> EvaluationResult:
        events = await self._window(rule, rec)
        if events is None:
            return self._outcome(rule, EvaluationResult(rule.rule_id, rule.version, OUTCOME_BUDGET,
                                                        ["window exceeds max_window_events"]))
        per_anchor = evaluate_rule(rule, events, await self._intel(rule, events), self.budget)
        self.metrics.inc("sequence_states", len(per_anchor))
        involving = [r for r in per_anchor if r.outcome == OUTCOME_MATCH
                     and any(e.stable_key == rec.stable_key for m in r.stages for e in m.evidence)]
        ml_only = [r for r in involving
                   if all(is_ml_evidence(e) for m in r.stages for e in m.evidence)]
        if ml_only:
            self.metrics.inc("ml_only_rejected", len(ml_only))
            involving = [r for r in involving if r not in ml_only]
            if not involving:
                return self._outcome(rule, EvaluationResult(rule.rule_id, rule.version,
                                                            OUTCOME_INSUFFICIENT, [ML_ONLY_REASON]))
        if not involving:
            outcomes = {r.outcome for r in per_anchor}
            for o in (OUTCOME_BUDGET, OUTCOME_INSUFFICIENT):
                if o in outcomes:
                    reasons = sorted({x for r in per_anchor if r.outcome == o for x in r.reasons})
                    return self._outcome(rule, EvaluationResult(rule.rule_id, rule.version, o, reasons))
            return self._outcome(rule, EvaluationResult(rule.rule_id, rule.version, OUTCOME_NO_MATCH))
        last = None
        for res in involving:
            last = await self._emit(rule, res, rec, mode, trigger)
        return last

    def _outcome(self, rule: SequenceRule, res: EvaluationResult) -> EvaluationResult:
        self.metrics.rule_outcome(rule.rule_id, rule.version, res.outcome)
        if res.outcome == OUTCOME_INSUFFICIENT:
            self.metrics.inc("insufficient_evidence")
        elif res.outcome == OUTCOME_BUDGET:
            self.metrics.inc("budget_exceeded")
        return res

    async def _emit(self, rule: SequenceRule, res: EvaluationResult, rec: EvidenceRecord, mode: str,
                    trigger: Optional[Dict[str, Any]]) -> EvaluationResult:
        now = self.clock()
        supp, notes = decide(rule, res.stages, tenant_id=rec.tenant_id, endpoint_id=rec.endpoint_id,
                             policy=self.suppression, now=now)
        det = build(rule, res, tenant_id=rec.tenant_id, endpoint_id=rec.endpoint_id, suppression=supp,
                    notes=notes, adjustments=adjustments(rule, res.stages), mode=mode,
                    trigger=trigger, now=now).to_dict()
        for _ in range(MAX_PUT_RETRIES):
            existing = await self.store.get(rec.tenant_id, det["detection_id"])
            if existing is None:
                existing = await self.store.find_overlapping(
                    tenant_id=rec.tenant_id, endpoint_id=rec.endpoint_id, rule_id=rule.rule_id,
                    rule_version=rule.version, scope_key=det["scope_key"],
                    evidence_keys=det["evidence_keys"])
            try:
                if existing is None:
                    await self.store.put(det, None)
                    self.metrics.inc("detections_created")
                else:
                    merged = merge(existing, det)
                    merged["status"], merged["suppression"] = det["status"], det["suppression"]
                    if material(merged) == material(existing):
                        self.metrics.inc("duplicates_prevented")
                    else:
                        await self.store.put(merged, existing.get("revision"))
                        self.metrics.inc("detections_merged")
                break
            except ConcurrencyConflict:
                self.metrics.inc("concurrency_retries")
        else:
            self.metrics.inc("rule_errors")
        outcome = OUTCOME_SUPPRESSED if supp else OUTCOME_MATCH
        self.metrics.inc("suppressed_matches" if supp else "matches")
        return self._outcome(rule, EvaluationResult(rule.rule_id, rule.version, outcome,
                                                    res.reasons + notes, res.stages))
