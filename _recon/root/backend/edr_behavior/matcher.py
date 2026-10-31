"""Bounded, deterministic sequence matcher over one (tenant, endpoint) window."""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from . import predicates as P
from .contracts import (FALSE, LINK_GUID, LINK_PID_SURROGATE, LINK_UNKNOWN,
                        OUTCOME_BUDGET, OUTCOME_INSUFFICIENT, OUTCOME_MATCH,
                        OUTCOME_NO_MATCH, TRUE, UNKNOWN, Enrichment,
                        EvaluationResult, EvidenceRecord, StageMatch)
from .normalize import scope_key
from .rules import SequenceRule, Stage

DEFAULT_BUDGET = 20000
IntelMap = Dict[Tuple[str, str], Optional[Enrichment]]


class _Budget:
    def __init__(self, n: int) -> None:
        self.left = n

    def spend(self) -> bool:
        self.left -= 1
        return self.left >= 0


def stage_value(stage: Stage, rec: EvidenceRecord, intel: IntelMap) -> str:
    if rec.kind not in stage.kinds:
        return FALSE
    base = P.evaluate(rec, stage.predicate) if stage.predicate else TRUE
    if stage.intel is None or base == FALSE:
        return base
    obs = P.get_field(rec, stage.intel["observable_field"])
    if obs is None:
        return UNKNOWN
    e = intel.get((rec.tenant_id, str(obs).lower()))
    if e is None or e.verdict == "UNKNOWN":
        return UNKNOWN
    hit = e.verdict in stage.intel["verdict_in"] and e.confidence >= stage.intel["min_confidence"]
    return (UNKNOWN if base == UNKNOWN else TRUE) if hit else FALSE


def _norm(v: Any) -> Any:
    if isinstance(v, str):
        return v.replace("\\", "/").lower()
    return v


def _vals(rec: EvidenceRecord, path: str) -> Optional[set]:
    v = P.get_field(rec, path)
    if v is None:
        return None
    return {_norm(x) for x in (v if isinstance(v, list) else [v])}


def relationship(rel: Dict[str, Any], a: Dict[str, EvidenceRecord]) -> Tuple[str, str]:
    """Evaluate one relationship over bound stage records. Returns (value, linkage/reason)."""
    t = rel["type"]
    if t == "parent_child":
        p, c = a[rel["parent"]], a[rel["child"]]
        pp, cp = p.process, c.process
        if pp and cp and pp.process_guid and cp.parent_process_guid:
            return (TRUE if pp.process_guid.lower() == cp.parent_process_guid.lower() else FALSE), LINK_GUID
        if rel.get("min_linkage", LINK_PID_SURROGATE) == LINK_GUID:
            return UNKNOWN, "parent_child: source process GUID linkage not present"
        if pp and cp and pp.pid and cp.parent_pid:
            if pp.pid != cp.parent_pid:
                return FALSE, LINK_PID_SURROGATE
            return (TRUE if p.event_time <= c.event_time else FALSE), LINK_PID_SURROGATE
        return UNKNOWN, "parent_child: parent linkage fields not present"
    if t == "same_process":
        recs = [a[s] for s in rel["stages"]]
        for attr in ("process_iid", "process_guid"):
            vals = [getattr(r.process, attr, None) if r.process else None for r in recs]
            if all(vals):
                return (TRUE if len(set(vals)) == 1 else FALSE), attr
        return UNKNOWN, "same_process: process identity not present"
    if t == "same_user":
        vals = [_vals(a[s], "user.name") for s in rel["stages"]]
        if any(v is None for v in vals):
            return UNKNOWN, "same_user: user not present"
        return (TRUE if set.intersection(*vals) else FALSE), "user.name"
    if t == "same_value":
        (ls, lf), (rs, rf) = rel["left"].split(":", 1), rel["right"].split(":", 1)
        lv, rv = _vals(a[ls], lf), _vals(a[rs], rf)
        if lv is None or rv is None:
            return UNKNOWN, f"same_value: {lf if lv is None else rf} not present"
        return (TRUE if lv & rv else FALSE), f"{lf}=={rf}"
    if t == "dns_to_ip":
        d, n = a[rel["dns"]], a[rel["network"]]
        ans, ip = _vals(d, "dns.answers"), _vals(n, "network.dest_ip")
        if ans is not None and ip is not None:
            return (TRUE if ans & ip else FALSE), "dns.answers∋network.dest_ip"
        q, h = _vals(d, "dns.query_name"), _vals(n, "network.dest_hostname")
        if q is not None and h is not None:
            return (TRUE if q & h else FALSE), "dns.query_name==network.dest_hostname"
        return UNKNOWN, "dns_to_ip: answers/destination not present"
    return UNKNOWN, f"unsupported relationship {t}"


def _stage_rels(rule: SequenceRule, sid: str, bound: Dict[str, EvidenceRecord]):
    for rel in rule.relationships:
        ids = _rel_ids(rel)
        if sid in ids and all(i == sid or i in bound for i in ids):
            yield rel


def _rel_ids(rel: Dict[str, Any]) -> List[str]:
    t = rel["type"]
    if t == "parent_child":
        return [rel["parent"], rel["child"]]
    if t in ("same_process", "same_user"):
        return list(rel["stages"])
    if t == "same_value":
        return [rel["left"].split(":", 1)[0], rel["right"].split(":", 1)[0]]
    return [rel["dns"], rel["network"]]


class _Search:
    def __init__(self, rule: SequenceRule, events: List[EvidenceRecord], intel: IntelMap,
                 budget: _Budget) -> None:
        self.rule, self.events, self.budget = rule, events, budget
        self.window = timedelta(seconds=rule.time_window_seconds)
        self.pv = {s.id: [stage_value(s, e, intel) for e in events] for s in rule.stages}
        self.unknowns: List[str] = []
        self.exhausted = False

    def _check(self, stage: Stage, idx: int, bound: Dict[str, EvidenceRecord]) -> Tuple[str, Dict[str, str]]:
        rec = self.events[idx]
        trial = dict(bound)
        trial[stage.id] = rec
        link: Dict[str, str] = {}
        worst = TRUE
        for rel in _stage_rels(self.rule, stage.id, trial):
            v, why = relationship(rel, trial)
            if v == FALSE:
                return FALSE, {}
            if v == UNKNOWN:
                worst = UNKNOWN
                self.unknowns.append(f"stage {stage.id}: {why}")
            elif rel["type"] == "parent_child":
                link[f"{rel['parent']}->{rel['child']}"] = why
        return worst, link

    def _in_window(self, anchor: EvidenceRecord, rec: EvidenceRecord, after) -> bool:
        if self.rule.ordered:
            return after <= rec.event_time <= anchor.event_time + self.window
        return abs(rec.event_time - anchor.event_time) <= self.window

    def run(self, anchor_idx: int, scope: str) -> Optional[List[StageMatch]]:
        anchor = self.events[anchor_idx]
        first = self.rule.positive_stages[0]
        group = self._group(first, anchor_idx, {}, anchor, anchor.event_time, scope)
        if group is None:
            return None
        bound = {first.id: anchor}
        return self._dfs(1, bound, [StageMatch(first.id, first.type, group)], anchor, anchor.event_time, scope)

    def _group(self, stage: Stage, idx: int, bound, anchor, after, scope) -> Optional[List[EvidenceRecord]]:
        rec = self.events[idx]
        members, keys = [rec], {rec.stable_key}
        if stage.min_count == 1:
            return members
        for j in range(idx + 1, len(self.events)):
            if not self.budget.spend():
                self.exhausted = True
                return None
            e = self.events[j]
            if e.event_time > anchor.event_time + self.window:
                break
            if self.pv[stage.id][j] != TRUE or e.stable_key in keys:
                continue
            if scope_key(e, self.rule.entity_scope)[0] != scope:
                continue
            ok, _ = self._check(stage, j, bound)
            if ok == TRUE:
                members.append(e)
                keys.add(e.stable_key)
        return members if len(members) >= stage.min_count else None

    def _dfs(self, i: int, bound, matched: List[StageMatch], anchor, after, scope):
        pos = self.rule.positive_stages
        if i == len(pos):
            return matched if self._negatives_clear(bound, anchor, matched) else None
        stage = pos[i]
        for j, rec in enumerate(self.events):
            if self.exhausted or not self.budget.spend():
                self.exhausted = True
                return None
            pv = self.pv[stage.id][j]
            if pv == FALSE or rec.stable_key in {e.stable_key for m in matched for e in m.evidence}:
                continue
            if not self._in_window(anchor, rec, after):
                continue
            if pv == UNKNOWN:
                self.unknowns.append(f"stage {stage.id}: predicate not evaluable (field absent)")
                continue
            ok, link = self._check(stage, j, bound)
            if ok != TRUE:
                continue
            group = self._group(stage, j, bound, anchor, rec.event_time, scope)
            if group is None:
                continue
            nb = dict(bound)
            nb[stage.id] = rec
            nxt = self._dfs(i + 1, nb, matched + [StageMatch(stage.id, stage.type, group,
                                                             stage.optional, link)],
                            anchor, rec.event_time if self.rule.ordered else after, scope)
            if nxt is not None:
                return nxt
        if stage.optional:
            return self._dfs(i + 1, bound, matched, anchor, after, scope)
        return None

    def _negatives_clear(self, bound, anchor, matched: List[StageMatch]) -> bool:
        last = max(e.event_time for m in matched for e in m.evidence)
        for stage in self.rule.negative_stages:
            for j, rec in enumerate(self.events):
                if not (anchor.event_time <= rec.event_time <= last):
                    continue
                pv = self.pv[stage.id][j]
                if pv == FALSE:
                    continue
                if pv == UNKNOWN:
                    self.unknowns.append(f"negative stage {stage.id}: absence not provable")
                    continue
                ok, _ = self._check(stage, j, bound)
                if ok == TRUE:
                    return False
                if ok == UNKNOWN:
                    self.unknowns.append(f"negative stage {stage.id}: absence not provable")
        return True


def evaluate_rule(rule: SequenceRule, events: List[EvidenceRecord], intel: IntelMap,
                  budget: int = DEFAULT_BUDGET) -> List[EvaluationResult]:
    """One result per anchor candidate; explicit NO_MATCH / INSUFFICIENT / BUDGET otherwise."""
    b = _Budget(budget)
    s = _Search(rule, events, intel, b)
    first = rule.positive_stages[0]
    results: List[EvaluationResult] = []
    anchors = [i for i, v in enumerate(s.pv[first.id]) if v == TRUE]
    if not anchors:
        if UNKNOWN in s.pv[first.id]:
            return [EvaluationResult(rule.rule_id, rule.version, OUTCOME_INSUFFICIENT,
                                     [f"stage {first.id}: predicate not evaluable (field absent)"])]
        return [EvaluationResult(rule.rule_id, rule.version, OUTCOME_NO_MATCH)]
    for ai in anchors:
        s.unknowns = []
        chain = s.run(ai, scope_key(events[ai], rule.entity_scope)[0])
        if s.exhausted:
            results.append(EvaluationResult(rule.rule_id, rule.version, OUTCOME_BUDGET,
                                            ["evaluation budget exhausted"]))
            break
        if chain is not None:
            missing = _requirements(rule, chain)
            if missing:
                results.append(EvaluationResult(rule.rule_id, rule.version, OUTCOME_INSUFFICIENT,
                                                [f"required evidence absent: {m}" for m in missing], chain))
            else:
                results.append(EvaluationResult(rule.rule_id, rule.version, OUTCOME_MATCH,
                                                sorted(set(s.unknowns)), chain))
        else:
            out = OUTCOME_INSUFFICIENT if s.unknowns else OUTCOME_NO_MATCH
            results.append(EvaluationResult(rule.rule_id, rule.version, out, sorted(set(s.unknowns))))
    return results


def _requirements(rule: SequenceRule, chain: List[StageMatch]) -> List[str]:
    recs = [e for m in chain for e in m.evidence]
    return [f for f in rule.evidence_requirements
            if not any(P.get_field(r, f) is not None for r in recs)]
