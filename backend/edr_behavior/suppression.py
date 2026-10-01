"""FP control: suppression never deletes evidence; it only changes detection status."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from . import predicates as P
from .contracts import TRUE, UNKNOWN, StageMatch
from .rules import SequenceRule


@dataclass(frozen=True)
class SuppressionEntry:
    entry_id: str
    tenant_id: str
    reason: str
    predicate: Dict[str, Any]
    created_by: str
    rule_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    stage: str = "*"
    expires_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("suppression entries are tenant-owned; tenant_id required")
        P.validate(self.predicate)


class SuppressionPolicy:
    def __init__(self, entries: Tuple[SuppressionEntry, ...] = ()) -> None:
        self._by_tenant: Dict[str, List[SuppressionEntry]] = {}
        for e in entries:
            self.add(e)

    def add(self, e: SuppressionEntry) -> None:
        self._by_tenant.setdefault(e.tenant_id, []).append(e)

    def entries(self, tenant_id: str) -> List[SuppressionEntry]:
        return list(self._by_tenant.get(tenant_id, []))


def _stage_hits(stages: List[StageMatch], stage: str, pred: Dict[str, Any]) -> Tuple[bool, bool]:
    hit, unknown = False, False
    for m in stages:
        if stage not in ("*", m.stage_id):
            continue
        for rec in m.evidence:
            v = P.evaluate(rec, pred)
            hit |= v == TRUE
            unknown |= v == UNKNOWN
    return hit, unknown


def decide(rule: SequenceRule, stages: List[StageMatch], *, tenant_id: str, endpoint_id: str,
           policy: Optional[SuppressionPolicy], now: datetime) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Returns (suppression record or None, notes). UNKNOWN never suppresses."""
    notes: List[str] = []
    for i, ex in enumerate(rule.exclusions):
        hit, unk = _stage_hits(stages, ex["stage"], ex["predicate"])
        if hit:
            return {"kind": "RULE_EXCLUSION", "index": i, "reason": ex["reason"]}, notes
        if unk:
            notes.append(f"rule exclusion {i} not evaluable (field absent); not applied")
    for e in (policy.entries(tenant_id) if policy else []):
        if e.tenant_id != tenant_id:
            continue
        if e.expires_at and e.expires_at <= now:
            continue
        if e.rule_id and e.rule_id != rule.rule_id:
            continue
        if e.endpoint_id and e.endpoint_id != endpoint_id:
            continue
        hit, unk = _stage_hits(stages, e.stage, e.predicate)
        if hit:
            return {"kind": "TENANT_SUPPRESSION", "entry_id": e.entry_id, "reason": e.reason,
                    "created_by": e.created_by}, notes
        if unk:
            notes.append(f"suppression {e.entry_id} not evaluable (field absent); not applied")
    return None, notes


def adjustments(rule: SequenceRule, stages: List[StageMatch]) -> List[Tuple[int, str]]:
    out = []
    for a in rule.confidence_adjustments:
        hit, _ = _stage_hits(stages, a["stage"], a["predicate"])
        if hit:
            out.append((int(a["delta"]), a["reason"]))
    return out
