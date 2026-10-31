"""Retrospective replay: same engine path, checkpointed, idempotent."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple

from .contracts import MODE_RETRO
from .engine import SequenceEngine
from .normalize import parse_time

REASONS = ("RULE_ADDED", "RULE_CHANGED", "INTEL_CHANGED", "MODEL_CHANGED", "MANUAL")


@dataclass(frozen=True)
class ReplayRequest:
    replay_id: str
    tenant_id: str
    endpoint_ids: Tuple[str, ...]
    start: datetime
    end: datetime
    reason: str
    rule_keys: Tuple[Tuple[str, int], ...] = ()
    page_size: int = 500
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.replay_id or not self.endpoint_ids:
            raise ValueError("replay needs replay_id, tenant_id and endpoint_ids")
        if self.reason not in REASONS:
            raise ValueError(f"reason must be one of {REASONS}")
        if not (1 <= self.page_size <= 5000) or self.end < self.start:
            raise ValueError("bad page_size or time range")


class CheckpointStore(Protocol):
    async def load(self, tenant_id: str, replay_id: str, endpoint_id: str) -> Optional[Dict[str, Any]]: ...

    async def save(self, tenant_id: str, replay_id: str, endpoint_id: str, cp: Dict[str, Any]) -> None: ...


class InMemoryCheckpointStore:
    def __init__(self) -> None:
        self._d: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    async def load(self, tenant_id, replay_id, endpoint_id):
        return self._d.get((tenant_id, replay_id, endpoint_id))

    async def save(self, tenant_id, replay_id, endpoint_id, cp):
        self._d[(tenant_id, replay_id, endpoint_id)] = dict(cp)


async def run_replay(engine: SequenceEngine, req: ReplayRequest, checkpoints: CheckpointStore,
                     max_pages: Optional[int] = None) -> Dict[str, Any]:
    rules = ([engine.registry.get(r, v) for r, v in req.rule_keys] if req.rule_keys
             else engine.registry.live_rules())
    rules = [r for r in rules if r.lifecycle != "DRAFT"]
    trigger = {"replay_id": req.replay_id, "reason": req.reason, **req.detail}
    engine.metrics.inc("replay_runs")
    summary: Dict[str, Any] = {"replay_id": req.replay_id, "events": 0, "pages": 0, "complete": True,
                               "rules": [f"{r.rule_id}@v{r.version}" for r in rules]}
    pages = 0
    for ep in sorted(req.endpoint_ids):
        cp = await checkpoints.load(req.tenant_id, req.replay_id, ep)
        if cp and cp.get("done"):
            continue
        after = (parse_time(cp["after_time"]), cp["after_key"]) if cp else None
        while True:
            if max_pages is not None and pages >= max_pages:
                summary["complete"] = False
                return summary
            page = await engine.provider.page(tenant_id=req.tenant_id, endpoint_id=ep, start=req.start,
                                              end=req.end, after=after, limit=req.page_size)
            pages += 1
            summary["pages"] = pages
            for rec in page:
                await engine.process(rec, mode=MODE_RETRO, trigger=trigger, rules=rules)
                engine.metrics.inc("replay_events")
                summary["events"] += 1
            if not page:
                await checkpoints.save(req.tenant_id, req.replay_id, ep, {"done": True})
                break
            last = page[-1]
            after = last.sort_key()
            await checkpoints.save(req.tenant_id, req.replay_id, ep,
                                   {"after_time": last.event_time.isoformat(),
                                    "after_key": last.stable_key, "done": False})
    return summary
