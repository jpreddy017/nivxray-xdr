"""Deterministic builders for E3 tests. No network, no Mongo."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from edr_behavior import content, normalize, provider, rules, store
from edr_behavior.engine import SequenceEngine

T0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
NOW = T0 + timedelta(days=1)


def run(coro):
    return asyncio.run(coro)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def win_path(name: str) -> str:
    return "C:\\Program Files\\App\\" + name


def canon_process(name: str, *, guid: Optional[str] = None, parent_guid: Optional[str] = None,
                  pid: Optional[str] = None, ppid: Optional[str] = None, cmd: Optional[str] = None,
                  path: Optional[str] = None, parent: Optional[str] = None,
                  user: Optional[str] = None, t: float = 0) -> Dict[str, Any]:
    proc = {"executable_path": path or win_path(name), "command_line": cmd, "pid": pid,
            "parent_pid": ppid, "process_guid": guid, "parent_process_guid": parent_guid,
            "parent_executable_path": win_path(parent) if parent else None}
    if guid:
        proc["process_iid"] = "proc_" + guid
    elif pid:
        proc["process_iid"] = f"proc_pid_{pid}"
    return {"activity": "PROCESS", "activity_time": at(t).isoformat(),
            "process": {k: v for k, v in proc.items() if v is not None},
            "identity": {"username": user} if user else {}}


def actor(guid: str, kind: str, t: float, **block) -> Dict[str, Any]:
    key = {"NETWORK": "network", "DNS": "dns", "FILE": "file", "REGISTRY": "registry"}[kind]
    return {"activity": kind, "activity_time": at(t).isoformat(),
            "process": {"process_guid": guid, "process_iid": "proc_" + guid},
            key: block}


def rec(canonical: Dict[str, Any], raw_id: str, *, tenant: str = "t1", endpoint: str = "ep1",
        generation: int = 0):
    return normalize.from_canonical(canonical, tenant_id=tenant, endpoint_id=endpoint, raw_id=raw_id,
                                    canonical_event_id=f"cev_{raw_id}_g{generation}",
                                    generation=generation, now=NOW)


class Harness:
    def __init__(self, registry: Optional[rules.RuleRegistry] = None, **kw) -> None:
        self.provider = provider.InMemoryEvidenceProvider()
        self.store = store.InMemoryDetectionStore()
        self.registry = registry or content.registry_from_pack()
        self.engine = SequenceEngine(self.registry, kw.pop("evidence_provider", self.provider),
                                     self.store, clock=lambda: NOW, **kw)

    def feed(self, *records):
        out = []
        for r in records:
            self.provider.add(r)
            out.append(run(self.engine.process(r)))
        return out

    def detections(self, tenant: str = "t1", rule_id: Optional[str] = None):
        return [d for d in self.store.all(tenant) if rule_id is None or d["rule_id"] == rule_id]

    def counters(self):
        return self.engine.metrics.snapshot()["counters"]


def simple_rule(**over) -> rules.SequenceRule:
    doc = {"rule_id": "T-PC", "version": 1, "lifecycle": "ACTIVE", "name": "word->ps",
           "description": "test", "severity": "HIGH", "confidence": 60, "time_window_seconds": 120,
           "entity_scope": "device",
           "stages": [{"id": "p", "type": "PROCESS",
                       "predicate": {"field": "process.name", "op": "eq", "value": "winword.exe"}},
                      {"id": "c", "type": "PROCESS",
                       "predicate": {"field": "process.name", "op": "eq", "value": "powershell.exe"}}],
           "relationships": [{"type": "parent_child", "parent": "p", "child": "c"}]}
    doc.update(over)
    return rules.parse_rule(doc)


def registry_of(*rs) -> rules.RuleRegistry:
    reg = rules.RuleRegistry()
    for r in rs:
        reg.register(r)
    return reg
