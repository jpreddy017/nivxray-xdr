"""Standalone integration adapter. NOT wired into E1 code.

Intended hook (documented, not applied): `edr_plane/canonical_bridge.py::bridge`, after the
`CANONICAL_EVIDENCE_CREATED` derivation is appended, call `BehaviorIntegration.on_canonical`
with the in-memory canonical dict and the bridge's authenticated context. The adapter never
raises into its caller, so a behavior fault cannot fail the canonical derivation or the
durable queue job.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from .contracts import STORE_UNSPECIFIED, EvidenceRecord
from .engine import SequenceEngine
from .normalize import NormalizationError, from_canonical


@dataclass(frozen=True)
class BridgeContext:
    tenant_id: str
    endpoint_id: str
    raw_id: str
    canonical_event_id: Optional[str] = None
    generation: Optional[int] = None
    store: str = STORE_UNSPECIFIED
    record_id: Optional[str] = None


class BehaviorIntegration:
    def __init__(self, engine: SequenceEngine, *, enabled: bool = False,
                 sink: Optional[Callable[[EvidenceRecord], Any]] = None) -> None:
        self.engine, self.enabled, self.sink = engine, enabled, sink

    async def on_canonical(self, canonical: Dict[str, Any], ctx: BridgeContext) -> Dict[str, Any]:
        if not self.enabled:
            return {"evaluated": False, "reason": "DISABLED"}
        try:
            rec = from_canonical(canonical, tenant_id=ctx.tenant_id, endpoint_id=ctx.endpoint_id,
                                 raw_id=ctx.raw_id, canonical_event_id=ctx.canonical_event_id,
                                 generation=ctx.generation, store=ctx.store, record_id=ctx.record_id,
                                 now=self.engine.clock())
        except NormalizationError as e:
            self.engine.metrics.inc("tenant_isolation_rejections" if e.code == "TENANT_MISMATCH"
                                    else "events_rejected_malformed")
            return {"evaluated": False, "reason": e.code}
        try:
            if self.sink is not None:
                self.sink(rec)
            results = await self.engine.process(rec)
        except Exception as e:  # noqa: BLE001 - isolation boundary towards E1
            self.engine.metrics.inc("rule_errors")
            return {"evaluated": False, "reason": "ENGINE_FAULT", "error": type(e).__name__}
        return {"evaluated": True, "evidence_key": rec.stable_key,
                "outcomes": [{"rule_id": r.rule_id, "rule_version": r.rule_version,
                              "outcome": r.outcome} for r in results]}


def canonical_doc_mapper(*, tenant_field: str, endpoint_field: str, raw_id_field: str,
                         canonical_field: Optional[str], event_id_field: Optional[str] = None,
                         generation_field: Optional[str] = None, store: str = STORE_UNSPECIFIED
                         ) -> Callable[[Dict[str, Any]], Optional[EvidenceRecord]]:
    """Mapper for MongoEvidenceProvider when the stored doc embeds the bridge canonical shape.

    Which store (and which field names) is the authority is an owner decision (doc 1); this
    mapper only assumes the documented runtime canonical dict shape.
    """
    def _get(doc: Dict[str, Any], path: Optional[str]) -> Any:
        cur: Any = doc
        for p in (path or "").split("."):
            if not p:
                continue
            cur = cur.get(p) if isinstance(cur, dict) else None
        return cur

    def mapper(doc: Dict[str, Any]) -> Optional[EvidenceRecord]:
        canonical = _get(doc, canonical_field) if canonical_field else doc
        try:
            return from_canonical(canonical, tenant_id=_get(doc, tenant_field),
                                  endpoint_id=_get(doc, endpoint_field), raw_id=_get(doc, raw_id_field),
                                  canonical_event_id=_get(doc, event_id_field),
                                  generation=_get(doc, generation_field), store=store,
                                  record_id=str(doc.get("_id")) if doc.get("_id") is not None else None)
        except NormalizationError:
            return None
    return mapper
