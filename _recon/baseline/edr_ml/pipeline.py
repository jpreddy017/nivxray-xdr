"""MLPipeline: extract -> score -> decide -> (then) update baselines. Signals only, never verdicts."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from edr_behavior.contracts import EvidenceRecord, EvidenceRef, MLSignal
from edr_behavior.normalize import parse_time
from edr_behavior.provider import EvidenceProvider

from .baseline import BaselineStore
from .features import FeatureExtractor, MLInputError
from .metrics import MLMetrics
from .models import OUT_COLD, SCHEMA_MISMATCH, SCORED, ModelRegistry, score
from .schema import COLD, UNKNOWN, FeatureSchema
from .signals import (BELOW_THRESHOLD, EMITTED, MODEL_ERROR, InMemorySignalStore, build_signal,
                      signal_id, to_evidence)


class MLPipeline:
    def __init__(self, schema: FeatureSchema, models: ModelRegistry, provider: EvidenceProvider,
                 baselines: BaselineStore, store: InMemorySignalStore, *,
                 metrics: Optional[MLMetrics] = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 update_baselines: bool = True, **extractor_kw) -> None:
        self.schema, self.models, self.baselines, self.store = schema, models, baselines, store
        self.metrics = metrics or MLMetrics()
        self.clock, self.update_baselines = clock, update_baselines
        self.extractor = FeatureExtractor(schema, provider, baselines, clock=clock, **extractor_kw)

    async def process(self, rec: EvidenceRecord) -> List[Dict[str, Any]]:
        t0 = time.perf_counter()
        try:
            return await self._process(rec)
        finally:
            self.metrics.latency((time.perf_counter() - t0) * 1000.0)
            self.metrics.baseline_state_size = self.baselines.state_size()

    async def _process(self, rec: EvidenceRecord) -> List[Dict[str, Any]]:
        if not rec.tenant_id or not rec.endpoint_id or rec.ref.tenant_id != rec.tenant_id:
            self.metrics.inc("events_rejected")
            return []
        self.metrics.inc("events_processed")
        models = self.models.live()
        sids = {(m.model_id, m.model_version): signal_id(rec.tenant_id, rec.endpoint_id, m, rec.stable_key)
                for m in models}
        existing = {k: self.store.get(rec.tenant_id, s) for k, s in sids.items()}
        if models and all(existing.values()):
            self.metrics.inc("duplicates")
            return [existing[k] for k in sorted(existing)]
        try:
            vector = await self.extractor.extract(rec)
        except MLInputError:
            self.metrics.inc("events_rejected")
            return []
        self.metrics.inc("features_extracted", len(vector.values))
        self.metrics.inc("features_unknown", sum(v.state == UNKNOWN for v in vector.values))
        self.metrics.inc("features_cold", sum(v.state == COLD for v in vector.values))
        out = []
        for m in models:
            key = (m.model_id, m.model_version)
            if existing[key]:
                out.append(existing[key])
                continue
            doc = {"signal_id": sids[key], "tenant_id": rec.tenant_id, "endpoint_id": rec.endpoint_id,
                   "model_id": m.model_id, "model_version": m.model_version,
                   "model_lifecycle": m.lifecycle, "anchor_key": rec.stable_key,
                   "score": None, "confidence": 0, "reasons": [], "signal": None}
            try:
                res = score(m, vector)
            except (ValueError, KeyError, TypeError, ArithmeticError):
                self.metrics.inc("model_errors")
                doc["outcome"] = MODEL_ERROR
            else:
                doc.update(score=res.score, confidence=res.confidence, reasons=list(res.reasons))
                if res.outcome == SCORED and res.score >= m.threshold:
                    _, env = build_signal(m, vector, res)
                    doc.update(outcome=EMITTED, signal=env)
                    self.metrics.inc("signals_emitted")
                elif res.outcome == SCORED:
                    doc["outcome"] = BELOW_THRESHOLD
                    self.metrics.inc("signals_suppressed")
                else:
                    doc["outcome"] = res.outcome
                    self.metrics.inc({OUT_COLD: "cold_start", SCHEMA_MISMATCH: "schema_mismatch"}
                                     .get(res.outcome, "unknown_outcomes"))
            self.metrics.model_outcome(m.model_id, m.model_version, doc["outcome"])
            self.store.put_if_absent(doc)
            out.append(self.store.get(rec.tenant_id, doc["signal_id"]))
        if self.update_baselines:
            for outcome in self.baselines.observe(rec, self.clock()).values():
                self.metrics.baseline(outcome)
        return out


def evidence_from_decision(decision: Dict[str, Any]) -> EvidenceRecord:
    """Rebuild the MLSignal from an EMITTED decision and convert it via the edr_behavior boundary."""
    env = decision["signal"]
    if decision.get("outcome") != EMITTED or not env:
        raise ValueError("only EMITTED decisions carry a signal")
    inference_time = parse_time(env["inference_time"])
    if inference_time is None:
        raise ValueError("signal inference_time malformed")
    refs = tuple(EvidenceRef(tenant_id=r["tenant_id"], raw_id=r["raw_id"],
                             canonical_event_id=r["canonical_event_id"], generation=r["generation"],
                             store=r["store"], record_id=r["record_id"], sub_key=r["sub_key"])
                 for r in env["evidence_refs"])
    sig = MLSignal(model_id=env["model_id"], model_version=env["model_version"],
                   feature_schema_version=env["feature_schema_version"], score=env["score"],
                   confidence=env["confidence"], explanation=env["explanation"], evidence_refs=refs,
                   inference_time=inference_time)
    return to_evidence(sig, env)
