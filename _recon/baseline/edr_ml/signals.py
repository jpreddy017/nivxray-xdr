"""MLSignal production through the existing edr_behavior MLSignal contract, plus a decision store."""
from __future__ import annotations

import copy
from dataclasses import replace
from typing import Any, Dict, List, Optional, Tuple

from edr_behavior.contracts import EvidenceRecord, EvidenceRef, MLSignal, ProcessRef, sha, utc
from edr_behavior.normalize import from_ml_signal

from . import ML_CONTRACT_VERSION, ML_ENGINE_VERSION
from .models import ModelSpec, ScoreResult
from .schema import FeatureVector

MAX_SIGNAL_REFS = 32
EMITTED, BELOW_THRESHOLD, MODEL_ERROR = "EMITTED", "BELOW_THRESHOLD", "MODEL_ERROR"


def signal_id(tenant_id: str, endpoint_id: str, model: ModelSpec, anchor_key: str) -> str:
    """tenant + endpoint + model id/version/schema + anchor evidence key. No generation, clock or retry."""
    return "e3mls_" + sha("mlsig.v1", tenant_id, endpoint_id, model.model_id, model.model_version,
                          model.feature_schema_version, anchor_key)[:32]


def _refs(vector: FeatureVector, result: ScoreResult) -> Tuple[EvidenceRef, ...]:
    used = {c["feature"] for c in result.contributions}
    by_key: Dict[str, EvidenceRef] = {}
    for v in vector.values:
        if v.name in used:
            for r in v.evidence_refs:
                by_key.setdefault(r.stable_key(), r)
    anchor = vector.anchor.stable_key()
    rest = [by_key[k] for k in sorted(by_key) if k != anchor]
    return (vector.anchor,) + tuple(rest[:MAX_SIGNAL_REFS - 1])


def build_signal(model: ModelSpec, vector: FeatureVector, result: ScoreResult) -> Tuple[MLSignal, Dict[str, Any]]:
    refs = _refs(vector, result)
    explanation = {
        "policy": "signal-not-verdict", "contract": ML_CONTRACT_VERSION, "engine": ML_ENGINE_VERSION,
        "model_type": model.model_type, "model_content_hash": model.content_hash,
        "model_lifecycle": model.lifecycle, "threshold": model.threshold,
        "feature_schema_hash": vector.schema_hash, "coverage": result.coverage,
        "top_features": [copy.deepcopy(c) for c in result.contributions[:5]],
        "unknown_features": list(result.unknown), "cold_features": list(result.cold),
    }
    sig = MLSignal(model_id=model.model_id, model_version=model.model_version,
                   feature_schema_version=model.feature_schema_version, score=result.score,
                   confidence=result.confidence, explanation=explanation, evidence_refs=refs,
                   inference_time=vector.anchor_time)
    sid = signal_id(vector.tenant_id, vector.endpoint_id, model, vector.anchor.stable_key())
    env = {"signal_id": sid, "tenant_id": vector.tenant_id, "endpoint_id": vector.endpoint_id,
           "entity": vector.entity, "anchor_key": vector.anchor.stable_key(),
           "model_id": model.model_id, "model_version": model.model_version,
           "feature_schema_version": model.feature_schema_version, "score": result.score,
           "confidence": result.confidence, "explanation": explanation,
           "evidence_refs": [r.to_dict() for r in refs], "inference_time": utc(vector.anchor_time),
           "lifecycle": model.lifecycle, "status": "TESTING" if model.lifecycle == "TESTING" else "LIVE",
           "verdict": None}
    return sig, env


def to_evidence(sig: MLSignal, env: Dict[str, Any]) -> EvidenceRecord:
    """Reuse the edr_behavior boundary; attach the entity so same_process relationships can bind."""
    if any(r.tenant_id != env["tenant_id"] for r in sig.evidence_refs):
        raise ValueError("signal evidence crosses tenants")
    if env["explanation"]["model_lifecycle"] != "ACTIVE":
        raise ValueError("only ACTIVE model signals may become behavioral evidence")
    rec = from_ml_signal(sig, endpoint_id=env["endpoint_id"])
    if env.get("entity"):
        rec = replace(rec, process=ProcessRef(process_iid=env["entity"]))
    return rec


class InMemorySignalStore:
    """Decisions (emitted or not) keyed by (tenant, signal_id); first write wins (retry-safe)."""

    def __init__(self) -> None:
        self._d: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def get(self, tenant_id: str, sid: str) -> Optional[Dict[str, Any]]:
        d = self._d.get((tenant_id, sid))
        return copy.deepcopy(d) if d else None

    def put_if_absent(self, doc: Dict[str, Any]) -> bool:
        k = (doc["tenant_id"], doc["signal_id"])
        if k in self._d:
            return False
        self._d[k] = copy.deepcopy(doc)
        return True

    def all(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return [copy.deepcopy(d) for (t, _), d in sorted(self._d.items())
                if tenant_id is None or t == tenant_id]
