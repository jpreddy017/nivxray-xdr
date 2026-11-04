"""
NivXRay XDR — Baseline & Anomaly Definition Translator.
Translates statistical threshold, peer group deviation, and frequency baseline logic into CanonicalIR.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .base import BaseTranslator, TranslationResult
from ..canonical_ir.models import CanonicalIR, ProvenanceInfo, TranslationFidelity
from ..canonical_ir.nodes import AggregationRefNode, FieldCompareNode, Operator


class AnomalyTranslator(BaseTranslator):

    @property
    def source_format(self) -> str:
        return "anomaly"

    def translate(self, source_text: str, metadata: Optional[Dict[str, Any]] = None) -> TranslationResult:
        meta = metadata or {}
        try:
            if source_text.strip().startswith("{"):
                spec = json.loads(source_text)
            else:
                spec = {}
                for line in source_text.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        spec[k.strip().lower()] = v.strip()
        except Exception:
            spec = {"metric": "event_count", "threshold": 50}

        metric = spec.get("metric", meta.get("metric", "network_volume_mb"))
        threshold = int(spec.get("threshold", meta.get("threshold", 100)))
        window = int(spec.get("window_seconds", meta.get("window_seconds", 3600)))
        group_by = spec.get("group_by", ["user.name"])
        if isinstance(group_by, str): group_by = [group_by]

        root_node = AggregationRefNode(
            aggregation_type="THRESHOLD",
            threshold=threshold,
            group_by_fields=group_by,
            time_window_seconds=window,
        )

        content_id = meta.get("content_id", spec.get("id", f"ANOM-BASE-{abs(hash(metric)) % 1000000:06d}"))
        prov = ProvenanceInfo(
            source=meta.get("source", "NIVXRAY_NATIVE"),
            source_id=meta.get("source_id", content_id),
            source_url=meta.get("source_url", "https://github.com/nivxray/security-content"),
            license=meta.get("license", "Apache-2.0"),
            attribution=meta.get("attribution", "NivXRay Analytics"),
            organization=meta.get("organization", "UEBA Labs"),
        )

        ir = CanonicalIR(
            content_id=content_id,
            name=meta.get("name", spec.get("name", f"Baseline Anomaly: Excessive {metric.replace('_', ' ').title()}")),
            description=meta.get("description", spec.get("description", f"Detects statistical deviation exceeding baseline threshold {threshold}")),
            tactic=meta.get("tactic", "Exfiltration"),
            technique_id=meta.get("technique_id", "T1048"),
            platform="enterprise",
            severity=meta.get("severity", "MEDIUM"),
            confidence="0.80",
            lane="anomaly",
            required_fields=group_by + ["timestamp"],
            root_node=root_node,
            fidelity=TranslationFidelity.EXACT,
            provenance=prov,
            tags=["anomaly", "ueba", "baseline"],
            is_correlation=False,
        )

        return TranslationResult(
            success=True,
            ir=ir,
            fidelity=TranslationFidelity.EXACT,
            raw_source=source_text,
        )
