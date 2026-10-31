"""
NivXRay XDR — Multi-Event Correlation Rule Translator.
Translates cross-stage sequence, temporal window, and multi-source correlation logic
into CanonicalIR with authoritative ICE / Correlation Engine metadata bindings.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .base import BaseTranslator, TranslationResult
from ..canonical_ir.models import CanonicalIR, ProvenanceInfo, TranslationFidelity
from ..canonical_ir.nodes import (
    BooleanLogicNode,
    BooleanOp,
    CorrelationRefNode,
    FieldCompareNode,
    Operator,
    SequenceRefNode,
    TimeWindowNode,
)


class CorrelationTranslator(BaseTranslator):

    @property
    def source_format(self) -> str:
        return "correlation"

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
        except Exception as e:
            return TranslationResult(
                success=False,
                fidelity=TranslationFidelity.UNSUPPORTED,
                errors=[f"Failed to parse correlation spec: {str(e)}"],
                raw_source=source_text,
            )

        scenario_id = spec.get("scenario_id", meta.get("scenario_id", "SCENARIO-AUTO"))
        window_seconds = int(spec.get("window_seconds", meta.get("window_seconds", 300)))
        stages = spec.get("stages", meta.get("stages", ["initial_access", "execution"]))
        operators = spec.get("operators", ["TEMPORAL_ORDERED", "SAME_ENTITY"])
        group_by = spec.get("group_by", ["host.id", "user.name"])
        if isinstance(group_by, str):
            group_by = [group_by]

        root_node = TimeWindowNode(
            window_seconds=window_seconds,
            child=SequenceRefNode(
                step_ids=stages,
                max_span_seconds=window_seconds,
                group_by_fields=group_by,
            ),
        )

        content_id = meta.get("content_id", f"CORR-{scenario_id}")
        prov = ProvenanceInfo(
            source=meta.get("source", "NIVXRAY_NATIVE"),
            source_id=meta.get("source_id", content_id),
            source_url=meta.get("source_url", "https://github.com/nivxray/security-content"),
            license=meta.get("license", "Apache-2.0"),
            attribution=meta.get("attribution", "NivXRay Threat Intelligence"),
            organization=meta.get("organization", "NivXRay Analytics"),
        )

        ir = CanonicalIR(
            content_id=content_id,
            name=meta.get("name", spec.get("name", f"Multi-Stage Correlation: {scenario_id}")),
            description=meta.get("description", spec.get("description", "Correlates multi-event attack sequence within bounded sliding window")),
            tactic=meta.get("tactic", "Lateral Movement"),
            technique_id=meta.get("technique_id", "T1021"),
            platform="enterprise",
            severity=meta.get("severity", "CRITICAL"),
            confidence=str(meta.get("confidence", "0.95")),
            lane="correlation",
            required_fields=list(set(group_by + ["timestamp", "event.action"])),
            root_node=root_node,
            fidelity=TranslationFidelity.EXACT,
            provenance=prov,
            tags=["correlation", "multi_stage", "ice"],
            is_correlation=True,
        )

        return TranslationResult(
            success=True,
            ir=ir,
            fidelity=TranslationFidelity.EXACT,
            raw_source=source_text,
        )
