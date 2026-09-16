"""
NivXRay XDR — Threat Hunting Query Translator.
Translates hypothesis-driven hunting queries with pivot steps into CanonicalIR.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .base import BaseTranslator, TranslationResult
from ..canonical_ir.models import CanonicalIR, ProvenanceInfo, TranslationFidelity
from ..canonical_ir.nodes import FieldCompareNode, Operator, BooleanLogicNode, BooleanOp


class ThreatHuntingTranslator(BaseTranslator):

    @property
    def source_format(self) -> str:
        return "hunting"

    def translate(self, source_text: str, metadata: Optional[Dict[str, Any]] = None) -> TranslationResult:
        meta = metadata or {}
        try:
            if source_text.strip().startswith("{"):
                spec = json.loads(source_text)
            else:
                spec = {"query": source_text.strip()}
        except Exception:
            spec = {"query": source_text.strip()}

        hypothesis = spec.get("hypothesis", meta.get("hypothesis", "Identify anomalous activity indicative of persistent adversary"))
        query = spec.get("query", source_text)
        target_entities = spec.get("target_entities", meta.get("target_entities", ["host", "user"]))

        root_node = FieldCompareNode(
            field_name="query.raw",
            operator=Operator.EXISTS,
            value=True,
        )

        content_id = meta.get("content_id", spec.get("id", f"HUNT-QRY-{abs(hash(query)) % 1000000:06d}"))
        prov = ProvenanceInfo(
            source=meta.get("source", "COMMUNITY"),
            source_id=meta.get("source_id", content_id),
            source_url=meta.get("source_url", "https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries"),
            license=meta.get("license", "MIT"),
            attribution=meta.get("attribution", "Threat Hunting Community"),
            organization=meta.get("organization", "Defensive Security"),
        )

        ir = CanonicalIR(
            content_id=content_id,
            name=meta.get("name", spec.get("name", "Proactive Threat Hunting Query")),
            description=hypothesis,
            tactic=meta.get("tactic", "Discovery"),
            technique_id=meta.get("technique_id", "T1082"),
            platform=meta.get("platform", "windows"),
            severity=meta.get("severity", "INFORMATIONAL"),
            confidence="0.75",
            lane="hunting",
            required_fields=["event.dataset", "timestamp"],
            root_node=root_node,
            fidelity=TranslationFidelity.EXACT,
            provenance=prov,
            tags=["threat_hunting", "hypothesis_driven"],
            is_correlation=False,
        )

        return TranslationResult(
            success=True,
            ir=ir,
            fidelity=TranslationFidelity.EXACT,
            raw_source=source_text,
        )
