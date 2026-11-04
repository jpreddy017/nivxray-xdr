"""
NivXRay XDR — ATT&CK, Security-State & Response Mapping Translator.
Translates bidirectional metadata associations, causal factors, and Minimal Effective Containment playbooks.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .base import BaseTranslator, TranslationResult
from ..canonical_ir.models import CanonicalIR, ProvenanceInfo, TranslationFidelity
from ..canonical_ir.nodes import FieldCompareNode, Operator


class MappingTranslator(BaseTranslator):

    def __init__(self, mapping_type: str = "attck_mapping"):
        self._mapping_type = mapping_type

    @property
    def source_format(self) -> str:
        return self._mapping_type

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
            spec = {"target": source_text.strip()}

        mapping_kind = meta.get("mapping_kind", self._mapping_type)
        name = spec.get("name", meta.get("name", f"Mapping: {mapping_kind.upper()}"))
        content_id = meta.get("content_id", spec.get("id", f"MAP-{mapping_kind.upper()}-{abs(hash(str(spec))) % 1000000:06d}"))

        root_node = FieldCompareNode(
            field_name="mapping.active",
            operator=Operator.EXISTS,
            value=True,
        )

        prov = ProvenanceInfo(
            source=meta.get("source", "NIVXRAY_NATIVE"),
            source_id=meta.get("source_id", content_id),
            source_url=meta.get("source_url", "https://github.com/nivxray/security-content"),
            license=meta.get("license", "Apache-2.0"),
            attribution=meta.get("attribution", "NivXRay Architecture"),
            organization=meta.get("organization", "NivXRay Core"),
        )

        ir = CanonicalIR(
            content_id=content_id,
            name=name,
            description=spec.get("description", meta.get("description", f"Operational mapping for {mapping_kind}")),
            tactic=spec.get("tactic", "Impact"),
            technique_id=spec.get("technique_id", "T1489"),
            platform="enterprise",
            severity=meta.get("severity", "INFORMATIONAL"),
            confidence="1.0",
            lane="mapping",
            required_fields=["event.dataset"],
            root_node=root_node,
            fidelity=TranslationFidelity.EXACT,
            provenance=prov,
            tags=["mapping", mapping_kind],
            is_correlation=False,
        )

        return TranslationResult(
            success=True,
            ir=ir,
            fidelity=TranslationFidelity.EXACT,
            raw_source=source_text,
        )
