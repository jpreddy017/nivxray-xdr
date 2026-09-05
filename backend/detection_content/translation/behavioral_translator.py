"""
NivXRay XDR — Behavioral Detection Rule Translator.
Translates multi-dimensional process ancestry, token manipulation, and LOLBAS invocation patterns
into deterministic Canonical IR nodes.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .base import BaseTranslator, TranslationResult
from ..canonical_ir.models import CanonicalIR, ProvenanceInfo, TranslationFidelity
from ..canonical_ir.nodes import FieldCompareNode, Operator, BooleanLogicNode, BooleanOp


class BehavioralTranslator(BaseTranslator):

    @property
    def source_format(self) -> str:
        return "behavioral"

    def translate(self, source_text: str, metadata: Optional[Dict[str, Any]] = None) -> TranslationResult:
        meta = metadata or {}
        # Structured behavioral rule format
        try:
            if source_text.strip().startswith("{"):
                spec = json.loads(source_text)
            else:
                # Key-value or YAML-like parsing
                spec = {}
                for line in source_text.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        spec[k.strip().lower()] = v.strip()
        except Exception as e:
            return TranslationResult(
                success=False,
                fidelity=TranslationFidelity.UNSUPPORTED,
                errors=[f"Invalid behavioral rule format: {str(e)}"],
                raw_source=source_text,
            )

        parent_proc = spec.get("parent_process", meta.get("parent_process"))
        target_proc = spec.get("process", meta.get("process", meta.get("image")))
        cmdline_flags = spec.get("command_line", meta.get("command_line", []))
        if isinstance(cmdline_flags, str):
            cmdline_flags = [cmdline_flags]

        predicates = []
        req_fields = []

        if parent_proc:
            predicates.append(FieldCompareNode(
                field_name="process.parent.name",
                operator=Operator.ENDSWITH,
                value=parent_proc,
                case_sensitive=False,
            ))
            req_fields.append("process.parent.name")

        if target_proc:
            predicates.append(FieldCompareNode(
                field_name="process.name",
                operator=Operator.ENDSWITH,
                value=target_proc,
                case_sensitive=False,
            ))
            req_fields.append("process.name")

        for flag in cmdline_flags:
            predicates.append(FieldCompareNode(
                field_name="command_line",
                operator=Operator.CONTAINS,
                value=flag,
                case_sensitive=False,
            ))
            req_fields.append("command_line")

        root_node = BooleanLogicNode(operator=BooleanOp.AND, children=predicates) if predicates else FieldCompareNode(
            field_name="process.name",
            operator=Operator.EXISTS,
            value=True,
        )

        content_id = meta.get("content_id", spec.get("id", f"BEH-RULE-{abs(hash(str(predicates))) % 1000000:06d}"))
        prov = ProvenanceInfo(
            source=meta.get("source", "RESEARCH_DERIVED"),
            source_id=meta.get("source_id", content_id),
            source_url=meta.get("source_url", "https://github.com/nivxray/security-content"),
            license=meta.get("license", "Apache-2.0"),
            attribution=meta.get("attribution", "NivXRay Threat Research"),
            organization=meta.get("organization", "NivXRay Detection Labs"),
        )

        ir = CanonicalIR(
            content_id=content_id,
            name=meta.get("name", spec.get("name", "Behavioral Process Lineage Anomaly")),
            description=meta.get("description", spec.get("description", "Detects anomalous process parent-child execution lineage")),
            tactic=meta.get("tactic", spec.get("tactic", "Execution")),
            technique_id=meta.get("technique_id", spec.get("technique_id", "T1059")),
            platform=meta.get("platform", "windows"),
            severity=meta.get("severity", "HIGH"),
            confidence=str(meta.get("confidence", "0.90")),
            lane="behavioral",
            required_fields=list(set(req_fields or ["process.name", "command_line"])),
            root_node=root_node,
            fidelity=TranslationFidelity.EXACT,
            provenance=prov,
            tags=["behavioral", "process_lineage"],
            is_correlation=False,
        )

        return TranslationResult(
            success=True,
            ir=ir,
            fidelity=TranslationFidelity.EXACT,
            raw_source=source_text,
        )
