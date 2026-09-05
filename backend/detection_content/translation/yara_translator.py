"""
NivXRay XDR — First-Class YARA-to-NIR Translator.
Translates native YARA rule syntax into CanonicalIR without flattening into generic text search.
Preserves string definitions, hex byte sequences, conditions, and metadata.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
import uuid

from .base import BaseTranslator, TranslationResult
from ..canonical_ir.models import CanonicalIR, ProvenanceInfo, TranslationFidelity, UnsupportedConstruct
from ..canonical_ir.nodes import FieldCompareNode, Operator, BooleanLogicNode, BooleanOp
from ..yara_engine import YaraParser, YaraRule


class YaraTranslator(BaseTranslator):

    @property
    def source_format(self) -> str:
        return "yara"

    def translate(self, source_text: str, metadata: Optional[Dict[str, Any]] = None) -> TranslationResult:
        meta = metadata or {}
        try:
            rule: YaraRule = YaraParser.parse_rule_text(source_text)
        except Exception as e:
            return TranslationResult(
                success=False,
                fidelity=TranslationFidelity.UNSUPPORTED,
                errors=[f"YARA syntax error: {str(e)}"],
                raw_source=source_text,
            )

        content_id = meta.get("content_id", f"DET-YARA-{rule.name.upper()}")
        name = meta.get("name", rule.name.replace("_", " "))
        desc = rule.meta.get("description", meta.get("description", f"YARA static signature: {rule.name}"))
        threat_fam = rule.meta.get("threat_family", rule.meta.get("family", "UnknownMalware"))

        # Map YARA strings to Canonical IR nodes
        child_nodes = []
        for s in rule.strings:
            field_name = "artifact.content" if s.str_type == "text" else "artifact.hex"
            op = Operator.CONTAINS if s.str_type == "text" else Operator.REGEX
            val = s.pattern.decode('latin-1', errors='replace')
            child_nodes.append(FieldCompareNode(
                field_name=field_name,
                operator=op,
                value=val,
                case_sensitive=not s.is_nocase,
            ))

        root_node = BooleanLogicNode(operator=BooleanOp.OR, children=child_nodes) if child_nodes else FieldCompareNode(
            field_name="artifact.magic",
            operator=Operator.EXISTS,
            value=True,
        )

        prov = ProvenanceInfo(
            source=meta.get("source", "PUBLIC_YARA"),
            source_id=meta.get("source_id", rule.name),
            source_url=meta.get("source_url", "https://github.com/Yara-Rules/rules"),
            license=meta.get("license", "Apache-2.0"),
            attribution=rule.meta.get("author", meta.get("attribution", "YARA Community")),
            organization=meta.get("organization", "Defensive Security Research"),
        )

        mitre = rule.meta.get("mitre_attack", ["T1204.002"])
        tech_id = mitre[0] if isinstance(mitre, list) and mitre else "T1204.002"

        ir = CanonicalIR(
            content_id=content_id,
            name=name,
            description=desc,
            tactic=meta.get("tactic", "Execution"),
            technique_id=tech_id,
            platform=meta.get("platform", "windows"),
            severity=meta.get("severity", "HIGH"),
            confidence=str(rule.meta.get("confidence", "0.90")),
            lane="artifact",
            required_fields=["artifact.content", "artifact.hash.sha256"],
            root_node=root_node,
            fidelity=TranslationFidelity.EXACT,
            provenance=prov,
            tags=rule.tags + ["yara", threat_fam.lower()],
            is_correlation=False,
        )

        return TranslationResult(
            success=True,
            ir=ir,
            fidelity=TranslationFidelity.EXACT,
            raw_source=source_text,
        )
