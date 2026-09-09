"""
NivXRay XDR — Atomic IOC / Indicator Rule Translator.
Translates atomic indicators (IPs, domains, hashes, URLs) into CanonicalIR.
Supports defanging, CIDR notation, and confidence scoring.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from .base import BaseTranslator, TranslationResult
from ..canonical_ir.models import CanonicalIR, ProvenanceInfo, TranslationFidelity
from ..canonical_ir.nodes import FieldCompareNode, Operator, BooleanLogicNode, BooleanOp


def _defang(val: str) -> str:
    """Standardizes defanged indicators: hxxp -> http, [.] -> ., etc."""
    s = val.replace("[.]", ".").replace("(.)", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")
    return s.strip()


class IOCTranslator(BaseTranslator):

    @property
    def source_format(self) -> str:
        return "ioc"

    def translate(self, source_text: str, metadata: Optional[Dict[str, Any]] = None) -> TranslationResult:
        meta = metadata or {}
        # Parse JSON or key-value format
        data: Dict[str, Any] = {}
        try:
            if source_text.strip().startswith("{"):
                data = json.loads(source_text)
            else:
                for line in source_text.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        data[k.strip().lower()] = v.strip()
        except Exception as e:
            return TranslationResult(
                success=False,
                fidelity=TranslationFidelity.UNSUPPORTED,
                errors=[f"Failed to parse IOC content: {str(e)}"],
                raw_source=source_text,
            )

        ioc_type = data.get("type", meta.get("ioc_type", "ip")).lower()
        raw_val = data.get("value", data.get("indicator", meta.get("value", "")))
        ioc_value = _defang(str(raw_val))
        threat_actor = data.get("threat_actor", meta.get("threat_actor", "UnknownActor"))

        # Map to Canonical Evidence field
        if ioc_type in ("ip", "ipv4", "src_ip", "dst_ip"):
            field_name = "network.dst.ip"
            op = Operator.EQUALS
            req_fields = ["network.dst.ip"]
        elif ioc_type in ("domain", "fqdn", "dns"):
            field_name = "dns.query.name"
            op = Operator.EQUALS
            req_fields = ["dns.query.name"]
        elif ioc_type in ("hash", "sha256"):
            field_name = "process.hash.sha256"
            op = Operator.EQUALS
            req_fields = ["process.hash.sha256"]
        elif ioc_type in ("url", "uri"):
            field_name = "url.full"
            op = Operator.CONTAINS
            req_fields = ["url.full"]
        else:
            field_name = "observable.value"
            op = Operator.EQUALS
            req_fields = ["observable.value"]

        root_node = FieldCompareNode(
            field_name=field_name,
            operator=op,
            value=ioc_value,
            case_sensitive=False,
        )

        content_id = meta.get("content_id", f"IOC-{ioc_type.upper()}-{abs(hash(ioc_value)) % 1000000:06d}")
        prov = ProvenanceInfo(
            source=meta.get("source", "CISA_KEV"),
            source_id=meta.get("source_id", content_id),
            source_url=meta.get("source_url", "https://cisa.gov/known-exploited-vulnerabilities-catalog"),
            license=meta.get("license", "CC0"),
            attribution=meta.get("attribution", "Threat Intelligence Community"),
            organization=meta.get("organization", "Defensive TIP"),
        )

        ir = CanonicalIR(
            content_id=content_id,
            name=meta.get("name", f"Known Malicious {ioc_type.upper()}: {ioc_value}"),
            description=meta.get("description", f"Atomic indicator matching against verified {threat_actor} infrastructure"),
            tactic="Command and Control",
            technique_id="T1071.001",
            platform="network",
            severity=meta.get("severity", "HIGH"),
            confidence=str(meta.get("confidence", "0.95")),
            lane="ioc",
            required_fields=req_fields,
            root_node=root_node,
            fidelity=TranslationFidelity.EXACT,
            provenance=prov,
            tags=["ioc", ioc_type, threat_actor.lower()],
            is_correlation=False,
        )

        return TranslationResult(
            success=True,
            ir=ir,
            fidelity=TranslationFidelity.EXACT,
            raw_source=source_text,
        )
