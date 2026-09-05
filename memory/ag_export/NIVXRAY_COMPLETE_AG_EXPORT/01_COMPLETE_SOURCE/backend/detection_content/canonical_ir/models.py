"""
NivXRay XDR — Canonical Content Intermediate Representation (NIR) Models.
Container for normalized detection logic, translation fidelity, and provenance.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from .nodes import IRNode


class TranslationFidelity(str, Enum):
    EXACT       = "EXACT"        # 100% 1:1 semantic translation without modifications
    STRONG      = "STRONG"       # Full logic represented; minor field naming / format normalization
    PARTIAL     = "PARTIAL"      # Core logic captured, but sub-filters, joins, or lookups dropped/unsupported
    APPROXIMATE = "APPROXIMATE"  # Statistical or heuristic condition approximated
    UNSUPPORTED = "UNSUPPORTED"  # Query relies on constructs that cannot be faithfully executed


@dataclass
class UnsupportedConstruct:
    construct_name: str
    raw_snippet: str
    explanation: str
    fatal: bool = True  # If fatal, prevents promotion to ACTIVE


@dataclass
class ProvenanceInfo:
    source: str
    source_id: str
    source_url: str = ""
    organization: str = ""
    license: str = ""
    license_verified: bool = False
    attribution: str = ""
    source_version: str = ""
    source_date: str = ""
    acquisition_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class CanonicalIR:
    """The authoritative Intermediate Representation container for NivXRay content."""
    content_id: str
    name: str
    description: str
    tactic: str
    technique_id: str
    platform: str
    severity: str
    confidence: str
    lane: str
    required_fields: List[str]
    root_node: IRNode
    fidelity: TranslationFidelity
    provenance: ProvenanceInfo
    unsupported_constructs: List[UnsupportedConstruct] = field(default_factory=list)
    normalized_field_map: Dict[str, str] = field(default_factory=dict)
    fixtures: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    is_correlation: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def evaluate(self, canonical_event: Dict[str, Any]) -> bool:
        """Safely evaluate NIR AST against canonical event dictionary."""
        # Never evaluate fatally unsupported content
        if self.fidelity == TranslationFidelity.UNSUPPORTED:
            return False
        try:
            return bool(self.root_node.evaluate(canonical_event))
        except Exception:
            return False

    def is_promotable(self) -> bool:
        """Rule can only be promoted if fidelity is EXACT or STRONG with zero fatal unsupported constructs."""
        if self.fidelity in (
            TranslationFidelity.UNSUPPORTED,
            TranslationFidelity.PARTIAL,
            TranslationFidelity.APPROXIMATE,
        ):
            return False
        return not any(u.fatal for u in self.unsupported_constructs)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content_id": self.content_id,
            "name": self.name,
            "description": self.description,
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "platform": self.platform,
            "severity": self.severity,
            "confidence": self.confidence,
            "lane": self.lane,
            "required_fields": self.required_fields,
            "root_node": self.root_node.to_dict(),
            "fidelity": self.fidelity.value,
            "provenance": asdict(self.provenance),
            "unsupported_constructs": [asdict(u) for u in self.unsupported_constructs],
            "normalized_field_map": self.normalized_field_map,
            "fixtures": self.fixtures,
            "tags": self.tags,
            "is_correlation": self.is_correlation,
            "is_promotable": self.is_promotable(),
            "created_at": self.created_at,
        }
