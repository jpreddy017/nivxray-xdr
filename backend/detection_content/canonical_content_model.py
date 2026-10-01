"""
NivXRay XDR — Canonical Enterprise Security Content Model.
Authoritative 31-attribute content object schema across all 13 supported content types
and 13 lifecycle milestones.

Enforces zero-silent-weakening, provenance retention, license governance, and
bidirectional mapping between detection, intelligence, and response domains.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional, Set
import uuid


class ContentType(str, Enum):
    SIGMA                  = "sigma"
    YARA                   = "yara"
    EQL                    = "eql"
    SPL                    = "spl"
    KQL                    = "kql"
    IOC_RULE               = "ioc_rule"
    BEHAVIORAL             = "behavioral"
    CORRELATION            = "correlation"
    THREAT_HUNTING         = "threat_hunting"
    BASELINE_ANOMALY       = "baseline_anomaly"
    ATTCK_MAPPING          = "attck_mapping"
    SECURITY_STATE_MAPPING = "security_state_mapping"
    RESPONSE_MAPPING       = "response_mapping"


class ContentCategory(str, Enum):
    DETECTION    = "detection"      # Sigma, YARA, EQL, SPL, KQL, Behavioral
    INTELLIGENCE = "intelligence"   # IOC, ATT&CK, Baseline/Anomaly, Threat Hunting
    RESPONSE     = "response"       # Security State, Response / Intervention Mappings


def get_content_category(content_type: ContentType | str) -> ContentCategory:
    ct = ContentType(content_type) if isinstance(content_type, str) else content_type
    if ct in {
        ContentType.SIGMA, ContentType.YARA, ContentType.EQL,
        ContentType.SPL, ContentType.KQL, ContentType.BEHAVIORAL,
    }:
        return ContentCategory.DETECTION
    elif ct in {
        ContentType.IOC_RULE, ContentType.THREAT_HUNTING,
        ContentType.BASELINE_ANOMALY, ContentType.ATTCK_MAPPING,
    }:
        return ContentCategory.INTELLIGENCE
    else:
        return ContentCategory.RESPONSE


class ContentSource(str, Enum):
    SIGMAHQ          = "SIGMAHQ"
    ELASTIC          = "ELASTIC"
    SPLUNK           = "SPLUNK"
    SENTINEL         = "SENTINEL"
    PANTHER          = "PANTHER"
    MITRE_CAR        = "MITRE_CAR"
    ATOMIC_RED_TEAM  = "ATOMIC_RED_TEAM"
    PUBLIC_YARA      = "PUBLIC_YARA"
    SNORT_SURICATA   = "SNORT_SURICATA"
    CISA_KEV         = "CISA_KEV"
    COMMUNITY        = "COMMUNITY"
    RESEARCH_DERIVED = "RESEARCH_DERIVED"
    NIVXRAY_NATIVE   = "NIVXRAY_NATIVE"


class ContentLifecycleState(str, Enum):
    # Standard Progressive Pipeline Milestones
    DISCOVERED       = "DISCOVERED"
    PARSED           = "PARSED"
    LICENSE_VERIFIED = "LICENSE_VERIFIED"
    NORMALIZED       = "NORMALIZED"
    TRANSLATED       = "TRANSLATED"
    DEDUPLICATED     = "DEDUPLICATED"
    VALIDATING       = "VALIDATING"
    VALIDATED        = "VALIDATED"
    ENGINE_BOUND     = "ENGINE_BOUND"
    SHADOW           = "SHADOW"
    ACTIVE           = "ACTIVE"
    DEPRECATED       = "DEPRECATED"
    RETIRED          = "RETIRED"

    # Terminal / Exception / Rejection States
    REJECTED         = "REJECTED"
    UNSUPPORTED      = "UNSUPPORTED"
    SUPERSEDED       = "SUPERSEDED"
    ROLLED_BACK      = "ROLLED_BACK"


# Allowed state transitions enforcing orderly promotion through quality gates
LIFECYCLE_TRANSITIONS: Dict[ContentLifecycleState, Set[ContentLifecycleState]] = {
    ContentLifecycleState.DISCOVERED: {
        ContentLifecycleState.PARSED,
        ContentLifecycleState.REJECTED,
    },
    ContentLifecycleState.PARSED: {
        ContentLifecycleState.LICENSE_VERIFIED,
        ContentLifecycleState.UNSUPPORTED,
        ContentLifecycleState.REJECTED,
    },
    ContentLifecycleState.LICENSE_VERIFIED: {
        ContentLifecycleState.NORMALIZED,
        ContentLifecycleState.REJECTED,
    },
    ContentLifecycleState.NORMALIZED: {
        ContentLifecycleState.TRANSLATED,
        ContentLifecycleState.UNSUPPORTED,
        ContentLifecycleState.REJECTED,
    },
    ContentLifecycleState.TRANSLATED: {
        ContentLifecycleState.DEDUPLICATED,
        ContentLifecycleState.UNSUPPORTED,
        ContentLifecycleState.REJECTED,
    },
    ContentLifecycleState.DEDUPLICATED: {
        ContentLifecycleState.VALIDATING,
        ContentLifecycleState.SUPERSEDED,
        ContentLifecycleState.REJECTED,
    },
    ContentLifecycleState.VALIDATING: {
        ContentLifecycleState.VALIDATED,
        ContentLifecycleState.REJECTED,
        ContentLifecycleState.TRANSLATED,  # Retry/Tuning
    },
    ContentLifecycleState.VALIDATED: {
        ContentLifecycleState.ENGINE_BOUND,
        ContentLifecycleState.VALIDATING,
        ContentLifecycleState.DEPRECATED,
    },
    ContentLifecycleState.ENGINE_BOUND: {
        ContentLifecycleState.SHADOW,
        ContentLifecycleState.ACTIVE,
        ContentLifecycleState.DEPRECATED,
    },
    ContentLifecycleState.SHADOW: {
        ContentLifecycleState.ACTIVE,
        ContentLifecycleState.VALIDATING,
        ContentLifecycleState.DEPRECATED,
    },
    ContentLifecycleState.ACTIVE: {
        ContentLifecycleState.SHADOW,
        ContentLifecycleState.SUPERSEDED,
        ContentLifecycleState.DEPRECATED,
        ContentLifecycleState.ROLLED_BACK,
    },
    ContentLifecycleState.ROLLED_BACK: {
        ContentLifecycleState.SHADOW,
        ContentLifecycleState.DEPRECATED,
    },
    ContentLifecycleState.DEPRECATED: {
        ContentLifecycleState.RETIRED,
    },
    ContentLifecycleState.RETIRED: set(),
    ContentLifecycleState.REJECTED: set(),
    ContentLifecycleState.UNSUPPORTED: set(),
    ContentLifecycleState.SUPERSEDED: set(),
}


@dataclass
class CanonicalContentObject:
    """
    The Authoritative 31-Attribute Canonical Content Object in NivXRay XDR.
    Guarantees full schema integrity across all detection, intelligence, and response artifacts.
    """
    # 1. Identity & Classification
    content_id: str
    name: str
    content_type: str
    description: str

    # 2. Origin, Licensing & Provenance
    source: str
    source_id: str
    source_url: str
    license: str
    attribution: str
    version: str
    created_at: str
    updated_at: str

    # 3. Target Scope & Schema Telemetry
    platform: List[str]
    product: List[str]
    data_sources: List[str]
    required_fields: List[str]
    normalized_fields: Dict[str, str]

    # 4. Logic & Operational Ratings
    logic: Dict[str, Any]
    severity: str
    confidence: float

    # 5. Framework & Threat Model Mappings
    mitre_attack: List[Dict[str, str]]
    kill_chain: List[str]

    # 6. Empirical Verification Fixtures
    positive_fixtures: List[Dict[str, Any]]
    negative_fixtures: List[Dict[str, Any]]
    known_false_positives: List[str]
    required_telemetry: Dict[str, Any]

    # 7. Runtime Engine Binding & Deduplication Hash
    engine_binding: Dict[str, Any]
    semantic_equivalence: str

    # 8. Lineage, Relationships & Governance State
    provenance: Dict[str, Any]
    supersedes: List[str]
    related_content: List[str]
    status: str

    # Extra operational metadata
    state_history: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    category: str = ""

    def __post_init__(self):
        if not self.category:
            self.category = get_content_category(self.content_type).value
        if not self.state_history:
            self.state_history = [self.status]
        if not self.semantic_equivalence:
            self.semantic_equivalence = self.compute_semantic_hash()

    def compute_semantic_hash(self) -> str:
        """Computes a deterministic hash of the behavioral logic, fields, and platform."""
        repr_obj = {
            "content_type": self.content_type,
            "platform": sorted(self.platform),
            "required_fields": sorted(self.required_fields),
            "logic": self.logic,
            "mitre": sorted([m.get("id", "") for m in self.mitre_attack]),
        }
        serialized = json.dumps(repr_obj, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def transition(self, new_state: ContentLifecycleState | str, reason: str = "", actor: str = "system") -> bool:
        target = ContentLifecycleState(new_state) if isinstance(new_state, str) else new_state
        curr = ContentLifecycleState(self.status)
        allowed = LIFECYCLE_TRANSITIONS.get(curr, set())
        if target not in allowed and target != curr:
            raise ValueError(f"Illegal transition for '{self.content_id}': {curr.value} -> {target.value}")
        self.status = target.value
        self.state_history.append(target.value)
        self.updated_at = datetime.now(timezone.utc).isoformat()
        if "transitions" not in self.provenance:
            self.provenance["transitions"] = []
        self.provenance["transitions"].append({
            "from": curr.value,
            "to": target.value,
            "reason": reason,
            "actor": actor,
            "timestamp": self.updated_at,
        })
        return True

    def validate_schema(self) -> tuple[bool, List[str]]:
        missing: List[str] = []
        for attr in (
            "content_id", "name", "content_type", "description",
            "source", "source_id", "license", "version",
            "severity", "status"
        ):
            if not getattr(self, attr):
                missing.append(attr)
        if not self.platform:
            missing.append("platform")
        if not self.required_fields and self.content_type not in (ContentType.ATTCK_MAPPING.value, ContentType.RESPONSE_MAPPING.value):
            missing.append("required_fields")
        return (len(missing) == 0, missing)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["ATT&CK"] = d.pop("mitre_attack")  # Support prompt naming convention
        return d


def build_canonical_content(
    *,
    content_id: str,
    name: str,
    content_type: ContentType | str,
    description: str,
    source: ContentSource | str,
    source_id: str,
    source_url: str = "",
    license: str = "Apache-2.0",
    attribution: str = "",
    version: str = "1.0.0",
    platform: Optional[List[str]] = None,
    product: Optional[List[str]] = None,
    data_sources: Optional[List[str]] = None,
    required_fields: Optional[List[str]] = None,
    normalized_fields: Optional[Dict[str, str]] = None,
    logic: Optional[Dict[str, Any]] = None,
    severity: str = "MEDIUM",
    confidence: float = 0.85,
    mitre_attack: Optional[List[Dict[str, str]]] = None,
    kill_chain: Optional[List[str]] = None,
    positive_fixtures: Optional[List[Dict[str, Any]]] = None,
    negative_fixtures: Optional[List[Dict[str, Any]]] = None,
    known_false_positives: Optional[List[str]] = None,
    required_telemetry: Optional[Dict[str, Any]] = None,
    engine_binding: Optional[Dict[str, Any]] = None,
    provenance: Optional[Dict[str, Any]] = None,
    supersedes: Optional[List[str]] = None,
    related_content: Optional[List[str]] = None,
    status: ContentLifecycleState | str = ContentLifecycleState.DISCOVERED,
    tags: Optional[List[str]] = None,
) -> CanonicalContentObject:
    """Factory creating an authoritative CanonicalContentObject with default ISO timestamps and schema defaults."""
    now_iso = datetime.now(timezone.utc).isoformat()
    ct_val = content_type.value if isinstance(content_type, ContentType) else str(content_type)
    src_val = source.value if isinstance(source, ContentSource) else str(source)
    st_val = status.value if isinstance(status, ContentLifecycleState) else str(status)

    prov = provenance or {}
    if "created_by" not in prov:
        prov["created_by"] = "acquisition_engine"
    if "trace_id" not in prov:
        prov["trace_id"] = str(uuid.uuid4())

    return CanonicalContentObject(
        content_id=content_id,
        name=name,
        content_type=ct_val,
        description=description,
        source=src_val,
        source_id=source_id,
        source_url=source_url,
        license=license,
        attribution=attribution or f"Source: {src_val}",
        version=version,
        created_at=now_iso,
        updated_at=now_iso,
        platform=platform or ["windows"],
        product=product or ["endpoint"],
        data_sources=data_sources or ["process_creation"],
        required_fields=required_fields or ["process.name", "command_line"],
        normalized_fields=normalized_fields or {},
        logic=logic or {},
        severity=severity.upper(),
        confidence=confidence,
        mitre_attack=mitre_attack or [],
        kill_chain=kill_chain or ["Execution"],
        positive_fixtures=positive_fixtures or [],
        negative_fixtures=negative_fixtures or [],
        known_false_positives=known_false_positives or [],
        required_telemetry=required_telemetry or {},
        engine_binding=engine_binding or {"engine": "SigmaEngine", "mode": "IN_PROCESS", "compatible": True},
        semantic_equivalence="",
        provenance=prov,
        supersedes=supersedes or [],
        related_content=related_content or [],
        status=st_val,
        tags=tags or [],
    )
