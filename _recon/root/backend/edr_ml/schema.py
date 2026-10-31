"""Versioned, content-hashed feature schema and evidence-backed feature values."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from edr_behavior.contracts import EVIDENCE_KINDS, EvidenceRef, sha, utc

from .safe import finite

FEATURE_TYPES = ("RATIO", "BOOL", "COUNT", "NUMBER")
BASELINE_SCOPES = ("none", "endpoint", "tenant")
KNOWN, UNKNOWN, COLD = "KNOWN", "UNKNOWN", "INSUFFICIENT_BASELINE"
STATES = (KNOWN, UNKNOWN, COLD)
SCHEMA_STATUS = ("DRAFT", "RELEASED")
MISSING_POLICIES = ("UNKNOWN",)  # missing never becomes 0 or clean
FEATURE_KEYS = {"name", "type", "unit", "source_kinds", "missing_policy", "baseline", "description"}
SCHEMA_KEYS = {"feature_schema_version", "status", "features", "description"}
MAX_FEATURES = 64
_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
DEFAULT_SCHEMA = Path(__file__).parent / "content" / "feature_schema_v1.json"


class SchemaError(ValueError):
    pass


def _req(cond: bool, msg: str) -> None:
    if not cond:
        raise SchemaError(msg)


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    type: str
    unit: str
    source_kinds: Tuple[str, ...]
    baseline: str
    missing_policy: str = "UNKNOWN"
    description: str = ""


@dataclass(frozen=True)
class FeatureSchema:
    version: str
    status: str
    features: Tuple[FeatureSpec, ...]
    content_hash: str

    def names(self) -> Tuple[str, ...]:
        return tuple(f.name for f in self.features)

    def spec(self, name: str) -> FeatureSpec:
        for f in self.features:
            if f.name == name:
                return f
        raise SchemaError(f"feature {name!r} not in schema {self.version}")

    def kinds(self) -> Tuple[str, ...]:
        return tuple(sorted({k for f in self.features for k in f.source_kinds}))


def schema_hash(doc: Dict[str, Any]) -> str:
    body = {k: v for k, v in doc.items() if k != "status"}
    return "fs_" + sha(json.dumps(body, sort_keys=True, separators=(",", ":")))[:32]


def _feature(d: Any) -> FeatureSpec:
    _req(isinstance(d, dict) and set(d) <= FEATURE_KEYS, f"bad feature keys: {d!r}"[:200])
    name = d.get("name")
    _req(isinstance(name, str) and bool(_ID.fullmatch(name)), f"bad feature name {name!r}")
    _req(d.get("type") in FEATURE_TYPES, f"{name}: type")
    _req(isinstance(d.get("unit"), str) and 0 < len(d["unit"]) <= 32, f"{name}: unit")
    kinds = d.get("source_kinds")
    _req(isinstance(kinds, list) and kinds and set(kinds) <= EVIDENCE_KINDS, f"{name}: source_kinds")
    _req(d.get("missing_policy", "UNKNOWN") in MISSING_POLICIES, f"{name}: missing_policy must be UNKNOWN")
    _req(d.get("baseline", "none") in BASELINE_SCOPES, f"{name}: baseline")
    return FeatureSpec(name=name, type=d["type"], unit=d["unit"], source_kinds=tuple(sorted(kinds)),
                       baseline=d.get("baseline", "none"), description=str(d.get("description", ""))[:512])


def parse_schema(doc: Dict[str, Any]) -> FeatureSchema:
    _req(isinstance(doc, dict) and set(doc) <= SCHEMA_KEYS, "unknown schema keys")
    ver = doc.get("feature_schema_version")
    _req(isinstance(ver, str) and bool(_ID.fullmatch(ver)), f"bad feature_schema_version {ver!r}")
    _req(doc.get("status", "DRAFT") in SCHEMA_STATUS, "status")
    feats = doc.get("features")
    _req(isinstance(feats, list) and 1 <= len(feats) <= MAX_FEATURES, "features: 1..64")
    parsed = tuple(_feature(f) for f in feats)
    _req(len({f.name for f in parsed}) == len(parsed), "duplicate feature names")
    return FeatureSchema(version=ver, status=doc.get("status", "DRAFT"), features=parsed,
                         content_hash=schema_hash(doc))


def load_schema(path: Path = DEFAULT_SCHEMA) -> FeatureSchema:
    return parse_schema(json.loads(Path(path).read_text(encoding="utf-8")))


class SchemaRegistry:
    """A RELEASED schema version is immutable; DRAFT versions may be replaced."""

    def __init__(self) -> None:
        self._s: Dict[str, FeatureSchema] = {}

    def register(self, schema: FeatureSchema) -> FeatureSchema:
        prev = self._s.get(schema.version)
        if prev is not None and prev.content_hash != schema.content_hash and prev.status == "RELEASED":
            raise SchemaError(f"schema {schema.version} is released and immutable")
        if prev is None or prev.content_hash != schema.content_hash or schema.status == "RELEASED":
            self._s[schema.version] = schema
        return self._s[schema.version]

    def get(self, version: str) -> FeatureSchema:
        if version not in self._s:
            raise SchemaError(f"unknown feature_schema_version {version!r}")
        return self._s[version]


@dataclass(frozen=True)
class FeatureValue:
    name: str
    state: str
    value: Optional[float]
    evidence_refs: Tuple[EvidenceRef, ...]
    baseline: Dict[str, Any] = field(default_factory=dict, compare=False)
    reason: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_refs or not all(isinstance(r, EvidenceRef) for r in self.evidence_refs):
            raise ValueError("FeatureValue requires evidence_refs")
        if self.state not in STATES:
            raise ValueError(f"bad feature state {self.state!r}")
        if self.state == KNOWN and finite(self.value) is None:
            raise ValueError("KNOWN feature value must be finite")
        if self.state != KNOWN and self.value is not None:
            raise ValueError("non-KNOWN feature must not carry a value")

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "state": self.state, "value": self.value,
                "evidence_keys": [r.stable_key() for r in self.evidence_refs],
                "baseline": dict(self.baseline), "reason": self.reason}


@dataclass(frozen=True)
class FeatureVector:
    schema_version: str
    schema_hash: str
    tenant_id: str
    endpoint_id: str
    entity: Optional[str]
    anchor: EvidenceRef
    anchor_time: datetime
    values: Tuple[FeatureValue, ...]

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.endpoint_id or self.anchor.tenant_id != self.tenant_id:
            raise ValueError("FeatureVector requires an explicit, consistent tenant and endpoint")
        if any(r.tenant_id != self.tenant_id for v in self.values for r in v.evidence_refs):
            raise ValueError("FeatureVector evidence crosses tenants")

    def get(self, name: str) -> FeatureValue:
        for v in self.values:
            if v.name == name:
                return v
        raise KeyError(name)

    def to_dict(self) -> Dict[str, Any]:
        return {"schema_version": self.schema_version, "schema_hash": self.schema_hash,
                "tenant_id": self.tenant_id, "endpoint_id": self.endpoint_id, "entity": self.entity,
                "anchor_key": self.anchor.stable_key(), "anchor_time": utc(self.anchor_time),
                "values": [v.to_dict() for v in self.values]}
