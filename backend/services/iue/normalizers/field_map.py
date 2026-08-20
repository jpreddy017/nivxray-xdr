"""Field-map normalizer (STEP 3 §2.4 · §3.3).

Layered detection order per v3 §6:
  schema → vendor → dictionary → type_infer → regex → semantic → validation

For Stage 1 Lane A we implement the deterministic **dictionary** and
**type_infer** layers.  Schema / vendor layers are stubs that the
dictionary walks first, so adding real schemas later is additive.
Every canonical field records its ``alias_source``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Mapping, Tuple

from canonical.ssot.models import Provenance
from .._prov import normalize_prov


# ── Alias dictionary (STEP 3 §3.3) ─────────────────────────────────
# canonical_key → list of (alias, source_tag)
_DICT: Dict[str, List[Tuple[str, str]]] = {
    "canonical.event.timestamp": [
        ("timestamp", "dictionary"),
        ("event_time", "dictionary"),
        ("eventTime", "dictionary"),
        ("@timestamp", "dictionary"),
        ("time", "dictionary"),
        ("ts", "dictionary"),
    ],
    "canonical.event.action": [
        ("action", "dictionary"),
        ("event_action", "dictionary"),
    ],
    "canonical.event.category": [
        ("category", "dictionary"),
        ("event_category", "dictionary"),
    ],
    "canonical.event.severity": [
        ("severity", "dictionary"),
        ("level", "dictionary"),
    ],
    "canonical.source.ip": [
        ("src_ip", "dictionary"),
        ("source_ip", "dictionary"),
        ("sourceAddress", "dictionary"),
        ("sip", "dictionary"),
    ],
    "canonical.source.port": [
        ("src_port", "dictionary"),
        ("source_port", "dictionary"),
        ("sourcePort", "dictionary"),
    ],
    "canonical.source.host": [
        ("host", "dictionary"),
        ("source_host", "dictionary"),
        ("hostname", "dictionary"),
    ],
    "canonical.source.user": [
        ("user", "dictionary"),
        ("username", "dictionary"),
        ("source_user", "dictionary"),
    ],
    "canonical.destination.ip": [
        ("dst_ip", "dictionary"),
        ("dest_ip", "dictionary"),
        ("destination_ip", "dictionary"),
        ("destinationAddress", "dictionary"),
        ("dip", "dictionary"),
    ],
    "canonical.destination.port": [
        ("dst_port", "dictionary"),
        ("dest_port", "dictionary"),
        ("destination_port", "dictionary"),
        ("destinationPort", "dictionary"),
    ],
    "canonical.destination.host": [
        ("dest_host", "dictionary"),
        ("destination_host", "dictionary"),
    ],
    "canonical.destination.domain": [
        ("domain", "dictionary"),
        ("destination_domain", "dictionary"),
    ],
    "canonical.destination.url": [
        ("url", "dictionary"),
        ("request_url", "dictionary"),
    ],
    "canonical.process.parent": [
        ("parent_process", "dictionary"),
        ("parent_process_name", "dictionary"),
        ("ParentProcessName", "dictionary"),
    ],
    "canonical.process.name": [
        ("process_name", "dictionary"),
        ("Image", "dictionary"),
    ],
    "canonical.process.command_line": [
        ("CommandLine", "dictionary"),
        ("cmd", "dictionary"),
        ("command_line", "dictionary"),
        ("process_command_line", "dictionary"),
    ],
    "canonical.file.path": [
        ("file_path", "dictionary"),
        ("FilePath", "dictionary"),
        ("path", "dictionary"),
    ],
    "canonical.file.hash.md5": [
        ("md5", "dictionary"),
        ("MD5", "dictionary"),
    ],
    "canonical.file.hash.sha1": [
        ("sha1", "dictionary"),
        ("SHA1", "dictionary"),
    ],
    "canonical.file.hash.sha256": [
        ("sha256", "dictionary"),
        ("SHA-256", "dictionary"),
        ("fileHash", "dictionary"),
    ],
    "canonical.tenant.id": [
        ("tenant_id", "dictionary"),
        ("tenantId", "dictionary"),
    ],
}


_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_MD5_RE    = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE   = re.compile(r"^[0-9a-fA-F]{40}$")


@dataclass(frozen=True)
class NormalizedRecord:
    record_id: str
    source_file_id: str
    input_id: str
    tenant_id: str
    canonical_fields: Mapping[str, Any]
    raw_fields: Mapping[str, Any]
    alias_map: Mapping[str, Tuple[str, str]]  # canonical → (raw_key, source)
    normalize_status: str = "ok"       # ok | partial | unmappable
    unmapped_fields: List[str] = field(default_factory=list)
    provenance: Provenance = field(default_factory=normalize_prov)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["raw_fields"] = dict(self.raw_fields)
        d["canonical_fields"] = dict(self.canonical_fields)
        d["alias_map"] = {k: list(v) for k, v in self.alias_map.items()}
        return d


def normalize(record) -> NormalizedRecord:
    """Map ``record.raw_fields`` (arbitrary vendor keys) → canonical
    namespace with per-field alias-source provenance."""
    raw = dict(record.raw_fields or {})
    canonical: Dict[str, Any] = {}
    alias_map: Dict[str, Tuple[str, str]] = {}
    used_raw_keys: set = set()

    # 1. Dictionary layer — exact key match wins first alias found.
    for canonical_key, aliases in _DICT.items():
        for alias, source in aliases:
            if alias in raw and canonical_key not in canonical:
                canonical[canonical_key] = raw[alias]
                alias_map[canonical_key] = (alias, source)
                used_raw_keys.add(alias)
                break

    # 2. Type-infer layer — for still-unassigned canonical keys, try
    #    regex on remaining raw values.
    for k, v in raw.items():
        if k in used_raw_keys or not isinstance(v, str):
            continue
        if _SHA256_RE.match(v) and "canonical.file.hash.sha256" not in canonical:
            canonical["canonical.file.hash.sha256"] = v
            alias_map["canonical.file.hash.sha256"] = (k, "type_infer")
            used_raw_keys.add(k)
        elif _MD5_RE.match(v) and "canonical.file.hash.md5" not in canonical:
            canonical["canonical.file.hash.md5"] = v
            alias_map["canonical.file.hash.md5"] = (k, "type_infer")
            used_raw_keys.add(k)
        elif _SHA1_RE.match(v) and "canonical.file.hash.sha1" not in canonical:
            canonical["canonical.file.hash.sha1"] = v
            alias_map["canonical.file.hash.sha1"] = (k, "type_infer")
            used_raw_keys.add(k)
        elif _IP_RE.match(v):
            if "canonical.source.ip" not in canonical:
                canonical["canonical.source.ip"] = v
                alias_map["canonical.source.ip"] = (k, "type_infer")
                used_raw_keys.add(k)

    unmapped = [k for k in raw if k not in used_raw_keys]
    status = "ok" if canonical else "unmappable"

    return NormalizedRecord(
        record_id=record.record_id,
        source_file_id=record.source_file_id,
        input_id=record.input_id,
        tenant_id=record.tenant_id,
        canonical_fields=canonical,
        raw_fields=raw,
        alias_map=alias_map,
        normalize_status=status,
        unmapped_fields=unmapped,
        provenance=normalize_prov(upstream=record.provenance,
                                    own_id=record.record_id),
    )
