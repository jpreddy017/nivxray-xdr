"""Stage 7 · Evidence Extraction.

Consumes CEM + DiscoveredArtifacts + DecodedLayers and produces a
consolidated `EvidenceBundle` — the atomic building blocks that the
Investigation Graph (Stage 8) will materialise as nodes / edges.

Evidence categories (Contract #3 taxonomy):
    hosts · users · processes · files · hashes · urls · domains · ips
    · registry · dns · detections · commands · decoded_payloads
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from nivxforge.investigation.cem import CanonicalEvent, CanonicalEventModel
from .artifact_discovery import DiscoveredArtifactRef
from .recursive_decoder import DecodedLayer


@dataclass(frozen=True)
class EvidenceItem:
    """A canonical piece of evidence with provenance to CEM."""
    kind: str                       # host | user | process | file | hash |
                                     # url | domain | ip | registry | dns |
                                     # detection | command | decoded_payload
    value: str
    attrs: Dict[str, Any] = field(default_factory=dict)
    event_ids: Tuple[str, ...] = field(default_factory=tuple)
    confidence: float = 1.0


@dataclass(frozen=True)
class EvidenceBundle:
    items: Tuple[EvidenceItem, ...]

    def by_kind(self, kind: str) -> List[EvidenceItem]:
        return [i for i in self.items if i.kind == kind]


def extract(
    cem: CanonicalEventModel,
    artifacts: List[DiscoveredArtifactRef],
    decoded: List[DecodedLayer],
) -> EvidenceBundle:
    """Extract typed evidence from CEM + discovered artefacts + decoded
    layers. Deterministic. Values normalised (lowercased where
    canonical) so the graph dedup by identity works."""
    seen: Dict[Tuple[str, str], EvidenceItem] = {}

    def _add(kind: str, value: str, event_id: Optional[str],
             attrs: Optional[Dict[str, Any]] = None,
             conf: float = 1.0) -> None:
        if value is None:
            return
        v = str(value).strip()
        if not v:
            return
        key = (kind, _canonical(kind, v))
        prev = seen.get(key)
        if prev is None:
            seen[key] = EvidenceItem(
                kind=kind, value=v, attrs=dict(attrs or {}),
                event_ids=tuple([event_id]) if event_id else tuple(),
                confidence=conf,
            )
        else:
            merged_events = set(prev.event_ids)
            if event_id:
                merged_events.add(event_id)
            merged_attrs = dict(prev.attrs)
            for k, val in (attrs or {}).items():
                merged_attrs.setdefault(k, val)
            seen[key] = EvidenceItem(
                kind=prev.kind, value=prev.value,
                attrs=merged_attrs,
                event_ids=tuple(sorted(merged_events)),
                confidence=max(prev.confidence, conf),
            )

    for evt in cem.events:
        eid = evt.event_id
        if evt.host:
            _add("host", evt.host.name or evt.host.fqdn or evt.host.ip
                          or evt.host.id or "", eid,
                 {"os": evt.host.os, "ip": evt.host.ip,
                  "fqdn": evt.host.fqdn})
        if evt.user:
            _add("user", evt.user.name or evt.user.id or "", eid,
                 {"domain": evt.user.domain, "sid": evt.user.sid})
        if evt.process:
            if evt.process.image:
                _add("process", evt.process.image, eid,
                     {"pid": evt.process.pid, "ppid": evt.process.ppid})
            if evt.process.command_line:
                _add("command", evt.process.command_line, eid,
                     {"integrity": evt.process.integrity_level})
            if evt.process.hash_sha256:
                _add("hash", evt.process.hash_sha256, eid,
                     {"algo": "sha256"})
        if evt.parent_process and evt.parent_process.command_line:
            _add("command", evt.parent_process.command_line, eid,
                 {"role": "parent"})
        if evt.file:
            if evt.file.path:
                _add("file", evt.file.path, eid,
                     {"name": evt.file.name})
            for algo in ("sha256", "sha1", "md5"):
                val = getattr(evt.file, f"hash_{algo}", None)
                if val:
                    _add("hash", val, eid, {"algo": algo})
        if evt.registry and evt.registry.key:
            _add("registry", evt.registry.key, eid,
                 {"value_name": evt.registry.value_name,
                  "value_data": evt.registry.value_data})
        if evt.network:
            if evt.network.url:
                _add("url", evt.network.url, eid,
                     {"dst_port": evt.network.dst_port})
            if evt.network.domain:
                _add("domain", evt.network.domain, eid, {})
            if evt.network.dst_ip:
                _add("ip", evt.network.dst_ip, eid,
                     {"role": "destination",
                      "port": evt.network.dst_port})
            if evt.network.src_ip:
                _add("ip", evt.network.src_ip, eid, {"role": "source"})
        if evt.dns and evt.dns.query:
            _add("dns", evt.dns.query, eid,
                 {"query_type": evt.dns.query_type,
                  "response": evt.dns.response})
        if evt.detection:
            _add("detection", evt.detection.name, eid,
                 {"severity": evt.detection.severity.value,
                  "category": evt.detection.category,
                  "threat_name": evt.detection.threat_name,
                  "threat_family": evt.detection.threat_family})

    # Artifacts add extra evidence (IOCs) not surfaced by structured fields.
    for art in artifacts:
        kind_map = {
            "command_line": "command",
            "encoded_command": "command",
            "script": "command",
            "url": "url",
            "ip": "ip",
            "domain": "dns",
            "hash_sha256": "hash",
            "hash_sha1": "hash",
            "hash_md5": "hash",
            "pe_header": "decoded_payload",
        }
        target_kind = kind_map.get(art.kind)
        if not target_kind:
            continue
        attrs: Dict[str, Any] = {"discovered_at": art.path,
                                  "field": art.name}
        if art.kind.startswith("hash_"):
            attrs["algo"] = art.kind.replace("hash_", "")
        if art.kind == "domain":
            attrs["source"] = "artifact_discovery"
        _add(target_kind, art.value, art.event_id, attrs,
             conf=art.confidence)

    # Decoded layers → decoded_payload evidence
    # We also scan the decoded output for additional IOCs (URLs, IPs,
    # hashes) so the graph sees IOCs from BOTH the vendor payload and
    # the recovered post-decoding text.
    from nivxforge.investigation.artifact_discovery import (
        discover_artifacts as _rade_scan,
    )
    for i, layer in enumerate(decoded):
        _add("decoded_payload",
             layer.output[:512] if len(layer.output) > 512 else layer.output,
             layer.parent_event_id,
             {"scheme": layer.scheme,
              "layer_index": layer.layer_index,
              "parent_value": layer.parent_value},
             conf=layer.confidence)
        # rescan decoded output for IOCs
        for sub in _rade_scan(layer.output):
            sub_kind = {
                "url": "url", "ip": "ip",
                "hash_sha256": "hash", "hash_sha1": "hash",
                "hash_md5": "hash",
                "command_line": "command",
                "encoded_command": "command",
                "script": "command",
            }.get(sub.kind)
            if not sub_kind:
                continue
            sub_attrs: Dict[str, Any] = {
                "discovered_in": "decoded_payload",
                "layer_index": layer.layer_index,
            }
            if sub.kind.startswith("hash_"):
                sub_attrs["algo"] = sub.kind.replace("hash_", "")
            _add(sub_kind, sub.value, layer.parent_event_id,
                 sub_attrs, conf=sub.confidence)

    return EvidenceBundle(items=tuple(seen.values()))


def _canonical(kind: str, value: str) -> str:
    """Normalise identity for dedup."""
    if kind in ("hash", "ip", "domain", "url", "dns"):
        return value.strip().lower()
    if kind in ("host", "user"):
        return value.strip().lower()
    if kind in ("command", "decoded_payload"):
        # commands / payloads dedup on first 200 chars, case-preserving
        return value.strip()[:200]
    return value.strip()


__all__ = ["EvidenceItem", "EvidenceBundle", "extract"]
