"""Stage 5 · Artifact Discovery — SEPARATE from decoding.

Consumes CEMv1 (from Stage 4) and returns a list of `DiscoveredArtifact`
records — every embedded IOC, command line, encoded blob, script block,
hash, URL etc. found in any event's `process.command_line`,
`file.path`, `network.url`, `registry.value_data`, or `raw` payload.

Downstream stages MUST use `DiscoveredArtifact` — they never re-scan
the vendor JSON.

Reuses the existing RADE engine (`artifact_discovery.discover_artifacts`)
that scans arbitrary Python trees, but drives it from CEMv1 so we
inherit provenance.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

from nivxforge.investigation.artifact_discovery import (
    DiscoveredArtifact as _RADEArtifact,
    discover_artifacts as _rade,
)
from nivxforge.investigation.cem import CanonicalEventModel, CanonicalEvent


@dataclass(frozen=True)
class DiscoveredArtifactRef:
    """Artifact + upstream CEM event id so provenance survives."""
    event_id: str
    path: str
    name: str
    value: str
    kind: str
    confidence: float


def discover(cem: CanonicalEventModel) -> List[DiscoveredArtifactRef]:
    """Walk every CanonicalEvent and surface artefacts. Deterministic."""
    out: List[DiscoveredArtifactRef] = []
    seen: set = set()
    for evt in cem.events:
        # Serialize the event's core content so RADE can scan it.
        payload: Dict[str, Any] = {}
        if evt.process:
            if evt.process.command_line:
                payload["command_line"] = evt.process.command_line
            if evt.process.parent_command_line:
                payload["parent_command_line"] = evt.process.parent_command_line
            if evt.process.image:
                payload["image"] = evt.process.image
        if evt.parent_process and evt.parent_process.command_line:
            payload["parent_command_line"] = evt.parent_process.command_line
        if evt.file:
            for k in ("path", "name", "hash_sha256", "hash_sha1", "hash_md5"):
                v = getattr(evt.file, k, None)
                if v:
                    payload[f"file_{k}"] = v
        if evt.network:
            for k in ("url", "domain", "dst_ip", "src_ip"):
                v = getattr(evt.network, k, None)
                if v:
                    payload[f"net_{k}"] = str(v)
        if evt.registry:
            payload["registry_key"] = evt.registry.key
            if evt.registry.value_data:
                payload["registry_value"] = evt.registry.value_data
        if evt.dns and evt.dns.query:
            payload["dns_query"] = evt.dns.query
        if evt.raw:
            payload["_raw"] = evt.raw
        serialized = json.dumps(payload, default=str)
        for art in _rade(serialized):
            key = (evt.event_id, art.kind, art.value)
            if key in seen:
                continue
            seen.add(key)
            out.append(DiscoveredArtifactRef(
                event_id=evt.event_id,
                path=art.path,
                name=art.name,
                value=art.value,
                kind=art.kind,
                confidence=art.confidence,
            ))
    return out


__all__ = ["DiscoveredArtifactRef", "discover"]
