"""UAIE Contract #1 · Artifact (Rule R25)

Immutable, URI-addressed unit of analysis.  Every discovered object
in the investigation is an Artifact; new observations produce NEW
artifacts with lineage links, never mutate existing ones.

URI format: ``uaie://artifact/<sha256-16-hex>``.  Deterministic —
same bytes produce the same URI.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing      import Any, Dict, Optional


ArtifactURI = str  # e.g. "uaie://artifact/1a2b3c…"


def compute_uri(payload: bytes) -> ArtifactURI:
    """Deterministic URI — same bytes → same URI, forever."""
    return f"uaie://artifact/{hashlib.sha256(payload).hexdigest()[:16]}"


@dataclass(frozen=True)
class Artifact:
    uri:            ArtifactURI
    parent_uri:     Optional[ArtifactURI]
    artifact_type:  str                   # e.g. "text", "base64", "gzip", "shellcode"
    payload:        bytes                 # raw bytes — text is UTF-8-encoded
    sha256:         str
    size:           int
    entropy:        float
    depth:          int                   # recursion depth (0 for the root paste)
    discovered_by:  str                   # name of the recognizer/capability
    discovered_at:  float = field(default_factory=lambda: time.time())
    meta:           Dict[str, Any] = field(default_factory=dict)


def make_artifact(payload: bytes,
                    artifact_type: str,
                    *,
                    parent_uri: Optional[ArtifactURI] = None,
                    depth: int = 0,
                    discovered_by: str = "root",
                    meta: Optional[Dict[str, Any]] = None) -> Artifact:
    """Factory — always call this to construct an Artifact so URI /
    hash / size / entropy are computed consistently."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("Artifact.payload MUST be bytes")
    b = bytes(payload)
    return Artifact(
        uri=compute_uri(b),
        parent_uri=parent_uri,
        artifact_type=artifact_type,
        payload=b,
        sha256=hashlib.sha256(b).hexdigest(),
        size=len(b),
        entropy=_shannon_entropy(b),
        depth=depth,
        discovered_by=discovered_by,
        meta=dict(meta or {}),
    )


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from math import log2
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    H = 0.0
    for c in counts:
        if c:
            p = c / n
            H -= p * log2(p)
    return round(H, 4)
