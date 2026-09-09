"""UAIE Contract #4 · Evidence (Rule R25)

A single normalised finding.  Type-agnostic — the same shape carries
a URL, an IP, a MITRE technique, a behaviour, or a config-blob field.

Family classifiers CONSUME evidence but must never CREATE evidence.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing      import Any, Dict, List, Optional

from .recognizer import Reason


@dataclass(frozen=True)
class Evidence:
    id:                str
    artifact_uri:      str
    kind:              str          # "url" · "ip" · "domain" · "mitre" · "behavior" · "hash" · "cmd" · …
    value:             Any
    source_capability: str
    confidence:        float        # global 0.00–1.00 semantics
    severity:          str = ""     # "info" · "low" · "medium" · "high" · "critical"
    reasons:           List[Reason]      = field(default_factory=list)
    mitre_techniques:  List[str]         = field(default_factory=list)
    mitre_tactics:     List[str]         = field(default_factory=list)
    kill_chain:        List[str]         = field(default_factory=list)
    location:          str = ""    # substring / offset / lineage marker
    meta:              Dict[str, Any]    = field(default_factory=dict)


def make_evidence(*, artifact_uri: str,
                    kind: str,
                    value: Any,
                    source_capability: str,
                    confidence: float,
                    severity: str = "",
                    reasons: Optional[List[Reason]] = None,
                    mitre_techniques: Optional[List[str]] = None,
                    mitre_tactics: Optional[List[str]] = None,
                    kill_chain: Optional[List[str]] = None,
                    location: str = "",
                    meta: Optional[Dict[str, Any]] = None) -> Evidence:
    return Evidence(
        id=f"ev_{uuid.uuid4().hex[:12]}",
        artifact_uri=artifact_uri,
        kind=kind,
        value=value,
        source_capability=source_capability,
        confidence=confidence,
        severity=severity,
        reasons=list(reasons or []),
        mitre_techniques=list(mitre_techniques or []),
        mitre_tactics=list(mitre_tactics or []),
        kill_chain=list(kill_chain or []),
        location=location,
        meta=dict(meta or {}),
    )
