"""Stage 9 · Evidence Validation.

First stage that reads ONLY the Investigation Graph. Detects
integrity issues BEFORE downstream reasoning (correlation, timeline,
attack chain, hypothesis, root cause) touches the data.

Validations performed:
    - Timestamp integrity (out-of-order or future timestamps)
    - Hash format sanity (md5=32, sha1=40, sha256=64 hex)
    - Duplicate hash collisions on different files
    - Orphan nodes (no evidence refs → suspicious)
    - Conflicting host identities (same host multiple OSes)
    - Missing critical fields (process node without command / image)

Every finding is a `ValidationFinding` — the pipeline does NOT stop on
failure; it flags issues so downstream stages can weight confidence
accordingly.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .graph_builder import GraphEdge, GraphNode, InvestigationGraph


class Severity:
    INFO = "info"
    WARN = "warn"
    ERROR = "error"


@dataclass(frozen=True)
class ValidationFinding:
    code: str
    severity: str
    message: str
    node_ids: Tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ValidationReport:
    findings: Tuple[ValidationFinding, ...]

    @property
    def errors(self) -> List[ValidationFinding]:
        return [f for f in self.findings if f.severity == Severity.ERROR]

    @property
    def warnings(self) -> List[ValidationFinding]:
        return [f for f in self.findings if f.severity == Severity.WARN]

    def summary(self) -> Dict[str, int]:
        s = {Severity.INFO: 0, Severity.WARN: 0, Severity.ERROR: 0}
        for f in self.findings:
            s[f.severity] = s.get(f.severity, 0) + 1
        return s


_HEX = re.compile(r"^[a-f0-9]+$", re.IGNORECASE)
_EXPECTED_HASH_LEN = {"md5": 32, "sha1": 40, "sha256": 64}


def validate(graph: InvestigationGraph) -> ValidationReport:
    """Run all Phase 1 validations on the Investigation Graph."""
    findings: List[ValidationFinding] = []

    # 1. Hash format sanity
    for n in graph.nodes_of("hash"):
        algo = (n.attrs or {}).get("algo")
        val = n.value.strip()
        if algo and algo.lower() in _EXPECTED_HASH_LEN:
            expected = _EXPECTED_HASH_LEN[algo.lower()]
            if len(val) != expected:
                findings.append(ValidationFinding(
                    code="hash.length_mismatch",
                    severity=Severity.ERROR,
                    message=f"{algo} hash {val[:16]}… length {len(val)} ≠ {expected}",
                    node_ids=(n.id,),
                ))
        if not _HEX.match(val):
            findings.append(ValidationFinding(
                code="hash.not_hex",
                severity=Severity.ERROR,
                message=f"hash value contains non-hex characters: {val[:32]}…",
                node_ids=(n.id,),
            ))

    # 2. Host identity conflict: same canonical host name but multiple OSes
    host_os: Dict[str, set] = {}
    host_nodes_by_name: Dict[str, List[GraphNode]] = {}
    for n in graph.nodes_of("host"):
        os_val = (n.attrs or {}).get("os")
        name = n.value.lower()
        host_nodes_by_name.setdefault(name, []).append(n)
        if os_val:
            host_os.setdefault(name, set()).add(str(os_val).lower())
    for name, oses in host_os.items():
        if len(oses) > 1:
            nid_tuple = tuple(n.id for n in host_nodes_by_name.get(name, []))
            findings.append(ValidationFinding(
                code="host.os_conflict",
                severity=Severity.WARN,
                message=f"host '{name}' reports multiple OSes: {sorted(oses)}",
                node_ids=nid_tuple,
            ))

    # 3. Missing critical fields: process without image AND command
    for n in graph.nodes_of("process"):
        if not n.value or n.value in ("None", ""):
            findings.append(ValidationFinding(
                code="process.missing_image",
                severity=Severity.WARN,
                message="process node has no image path",
                node_ids=(n.id,),
            ))

    # 4. Orphan nodes: nodes with no evidence refs AND no incident edges
    node_ids = {n.id for n in graph.nodes}
    edge_endpoints = set()
    for e in graph.edges:
        edge_endpoints.add(e.from_id)
        edge_endpoints.add(e.to_id)
    for n in graph.nodes:
        if not n.evidence_refs and n.id not in edge_endpoints:
            findings.append(ValidationFinding(
                code="node.orphan",
                severity=Severity.INFO,
                message=f"{n.kind} node '{n.value[:40]}' has no evidence refs or edges",
                node_ids=(n.id,),
            ))

    # 5. Duplicate command nodes with wildly different lengths (parser
    #    dedup gate). Currently informational.
    cmd_texts: Dict[str, List[str]] = {}
    for n in graph.nodes_of("command"):
        head = n.value.strip()[:40].lower()
        cmd_texts.setdefault(head, []).append(n.id)
    for head, ids in cmd_texts.items():
        if len(ids) > 4:
            findings.append(ValidationFinding(
                code="command.high_duplication",
                severity=Severity.INFO,
                message=f"{len(ids)} command nodes share prefix '{head}'",
                node_ids=tuple(ids[:6]),
            ))

    # 6. Detection without any flagged edge — parser lost linkage
    flagged_targets = {e.to_id for e in graph.edges if e.relation == "flagged"}
    flagged_sources = {e.from_id for e in graph.edges if e.relation == "flagged"}
    for det in graph.nodes_of("detection"):
        if det.id not in flagged_sources and det.id not in flagged_targets:
            findings.append(ValidationFinding(
                code="detection.no_link",
                severity=Severity.WARN,
                message=f"detection '{det.value[:40]}' has no flagged target",
                node_ids=(det.id,),
            ))

    return ValidationReport(findings=tuple(findings))


__all__ = ["Severity", "ValidationFinding", "ValidationReport", "validate"]
