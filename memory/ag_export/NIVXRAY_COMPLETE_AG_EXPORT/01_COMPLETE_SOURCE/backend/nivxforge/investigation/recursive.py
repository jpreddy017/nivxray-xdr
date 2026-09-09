"""P2-05d · Recursive Command Investigation orchestration.

Deterministic investigation platform primitives:

  * ArtifactQueue        — extensibility backbone (any artifact kind)
  * FixedPoint           — snapshot-based termination oracle
  * InvestigatorRegistry — static registry (deterministic + auditable)
  * Orchestrator         — pulls artifacts → invokes investigators →
                           merges into the SAME CIO → refreshes verdict
                           + truth → recomputes snapshot → loops until
                           fixed point OR budget exhausted
  * RecursionReport      — every metric an analyst / CI / customer needs

Six termination conditions (ALL required for a successful fixed point):
    no-new-nodes · no-new-edges · no-new-IOCs · no-new-MITRE ·
    no-new-hypotheses · no-confidence-delta

If any budget is exhausted before the fixed point → status="partial".
Never HTTP 500.
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from nivxforge.investigation.graph import Node, Edge


# ─── Policy-driven budgets ─────────────────────────────────────────

RECURSION_POLICIES: Dict[str, Dict[str, int]] = {
    "small":     {"depth": 4,  "artifacts": 32,  "budget_ms": 5_000},
    "standard":  {"depth": 8,  "artifacts": 128, "budget_ms": 20_000},
    "deep":      {"depth": 16, "artifacts": 512, "budget_ms": 60_000},
    "unlimited": {"depth": 128, "artifacts": 4096, "budget_ms": 600_000},
}


# ─── Artifact + Queue ─────────────────────────────────────────────

@dataclass
class Artifact:
    id: str
    kind: str            # command | base64 | url | hash | shellcode | script | ...
    content: str
    depth: int = 0
    parent_id: Optional[str] = None
    provenance: str = ""


@dataclass
class ArtifactQueue:
    """FIFO with dedup by (kind, sha256(content))."""
    _items: List[Artifact] = field(default_factory=list)
    _seen: set = field(default_factory=set)
    max_size: int = 512
    dropped: int = 0

    def _key(self, a: Artifact) -> str:
        h = hashlib.sha256(a.content.encode("utf-8", errors="ignore")).hexdigest()[:16]
        return f"{a.kind}:{h}"

    def push(self, artifact: Artifact) -> bool:
        k = self._key(artifact)
        if k in self._seen:
            return False
        if len(self._items) + 1 > self.max_size:
            self.dropped += 1
            return False
        self._seen.add(k)
        self._items.append(artifact)
        return True

    def pop(self) -> Optional[Artifact]:
        return self._items.pop(0) if self._items else None

    def __len__(self) -> int:
        return len(self._items)


# ─── Investigator registry (static, auditable) ─────────────────────

@dataclass
class InvestigatorResult:
    new_nodes: List[Node] = field(default_factory=list)
    new_edges: List[Edge] = field(default_factory=list)
    new_artifacts: List[Artifact] = field(default_factory=list)
    metadata_updates: Dict[str, Any] = field(default_factory=dict)
    note: str = ""


InvestigatorFn = Callable[[Artifact], InvestigatorResult]


class InvestigatorRegistry:
    """Static kind → investigator map. Deterministic + auditable."""
    _by_kind: Dict[str, InvestigatorFn] = {}

    @classmethod
    def register(cls, kind: str, fn: InvestigatorFn) -> None:
        cls._by_kind[kind] = fn

    @classmethod
    def get(cls, kind: str) -> Optional[InvestigatorFn]:
        return cls._by_kind.get(kind)

    @classmethod
    def kinds(cls) -> List[str]:
        return sorted(cls._by_kind.keys())


# ─── Fixed-point snapshot fingerprint ───────────────────────────────

def snapshot_hash(cio) -> str:
    """Stable hash over the CIO state that must be invariant to declare
    a fixed point. Six components: nodes · edges · IOCs · MITRE ·
    hypotheses · confidence.
    """
    graph = getattr(cio, "evidence_graph", None)
    md = getattr(cio, "metadata", {}) or {}
    truth = getattr(cio, "truth", {}) or {}
    v = getattr(cio, "verdict", {}) or {}
    parts = [
        str(len(graph.nodes) if graph else 0),
        str(len(graph.edges) if graph else 0),
        # IOCs
        str(sorted((n.value, (n.attrs or {}).get("ioc_kind", ""))
                    for n in (graph.nodes if graph else [])
                    if n.kind == "ioc")),
        # MITRE
        str(sorted(n.value for n in (graph.nodes if graph else [])
                    if n.kind == "mitre_technique")),
        # Hypotheses
        str(sorted(h.get("id", "") for h in (truth.get("hypotheses") or []))),
        # Confidence (int, so tiny drift is stable)
        str(int(v.get("confidence_pct") or 0)),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


# ─── Recursion Report ──────────────────────────────────────────────

@dataclass
class RecursionReport:
    iterations: int = 0
    artifacts_processed: int = 0
    artifacts_discovered: int = 0
    commands_decoded: int = 0
    scripts_recovered: int = 0
    archives_unpacked: int = 0
    iocs_extracted: int = 0
    mitre_techniques: int = 0
    hypotheses_validated: int = 0
    fixed_point_reached: bool = False
    reason_no_new: Dict[str, bool] = field(default_factory=dict)
    max_depth_reached: int = 0
    duration_ms: int = 0
    status: str = "partial"     # complete | partial
    policy: str = "standard"
    trace: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "iterations": self.iterations,
            "artifacts_processed": self.artifacts_processed,
            "artifacts_discovered": self.artifacts_discovered,
            "commands_decoded": self.commands_decoded,
            "scripts_recovered": self.scripts_recovered,
            "archives_unpacked": self.archives_unpacked,
            "iocs_extracted": self.iocs_extracted,
            "mitre_techniques": self.mitre_techniques,
            "hypotheses_validated": self.hypotheses_validated,
            "fixed_point_reached": self.fixed_point_reached,
            "reason_no_new": self.reason_no_new,
            "max_depth_reached": self.max_depth_reached,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "policy": self.policy,
            "trace": self.trace,
        }


# ─── Orchestrator ──────────────────────────────────────────────────

def _diff_snapshots(cio, prev: Dict[str, Any]) -> Dict[str, bool]:
    """Return per-condition no-new flags."""
    graph = getattr(cio, "evidence_graph", None)
    md = getattr(cio, "metadata", {}) or {}
    truth = getattr(cio, "truth", {}) or {}
    v = getattr(cio, "verdict", {}) or {}
    return {
        "nodes":    (len(graph.nodes) if graph else 0) == prev.get("nodes", 0),
        "edges":    (len(graph.edges) if graph else 0) == prev.get("edges", 0),
        "iocs":     sum(1 for n in (graph.nodes if graph else []) if n.kind == "ioc") == prev.get("iocs", 0),
        "mitre":    sum(1 for n in (graph.nodes if graph else []) if n.kind == "mitre_technique") == prev.get("mitre", 0),
        "hypotheses": len(truth.get("hypotheses") or []) == prev.get("hypotheses", 0),
        "confidence": int(v.get("confidence_pct") or 0) == prev.get("confidence", 0),
    }


def _cio_counts(cio) -> Dict[str, int]:
    graph = getattr(cio, "evidence_graph", None)
    truth = getattr(cio, "truth", {}) or {}
    v = getattr(cio, "verdict", {}) or {}
    return {
        "nodes":      len(graph.nodes) if graph else 0,
        "edges":      len(graph.edges) if graph else 0,
        "iocs":       sum(1 for n in (graph.nodes if graph else []) if n.kind == "ioc"),
        "mitre":      sum(1 for n in (graph.nodes if graph else []) if n.kind == "mitre_technique"),
        "hypotheses": len(truth.get("hypotheses") or []),
        "confidence": int(v.get("confidence_pct") or 0),
    }


def recursively_investigate(
    cio,
    seed_content: str,
    seed_kind: str = "command",
    policy: str = "standard",
) -> RecursionReport:
    """Run the recursive investigation loop over `cio` until fixed
    point OR budget exhausted. Mutates `cio` in place. Always returns
    a valid RecursionReport — never raises for policy exhaustion.
    """
    from nivxforge.investigation.verdict_engine import refresh_verdict
    budget = RECURSION_POLICIES.get(policy) or RECURSION_POLICIES["standard"]
    depth_max = budget["depth"]
    art_max = budget["artifacts"]
    time_max_s = budget["budget_ms"] / 1000.0

    queue = ArtifactQueue(max_size=art_max)
    seed = Artifact(id="A-0", kind=seed_kind, content=seed_content, depth=0,
                    provenance="seed")
    queue.push(seed)

    report = RecursionReport(policy=policy)
    t0 = time.monotonic()
    prev_counts = _cio_counts(cio)
    prev_snapshot = snapshot_hash(cio)

    while len(queue) > 0:
        elapsed = time.monotonic() - t0
        if elapsed > time_max_s:
            break
        if report.artifacts_processed >= art_max:
            break
        art = queue.pop()
        if art is None:
            break
        if art.depth > depth_max:
            continue

        # Snapshot the CIO state BEFORE this iteration — so we can tell
        # if THIS iteration produced anything new.
        prev_counts = _cio_counts(cio)

        investigator = InvestigatorRegistry.get(art.kind)
        if investigator is None:
            continue
        try:
            res = investigator(art)
        except Exception:  # noqa: BLE001
            res = InvestigatorResult(note="investigator error")

        # Merge into CIO
        graph = getattr(cio, "evidence_graph", None)
        added_nodes = 0
        if graph:
            existing_ids = {n.id for n in graph.nodes}
            for n in res.new_nodes:
                if n.id not in existing_ids:
                    graph.add_node(n)
                    existing_ids.add(n.id)
                    added_nodes += 1
            for e in res.new_edges:
                try:
                    graph.add_edge(e)
                except Exception:  # noqa: BLE001
                    pass

        # Merge metadata
        for k, v in (res.metadata_updates or {}).items():
            cio.metadata[k] = v

        # Queue newly discovered artifacts
        for child in res.new_artifacts:
            child.depth = art.depth + 1
            if queue.push(child):
                report.artifacts_discovered += 1

        # Refresh verdict + truth on the same CIO (deterministic)
        try:
            refresh_verdict(cio)
        except Exception:  # noqa: BLE001
            pass

        report.iterations += 1
        report.artifacts_processed += 1
        report.max_depth_reached = max(report.max_depth_reached, art.depth)
        if art.kind == "command":
            report.commands_decoded += 1
        elif art.kind == "script":
            report.scripts_recovered += 1
        elif art.kind == "archive":
            report.archives_unpacked += 1
        report.trace.append({
            "iteration": report.iterations,
            "artifact_id": art.id,
            "kind": art.kind,
            "depth": art.depth,
            "investigator": art.kind,
            "new_nodes": added_nodes,
            "new_artifacts": len(res.new_artifacts),
            "note": res.note,
            "snapshot_hash": snapshot_hash(cio),
        })

        # Fixed-point check: only when queue is empty
        if len(queue) == 0:
            diffs = _diff_snapshots(cio, prev_counts)
            if all(diffs.values()):
                report.fixed_point_reached = True
                report.reason_no_new = diffs
                break
            prev_counts = _cio_counts(cio)
            prev_snapshot = snapshot_hash(cio)

    # Finalize report
    counts = _cio_counts(cio)
    report.iocs_extracted = counts["iocs"]
    report.mitre_techniques = counts["mitre"]
    truth = getattr(cio, "truth", {}) or {}
    report.hypotheses_validated = sum(
        1 for h in (truth.get("hypotheses") or []) if h.get("status") == "validated"
    )
    report.duration_ms = int((time.monotonic() - t0) * 1000)
    report.status = "complete" if report.fixed_point_reached else "partial"
    if not report.reason_no_new:
        report.reason_no_new = _diff_snapshots(cio, prev_counts)
    # Attach the recursion report to the CIO so every surface can read it.
    cio.metadata["recursion_report"] = report.to_dict()
    return report


# ─── Day-1 investigators ─────────────────────────────────────────

_URL_RE = re.compile(r"https?://[\w\-\.]+(?:/[^\s\"'<>]*)?")
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")


def _nid_gen(prefix: str) -> Callable[[], str]:
    i = [0]
    def _(): i[0] += 1; return f"{prefix}-{i[0]:04d}"
    return _


def _investigate_command(art: Artifact) -> InvestigatorResult:
    """Extract URLs, IPs, hashes, and Base64 blobs from a command line."""
    out = InvestigatorResult()
    nid = _nid_gen(f"REC-{art.id}")
    seen = set()
    for m in _URL_RE.findall(art.content):
        if m in seen: continue
        seen.add(m)
        node_id = nid()
        out.new_nodes.append(Node(
            id=node_id, kind="ioc", label=f"URL · {m}", value=m,
            confidence=0.85, provenance=f"recursive:{art.id}",
            attrs={"ioc_kind": "url"}))
        out.new_artifacts.append(Artifact(id=f"{node_id}-a", kind="url",
                                          content=m, parent_id=art.id))
    for m in _IP_RE.findall(art.content):
        if m in seen: continue
        seen.add(m)
        node_id = nid()
        out.new_nodes.append(Node(
            id=node_id, kind="ioc", label=f"IP · {m}", value=m,
            confidence=0.8, provenance=f"recursive:{art.id}",
            attrs={"ioc_kind": "ip"}))
    for m in _HASH_RE.findall(art.content):
        if m in seen: continue
        seen.add(m)
        node_id = nid()
        out.new_nodes.append(Node(
            id=node_id, kind="ioc", label=f"HASH · {m[:16]}…", value=m,
            confidence=0.85, provenance=f"recursive:{art.id}",
            attrs={"ioc_kind": "sha256" if len(m) == 64 else "md5" if len(m) == 32 else "sha1"}))
        out.new_artifacts.append(Artifact(id=f"{node_id}-a", kind="hash",
                                          content=m, parent_id=art.id))
    for m in _B64_RE.findall(art.content):
        if m in seen: continue
        seen.add(m)
        out.new_artifacts.append(Artifact(
            id=nid() + "-b64", kind="base64", content=m, parent_id=art.id
        ))
    out.note = f"extracted {len(out.new_nodes)} nodes / {len(out.new_artifacts)} artifacts"
    return out


def _investigate_base64(art: Artifact) -> InvestigatorResult:
    """Decode base64 → if it's text with commands, queue as command."""
    import base64
    out = InvestigatorResult()
    try:
        raw = base64.b64decode(art.content, validate=False)
    except Exception:  # noqa: BLE001
        out.note = "base64 decode failed"
        return out
    # Try UTF-8 / UTF-16LE
    text = None
    for enc in ("utf-8", "utf-16le"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text and any(c.isprintable() for c in text[:64]):
        out.new_artifacts.append(Artifact(
            id=f"{art.id}-t", kind="command", content=text, parent_id=art.id))
        out.note = f"decoded to {len(text)} chars text"
    else:
        out.note = "decoded to binary"
    return out


def _investigate_url(art: Artifact) -> InvestigatorResult:
    return InvestigatorResult(note="url pivots to OSINT via cio.metadata.osint")


def _investigate_hash(art: Artifact) -> InvestigatorResult:
    return InvestigatorResult(note="hash pivots to OSINT / family recognizer")


def _investigate_shellcode(art: Artifact) -> InvestigatorResult:
    return InvestigatorResult(note="shellcode handled by shellcode_analyzer during build_cio")


# Static registration — deterministic + auditable.
InvestigatorRegistry.register("command",   _investigate_command)
InvestigatorRegistry.register("base64",    _investigate_base64)
InvestigatorRegistry.register("url",       _investigate_url)
InvestigatorRegistry.register("hash",      _investigate_hash)
InvestigatorRegistry.register("shellcode", _investigate_shellcode)


__all__ = [
    "Artifact", "ArtifactQueue", "InvestigatorRegistry", "InvestigatorResult",
    "RecursionReport", "recursively_investigate",
    "snapshot_hash", "RECURSION_POLICIES",
]
