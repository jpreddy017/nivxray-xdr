"""Behaviour Graph · canonical models.

The graph consists of typed :class:`BehaviorNode` s wired together by
typed :class:`BehaviorEdge` s. Both models are frozen dataclasses so
graphs are hashable, deterministic, and safe to compare in tests.

The behaviour taxonomy is intentionally SMALL. The SME directive:

    "Start with the behaviours you already support. As new real-world
     samples arrive through the Trust Corpus, add new behaviour types
     only when they are justified."

Schema is a *versioned contract* — see ``BEHAVIOR_GRAPH_SCHEMA.md``
at the repo root. Any change to the enums below requires bumping
:data:`BEHAVIOR_GRAPH_SCHEMA_VERSION` in the same commit, or the
``tests/test_behavior_graph_schema_freeze.py`` regression fails.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from ..evidence import Evidence

# ── Behaviour Graph schema version ─────────────────────────────
# Bump according to the rules in ``BEHAVIOR_GRAPH_SCHEMA.md``:
#   * add a new BehaviorKind / EdgeKind / ArgKind → MINOR bump
#   * remove or rename an existing member          → MAJOR bump
#   * change the semantic meaning of a member      → MAJOR bump
# Non-schema changes (builders, formatters, docs)  → no bump.
BEHAVIOR_GRAPH_SCHEMA_VERSION = "1.1.0"


class BehaviorKind(str, Enum):
    """The closed, evidence-supported behaviour taxonomy.

    Every current detection in NivXRay maps onto one of these
    behaviours. Adding a new kind requires:
        (1) a real-world Trust-Corpus sample that proves the gap,
        (2) at least one Intent rule (or dedicated capability) that
             can supply canonical Evidence for the new kind.
    """
    DOWNLOAD                = "download"                 # retrieve remote content
    WRITE_FILE              = "write_file"               # persist bytes to disk
    EXECUTE                 = "execute"                  # run a local file / command
    REMOTE_EXECUTION        = "remote_execution"         # execute code fetched from a remote source
    NETWORK_CONNECTION      = "network_connection"       # deliberate outbound connect (C2, beacon)
    REGISTRY_MODIFICATION   = "registry_modification"    # write / delete a registry value
    PROCESS_CREATION        = "process_creation"         # spawn a subprocess
    PERSISTENCE             = "persistence"              # survives reboot (Run key, task, service)
    LATERAL_MOVEMENT        = "lateral_movement"         # credentialed remote execution / remote-management enablement
    DEFENSE_EVASION         = "defense_evasion"          # AMSI / ETW / Defender / firewall tamper
    DISCOVERY               = "discovery"                # host / user / network enumeration
    CREDENTIAL_ACCESS       = "credential_access"        # LSASS, DPAPI, browser stores
    RUNTIME_DEPENDENT       = "runtime_dependent"        # behaviour resolves only at runtime


class BehaviorEdgeKind(str, Enum):
    """Typed relationships between behaviour nodes.

    The set is small on purpose — analysts should be able to read the
    graph without a legend.
    """
    THEN         = "then"          # sequential — B happened after A
    WRITES_TO    = "writes_to"     # download / process wrote a specific file
    EXECUTES     = "executes"      # a process spawned / invoked a file
    TARGETS      = "targets"       # behaviour operates on a specific IOC / arg


class BehaviorArgKind(str, Enum):
    """Typed argument attached to a behaviour node.

    Args carry the concrete IOC or reference the behaviour operates
    on (URL, file, registry key, process, host). Keeping them typed
    lets downstream consumers (Verdict Engine, Correlation, PDF
    report) pivot without re-parsing free-form strings.
    """
    URL      = "url"
    DOMAIN   = "domain"
    IP       = "ip"
    FILE     = "file"
    REGISTRY = "registry"
    PROCESS  = "process"


@dataclass(frozen=True)
class BehaviorArg:
    """A single typed argument attached to a behaviour node."""
    kind:  BehaviorArgKind
    value: str

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "value": self.value}


@dataclass(frozen=True)
class BehaviorNode:
    """One normalised behaviour observed in the artefact.

    Fields:
        id         — stable string identifier (``b#<index>``).
        kind       — canonical behaviour kind (closed enum).
        purpose    — one plain-English sentence describing the
                     behaviour, analyst-facing.
        args       — typed arguments (URL, file, etc.). Ordered.
        evidence   — canonical Evidence objects that produced the
                     node. Never empty — a behaviour without evidence
                     is a fabrication and must not be emitted.
        confidence — 0-100 strength, propagated from the source
                     Intent(s).
        mitre_ids  — MITRE hints inherited from the source Intent(s).
        source_intent — the intent category (string) that produced
                     this behaviour, for provenance.
    """
    id:            str
    kind:          BehaviorKind
    purpose:       str
    args:          tuple[BehaviorArg, ...] = ()
    evidence:      tuple[Evidence, ...] = ()
    confidence:    int = 0
    mitre_ids:     tuple[str, ...] = ()
    source_intent: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id":            self.id,
            "kind":          self.kind.value,
            "purpose":       self.purpose,
            "args":          [a.to_dict() for a in self.args],
            "evidence":      [e.to_dict() for e in self.evidence],
            "confidence":    self.confidence,
            "mitre_ids":     list(self.mitre_ids),
            "source_intent": self.source_intent,
        }


@dataclass(frozen=True)
class BehaviorEdge:
    """One typed edge between two behaviour nodes."""
    src:  str
    dst:  str
    kind: BehaviorEdgeKind

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "kind": self.kind.value}


@dataclass
class BehaviorGraph:
    """Complete behaviour graph for a single investigation.

    Deterministic — same intent set → same graph. Analyst Report
    surfaces this graph so future correlation engines can pivot on
    normalised behaviours instead of raw commands.

    The emitted ``schema_version`` lets downstream consumers detect
    contract drift without having to inspect the enum members.
    """
    nodes: list[BehaviorNode] = field(default_factory=list)
    edges: list[BehaviorEdge] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": BEHAVIOR_GRAPH_SCHEMA_VERSION,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }

    # ── Convenience accessors for downstream engines ────────────
    def kinds(self) -> list[str]:
        """Deduplicated list of behaviour kinds in the graph, in
        first-seen order — the "shape" of the graph."""
        out: list[str] = []
        for n in self.nodes:
            v = n.kind.value
            if v not in out:
                out.append(v)
        return out

    def has_chain(self, *chain: BehaviorKind | str) -> bool:
        """Return True when the given chain of behaviour kinds is
        connected via ``THEN`` / ``WRITES_TO`` / ``EXECUTES`` edges
        in the graph. Order-preserving.

        This is the primitive the Verdict Engine and future
        Behaviour Correlation call — analysts should not have to
        walk edges by hand.
        """
        wanted = [k.value if isinstance(k, BehaviorKind) else k for k in chain]
        if not wanted:
            return True
        by_id = {n.id: n for n in self.nodes}
        adjacency: dict[str, list[str]] = {}
        for e in self.edges:
            adjacency.setdefault(e.src, []).append(e.dst)

        def _walk(node_id: str, idx: int) -> bool:
            node = by_id.get(node_id)
            if not node or node.kind.value != wanted[idx]:
                return False
            if idx == len(wanted) - 1:
                return True
            for nxt in adjacency.get(node_id, []):
                if _walk(nxt, idx + 1):
                    return True
            return False

        return any(_walk(n.id, 0) for n in self.nodes
                     if n.kind.value == wanted[0])


__all__ = [
    "BEHAVIOR_GRAPH_SCHEMA_VERSION",
    "BehaviorArg",
    "BehaviorArgKind",
    "BehaviorEdge",
    "BehaviorEdgeKind",
    "BehaviorGraph",
    "BehaviorKind",
    "BehaviorNode",
]
