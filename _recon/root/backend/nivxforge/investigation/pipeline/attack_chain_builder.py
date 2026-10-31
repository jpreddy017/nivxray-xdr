"""Stage 10 · Attack Chain Builder.

Deterministic causal edge builder over the canonical `TimelineEvent`
stream and the validated `InvestigationGraph`. Produces `AttackEdge`s
that link timeline events by observable, testable relationships.

Architectural contract (owner directives 2026-08-02 · 2026-02-XX):

    * Attack Chain is a **derivation** stage over already-validated
      evidence — never an inference engine that fabricates events.
    * Every edge is grounded in one or more `DerivationRule` rows.
      Each rule is a concrete, testable predicate over TimelineEvent
      fields or InvestigationGraph edges.
    * **Event confidence ≠ Relationship confidence.** An edge carries
      its own `confidence` derived from *how many rules fired*, and it
      is bounded by the *event* confidence of its endpoints.
    * If a required rule cannot be verified (e.g. both endpoints have
      unknown timestamps), the edge is not emitted — never guessed.
    * Attack Chain reads only `TimelineEvent`s and existing graph
      edges. It never reads raw CEM events or vendor JSON.

Downstream: `Correlation` clusters `TimelineEvent`s using AttackEdges
as a graph. It, too, never invents events.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from .graph_builder import InvestigationGraph
from .timeline_builder import Timeline, TimelineEvent


# ── Configuration ────────────────────────────────────────────────────

# Default time windows for the two purely-temporal edge kinds. Chosen
# to be conservative so they under-connect rather than over-connect;
# real-telemetry validation may shift these once the corpus arrives.
DEFAULT_LED_TO_WINDOW = timedelta(seconds=30)
DEFAULT_SAME_CONTEXT_WINDOW = timedelta(minutes=5)

# Confidence weights per rule. Any rule that *fires* contributes its
SCHEMA_VERSION = "1.0"

# Confidence weights per rule. Any rule that *fires* contributes its
# weight; confidence = sum(weights of firing rules) / sum(all weights
# considered for the edge). Weights encode strength of evidence.
_RULE_WEIGHTS: Dict[str, float] = {
    "graph_child_of_edge":  1.0,   # graph_builder saw a parent CEM field
    "shared_actor":         0.6,
    "shared_host":          0.6,
    "shared_process_tree":  0.4,   # actor of A appears as actor's parent
                                    # of B (walked via graph)
    "within_30_seconds":    0.5,
    "within_5_minutes":     0.3,
    "time_ordered":         0.3,   # A.timestamp <= B.timestamp
}


# ── Data classes ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class DerivationRule:
    """A concrete, testable fact that contributed to an edge.

    `observed` is `True` when the rule verifiably fired, `False` when
    the rule was checked and did NOT fire (edge would be dropped or
    downgraded), `None` when the rule could not be checked because
    the required data was absent (e.g. an unknown timestamp)."""

    name: str
    observed: Optional[bool]     # True | False | None(=unknown)
    detail: str                  # human-readable, deterministic string
    weight: float                # contribution weight (0..1)


@dataclass(frozen=True)
class EvidenceRef:
    """A typed pointer back to primary evidence.

    Every AttackEdge carries a `supporting_evidence[]` of these so an
    analyst can walk from the causal claim ("cmd led to powershell")
    all the way back to the raw CEM event, the graph edge that made
    the parent-child relationship legible, and the two TimelineEvent
    rows the edge connects.
    """

    type: str    # "cem_event" | "graph_edge" | "graph_node" | "timeline_event"
    id: str


@dataclass(frozen=True)
class AttackEdge:
    """A causal or contextual link between two `TimelineEvent`s."""

    id: str
    kind: str                    # parent_of | led_to | same_context
    from_event: str              # TimelineEvent.id
    to_event: str                # TimelineEvent.id
    derivation_rules: Tuple[DerivationRule, ...]
    supporting_evidence: Tuple[EvidenceRef, ...]
    confidence: float            # RELATIONSHIP confidence (not event)
    provenance: Dict[str, Any]   # {source, reason}


@dataclass(frozen=True)
class AttackChain:
    """The full set of causal edges over a Timeline."""

    edges: Tuple[AttackEdge, ...]
    edge_kinds: Dict[str, int] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "edges": [
                {
                    "id": e.id,
                    "kind": e.kind,
                    "from_event": e.from_event,
                    "to_event": e.to_event,
                    "derivation_rules": [
                        {
                            "name": r.name,
                            "observed": r.observed,
                            "detail": r.detail,
                            "weight": r.weight,
                        }
                        for r in e.derivation_rules
                    ],
                    "supporting_evidence": [
                        {"type": ev.type, "id": ev.id}
                        for ev in e.supporting_evidence
                    ],
                    "confidence": e.confidence,
                    "provenance": dict(e.provenance),
                }
                for e in self.edges
            ],
            "edge_count": len(self.edges),
            "edge_kinds": dict(self.edge_kinds),
        }


# ── Internals ────────────────────────────────────────────────────────

def _hash_id(*parts: str) -> str:
    h = hashlib.sha256("::".join(parts).encode("utf-8")).hexdigest()[:12]
    return f"ae-{h}"


def _rule(name: str, observed: Optional[bool], detail: str) -> DerivationRule:
    return DerivationRule(
        name=name, observed=observed, detail=detail,
        weight=_RULE_WEIGHTS[name],
    )


def _confidence(rules: Tuple[DerivationRule, ...],
                 endpoint_min: float) -> float:
    """Edge confidence = weighted score across the rules considered,
    then capped by the weaker endpoint's event confidence.

    Rules that fired (observed=True) contribute their weight to the
    numerator. Rules with observed=None (unverifiable) shrink the
    denominator so an edge that could only *partially* be checked
    doesn't get artificially deflated — but the endpoint cap ensures
    the edge never exceeds the weakest event it links.
    """
    if not rules:
        return 0.0
    fired = sum(r.weight for r in rules if r.observed is True)
    considered = sum(
        r.weight for r in rules if r.observed is not None
    )
    if considered == 0:
        return 0.0
    return min(fired / considered, endpoint_min)


def _shared_host(a: TimelineEvent, b: TimelineEvent,
                  graph: InvestigationGraph) -> DerivationRule:
    """Both actors executed on the same host node in the graph."""
    host_a = _actor_host(a, graph)
    host_b = _actor_host(b, graph)
    if host_a is None or host_b is None:
        return _rule("shared_host", None,
                     "host relationship not resolvable from graph")
    if host_a == host_b:
        return _rule("shared_host", True,
                     f"both actors executed on host node {host_a}")
    return _rule("shared_host", False,
                 f"different hosts: {host_a} vs {host_b}")


def _actor_host(evt: TimelineEvent,
                 graph: InvestigationGraph) -> Optional[str]:
    """Return the host node id the actor executed on for *this specific
    event*.

    The graph may contain multiple `executed_on` edges from the same
    process node (the same image legitimately runs on many hosts).
    We disambiguate by matching the edge's evidence_refs against the
    TimelineEvent's `source_event`.
    """
    if not evt.actor:
        return None
    # Prefer an executed_on edge that references THIS event.
    for edge in graph.edges_from(evt.actor):
        if (edge.relation == "executed_on"
                and evt.source_event in edge.evidence_refs):
            return edge.to_id
    # Fallback: if the process only ever executed on one host in the
    # graph, use it. Multi-host case with no source_event match ⇒
    # unknown (don't guess).
    hosts = {edge.to_id for edge in graph.edges_from(evt.actor)
             if edge.relation == "executed_on"}
    if len(hosts) == 1:
        return next(iter(hosts))
    return None


def _shared_actor(a: TimelineEvent, b: TimelineEvent) -> DerivationRule:
    if a.actor is None or b.actor is None:
        return _rule("shared_actor", None,
                     "one or both events have no resolved actor")
    if a.actor == b.actor:
        return _rule("shared_actor", True,
                     f"both events share actor node {a.actor}")
    return _rule("shared_actor", False,
                 f"different actors: {a.actor} vs {b.actor}")


def _time_delta(a: TimelineEvent,
                 b: TimelineEvent) -> Optional[timedelta]:
    if a.timestamp is None or b.timestamp is None:
        return None
    return b.timestamp - a.timestamp


def _within(a: TimelineEvent, b: TimelineEvent,
             window: timedelta, name: str) -> DerivationRule:
    delta = _time_delta(a, b)
    if delta is None:
        return _rule(name, None,
                     "one or both timestamps unavailable")
    if timedelta(0) <= delta <= window:
        return _rule(name, True,
                     f"gap {delta.total_seconds():.3f}s ≤ "
                     f"{int(window.total_seconds())}s")
    return _rule(name, False,
                 f"gap {delta.total_seconds():.3f}s outside window")


def _time_ordered(a: TimelineEvent, b: TimelineEvent) -> DerivationRule:
    delta = _time_delta(a, b)
    if delta is None:
        return _rule("time_ordered", None,
                     "one or both timestamps unavailable")
    if delta >= timedelta(0):
        return _rule("time_ordered", True,
                     "A.timestamp ≤ B.timestamp")
    return _rule("time_ordered", False,
                 "A.timestamp > B.timestamp (out of order)")


def _graph_child_of(a: TimelineEvent, b: TimelineEvent,
                     graph: InvestigationGraph) -> DerivationRule:
    """Did graph_builder record a `child_of` edge from B's command to
    A's command? If so, we have a *direct* parent→child from the CEM
    event's `parent_command_line` field — the strongest signal."""
    # An A→B parent_of relationship shows up in the graph as an edge
    # from B's command (child) to A's command (parent) with
    # relation="child_of".
    cmd_b = _command_node(b)
    cmd_a = _command_node(a)
    if not cmd_a or not cmd_b:
        return _rule("graph_child_of_edge", None,
                     "one or both events lack a command node")
    for edge in graph.edges_from(cmd_b):
        if edge.relation == "child_of" and edge.to_id == cmd_a:
            return _rule("graph_child_of_edge", True,
                         f"graph edge child_of {cmd_b} → {cmd_a}")
    return _rule("graph_child_of_edge", False,
                 "no child_of edge in graph")


def _command_node(evt: TimelineEvent) -> Optional[str]:
    """Return the event's command graph-node if any (targets contain
    the command for process_create events)."""
    for tid in evt.targets:
        if tid.startswith("command-"):
            return tid
    return None


def _shared_process_tree(a: TimelineEvent, b: TimelineEvent,
                          graph: InvestigationGraph) -> DerivationRule:
    """Are A's actor and B's actor in the same process tree? We walk
    `child_of` edges on the command graph — if either command has an
    ancestor in common with the other's command, they share a tree."""
    cmd_a, cmd_b = _command_node(a), _command_node(b)
    if not cmd_a or not cmd_b:
        return _rule("shared_process_tree", None,
                     "one or both events lack a command node")
    ancestors_a = _walk_ancestors(cmd_a, graph)
    ancestors_b = _walk_ancestors(cmd_b, graph)
    ancestors_a.add(cmd_a)
    ancestors_b.add(cmd_b)
    common = ancestors_a & ancestors_b
    if common:
        return _rule("shared_process_tree", True,
                     f"shared ancestor(s): {sorted(common)[:2]}")
    return _rule("shared_process_tree", False,
                 "no shared ancestor in the graph")


def _walk_ancestors(cmd_id: str, graph: InvestigationGraph,
                     limit: int = 16) -> set:
    """Walk `child_of` edges upward from cmd_id. Bounded to avoid
    pathological cycles (shouldn't happen but defensive)."""
    visited: set = set()
    frontier = [cmd_id]
    while frontier and len(visited) < limit:
        cur = frontier.pop()
        if cur in visited:
            continue
        visited.add(cur)
        for edge in graph.edges_from(cur):
            if edge.relation == "child_of" and edge.to_id not in visited:
                frontier.append(edge.to_id)
    visited.discard(cmd_id)
    return visited


def _supporting_evidence(a: TimelineEvent, b: TimelineEvent,
                          graph: InvestigationGraph,
                          include_graph_edge_relation: Optional[str] = None,
                          ) -> Tuple[EvidenceRef, ...]:
    """Assemble a typed evidence trail for one AttackEdge.

    Always emits (deterministic order):
        cem_event(a.source_event) · cem_event(b.source_event)
        · timeline_event(a.id)   · timeline_event(b.id)
        · graph_node(a.actor)    · graph_node(b.actor)    when present

    When a specific graph relation contributed to the rule (e.g.
    "child_of" for parent_of edges), the matching graph_edge is
    appended so the analyst can jump straight to the exact edge
    graph_builder emitted.
    """
    refs: List[EvidenceRef] = []
    seen: set = set()

    def _push(t: str, i: str) -> None:
        key = (t, i)
        if i and key not in seen:
            seen.add(key)
            refs.append(EvidenceRef(type=t, id=i))

    _push("cem_event", a.source_event)
    _push("cem_event", b.source_event)
    _push("timeline_event", a.id)
    _push("timeline_event", b.id)
    if a.actor:
        _push("graph_node", a.actor)
    if b.actor:
        _push("graph_node", b.actor)

    if include_graph_edge_relation:
        # Find the graph edge (from b's command → a's command) that
        # matches this relation and reference it explicitly.
        cmd_a, cmd_b = _command_node(a), _command_node(b)
        if cmd_a and cmd_b:
            for edge in graph.edges_from(cmd_b):
                if (edge.relation == include_graph_edge_relation
                        and edge.to_id == cmd_a):
                    _push("graph_edge", edge.id)
                    break

    return tuple(refs)


# ── Edge candidate builders ──────────────────────────────────────────

def _try_parent_of(a: TimelineEvent, b: TimelineEvent,
                    graph: InvestigationGraph) -> Optional[AttackEdge]:
    """A `parent_of` edge fires when the graph already recorded a
    `child_of` relationship from B's command → A's command (i.e. A
    was named as B's parent by the CEM adapter)."""
    r_graph = _graph_child_of(a, b, graph)
    if r_graph.observed is not True:
        return None
    r_host  = _shared_host(a, b, graph)
    r_ord   = _time_ordered(a, b)
    rules = (r_graph, r_host, r_ord)
    endpoint_min = min(a.confidence, b.confidence)
    conf = _confidence(rules, endpoint_min)
    return AttackEdge(
        id=_hash_id("parent_of", a.id, b.id),
        kind="parent_of",
        from_event=a.id,
        to_event=b.id,
        derivation_rules=rules,
        supporting_evidence=_supporting_evidence(
            a, b, graph, include_graph_edge_relation="child_of"),
        confidence=conf,
        provenance={
            "source": "attack_chain_builder",
            "reason": "graph.child_of edge recorded by graph_builder",
        },
    )


def _try_led_to(a: TimelineEvent, b: TimelineEvent,
                 graph: InvestigationGraph) -> Optional[AttackEdge]:
    """A `led_to` edge fires when A and B share host + actor + occur
    within 30 s, in order. Weaker than `parent_of` (no explicit
    parent-child in the graph) but still observable."""
    r_actor = _shared_actor(a, b)
    r_host  = _shared_host(a, b, graph)
    r_win   = _within(a, b, DEFAULT_LED_TO_WINDOW, "within_30_seconds")
    r_ord   = _time_ordered(a, b)
    # Required: shared actor + shared host + within window observed
    required = [r_actor, r_host, r_win]
    if not all(r.observed is True for r in required):
        return None
    rules = (r_actor, r_host, r_win, r_ord)
    endpoint_min = min(a.confidence, b.confidence)
    conf = _confidence(rules, endpoint_min)
    return AttackEdge(
        id=_hash_id("led_to", a.id, b.id),
        kind="led_to",
        from_event=a.id,
        to_event=b.id,
        derivation_rules=rules,
        supporting_evidence=_supporting_evidence(a, b, graph),
        confidence=conf,
        provenance={
            "source": "attack_chain_builder",
            "reason": ("shared actor + host + within "
                       f"{int(DEFAULT_LED_TO_WINDOW.total_seconds())}s"),
        },
    )


def _try_same_context(a: TimelineEvent, b: TimelineEvent,
                       graph: InvestigationGraph) -> Optional[AttackEdge]:
    """A weak, wide-window edge — same host + same process tree +
    within 5 minutes. Useful for Correlation to cluster loosely."""
    r_host = _shared_host(a, b, graph)
    r_tree = _shared_process_tree(a, b, graph)
    r_win  = _within(a, b, DEFAULT_SAME_CONTEXT_WINDOW, "within_5_minutes")
    required = [r_host, r_tree, r_win]
    if not all(r.observed is True for r in required):
        return None
    rules = (r_host, r_tree, r_win)
    endpoint_min = min(a.confidence, b.confidence)
    conf = _confidence(rules, endpoint_min)
    return AttackEdge(
        id=_hash_id("same_context", a.id, b.id),
        kind="same_context",
        from_event=a.id,
        to_event=b.id,
        derivation_rules=rules,
        supporting_evidence=_supporting_evidence(a, b, graph),
        confidence=conf,
        provenance={
            "source": "attack_chain_builder",
            "reason": ("shared host + shared process tree + within "
                       f"{int(DEFAULT_SAME_CONTEXT_WINDOW.total_seconds()/60)}m"),
        },
    )


# ── Builder ──────────────────────────────────────────────────────────

def build(timeline: Timeline, graph: InvestigationGraph) -> AttackChain:
    """Derive causal edges from the canonical Timeline.

    O(N²) pairwise scan over `timeline.entries`. Deterministic order:
    the timeline is already sorted chronologically, and edge ids are
    hashed from the event ids so the result is byte-stable given the
    same input.

    Only *forward-in-time* candidates (A before or equal to B in the
    timeline) are considered. Each ordered pair may yield at most one
    edge per kind. Stronger kinds are tested first; if a stronger edge
    fires, the weaker kinds are skipped so the graph is not doubled.
    """
    entries = timeline.entries
    edges: List[AttackEdge] = []
    kinds_counter: Dict[str, int] = {}

    for i, a in enumerate(entries):
        for b in entries[i + 1:]:
            # Try strongest → weakest. First hit wins per (a, b) pair.
            edge = (_try_parent_of(a, b, graph)
                    or _try_led_to(a, b, graph)
                    or _try_same_context(a, b, graph))
            if edge is None:
                continue
            edges.append(edge)
            kinds_counter[edge.kind] = kinds_counter.get(edge.kind, 0) + 1

    edges.sort(key=lambda e: (e.kind, e.from_event, e.to_event, e.id))
    return AttackChain(edges=tuple(edges), edge_kinds=dict(kinds_counter))


__all__ = [
    "SCHEMA_VERSION",
    "AttackChain", "AttackEdge", "DerivationRule", "EvidenceRef",
    "DEFAULT_LED_TO_WINDOW", "DEFAULT_SAME_CONTEXT_WINDOW",
    "build",
]
