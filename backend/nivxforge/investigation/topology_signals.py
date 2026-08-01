"""P1-02c · Sprint 1 · Graph topology + temporal correlation signals.

Two pure functions that turn structural properties of the Evidence
Graph into first-class contributors — no fork, no engine change,
just observations the verdict engine folds through the same tiered
class model.

  * `graph_topology_signal(graph)` — longest `contributes_to /
    produces / supports / derived_from / escalates_to` chain depth.
    Depth ≥ 3 emits a HIGH-class synthetic contributor
    `execution_chain_correlated`. Chain of length ≥ 5 tags it as an
    attack-chain kind → participates in escalation rules.

  * `temporal_correlation_signal(graph)` — inspects `attrs.timestamp`
    on nodes. When ≥ 2 attack-chain-eligible nodes fire within 60 s
    of each other, emits a HIGH-class synthetic contributor
    `temporal_burst`. Uses a monotonic bonus schedule (never lowers
    confidence).

Both signals are attached to the graph as SYNTHETIC nodes with
`kind='behaviour'` so they flow through the existing
`_kind_for_graph_node` mapper — and appear in `verdict.contributors`
with `source='graph'`, fully traceable.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, List, Optional

from nivxforge.investigation.graph import EvidenceGraph, Node


# Edges that indicate a real causal / evidentiary chain (not
# `contradicts` which weakens rather than propagates).
_CHAIN_EDGES = frozenset({
    "produces", "contributes_to", "supports", "derived_from", "escalates_to",
})

# Nodes that ANCHOR an attack chain (kinds worth pathing through).
_CHAIN_ANCHOR_KINDS = frozenset({
    "decoded_fragment", "ioc", "lolbin", "family_match",
    "behaviour", "mitre_technique",
})


def _longest_chain_depth(graph: EvidenceGraph) -> tuple[int, List[str]]:
    """Return `(depth, path_node_ids)` — the deepest chain through
    causal edges, restricted to anchor kinds.

    Pure DFS with memoisation. Deterministic (nodes iterated in id order).
    """
    node_by_id = {n.id: n for n in graph.nodes}
    adj: dict[str, list[str]] = {n.id: [] for n in graph.nodes}
    for e in graph.edges:
        if e.kind in _CHAIN_EDGES and e.source in node_by_id and e.target in node_by_id:
            adj[e.source].append(e.target)
    for k in adj:
        adj[k].sort()

    memo: dict[str, tuple[int, List[str]]] = {}

    def dfs(nid: str, seen: frozenset[str]) -> tuple[int, List[str]]:
        if nid in memo:
            return memo[nid]
        best_depth, best_path = 1, [nid]
        for child in adj[nid]:
            if child in seen:
                continue
            n = node_by_id.get(child)
            if not n or n.kind not in _CHAIN_ANCHOR_KINDS:
                continue
            d, p = dfs(child, seen | {child})
            if 1 + d > best_depth:
                best_depth, best_path = 1 + d, [nid] + p
        memo[nid] = (best_depth, best_path)
        return memo[nid]

    overall_depth, overall_path = 0, []
    for n in sorted(graph.nodes, key=lambda x: x.id):
        if n.kind not in _CHAIN_ANCHOR_KINDS:
            continue
        d, p = dfs(n.id, frozenset({n.id}))
        if d > overall_depth:
            overall_depth, overall_path = d, p
    return overall_depth, overall_path


def graph_topology_signal(graph: EvidenceGraph) -> Optional[Node]:
    """Return a synthetic behaviour node summarising the longest chain,
    or `None` if the graph has no chain worth citing (depth < 3, or the
    chain contains no attack-chain-eligible kinds — benign decode
    ladders no longer trigger this signal).
    """
    depth, path = _longest_chain_depth(graph)
    if depth < 3:
        return None
    # Sprint 1 fix · require the chain to include at least one
    # attack-worthy kind (LOLBIN / IOC / MITRE / family / behaviour with
    # an execution semantic). A pure "layer0 → layer1 → layer2 → …"
    # decode ladder on a benign echo string must NOT trigger.
    node_by_id = {n.id: n for n in graph.nodes}
    attack_kinds = frozenset({"lolbin", "family_match", "mitre_technique"})
    saw_attack_kind = False
    for nid in path:
        n = node_by_id.get(nid)
        if not n:
            continue
        if n.kind in attack_kinds:
            saw_attack_kind = True
            break
        if n.kind == "ioc":
            ik = ((n.attrs or {}).get("ioc_kind") or "").lower()
            if ik in ("url", "domain", "ip", "hash", "sha256", "sha1", "md5"):
                saw_attack_kind = True
                break
        if n.kind == "behaviour":
            # execution-semantic behaviour labels
            lbl = (n.label or "").lower() + " " + (n.value or "").lower()
            if any(k in lbl for k in ("shellcode", "beacon", "download", "persist",
                                       "credential", "lateral", "reflect")):
                saw_attack_kind = True
                break
    if not saw_attack_kind:
        return None
    # Chains of 5+ are strong enough to participate in escalation rules.
    if depth >= 5:
        label = f"Execution chain · {depth} correlated stages"
        conf = 0.95
    elif depth == 4:
        label = f"Execution chain · {depth} correlated stages"
        conf = 0.9
    else:
        label = f"Correlated evidence chain · {depth} stages"
        conf = 0.8
    return Node(
        id=f"SYNTH-CHAIN-{depth}",
        kind="behaviour",
        label=label,
        value="execution_chain_correlated",
        confidence=conf,
        provenance="verdict-engine/graph-topology",
        attrs={
            "synthetic": True,
            "signal": "graph_topology",
            "chain_depth": depth,
            "chain_path": path,
        },
    )


# ─── Temporal correlation ─────────────────────────────────────────────

_TEMPORAL_ANCHOR_KINDS = frozenset({
    "ioc", "lolbin", "behaviour", "mitre_technique", "family_match",
})


def _parse_ts(v) -> Optional[datetime]:
    """Best-effort ISO-8601 / epoch parser."""
    if v is None:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, (int, float)):
        try:
            return datetime.fromtimestamp(float(v), tz=timezone.utc)
        except Exception:  # noqa: BLE001
            return None
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        # Python accepts "2026-02-01T12:34:56Z" only via fromisoformat with Z→+00:00.
        s2 = s.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(s2)
        except Exception:  # noqa: BLE001
            try:
                return datetime.fromtimestamp(float(s), tz=timezone.utc)
            except Exception:  # noqa: BLE001
                return None
    return None


def _collect_timestamps(graph: EvidenceGraph) -> List[tuple[str, datetime]]:
    out: List[tuple[str, datetime]] = []
    for n in graph.nodes:
        if n.kind not in _TEMPORAL_ANCHOR_KINDS:
            continue
        attrs = n.attrs or {}
        ts = attrs.get("timestamp") or attrs.get("ts") or attrs.get("event_time")
        dt = _parse_ts(ts)
        if dt is not None:
            out.append((n.id, dt))
    out.sort(key=lambda p: p[1])
    return out


def temporal_correlation_signal(graph: EvidenceGraph) -> Optional[Node]:
    """When ≥ 2 attack-chain-eligible nodes fire within 60 s of each
    other, emit a HIGH-class synthetic node."""
    ts_list = _collect_timestamps(graph)
    if len(ts_list) < 2:
        return None
    # Sliding window: max cluster within 60 s.
    best_cluster: List[tuple[str, datetime]] = []
    for i, (nid, dt) in enumerate(ts_list):
        cluster = [(nid, dt)]
        for j in range(i + 1, len(ts_list)):
            if (ts_list[j][1] - dt).total_seconds() <= 60.0:
                cluster.append(ts_list[j])
            else:
                break
        if len(cluster) > len(best_cluster):
            best_cluster = cluster
    if len(best_cluster) < 2:
        return None
    span_s = (best_cluster[-1][1] - best_cluster[0][1]).total_seconds()
    if span_s <= 10:
        conf, tier_word = 0.95, "<10s"
    elif span_s <= 60:
        conf, tier_word = 0.90, "<60s"
    elif span_s <= 300:
        conf, tier_word = 0.75, "<5m"
    else:
        return None
    return Node(
        id=f"SYNTH-TIME-{len(best_cluster)}-{int(span_s)}s",
        kind="behaviour",
        label=f"Temporal burst · {len(best_cluster)} signals in {tier_word}",
        value="temporal_burst",
        confidence=conf,
        provenance="verdict-engine/temporal-correlation",
        attrs={
            "synthetic": True,
            "signal": "temporal_correlation",
            "cluster_size": len(best_cluster),
            "cluster_span_s": span_s,
            "cluster_node_ids": [nid for nid, _ in best_cluster],
        },
    )


def attach_topology_and_temporal_signals(graph: EvidenceGraph) -> List[str]:
    """Attach synthetic behaviour nodes to the graph. Returns the ids
    that were added (empty list if none). Idempotent — running twice
    doesn't duplicate nodes."""
    added: List[str] = []
    existing = {n.id for n in graph.nodes}
    for signal in (graph_topology_signal(graph), temporal_correlation_signal(graph)):
        if signal is None or signal.id in existing:
            continue
        graph.add_node(signal)
        added.append(signal.id)
    return added


__all__ = [
    "graph_topology_signal",
    "temporal_correlation_signal",
    "attach_topology_and_temporal_signals",
]
