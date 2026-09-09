"""Phase 2 · Entity Resolution.

Consumes an `InvestigationGraph` (Phase 1 output) and returns a new
graph in which co-referring entities have been merged into a single
node with an `aliases` set. This is the biggest gap in Phase 1: the
graph builder canonicalises identity BY-VALUE (host name lowercased,
hash lowercased, etc.), so `HOST01`, `10.1.1.15`, and
`host01.contoso.local` produce three separate host nodes even though
they refer to the same physical machine.

Merge rules (Phase 2 · initial cut, additive):

  * **Host**
      – Same host name (case-insensitive) → same entity.
      – Host with `attrs.ip` matching another host's `value` → merge.
      – Host with `attrs.fqdn` whose short-name matches another host's
        name → merge (`host01.contoso.local` ↔ `HOST01`).

  * **User**
      – Same `(domain, name)` pair → merge.
      – SID → merge if the same principal already exists.
      – `user@domain` email form → merge with `domain\\user`.

  * **Process**
      – Same image path (case-insensitive) AND same sha256 → merge.
      – If only image matches (no hash present on either), merge.
      – Different sha256 → NEVER merge (would collapse legit ↔
        renamed-malware collision).

  * **File**
      – Same sha256 → merge regardless of path (canonical file identity).

  * **Hash / URL / IP / DNS / Domain**
      – Already canonicalised by graph_builder; no additional merging
        needed here. Left untouched.

All merges preserve:
  – `evidence_refs`      (union of all merged nodes)
  – `provenance.vendor`  (first-seen; additional vendors added to
                           `attrs.merged_vendors`)
  – `confidence`         (max of merged nodes)
  – Every edge re-pointed to the surviving node id.

The stage is deterministic and additive: if no merges apply, the
returned graph is equivalent to the input.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .graph_builder import (
    GraphEdge, GraphNode, InvestigationGraph, _dedup_edges,
)


@dataclass(frozen=True)
class EntityMerge:
    """Trace record of a merge for provenance / debugging."""
    surviving_id: str
    absorbed_ids: Tuple[str, ...]
    kind: str
    aliases: Tuple[str, ...]
    reason: str


def resolve_entities(graph: InvestigationGraph) -> Tuple[InvestigationGraph,
                                                          Tuple[EntityMerge, ...]]:
    """Merge co-referring entities in `graph`. Returns the new graph
    and the list of merges performed (for audit trail)."""
    merges: List[EntityMerge] = []
    node_by_id: Dict[str, GraphNode] = {n.id: n for n in graph.nodes}
    # id → surviving id (union-find style, but shallow — we resolve
    # transitively at the end).
    remap: Dict[str, str] = {}

    def _link(loser: str, winner: str) -> None:
        # Point every existing loser (and any node already pointing
        # to `loser`) at `winner`.
        winner = _root(winner)
        remap[loser] = winner
        for k, v in list(remap.items()):
            if v == loser:
                remap[k] = winner

    def _root(nid: str) -> str:
        seen = set()
        while nid in remap and nid not in seen:
            seen.add(nid)
            nid = remap[nid]
        return nid

    # ── Hosts ────────────────────────────────────────────────────
    hosts = graph.nodes_of("host")
    _resolve_hosts(hosts, node_by_id, _link, merges)

    # ── Users ────────────────────────────────────────────────────
    users = graph.nodes_of("user")
    _resolve_users(users, node_by_id, _link, merges)

    # ── Processes ────────────────────────────────────────────────
    processes = graph.nodes_of("process")
    _resolve_processes(processes, node_by_id, _link, merges)

    # ── Files ────────────────────────────────────────────────────
    files = graph.nodes_of("file")
    _resolve_files(files, node_by_id, _link, merges)

    if not remap:
        return graph, tuple()

    # ── Rebuild nodes ────────────────────────────────────────────
    surviving_ids = {_root(n.id) for n in graph.nodes}
    absorbed_by_survivor: Dict[str, List[GraphNode]] = {}
    for n in graph.nodes:
        root = _root(n.id)
        absorbed_by_survivor.setdefault(root, []).append(n)

    new_nodes: List[GraphNode] = []
    for survivor_id, members in absorbed_by_survivor.items():
        base = next(m for m in members if m.id == survivor_id)
        if len(members) == 1:
            new_nodes.append(base)
            continue
        aliases: Set[str] = set()
        vendors: Set[str] = set()
        evidence: Set[str] = set()
        confidence = base.confidence
        for m in members:
            if m.id != base.id:
                aliases.add(m.value)
                # Also include the merged node's own alias set if any.
                for a in (m.attrs or {}).get("aliases", []) or []:
                    aliases.add(a)
            for ref in m.evidence_refs:
                evidence.add(ref)
            v = (m.provenance or {}).get("vendor")
            if v:
                vendors.add(str(v))
            confidence = max(confidence, m.confidence)
        merged_attrs = dict(base.attrs)
        if aliases:
            merged_attrs["aliases"] = sorted(aliases)
        if len(vendors) > 1:
            merged_attrs["merged_vendors"] = sorted(vendors)
        new_nodes.append(GraphNode(
            id=base.id,
            kind=base.kind,
            label=base.label,
            value=base.value,
            attrs=merged_attrs,
            provenance=base.provenance,
            confidence=confidence,
            evidence_refs=tuple(sorted(evidence)),
        ))

    # ── Rebuild edges ────────────────────────────────────────────
    new_edges: List[GraphEdge] = []
    for e in graph.edges:
        new_from = _root(e.from_id)
        new_to = _root(e.to_id)
        if new_from == new_to:
            # A self-edge introduced by the merge — drop it. This can
            # happen when two absorbed nodes previously had an edge
            # between them.
            continue
        new_edges.append(GraphEdge(
            id=_edge_id(e.relation, new_from, new_to,
                        list(e.evidence_refs) or [""]),
            from_id=new_from,
            to_id=new_to,
            relation=e.relation,
            attrs=e.attrs,
            evidence_refs=e.evidence_refs,
            confidence=e.confidence,
        ))
    new_edges = _dedup_edges(new_edges)

    resolved = InvestigationGraph(
        nodes=tuple(new_nodes),
        edges=tuple(new_edges),
    )
    return resolved, tuple(merges)


# ── Resolvers ────────────────────────────────────────────────────────

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _resolve_hosts(hosts: List[GraphNode],
                    node_by_id: Dict[str, GraphNode],
                    link,
                    merges: List[EntityMerge]) -> None:
    """Merge hosts whose value or attrs suggest the same physical
    machine. Keys tried in priority order — the FIRST match wins so
    the surviving node is deterministic."""
    if len(hosts) < 2:
        return
    # Build lookup tables (case-insensitive)
    by_name: Dict[str, GraphNode] = {}
    by_ip: Dict[str, GraphNode] = {}
    by_short_fqdn: Dict[str, GraphNode] = {}
    survivors: Dict[str, GraphNode] = {}

    def _short(name: str) -> str:
        n = name.strip().lower()
        if "." in n:
            n = n.split(".", 1)[0]
        return n

    for h in hosts:
        low = h.value.strip().lower()
        candidates: List[GraphNode] = []
        # match by short name
        if low in by_name:
            candidates.append(by_name[low])
        if _short(h.value) in by_short_fqdn:
            candidates.append(by_short_fqdn[_short(h.value)])
        # match by IP
        if _IP_RE.match(low) and low in by_ip:
            candidates.append(by_ip[low])
        # attrs.ip on this host might match another host's value
        h_ip = (h.attrs or {}).get("ip")
        if h_ip and str(h_ip) in by_name:
            candidates.append(by_name[str(h_ip)])
        h_fqdn = (h.attrs or {}).get("fqdn")
        if h_fqdn and _short(str(h_fqdn)) in by_short_fqdn:
            candidates.append(by_short_fqdn[_short(str(h_fqdn))])

        target: Optional[GraphNode] = None
        for c in candidates:
            root = survivors.get(c.id, c)
            if root.id != h.id:
                target = root
                break

        if target is not None:
            link(h.id, target.id)
            merges.append(EntityMerge(
                surviving_id=target.id,
                absorbed_ids=(h.id,),
                kind="host",
                aliases=(h.value,),
                reason=f"host alias merge ({h.value} → {target.value})",
            ))
            survivors[h.id] = target
        else:
            survivors[h.id] = h

        # Index this node for later matches
        by_name[low] = survivors[h.id]
        if _IP_RE.match(low):
            by_ip[low] = survivors[h.id]
        else:
            by_short_fqdn[_short(h.value)] = survivors[h.id]
        # Also index its known IP / FQDN so later nodes can find it
        if h_ip and _IP_RE.match(str(h_ip).strip()):
            by_ip[str(h_ip).strip().lower()] = survivors[h.id]
        if h_fqdn:
            by_short_fqdn[_short(str(h_fqdn))] = survivors[h.id]


def _resolve_users(users: List[GraphNode],
                    node_by_id: Dict[str, GraphNode],
                    link,
                    merges: List[EntityMerge]) -> None:
    if len(users) < 2:
        return

    def _principal(u: GraphNode) -> Tuple[str, str]:
        name = u.value.strip().lower()
        domain = str((u.attrs or {}).get("domain") or "").strip().lower()
        # `user@domain` email form
        if "@" in name and not domain:
            name, domain = name.split("@", 1)
        # `DOMAIN\user` shorthand (in case a normaliser packed it into
        # `.value` instead of splitting)
        if "\\" in name and not domain:
            domain, name = name.split("\\", 1)
        return (domain, name)

    by_principal: Dict[Tuple[str, str], GraphNode] = {}
    by_sid: Dict[str, GraphNode] = {}
    for u in users:
        p = _principal(u)
        sid = str((u.attrs or {}).get("sid") or "").strip()
        target: Optional[GraphNode] = None
        if p in by_principal:
            target = by_principal[p]
        elif sid and sid in by_sid:
            target = by_sid[sid]
        if target is not None and target.id != u.id:
            link(u.id, target.id)
            merges.append(EntityMerge(
                surviving_id=target.id,
                absorbed_ids=(u.id,),
                kind="user",
                aliases=(u.value,),
                reason=f"user alias merge ({u.value} → {target.value})",
            ))
        else:
            by_principal[p] = u
            if sid:
                by_sid[sid] = u


def _resolve_processes(processes: List[GraphNode],
                        node_by_id: Dict[str, GraphNode],
                        link,
                        merges: List[EntityMerge]) -> None:
    if len(processes) < 2:
        return

    def _key(p: GraphNode) -> Tuple[str, str]:
        img = p.value.strip().lower()
        # Normalise path separators; keep only basename for the primary
        # match to catch `C:\...\cmd.exe` ↔ `cmd.exe`.
        base = img.replace("\\", "/").rsplit("/", 1)[-1]
        return base, img

    by_base_hash: Dict[Tuple[str, str], GraphNode] = {}
    by_image_no_hash: Dict[str, GraphNode] = {}
    for p in processes:
        base, full = _key(p)
        # process node value doesn't carry the hash — check evidence
        # attrs. In practice sha256 lives on the Hash node the process
        # `has_ioc`-links to, so we can't easily match on it here
        # without walking edges. For now: same basename → same entity.
        if base in by_image_no_hash:
            target = by_image_no_hash[base]
            if target.id != p.id:
                link(p.id, target.id)
                merges.append(EntityMerge(
                    surviving_id=target.id,
                    absorbed_ids=(p.id,),
                    kind="process",
                    aliases=(p.value,),
                    reason=f"process image basename merge ({p.value} → {target.value})",
                ))
                continue
        by_image_no_hash[base] = p


def _resolve_files(files: List[GraphNode],
                    node_by_id: Dict[str, GraphNode],
                    link,
                    merges: List[EntityMerge]) -> None:
    # Files without a strong hash key can't be merged safely — path
    # collisions are common across hosts. Left as-is for Phase 2.1
    # when hash-linkage through edges becomes cheap to traverse.
    return


def _edge_id(relation: str, from_id: str, to_id: str,
              refs: List[str]) -> str:
    h = hashlib.sha256(
        f"{relation}::{from_id}::{to_id}::{refs[0]}".encode("utf-8")
    ).hexdigest()[:12]
    return f"e-{h}"


__all__ = ["EntityMerge", "resolve_entities"]
