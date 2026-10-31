"""P1-02c · Sprint 2 · Entity correlation + Negative-evidence signals.

  * `entity_correlation_signal(graph)` — groups nodes by any of
    `parent_process_id / process_id / image_hash / image_path /
    user_sid / host_id`. When ≥ 3 attack-chain-eligible nodes share
    an entity, emits a HIGH-class `entity_chain_correlated` signal.

  * `negative_evidence_signals(graph)` — detects mitigating factors:
      - Signed Microsoft binaries (Publisher = "Microsoft Corporation")
      - Internal RFC1918 / link-local / loopback IPs
      - Enterprise-allowlist paths
      - Benign parent processes (`explorer.exe`, `services.exe`, etc.)
      - Known-admin scripts (tag = "admin-script" / "sccm" / "intune")
    Each emits a synthetic `behaviour` node with kind mapped to the
    new `mitigating_signal` (MITIGATING class, weight −1). These
    contributors REDUCE confidence but never override a CRITICAL
    contributor (rule enforced in the verdict engine's cap layer).
"""
from __future__ import annotations

import ipaddress
from typing import Iterable, List, Optional, Set

from nivxforge.investigation.graph import EvidenceGraph, Node


# ────────────────────────── Entity correlation ──────────────────────

_ENTITY_KEYS = ("parent_process_id", "ppid", "process_id", "pid",
                "image_hash", "image_path", "user_sid", "host_id")

_ATTACK_ANCHORS = frozenset({
    "ioc", "lolbin", "behaviour", "family_match", "mitre_technique",
})


def _entities_of(node: Node) -> List[tuple[str, str]]:
    attrs = node.attrs or {}
    out: List[tuple[str, str]] = []
    for k in _ENTITY_KEYS:
        v = attrs.get(k)
        if v is not None and str(v).strip():
            out.append((k, str(v).strip()))
    return out


def entity_correlation_signal(graph: EvidenceGraph) -> Optional[Node]:
    """When ≥ 3 attack-chain-eligible nodes share an entity → HIGH signal."""
    from collections import defaultdict
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for n in graph.nodes:
        if n.kind not in _ATTACK_ANCHORS:
            continue
        for ent in _entities_of(n):
            groups[ent].append(n.id)
    best: Optional[tuple[tuple[str, str], list[str]]] = None
    for ent, nids in groups.items():
        if len(nids) < 3:
            continue
        if best is None or len(nids) > len(best[1]):
            best = (ent, sorted(nids))
    if best is None:
        return None
    (key, val), nids = best
    return Node(
        id=f"SYNTH-ENTITY-{key}-{val[:16]}",
        kind="behaviour",
        label=f"Execution chain · {len(nids)} signals share {key}={val}",
        value="entity_chain_correlated",
        confidence=0.9,
        provenance="verdict-engine/entity-correlation",
        attrs={
            "synthetic": True,
            "signal": "entity_correlation",
            "entity_key": key,
            "entity_value": val,
            "correlated_node_ids": nids,
        },
    )


# ────────────────────────── Negative evidence ────────────────────────

_MICROSOFT_PUBLISHERS = frozenset({
    "microsoft corporation", "microsoft windows",
    "microsoft windows publisher", "microsoft windows hardware compatibility",
})

_ADMIN_TAGS = frozenset({
    "admin-script", "sccm", "intune", "gpo", "wsus", "config-manager",
    "corporate-tool", "enterprise-allowlist",
})

_BENIGN_PARENTS = frozenset({
    "explorer.exe", "services.exe", "svchost.exe",
    "system", "wininit.exe", "smss.exe",
})


def _is_internal_ip(v: str) -> bool:
    try:
        ip = ipaddress.ip_address(v)
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False


def negative_evidence_signals(graph: EvidenceGraph) -> List[Node]:
    """Detect mitigating factors on the existing graph nodes."""
    out: List[Node] = []
    seen_ids: Set[str] = set()

    def _add(nid: str, label: str, subkind: str, refs: List[str], conf: float):
        if nid in seen_ids:
            return
        seen_ids.add(nid)
        out.append(Node(
            id=nid, kind="behaviour",
            label=label, value="mitigating_signal",
            confidence=conf,
            provenance="verdict-engine/negative-evidence",
            attrs={
                "synthetic": True,
                "signal": "negative_evidence",
                "subkind": subkind,
                "supporting_node_ids": refs,
            },
        ))

    for n in graph.nodes:
        attrs = n.attrs or {}
        # 1) Signed Microsoft binary
        pub = str(attrs.get("publisher") or attrs.get("signer") or "").lower()
        if pub and any(mp in pub for mp in _MICROSOFT_PUBLISHERS):
            _add(f"SYNTH-NEG-MSSIGNED-{n.id}",
                 f"Signed by Microsoft · {pub}", "signed_microsoft_binary",
                 [n.id], 0.9)

        # 2) Internal IP
        if n.kind == "ioc" and (attrs.get("ioc_kind") or "").lower() == "ip":
            if _is_internal_ip(n.value or ""):
                _add(f"SYNTH-NEG-INTERNALIP-{n.id}",
                     f"Internal / private IP · {n.value}", "internal_ip",
                     [n.id], 0.85)

        # 3) Enterprise / admin tag
        tags = [str(t).lower() for t in (attrs.get("tags") or [])]
        matched_tag = next((t for t in tags if t in _ADMIN_TAGS), None)
        if matched_tag:
            _add(f"SYNTH-NEG-ADMIN-{n.id}",
                 f"Enterprise-allowlist tag · {matched_tag}",
                 "enterprise_allowlist", [n.id], 0.75)

        # 4) Benign parent process
        parent = str(attrs.get("parent_image") or attrs.get("parent_process")
                     or "").lower()
        if parent:
            leaf = parent.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            if leaf in _BENIGN_PARENTS:
                _add(f"SYNTH-NEG-PARENT-{n.id}",
                     f"Benign parent process · {leaf}", "benign_parent",
                     [n.id], 0.7)
    return out


def attach_entity_and_negative_signals(graph: EvidenceGraph) -> List[str]:
    """Attach entity + negative signals. Idempotent."""
    added: List[str] = []
    existing = {n.id for n in graph.nodes}
    ent = entity_correlation_signal(graph)
    if ent and ent.id not in existing:
        graph.add_node(ent)
        added.append(ent.id)
    for neg in negative_evidence_signals(graph):
        if neg.id in existing:
            continue
        graph.add_node(neg)
        added.append(neg.id)
    return added


__all__ = [
    "entity_correlation_signal",
    "negative_evidence_signals",
    "attach_entity_and_negative_signals",
]
