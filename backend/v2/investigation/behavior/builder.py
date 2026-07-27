"""Behaviour Graph builder.

Transforms the fired :class:`Intent` set + effective payload into a
normalised :class:`BehaviorGraph`. Command-agnostic and evidence-
anchored — every node reuses the canonical Evidence emitted by the
Intent Layer. No new detection happens here; the builder is a pure
translator between the semantic intent layer and the canonical
behaviour vocabulary.
"""
from __future__ import annotations

import re

from ..evidence import Evidence
from ..intent.models import Intent, IntentAssessment, IntentCategory, RiskBand
from ..intent.rules._chain import find_download_destinations
from .models import (
    BehaviorArg,
    BehaviorArgKind,
    BehaviorEdge,
    BehaviorEdgeKind,
    BehaviorGraph,
    BehaviorKind,
    BehaviorNode,
)

_URL_RE  = re.compile(r"(?i)\bhttps?://[a-z0-9\-._~%!$&()*+,;=:@/?#\[\]]+")
_HOST_RE = re.compile(r"(?i)^https?://([^/:\s]+)")
_REG_RE  = re.compile(r"(?i)HK(?:LM|CU|CR|U|CC)[:\\][^\s\"'`]+")
_IP_RE   = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def _urls_and_hosts(text: str) -> tuple[list[str], list[str]]:
    urls: list[str] = []
    for u in _URL_RE.findall(text or ""):
        if u not in urls:
            urls.append(u)
    hosts: list[str] = []
    for u in urls:
        m = _HOST_RE.match(u)
        if not m:
            continue
        host = m.group(1)
        if host and host not in hosts \
                and not _IP_RE.fullmatch(host):
            hosts.append(host)
    return urls, hosts


def _next_id(seq: list[int]) -> str:
    seq[0] += 1
    return f"b#{seq[0]:03d}"


def _staging_node(intent: Intent, payload: str, seq: list[int]) -> list[BehaviorNode]:
    """A ``staging`` intent maps to a ``DOWNLOAD`` node plus zero-or-
    more ``WRITE_FILE`` nodes (one per destination the pipeline could
    identify). The URL / host / destination are attached as typed args.
    """
    urls, hosts = _urls_and_hosts(payload)
    args: list[BehaviorArg] = []
    for url in urls:
        args.append(BehaviorArg(kind=BehaviorArgKind.URL, value=url))
    for host in hosts:
        args.append(BehaviorArg(kind=BehaviorArgKind.DOMAIN, value=host))

    download = BehaviorNode(
        id=_next_id(seq),
        kind=BehaviorKind.DOWNLOAD,
        purpose="Downloads executable / script content from a remote URL.",
        args=tuple(args),
        evidence=tuple(intent.evidence),
        confidence=intent.confidence,
        mitre_ids=tuple(intent.mitre_ids),
        source_intent=intent.category.value,
    )
    out: list[BehaviorNode] = [download]

    for dest in find_download_destinations(payload):
        target = dest.raw or dest.base
        write = BehaviorNode(
            id=_next_id(seq),
            kind=BehaviorKind.WRITE_FILE,
            purpose=f"Writes downloaded content to disk (`{target}`).",
            args=(BehaviorArg(kind=BehaviorArgKind.FILE, value=target),),
            evidence=tuple(intent.evidence),
            confidence=intent.confidence,
            mitre_ids=tuple(intent.mitre_ids),
            source_intent=intent.category.value,
        )
        out.append(write)
    return out


def _remote_exec_node(intent: Intent, payload: str, seq: list[int]) -> BehaviorNode:
    """A ``remote_execution`` intent maps to ``REMOTE_EXECUTION`` — a
    single node that captures "execute code fetched at runtime"."""
    return BehaviorNode(
        id=_next_id(seq),
        kind=BehaviorKind.REMOTE_EXECUTION,
        purpose="Executes code retrieved from a remote source at runtime.",
        args=(),
        evidence=tuple(intent.evidence),
        confidence=intent.confidence,
        mitre_ids=tuple(intent.mitre_ids),
        source_intent=intent.category.value,
    )


def _execute_nodes(intent: Intent, payload: str,
                    dest_files: list[str], seq: list[int]) -> list[BehaviorNode]:
    """When ``remote_execution`` fires AND the pipeline identified a
    download destination, emit a concrete ``EXECUTE`` node per
    invoked destination. This makes the Download → Write → Execute
    chain explicit in the graph without command-specific logic.
    """
    if not dest_files:
        return []
    nodes: list[BehaviorNode] = []
    for f in dest_files:
        nodes.append(BehaviorNode(
            id=_next_id(seq),
            kind=BehaviorKind.EXECUTE,
            purpose=f"Invokes local file `{f}` as a command.",
            args=(BehaviorArg(kind=BehaviorArgKind.FILE, value=f),),
            evidence=tuple(intent.evidence),
            confidence=intent.confidence,
            mitre_ids=("T1204.002",),
            source_intent=intent.category.value,
        ))
    return nodes


def _persistence_node(intent: Intent, payload: str, seq: list[int]) -> BehaviorNode:
    """A ``persistence`` intent maps to ``PERSISTENCE`` — with the
    registry key / task name / service name attached as an arg when
    the pipeline could identify one deterministically."""
    args: list[BehaviorArg] = []
    for reg in _REG_RE.findall(payload or "")[:3]:
        args.append(BehaviorArg(kind=BehaviorArgKind.REGISTRY, value=reg))
    return BehaviorNode(
        id=_next_id(seq),
        kind=BehaviorKind.PERSISTENCE,
        purpose=("Installs a persistence mechanism that survives reboot "
                  "(registry Run key, scheduled task, or service)."),
        args=tuple(args),
        evidence=tuple(intent.evidence),
        confidence=intent.confidence,
        mitre_ids=tuple(intent.mitre_ids),
        source_intent=intent.category.value,
    )


def _simple_node(intent: Intent, kind: BehaviorKind, purpose: str,
                  seq: list[int]) -> BehaviorNode:
    return BehaviorNode(
        id=_next_id(seq),
        kind=kind,
        purpose=purpose,
        args=(),
        evidence=tuple(intent.evidence),
        confidence=intent.confidence,
        mitre_ids=tuple(intent.mitre_ids),
        source_intent=intent.category.value,
    )


# ── The single translation table intent → behaviour ────────────
# Each intent category emits one or more behaviour nodes. The two
# rich cases (staging / remote_execution) delegate to bespoke
# builders that also attach typed args; every other category maps
# 1:1 onto a canonical behaviour kind.
_SIMPLE_MAPPING: dict[IntentCategory, tuple[BehaviorKind, str]] = {
    IntentCategory.DEFENSE_EVASION: (
        BehaviorKind.DEFENSE_EVASION,
        "Disables or tampers with defensive tooling (AMSI, ETW, Defender).",
    ),
    IntentCategory.DISCOVERY: (
        BehaviorKind.DISCOVERY,
        "Enumerates host / user / directory / network information.",
    ),
    IntentCategory.CREDENTIAL_ACCESS: (
        BehaviorKind.CREDENTIAL_ACCESS,
        "Extracts cached, interactive, or stored credentials.",
    ),
    IntentCategory.RUNTIME_DEPENDENT: (
        BehaviorKind.RUNTIME_DEPENDENT,
        "Final behaviour cannot be determined without runtime data.",
    ),
}


def build(assessment: IntentAssessment,
           effective_payload: str = "") -> BehaviorGraph:
    """Translate an ``IntentAssessment`` into a canonical
    :class:`BehaviorGraph`.

    The builder is a pure function of its inputs — same inputs
    always yield the same graph. Detection remains the Intent
    Layer's responsibility; this module only *normalises* what the
    intent layer already found.
    """
    graph = BehaviorGraph()
    seq: list[int] = [0]   # mutable box for the id sequence

    # ── Deterministic processing order ──────────────────────────
    # Staging (download / write) MUST be processed before
    # Remote Execution so that concrete EXECUTE nodes can be wired
    # to the WRITE_FILE nodes they invoke. Every other intent then
    # falls in behind by (confidence desc, category name).
    _PRIORITY = {
        IntentCategory.STAGING:          0,
        IntentCategory.REMOTE_EXECUTION: 1,
        IntentCategory.PERSISTENCE:      2,
        IntentCategory.DEFENSE_EVASION:  3,
        IntentCategory.CREDENTIAL_ACCESS: 4,
        IntentCategory.DISCOVERY:        5,
        IntentCategory.RUNTIME_DEPENDENT: 6,
    }
    ordered = sorted(assessment.intents,
                      key=lambda i: (_PRIORITY.get(i.category, 99),
                                       -i.confidence,
                                       i.category.value))

    # Track the concrete download destinations so a downstream
    # remote_execution intent can wire EXECUTE(file) nodes to the
    # right WRITE_FILE nodes.
    write_nodes_by_file: dict[str, str] = {}     # file value -> node id
    download_node_id: str | None = None
    remote_exec_node_id: str | None = None
    prior_node_id: str | None = None

    def _append(node: BehaviorNode) -> str:
        graph.nodes.append(node)
        return node.id

    for intent in ordered:
        cat = intent.category
        if cat == IntentCategory.STAGING:
            nodes = _staging_node(intent, effective_payload, seq)
            last_added: str | None = None
            for n in nodes:
                nid = _append(n)
                last_added = nid
                if n.kind == BehaviorKind.DOWNLOAD:
                    download_node_id = nid
                elif n.kind == BehaviorKind.WRITE_FILE:
                    if download_node_id and download_node_id != nid:
                        graph.edges.append(BehaviorEdge(
                            src=download_node_id, dst=nid,
                            kind=BehaviorEdgeKind.WRITES_TO,
                        ))
                    for a in n.args:
                        if a.kind == BehaviorArgKind.FILE:
                            write_nodes_by_file[a.value] = nid
            if download_node_id and prior_node_id and prior_node_id != download_node_id:
                graph.edges.append(BehaviorEdge(
                    src=prior_node_id, dst=download_node_id,
                    kind=BehaviorEdgeKind.THEN,
                ))
            # Chain the NEXT behaviour off the deepest node we just
            # emitted (the last write_file when destinations exist, the
            # download node otherwise) so the sequential `then` edges
            # tell the analyst a coherent story.
            prior_node_id = last_added or download_node_id or prior_node_id

        elif cat == IntentCategory.REMOTE_EXECUTION:
            re_node = _remote_exec_node(intent, effective_payload, seq)
            remote_exec_node_id = _append(re_node)
            if prior_node_id and prior_node_id != remote_exec_node_id:
                graph.edges.append(BehaviorEdge(
                    src=prior_node_id, dst=remote_exec_node_id,
                    kind=BehaviorEdgeKind.THEN,
                ))
            # Wire concrete EXECUTE nodes to the WRITE_FILE nodes
            # they invoke, so the Download → Write → Execute chain
            # is *explicit* in the graph.
            dest_files = list(write_nodes_by_file.keys())
            for exec_node in _execute_nodes(intent, effective_payload,
                                              dest_files, seq):
                eid = _append(exec_node)
                graph.edges.append(BehaviorEdge(
                    src=remote_exec_node_id, dst=eid,
                    kind=BehaviorEdgeKind.EXECUTES,
                ))
                for a in exec_node.args:
                    if a.kind == BehaviorArgKind.FILE and a.value in write_nodes_by_file:
                        graph.edges.append(BehaviorEdge(
                            src=write_nodes_by_file[a.value], dst=eid,
                            kind=BehaviorEdgeKind.EXECUTES,
                        ))
            prior_node_id = remote_exec_node_id

        elif cat == IntentCategory.PERSISTENCE:
            n = _persistence_node(intent, effective_payload, seq)
            nid = _append(n)
            if prior_node_id and prior_node_id != nid:
                graph.edges.append(BehaviorEdge(
                    src=prior_node_id, dst=nid,
                    kind=BehaviorEdgeKind.THEN,
                ))
            prior_node_id = nid

        elif cat in _SIMPLE_MAPPING:
            kind, purpose = _SIMPLE_MAPPING[cat]
            n = _simple_node(intent, kind, purpose, seq)
            nid = _append(n)
            if prior_node_id and prior_node_id != nid:
                graph.edges.append(BehaviorEdge(
                    src=prior_node_id, dst=nid,
                    kind=BehaviorEdgeKind.THEN,
                ))
            prior_node_id = nid
        # Any category outside the mapping is intentionally ignored —
        # a category we cannot yet translate must not silently emit a
        # placeholder behaviour. Fail closed, add a mapping when the
        # Trust Corpus proves the gap.

    return graph


__all__ = ["build"]
