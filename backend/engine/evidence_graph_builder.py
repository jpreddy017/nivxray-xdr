"""RC5 · Phase 11.0 — Evidence Graph side-car builder.

Reads an `ExecGraph` and emits an `EvidenceGraph`. **Read-only** on the
`ExecGraph`; **never influences verdicts**. Wire this at the end of the
pipeline via `build_evidence_graph_sidecar(exec_graph)` and attach the
result to your response payload under `evidence_graph`.

Phase 11.0 mapping table (deliberately conservative)
----------------------------------------------------
The table below is the *only* place an `ExecNode` is translated into
evidence-graph entities. Adding rows here is the extension point for
Phase 11.1 (Evidence Graph population).

| ExecNode.kind      | EvidenceNode(kind)                       | Edges emitted                                             |
| ------------------ | ---------------------------------------- | --------------------------------------------------------- |
| script             | Script(sha1 or reconstructed head)       | —                                                         |
| process            | Process(image=cmd_head)                  | Process --executes--> Command (if args["command"] set)     |
| http               | URL, Domain, IP  (whichever known)       | Process --contacts--> URL/Domain/IP                        |
| dns                | Domain                                   | Process --contacts--> Domain                               |
| file               | File(path)                               | Process --creates/reads/writes--> File (from side_effects) |
| registry           | Registry(key)                            | Process --writes--> Registry (from side_effects)           |
| assembly_load      | MemObj(assembly=name)                    | Process --loads--> MemObj                                  |
| reflection         | MemObj(via=reflection)                   | Process --reflects--> MemObj                               |
| decode             | (no evidence node; edge-only if useful)  | source --decodes--> derived (dependsOn on same script)     |

Everything else is intentionally skipped in Phase 11.0. Phase 11.1 will
extend this table; Phase 11.2 will validate that every ExecGraph shape
in the golden corpus produces a well-formed evidence graph.
"""
from __future__ import annotations

import hashlib
import time
import tracemalloc
from typing import Optional, Tuple

from .evidence_graph import (
    EvidenceEdge,
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceNode,
    EvidenceNodeKind,
)
from .evidence_graph_config import (
    EvidenceGraphMetrics,
    evidence_graph_metrics_enabled,
    evidence_graph_mode,
)
from .exec_graph import (
    SCHEMA_VERSION as EXEC_GRAPH_SCHEMA_VERSION,
    ExecGraph,
    ExecNode,
    NodeKind,
    SideEffectVerb,
)


# ---------------------------------------------------------------------------
# Small helpers.
# ---------------------------------------------------------------------------
def _script_key_from(node: ExecNode) -> dict:
    """Content-address a Script by SHA-1 of `reconstructed` (or empty)."""
    body = node.reconstructed or ""
    sha1 = hashlib.sha1(body.encode("utf-8", errors="replace")).hexdigest()
    return {"sha1": sha1}


def _process_key_from(node: ExecNode) -> dict:
    args = node.args or {}
    image = str(args.get("image") or args.get("command") or "").strip()
    # For processes we key by image name only — arguments live on the
    # Command edge / node so identical `powershell.exe` invocations
    # collapse to a single process entity.
    return {"image": image}


def _pick(args: dict, *keys: str) -> Optional[str]:
    for k in keys:
        v = args.get(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return None


# ---------------------------------------------------------------------------
# Side effect verb → edge kind mapping (Phase 11.0 subset).
# ---------------------------------------------------------------------------
_SE_EDGE = {
    SideEffectVerb.create_file:  EvidenceEdgeKind.creates,
    SideEffectVerb.write_file:   EvidenceEdgeKind.writes,
    SideEffectVerb.modify_file:  EvidenceEdgeKind.writes,
    SideEffectVerb.read_file:    EvidenceEdgeKind.reads,
    SideEffectVerb.write_registry: EvidenceEdgeKind.writes,
    SideEffectVerb.read_registry:  EvidenceEdgeKind.reads,
    SideEffectVerb.download:     EvidenceEdgeKind.downloads,
    SideEffectVerb.upload:       EvidenceEdgeKind.uploads,
    SideEffectVerb.inject_process: EvidenceEdgeKind.injects,
    SideEffectVerb.create_process: EvidenceEdgeKind.spawns,
    SideEffectVerb.http_request:   EvidenceEdgeKind.contacts,
    SideEffectVerb.https_request:  EvidenceEdgeKind.contacts,
    SideEffectVerb.dns_query:      EvidenceEdgeKind.contacts,
    SideEffectVerb.tcp_connect:    EvidenceEdgeKind.contacts,
    SideEffectVerb.udp_connect:    EvidenceEdgeKind.contacts,
}


# ---------------------------------------------------------------------------
# Root process — a single stable "unknown host process" that anchors
# script/process/file evidence when we don't have a real process node
# yet. Phase 11.1 will replace this with real process reconstruction.
# ---------------------------------------------------------------------------
def _root_process() -> EvidenceNode:
    return EvidenceNode.build(
        EvidenceNodeKind.process,
        {"image": "<root>"},
        attrs={"synthetic": True},
    )


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
def _build(exec_graph: ExecGraph) -> EvidenceGraph:
    """Pure-function evidence-graph builder (no I/O, no globals)."""
    eg = EvidenceGraph()

    # Anchor everything to a synthetic root process. Phase 11.1 will
    # replace this with real process reconstruction.
    root = _root_process()
    eg = eg.add_node(root)

    # Map ExecNode.id -> EvidenceNode.id for cross-referencing.
    ev_by_exec: dict[str, str] = {}

    # Pass 1: create entity nodes for each ExecNode.
    for xn in exec_graph.nodes:
        ev: Optional[EvidenceNode] = None
        if xn.kind == NodeKind.script:
            ev = EvidenceNode.build(
                EvidenceNodeKind.script,
                _script_key_from(xn),
                attrs={"len": len(xn.reconstructed or "")},
                source_node_ids=(xn.id,),
            )
        elif xn.kind == NodeKind.process:
            ev = EvidenceNode.build(
                EvidenceNodeKind.process,
                _process_key_from(xn),
                source_node_ids=(xn.id,),
            )
        elif xn.kind == NodeKind.http:
            url = _pick(xn.args, "url", "uri")
            host = _pick(xn.args, "host", "domain")
            ip = _pick(xn.args, "ip")
            if url is not None:
                ev = EvidenceNode.build(
                    EvidenceNodeKind.url,
                    {"url": url},
                    source_node_ids=(xn.id,),
                )
            elif host is not None:
                ev = EvidenceNode.build(
                    EvidenceNodeKind.domain,
                    {"domain": host},
                    source_node_ids=(xn.id,),
                )
            elif ip is not None:
                ev = EvidenceNode.build(
                    EvidenceNodeKind.ip,
                    {"ip": ip},
                    source_node_ids=(xn.id,),
                )
        elif xn.kind == NodeKind.dns:
            domain = _pick(xn.args, "domain", "host", "name")
            if domain is not None:
                ev = EvidenceNode.build(
                    EvidenceNodeKind.domain,
                    {"domain": domain},
                    source_node_ids=(xn.id,),
                )
        elif xn.kind == NodeKind.file:
            path = _pick(xn.args, "path", "file")
            if path is not None:
                ev = EvidenceNode.build(
                    EvidenceNodeKind.file,
                    {"path": path},
                    source_node_ids=(xn.id,),
                )
        elif xn.kind == NodeKind.registry:
            key = _pick(xn.args, "key", "path")
            if key is not None:
                ev = EvidenceNode.build(
                    EvidenceNodeKind.registry,
                    {"key": key},
                    source_node_ids=(xn.id,),
                )
        elif xn.kind == NodeKind.assembly_load:
            asm = _pick(xn.args, "assembly", "name") or "<unknown>"
            ev = EvidenceNode.build(
                EvidenceNodeKind.memobj,
                {"assembly": asm},
                source_node_ids=(xn.id,),
            )
        elif xn.kind == NodeKind.reflection:
            target = _pick(xn.args, "target", "assembly", "method") or "<reflection>"
            ev = EvidenceNode.build(
                EvidenceNodeKind.memobj,
                {"reflection": target},
                source_node_ids=(xn.id,),
            )

        if ev is not None:
            eg = eg.add_node(ev)
            ev_by_exec[xn.id] = ev.id

    # Pass 2: derivation edges (`derivedFrom`) between ExecNode inputs and outputs.
    for xn in exec_graph.nodes:
        dst_ev = ev_by_exec.get(xn.id)
        if dst_ev is None:
            continue
        for parent_id in xn.inputs or ():
            src_ev = ev_by_exec.get(parent_id)
            if src_ev is None or src_ev == dst_ev:
                continue
            eg = eg.add_edge(
                EvidenceEdge.build(
                    dst_ev,
                    EvidenceEdgeKind.derived_from,
                    src_ev,
                    source_node_ids=(xn.id, parent_id),
                )
            )

    # Pass 3: side-effect edges. Anchor every side-effect to the
    # nearest process ancestor (transitive over `inputs`) so that the
    # semantics are "the responsible process did X" rather than
    # "the intermediate node did X". Falls back to the synthetic root.
    def _nearest_process(xn: ExecNode) -> str:
        seen: set[str] = set()
        stack: list[str] = list(xn.inputs or ())
        while stack:
            pid = stack.pop()
            if pid in seen:
                continue
            seen.add(pid)
            parent = exec_graph.find(pid)
            if parent is None:
                continue
            if parent.kind == NodeKind.process:
                ev = ev_by_exec.get(parent.id)
                if ev is not None:
                    return ev
            stack.extend(parent.inputs or ())
        return root.id

    for xn in exec_graph.nodes:
        for se in xn.side_effects or ():
            edge_kind = _SE_EDGE.get(se.verb)
            if edge_kind is None:
                continue
            dst_ev = ev_by_exec.get(se.node_id)
            if dst_ev is None:
                # The side-effect points at an ExecNode we didn't
                # materialise in Phase 11.0 (e.g. named_pipe). Skip
                # rather than materialising a placeholder.
                continue
            src_ev = _nearest_process(xn)
            if src_ev == dst_ev:
                continue
            eg = eg.add_edge(
                EvidenceEdge.build(
                    src_ev,
                    edge_kind,
                    dst_ev,
                    attrs={"evidence": se.evidence} if se.evidence else None,
                    source_node_ids=(xn.id,),
                )
            )

    return eg


def build_evidence_graph_sidecar(
    exec_graph: ExecGraph,
    *,
    force: bool = False,
) -> Tuple[Optional[EvidenceGraph], Optional[EvidenceGraphMetrics]]:
    """Public side-car entry point.

    Parameters
    ----------
    exec_graph
        The finalised `ExecGraph` from the RC5 pipeline. Read-only.
    force
        Ignore the `NIVX_EVIDENCE_GRAPH` feature flag and build anyway.
        Only used by tests and CI regression jobs.

    Returns
    -------
    (graph, metrics)
        `graph` is `None` when the feature flag is `"off"` (default) and
        `force=False`. `metrics` is `None` unless
        `NIVX_EVIDENCE_GRAPH_METRICS=on`.
    """
    if not force and evidence_graph_mode() == "off":
        return None, None

    want_metrics = evidence_graph_metrics_enabled() or force

    tracing_here = False
    if want_metrics and not tracemalloc.is_tracing():
        tracemalloc.start()
        tracing_here = True

    t0 = time.perf_counter()
    graph = _build(exec_graph)
    t1 = time.perf_counter()

    peak_kb = 0.0
    if want_metrics:
        _, peak_bytes = tracemalloc.get_traced_memory()
        peak_kb = round(peak_bytes / 1024.0, 3)
        if tracing_here:
            tracemalloc.stop()

    metrics: Optional[EvidenceGraphMetrics] = None
    if want_metrics:
        errors = [e for e in graph.validate_integrity() if not e.startswith("[warn]")]
        metrics = EvidenceGraphMetrics(
            node_count=len(graph.nodes),
            edge_count=len(graph.edges),
            build_ms=round((t1 - t0) * 1000.0, 3),
            peak_memory_kb=peak_kb,
            integrity_errors=len(errors),
            exec_graph_schema_version=EXEC_GRAPH_SCHEMA_VERSION,
            evidence_graph_schema_version=graph.schema_version,
        )
    return graph, metrics


__all__ = ["build_evidence_graph_sidecar"]
