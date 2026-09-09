"""NivXRay Threat-Model Assessor — Mermaid parser (Feb 2026).

Accepts either:

    * ``graph TD`` / ``graph LR`` component diagrams — nodes are services,
      edges are calls / data-flows.
    * ``flowchart TD`` DFDs with trust-boundary annotations. Analysts tag a
      node's zone via a bracketed suffix on the node label, e.g.::

          User[[EXT]] --> LB[[DMZ]]
          LB --> API[[INT]]
          API --> DB[[INT]] & Cache[[INT]]

      Recognised zones: ``EXT`` (external / internet), ``DMZ`` (perimeter),
      ``INT`` (internal / trusted), ``DATA`` (data-plane / sensitive store).
      Any edge that CROSSES a trust boundary is flagged for STRIDE analysis.

The parser is DELIBERATELY tolerant — it never raises on malformed input.
Anything it can't parse is dropped with a warning attached to the report,
and the caller falls back to whatever partial graph was recovered. This
matches the platform-wide "deterministic core is the source of truth"
discipline: parser failures degrade gracefully, not catastrophically.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

ALLOWED_ZONES = ("EXT", "DMZ", "INT", "DATA")


@dataclass
class MermaidNode:
    id: str
    label: str = ""
    zone: Optional[str] = None
    kind: Optional[str] = None  # inferred later (web/api/db/cache/queue/...)

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {"id": self.id, "label": self.label,
                "zone": self.zone, "kind": self.kind}


@dataclass
class MermaidEdge:
    src: str
    dst: str
    label: str = ""
    kind: str = "call"  # call | data | trust-boundary

    def to_dict(self) -> Dict[str, str]:
        return {"src": self.src, "dst": self.dst,
                "label": self.label, "kind": self.kind}


@dataclass
class ParsedDiagram:
    direction: str = "TD"        # TD | LR | BT | RL
    nodes: Dict[str, MermaidNode] = field(default_factory=dict)
    edges: List[MermaidEdge] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "direction": self.direction,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "warnings": list(self.warnings),
        }


# ─── Line-level parsers ──────────────────────────────────────────────────
_HEADER_RE = re.compile(
    r"^\s*(?:graph|flowchart)\s+(TD|TB|BT|LR|RL)\s*$", re.IGNORECASE)
# node syntax: ID, ID[label], ID(label), ID((label)), ID{{label}}, ID>label], ID{label}
_NODE_INLINE_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_\-]*)\s*"
    r"(?:\[\[([^\]]+?)\]\]"
    r"|\{\{([^}]+?)\}\}"
    r"|\[([^\]]+?)\]"
    r"|\(\(([^)]+?)\)\)"
    r"|\(([^)]+?)\)"
    r"|\{([^}]+?)\}"
    r")?"
)
# edge syntax:  A --> B    A --- B    A -.-> B    A ==> B    A -->|label| B
_EDGE_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_\-]*)"
    r"(?:\[\[([^\]]+?)\]\]|\{\{([^}]+?)\}\}|\[([^\]]+?)\]|\(([^)]+?)\)|\{([^}]+?)\})?"
    r"\s*(?:--?[-=.]?>?|==+>?|-\.-+>?|--\|.*?\|)\s*"
    r"(?:\|([^|]+?)\|\s*)?"
    r"([A-Za-z_][A-Za-z0-9_\-]*)"
    r"(?:\[\[([^\]]+?)\]\]|\{\{([^}]+?)\}\}|\[([^\]]+?)\]|\(([^)]+?)\)|\{([^}]+?)\})?"
)

_ZONE_TAG_RE = re.compile(r"^(.*?)\s*\[\[(" + "|".join(ALLOWED_ZONES) + r")\]\]\s*$")


def _extract_zone(label: str) -> Tuple[str, Optional[str]]:
    """If the label carries a `[[EXT|DMZ|INT|DATA]]` trailing tag, split it.

    NOTE: an alternative encoding is the mermaid double-bracket node
    (`ID[[X]]`) which we treat as a zone marker regardless of position.
    """
    if not label:
        return "", None
    m = _ZONE_TAG_RE.match(label)
    if m:
        return m.group(1).strip(), m.group(2)
    return label, None


def _upsert_node(diag: ParsedDiagram, node_id: str, raw_label: str) -> MermaidNode:
    label, zone = _extract_zone(raw_label)
    # When the raw_label is a zone marker (`ID[[EXT]]`), the label should
    # default to the node ID — not the zone string.
    if raw_label in ALLOWED_ZONES:
        zone = raw_label
        label = ""
    if node_id in diag.nodes:
        n = diag.nodes[node_id]
        if label and (not n.label or n.label == n.id):
            n.label = label
        if zone and not n.zone:
            n.zone = zone
        return n
    n = MermaidNode(id=node_id, label=(label or node_id), zone=zone)
    diag.nodes[node_id] = n
    return n


def _first_group(m: re.Match, indices: List[int]) -> Optional[str]:
    for i in indices:
        v = m.group(i)
        if v:
            return v
    return None


def parse_mermaid(source: str) -> ParsedDiagram:
    """Parse a Mermaid diagram string and return the structured graph.

    NEVER raises. Malformed lines are dropped with a warning entry.
    """
    diag = ParsedDiagram()
    if not source or not source.strip():
        diag.warnings.append("empty input")
        return diag

    # Strip fenced code blocks: ```mermaid ... ```
    src = source.strip()
    src = re.sub(r"^```(?:mermaid)?\s*\n", "", src, count=1)
    src = re.sub(r"\n```\s*$", "", src, count=1)

    for raw_line in src.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("%%"):    # mermaid comment
            continue

        m = _HEADER_RE.match(line)
        if m:
            diag.direction = m.group(1).upper()
            continue

        # subgraph headers — record as a group but not enforced structurally
        if re.match(r"^subgraph\b", line, re.IGNORECASE) or line.lower() == "end":
            continue

        # Try edge first (it matches strict prefix of node-only line otherwise)
        if re.search(r"--?[-=.]?>|==+>?|-\.-+>", line):
            # Feb 2026 — support chained arrows in a single line:
            #     A --> B --> C
            # and the `&` shorthand for multiple sources / dests:
            #     A & B --> C
            #     A --> B & C
            # Split the line into edge segments joined by arrow-tokens.
            _ARROW_TOKEN = r"(?:--?[-=.]?>|==+>?|-\.-+>)(?:\|[^|]*\|)?"
            arrow_iter = list(re.finditer(_ARROW_TOKEN, line))
            if arrow_iter:
                # Extract quoted-or-bare node segments between arrows.
                segments: List[str] = []
                prev = 0
                for a in arrow_iter:
                    segments.append(line[prev:a.start()])
                    prev = a.end()
                segments.append(line[prev:])

                # Parse each segment for one or more nodes separated by `&`.
                def _parse_node_segment(seg: str) -> List[Tuple[str, str]]:
                    # returns list of (id, raw_label)
                    hits: List[Tuple[str, str]] = []
                    for part in re.split(r"\s*&\s*", seg.strip()):
                        m = _NODE_INLINE_RE.search(part)
                        if not m:
                            continue
                        nid = m.group(1)
                        lbl = _first_group(m, [2, 3, 4, 5, 6, 7]) or ""
                        if nid:
                            hits.append((nid, lbl))
                    return hits

                node_segments = [_parse_node_segment(seg) for seg in segments]
                if all(node_segments) and len(node_segments) >= 2:
                    # Extract per-arrow labels (`-->|HTTPS| B`).
                    arrow_labels: List[str] = []
                    for a in arrow_iter:
                        tok = a.group(0)
                        lm = re.match(r"^.*?\|([^|]*)\|\s*$", tok)
                        arrow_labels.append(lm.group(1).strip() if lm else "")
                    # Emit edges between every consecutive pair of segments,
                    # cartesian across `&` shorthand.
                    for i, (prev_seg, next_seg) in enumerate(
                            zip(node_segments, node_segments[1:])):
                        lbl = arrow_labels[i] if i < len(arrow_labels) else ""
                        for pid, plbl in prev_seg:
                            _upsert_node(diag, pid, plbl)
                        for nid, nlbl in next_seg:
                            _upsert_node(diag, nid, nlbl)
                        for pid, _ in prev_seg:
                            for nid, _ in next_seg:
                                diag.edges.append(MermaidEdge(
                                    src=pid, dst=nid, label=lbl, kind="call",
                                ))
                    continue
            # Fall-through — single edge legacy path.
            em = _EDGE_RE.search(line)
            if em:
                src_id = em.group(1)
                src_label = _first_group(em, [2, 3, 4, 5, 6]) or ""
                edge_label = em.group(7) or ""
                dst_id = em.group(8)
                dst_label = _first_group(em, [9, 10, 11, 12, 13]) or ""
                _upsert_node(diag, src_id, src_label)
                _upsert_node(diag, dst_id, dst_label)
                diag.edges.append(MermaidEdge(
                    src=src_id, dst=dst_id, label=edge_label.strip(), kind="call",
                ))
                continue

        # Otherwise try node-only line: e.g. `LB[[DMZ]]` or `DB[(Postgres)]`
        for nm in _NODE_INLINE_RE.finditer(line):
            nid = nm.group(1)
            label = _first_group(nm, [2, 3, 4, 5, 6, 7]) or ""
            if nid and (label or nid not in diag.nodes):
                _upsert_node(diag, nid, label)

    # Post-pass: mark edges that cross trust boundaries.
    for e in diag.edges:
        src = diag.nodes.get(e.src)
        dst = diag.nodes.get(e.dst)
        if src and dst and src.zone and dst.zone and src.zone != dst.zone:
            e.kind = "trust-boundary"

    return diag
