import dagre from "dagre";

/**
 * Auto-layout nodes/edges using dagre. Returns nodes with `.position` set,
 * edges unchanged. Direction: LR (analyst-readable, default) or TB.
 * Ranks/nodes are spaced to leave room for the icon + two-line label of
 * StageNode (200 × 84 by default).
 */
export function layoutGraph({ nodes, edges, direction = "LR", nodeWidth = 220, nodeHeight = 92 }) {
  if (!nodes || nodes.length === 0) return { nodes: [], edges: edges || [] };

  const g = new dagre.graphlib.Graph({ multigraph: true });
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({
    rankdir: direction,
    nodesep: direction === "LR" ? 40 : 32,
    ranksep: direction === "LR" ? 100 : 80,
    edgesep: 20,
    marginx: 24,
    marginy: 24,
  });

  nodes.forEach((n) => {
    g.setNode(n.id, {
      width: n.width || nodeWidth,
      height: n.height || nodeHeight,
    });
  });
  edges.forEach((e, i) => {
    g.setEdge(e.source, e.target, {}, `${e.id || i}`);
  });

  dagre.layout(g);

  const laidOut = nodes.map((n) => {
    const pos = g.node(n.id);
    if (!pos) return { ...n, position: { x: 0, y: 0 } };
    return {
      ...n,
      position: {
        x: pos.x - (n.width || nodeWidth) / 2,
        y: pos.y - (n.height || nodeHeight) / 2,
      },
    };
  });

  return { nodes: laidOut, edges };
}
