/**
 * NxGraph · entity / causality graph.
 *
 * Deliberately DETERMINISTIC: a layered left-to-right layout, not a physics
 * simulation. Two analysts looking at the same incident must see the same
 * picture, and a node must not drift while it is being read.
 *
 * Cortex XDR's causality vocabulary and Microsoft Defender XDR's graph node
 * categories are the SEMANTIC benchmark — which entity classes must be
 * distinguishable at a glance — but every glyph here is the NivX family.
 *
 * An edge the platform cannot substantiate is drawn dashed and labelled
 * with its basis, so an inferred relationship never looks observed.
 */
import React, { useMemo, useState } from "react";
import NxEntityIcon from "./NxEntityIcon";
import { ENTITY_ICONS } from "./NxEntityIcon";
import "./nx-graph.css";

const NODE_W = 178;
const NODE_H = 46;
const GAP_X = 96;
const GAP_Y = 18;

/**
 * @param nodes [{ id, kind, label, sub?, state? }]
 * @param edges [{ from, to, label?, observed?: boolean }]
 */
export default function NxGraph({ nodes = [], edges = [], rootId = null,
                                  onSelect = null, height = 420,
                                  testid = "nx-graph" }) {
  const [hover, setHover] = useState(null);

  const layout = useMemo(() => {
    if (!nodes.length) return { placed: [], depth: 0 };
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const out = new Map();
    for (const e of edges) {
      if (!out.has(e.from)) out.set(e.from, []);
      out.get(e.from).push(e.to);
    }
    //: Depth = distance from the root. A node with no path from the root is
    //: still shown, in its own column, rather than hidden.
    const level = new Map();
    const start = rootId && byId.has(rootId) ? rootId : nodes[0].id;
    const queue = [[start, 0]];
    while (queue.length) {
      const [id, d] = queue.shift();
      if (level.has(id)) continue;
      level.set(id, d);
      for (const next of out.get(id) || []) {
        if (!level.has(next)) queue.push([next, d + 1]);
      }
    }
    let orphanCol = Math.max(0, ...[...level.values()]) + 1;
    for (const n of nodes) if (!level.has(n.id)) level.set(n.id, orphanCol);

    const columns = new Map();
    for (const n of nodes) {
      const d = level.get(n.id);
      if (!columns.has(d)) columns.set(d, []);
      columns.get(d).push(n);
    }
    const placed = [];
    for (const [d, group] of [...columns.entries()].sort((a, b) => a[0] - b[0])) {
      group.forEach((n, i) => {
        placed.push({
          ...n,
          x: 16 + d * (NODE_W + GAP_X),
          y: 16 + i * (NODE_H + GAP_Y),
        });
      });
    }
    return { placed, depth: columns.size };
  }, [nodes, edges, rootId]);

  if (!nodes.length) {
    return (
      <p className="nx-sec-note" data-testid={`${testid}-empty`}>
        No relationship has been established between the objects in this
        scope. The graph stays empty rather than drawing a plausible one.
      </p>
    );
  }

  const pos = new Map(layout.placed.map((n) => [n.id, n]));
  const width = 32 + layout.depth * (NODE_W + GAP_X);

  return (
    <div className="nx-graph" data-testid={testid} style={{ height }}>
      <svg width={width} height={Math.max(height,
        32 + layout.placed.reduce((m, n) => Math.max(m, n.y + NODE_H), 0))}>
        <g>
          {edges.map((e, i) => {
            const a = pos.get(e.from); const b = pos.get(e.to);
            if (!a || !b) return null;
            const x1 = a.x + NODE_W; const y1 = a.y + NODE_H / 2;
            const x2 = b.x; const y2 = b.y + NODE_H / 2;
            const mid = (x1 + x2) / 2;
            return (
              <g key={`${e.from}-${e.to}-${i}`} className="nx-graph-edge"
                 data-observed={e.observed === false ? "false" : "true"}>
                <path d={`M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`} />
                {e.label && (
                  <text x={mid} y={(y1 + y2) / 2 - 4} textAnchor="middle">
                    {e.label}
                  </text>
                )}
              </g>
            );
          })}
        </g>
        <g>
          {layout.placed.map((n) => (
            <foreignObject key={n.id} x={n.x} y={n.y} width={NODE_W}
                           height={NODE_H}>
              <div className={`nx-graph-node${hover === n.id ? " is-hover" : ""}`}
                   data-nx-entity={n.kind}
                   data-testid={`${testid}-node-${n.id}`}
                   onMouseEnter={() => setHover(n.id)}
                   onMouseLeave={() => setHover(null)}
                   onClick={() => onSelect && onSelect(n)}>
                <NxEntityIcon kind={n.kind} boxed />
                <span className="nx-graph-node-text">
                  <span className="nx-graph-node-label" title={n.label}>
                    {n.label}
                  </span>
                  <span className="nx-graph-node-sub">
                    {n.sub || ENTITY_ICONS[n.kind]?.label || n.kind}
                  </span>
                </span>
              </div>
            </foreignObject>
          ))}
        </g>
      </svg>
    </div>
  );
}
