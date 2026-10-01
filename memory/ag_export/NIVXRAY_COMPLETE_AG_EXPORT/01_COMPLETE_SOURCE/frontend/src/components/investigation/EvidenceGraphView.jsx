/**
 * EvidenceGraphView — Phase 4 · P1.
 *
 * SVG-based force-directed evidence graph. Deterministic layout — no
 * physics simulation library (keeps the bundle small). Nodes are laid out
 * in concentric rings anchored on the root node; IOC satellites orbit
 * their owning case node.
 */
import { useMemo, useState } from "react";
import { Network as NetIcon } from "lucide-react";

const NODE_COLOR = {
  case:     "#67e8f9",
  artifact: "#c4b5fd",
  ioc:      "#94a3b8",
};

export default function EvidenceGraphView({ graph }) {
  const [hover, setHover] = useState(null);
  const layout = useMemo(() => computeLayout(graph), [graph]);
  if (!graph || !graph.nodes || graph.nodes.length === 0) {
    return (
      <div data-testid="graph-empty"
           style={{ padding: 40, textAlign: "center", color: "#64748b",
                    background: "rgba(2,6,23,0.5)",
                    border: "1px dashed rgba(148,163,184,0.14)",
                    borderRadius: 10, fontSize: 12 }}>
        No evidence graph yet.
      </div>
    );
  }
  const w = 780, h = 480;
  return (
    <div data-testid="evidence-graph"
         style={{ background: "rgba(2,6,23,0.7)",
                  border: "1px solid rgba(148,163,184,0.16)",
                  borderRadius: 10, padding: 14 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8,
                    marginBottom: 8, color: "#94a3b8",
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: 10, letterSpacing: "0.12em",
                    textTransform: "uppercase" }}>
        <NetIcon size={12} /> Evidence Graph · {graph.node_count} nodes · {graph.edge_count} edges
      </div>
      <svg viewBox={`0 0 ${w} ${h}`}
           style={{ width: "100%", height: h,
                    background: "radial-gradient(circle at center, rgba(15,23,42,0.9), rgba(2,6,23,0.95))",
                    borderRadius: 8 }}>
        {(graph.edges || []).map((e, i) => {
          const a = layout.pos[e.from]; const b = layout.pos[e.to];
          if (!a || !b) return null;
          const isChain = e.kind === "chain";
          const isHov = hover && (hover === e.from || hover === e.to);
          return (
            <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                  stroke={isChain ? "rgba(103,232,249,0.55)" : "rgba(148,163,184,0.35)"}
                  strokeWidth={isHov ? 2 : 1}
                  strokeDasharray={isChain ? "0" : "3 3"} />
          );
        })}
        {(graph.nodes || []).map((n) => {
          const p = layout.pos[n.id]; if (!p) return null;
          const r = n.kind === "case" ? 14 : (n.kind === "artifact" ? 10 : 6);
          const fill = NODE_COLOR[n.kind] || "#94a3b8";
          const isHov = hover === n.id;
          return (
            <g key={n.id}
               onMouseEnter={() => setHover(n.id)}
               onMouseLeave={() => setHover(null)}
               style={{ cursor: "pointer" }}
               data-testid={`graph-node-${n.id}`}>
              <circle cx={p.x} cy={p.y} r={r}
                      fill={fill} opacity={isHov ? 1 : 0.85}
                      stroke={isHov ? "#fff" : "rgba(2,6,23,0.9)"}
                      strokeWidth={isHov ? 2 : 1.5} />
              {(n.kind === "case" || n.kind === "artifact") && (
                <text x={p.x} y={p.y + r + 12}
                      textAnchor="middle" fill="#cbd5e1" fontSize={9}
                      fontFamily="JetBrains Mono, monospace"
                      style={{ pointerEvents: "none" }}>
                  {(n.label || n.id).slice(0, 22)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <Legend />
      {hover && layout.byId[hover] && (
        <HoverCard node={layout.byId[hover]} />
      )}
    </div>
  );
}

function Legend() {
  return (
    <div style={{ marginTop: 8, display: "flex", gap: 14,
                  color: "#64748b", fontFamily: "JetBrains Mono, monospace",
                  fontSize: 10 }}>
      <LegendDot color={NODE_COLOR.case}     label="Case" />
      <LegendDot color={NODE_COLOR.artifact} label="Artifact" />
      <LegendDot color={NODE_COLOR.ioc}      label="IOC" />
      <span style={{ marginLeft: "auto" }}>
        <span style={{ color: "#67e8f9" }}>—</span> chain edge &nbsp;·&nbsp;
        <span style={{ color: "#94a3b8" }}>- -</span> IOC satellite
      </span>
    </div>
  );
}

function LegendDot({ color, label }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
      <span style={{ width: 8, height: 8, borderRadius: "50%",
                     background: color, display: "inline-block" }} />
      {label}
    </span>
  );
}

function HoverCard({ node }) {
  return (
    <div style={{ marginTop: 10, padding: 10,
                  background: "rgba(15,23,42,0.85)",
                  border: "1px solid rgba(103,232,249,0.30)",
                  borderRadius: 6, fontSize: 11,
                  fontFamily: "JetBrains Mono, monospace",
                  color: "#e2e8f0" }}>
      <div style={{ color: "#67e8f9", fontSize: 10, letterSpacing: "0.10em",
                    textTransform: "uppercase", marginBottom: 4 }}>
        {node.kind}
        {node.artifact_type ? ` · ${node.artifact_type}` : ""}
        {node.ioc_kind ? ` · ${node.ioc_kind}` : ""}
      </div>
      <div style={{ wordBreak: "break-all" }}>{node.label}</div>
      {node.verdict && (
        <div style={{ marginTop: 3, color: "#94a3b8" }}>
          Verdict: <span style={{ color: "#e2e8f0" }}>{node.verdict}</span>
        </div>
      )}
    </div>
  );
}

/**
 * Deterministic layout — concentric rings.
 *   - Case nodes: outer ring (or inner if only one)
 *   - Artifact nodes: middle ring near their parent
 *   - IOC nodes: outermost ring, orbiting their owning case
 */
function computeLayout(graph) {
  const pos = {}; const byId = {};
  if (!graph || !graph.nodes) return { pos, byId };
  const w = 780, h = 480, cx = w / 2, cy = h / 2;

  const cases     = graph.nodes.filter(n => n.kind === "case");
  const artifacts = graph.nodes.filter(n => n.kind === "artifact");
  const iocs      = graph.nodes.filter(n => n.kind === "ioc");

  cases.forEach((n, i) => {
    byId[n.id] = n;
    if (cases.length === 1) {
      pos[n.id] = { x: cx, y: cy };
    } else {
      const angle = (i / cases.length) * 2 * Math.PI - Math.PI / 2;
      const R = Math.min(w, h) * 0.22;
      pos[n.id] = { x: cx + R * Math.cos(angle), y: cy + R * Math.sin(angle) };
    }
  });

  // Artifacts orbit their parent case at radius ~40
  const parents = {}; // node_id → parent case node_id derived from edges
  (graph.edges || []).forEach(e => {
    if (e.kind === "chain" && !parents[e.to]) parents[e.to] = e.from;
  });
  const artIdxByParent = {};
  artifacts.forEach((n) => {
    byId[n.id] = n;
    const p = parents[n.id] && pos[parents[n.id]];
    const idx = (artIdxByParent[parents[n.id]] || 0);
    artIdxByParent[parents[n.id]] = idx + 1;
    if (p) {
      const angle = (idx * 0.9) - 1.2;
      pos[n.id] = { x: p.x + 62 * Math.cos(angle), y: p.y + 62 * Math.sin(angle) };
    } else {
      pos[n.id] = { x: cx + 80, y: cy };
    }
  });

  // IOCs orbit their satellite case at radius ~110
  const iocParents = {};
  (graph.edges || []).forEach(e => {
    if (e.kind === "has_ioc") iocParents[e.to] = e.from;
  });
  const iocIdxByParent = {};
  iocs.forEach((n) => {
    byId[n.id] = n;
    const p = iocParents[n.id] && pos[iocParents[n.id]];
    const idx = (iocIdxByParent[iocParents[n.id]] || 0);
    iocIdxByParent[iocParents[n.id]] = idx + 1;
    if (p) {
      const angle = (idx * 0.55) + 0.7;
      pos[n.id] = { x: p.x + 110 * Math.cos(angle), y: p.y + 110 * Math.sin(angle) };
    } else {
      pos[n.id] = { x: cx - 100, y: cy - 100 };
    }
  });

  return { pos, byId };
}
