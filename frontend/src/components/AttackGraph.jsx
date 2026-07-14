import { useMemo } from "react";
import {
  User, Cog, FileText, HardDrive, Globe, Router, Mail,
  Database, ScrollText, Link as LinkIcon, Skull,
} from "lucide-react";

/**
 * AttackGraph — Cortex XDR-style entity relationship diagram.
 * Renders typed nodes (with icons) and labeled directional edges via SVG.
 * Layout: layered left-to-right by dependency depth (topological levels).
 */
const TYPE_ICON = {
  process: Cog, file: FileText, device: HardDrive, user: User,
  url: LinkIcon, ip: Router, domain: Globe, email: Mail,
  hash: FileText, registry: Database, script: ScrollText,
};
const TYPE_COLOR = {
  process: "#c0ca33", file: "#8b949e", device: "#7fb9ff", user: "#4AA890",
  url: "#E27E5D", ip: "#7fb9ff", domain: "#7fb9ff", email: "#d96c6c",
  hash: "#8b949e", registry: "#8b949e", script: "#c0ca33",
};

export default function AttackGraph({ nodes = [], edges = [] }) {
  const { positions, width, height } = useMemo(() => layout(nodes, edges), [nodes, edges]);
  if (!nodes.length) return null;

  return (
    <div style={{ overflow: "auto", background: "var(--inset)", border: "1px solid var(--border)" }}>
      <svg width={width} height={height} style={{ display: "block", minWidth: "100%" }} data-testid="attack-graph-svg">
        {/* grid dots */}
        {Array.from({ length: Math.ceil(width / 24) }).map((_, gi) => (
          Array.from({ length: Math.ceil(height / 24) }).map((_, gj) => (
            <circle key={`g${gi}-${gj}`} cx={gi * 24} cy={gj * 24} r={0.5} fill="#2d3135" />
          ))
        )).flat()}

        {/* arrowhead marker */}
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#4aa890" />
          </marker>
          <marker id="arrow-red" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#d96c6c" />
          </marker>
        </defs>

        {/* edges first (behind nodes) */}
        {edges.map((e, i) => {
          const a = positions[e.from]; const b = positions[e.to];
          if (!a || !b) return null;
          const midX = (a.x + b.x) / 2;
          const midY = (a.y + b.y) / 2;
          const fromNode = nodes.find((n) => n.id === e.from);
          const targetNode = nodes.find((n) => n.id === e.to);
          const stroke = (fromNode?.malicious || targetNode?.malicious) ? "#d96c6c" : "#4aa890";
          const marker = stroke === "#d96c6c" ? "arrow-red" : "arrow";
          const path = `M ${a.x} ${a.y} L ${b.x} ${b.y}`;
          return (
            <g key={i}>
              <path d={path} stroke={stroke} strokeWidth={1.6} fill="none" markerEnd={`url(#${marker})`} opacity={0.85} />
              {e.label && (
                <g>
                  <rect x={midX - (e.label.length * 3.4)} y={midY - 8} width={e.label.length * 6.8} height={14} fill="var(--bg)" opacity={0.85} />
                  <text x={midX} y={midY + 2} fontSize={10} fontFamily="'JetBrains Mono',monospace" fill="#e5e7eb" textAnchor="middle">
                    {e.label.length > 24 ? e.label.slice(0, 22) + "…" : e.label}
                  </text>
                </g>
              )}
            </g>
          );
        })}

        {/* nodes */}
        {nodes.map((n) => {
          const p = positions[n.id];
          if (!p) return null;
          const Icon = TYPE_ICON[n.type] || Cog;
          const color = n.malicious ? "#d96c6c" : TYPE_COLOR[n.type] || "#4aa890";
          return (
            <g key={n.id} transform={`translate(${p.x}, ${p.y})`} data-testid={`ag-node-${n.id}`}>
              {n.malicious && (
                <g>
                  {/* dashed halo */}
                  <circle r={28} fill="none" stroke={color} strokeWidth={1.5} strokeDasharray="4 3" />
                </g>
              )}
              <circle r={22} fill="var(--bg)" stroke={color} strokeWidth={n.malicious ? 2 : 1.5} />
              <foreignObject x={-10} y={-10} width={20} height={20}>
                <div xmlns="http://www.w3.org/1999/xhtml" style={{ color, width: 20, height: 20 }}>
                  <Icon size={20} />
                </div>
              </foreignObject>
              {n.malicious && (
                <g transform="translate(14, -14)">
                  <circle r={7} fill="var(--bg)" stroke={color} strokeWidth={1.5} />
                  <foreignObject x={-5} y={-5} width={10} height={10}>
                    <div xmlns="http://www.w3.org/1999/xhtml" style={{ color, width: 10, height: 10 }}>
                      <Skull size={10} />
                    </div>
                  </foreignObject>
                </g>
              )}
              <text
                x={0} y={38} fontSize={10.5} fontFamily="'JetBrains Mono',monospace"
                fill="#e5e7eb" textAnchor="middle" fontWeight={700}
              >
                {(n.label || n.id).slice(0, 22)}
              </text>
              <text
                x={0} y={50} fontSize={9} fontFamily="'JetBrains Mono',monospace"
                fill="#8b949e" textAnchor="middle" style={{ textTransform: "uppercase", letterSpacing: "0.12em" }}
              >
                {n.type}
              </text>
              {n.note && (
                <text x={0} y={62} fontSize={9} fontFamily="'JetBrains Mono',monospace" fill="#8b949e" textAnchor="middle">
                  {n.note.slice(0, 28)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function layout(nodes, edges) {
  // Compute layer (longest incoming-chain length) for a left-to-right layered layout
  const incoming = Object.fromEntries(nodes.map((n) => [n.id, []]));
  for (const e of edges) if (incoming[e.to] !== undefined) incoming[e.to].push(e.from);
  const level = {};
  const compute = (id, seen = new Set()) => {
    if (level[id] !== undefined) return level[id];
    if (seen.has(id)) return 0;
    seen.add(id);
    const inc = incoming[id] || [];
    if (!inc.length) { level[id] = 0; return 0; }
    level[id] = 1 + Math.max(0, ...inc.map((p) => compute(p, seen)));
    return level[id];
  };
  for (const n of nodes) compute(n.id);
  const byLevel = {};
  for (const n of nodes) (byLevel[level[n.id]] ||= []).push(n.id);
  const positions = {};
  const CELL_W = 200, CELL_H = 140, PAD = 60;
  const maxLevel = Math.max(0, ...Object.keys(byLevel).map(Number));
  const maxCol = Math.max(...Object.values(byLevel).map((a) => a.length), 1);
  Object.entries(byLevel).forEach(([lvl, ids]) => {
    const l = parseInt(lvl, 10);
    ids.forEach((id, i) => {
      positions[id] = {
        x: PAD + l * CELL_W,
        y: PAD + i * CELL_H + (maxCol - ids.length) * CELL_H / 2,
      };
    });
  });
  const width = PAD * 2 + (maxLevel + 1) * CELL_W;
  const height = PAD * 2 + maxCol * CELL_H;
  return { positions, width, height };
}
