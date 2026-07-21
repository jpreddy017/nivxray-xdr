/**
 * RC5 · Execution Graph SVG visualization.
 *
 * Renders the ExecGraph as a deterministic node/edge SVG. Layout is
 * grid-based (no force-directed physics — reproducibility matters
 * more than pretty). Nodes are colour-coded by NodeKind class.
 *
 * Props:
 *   graph = { nodes: [{ id, kind, reconstructed, args, side_effects, confidence }], edges? }
 *   onNodeClick = (node) => void
 */
import React, { useMemo, useState } from "react";

const KIND_COLORS = {
  ProcessNode:      "#ef4444",  // red
  HttpNode:         "#f59e0b",  // amber
  DNSNode:          "#f59e0b",
  SocketNode:       "#f59e0b",
  RegistryNode:     "#a855f7",  // purple
  ScheduledTaskNode:"#a855f7",
  ServiceNode:      "#a855f7",
  WMINode:          "#a855f7",
  FileNode:         "#0ea5e9",  // sky
  MemoryNode:       "#e11d48",  // rose
  ShellcodeNode:    "#e11d48",
  AssemblyLoadNode: "#e11d48",
  ReflectionNode:   "#e11d48",
  ScriptBlockNode:  "#22d3ee",  // cyan
  VarBindNode:      "#64748b",  // slate
  VarExpandNode:    "#64748b",
  StringOpNode:     "#475569",
  DecodeNode:       "#38bdf8",
  NormalizeNode:    "#38bdf8",
  UnresolvedNode:   "#71717a",  // zinc
};

const KIND_LABEL = {
  ProcessNode: "PROC", HttpNode: "HTTP", DNSNode: "DNS",
  RegistryNode: "REG", ScheduledTaskNode: "TASK",
  ServiceNode: "SVC", FileNode: "FILE", MemoryNode: "MEM",
  ShellcodeNode: "SHELL", AssemblyLoadNode: "ASM",
  ReflectionNode: "REFL", ScriptBlockNode: "SB",
  VarBindNode: "BIND", VarExpandNode: "EXPAND",
  StringOpNode: "STR", DecodeNode: "DECODE",
  NormalizeNode: "NORM", UnresolvedNode: "?",
  WMINode: "WMI", NamedPipeNode: "PIPE",
  ClipboardNode: "CLIP", COMNode: "COM",
};

export const ExecutionGraphSVG = ({ graph, onNodeClick }) => {
  const [hoverId, setHoverId] = useState(null);
  const layout = useMemo(() => {
    if (!graph?.nodes?.length) return null;
    const nodes = graph.nodes;
    // Simple grid layout — up to 4 columns, wraps to next row.
    const cols = Math.min(4, Math.max(1, Math.ceil(Math.sqrt(nodes.length))));
    const CELL_W = 200;
    const CELL_H = 80;
    const positions = {};
    nodes.forEach((n, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      positions[n.id] = {
        x: col * CELL_W + 24,
        y: row * CELL_H + 24,
        w: CELL_W - 32,
        h: CELL_H - 20,
      };
    });
    const rows = Math.ceil(nodes.length / cols);
    return {
      positions,
      viewW: cols * CELL_W + 24,
      viewH: rows * CELL_H + 24,
    };
  }, [graph]);

  if (!layout) {
    return (
      <div className="text-xs text-slate-500 font-mono py-8 text-center border border-dashed border-slate-800 rounded">
        No execution graph yet — analyze a sample first.
      </div>
    );
  }

  return (
    <div className="w-full overflow-auto border border-slate-800 rounded bg-slate-950"
         data-testid="execution-graph-svg">
      <svg
        width={layout.viewW}
        height={layout.viewH}
        style={{
          backgroundImage:
            "linear-gradient(to right, #0f172a 1px, transparent 1px), linear-gradient(to bottom, #0f172a 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      >
        {/* Edges — parent-child inputs field */}
        {graph.nodes.map((n) =>
          (n.inputs || []).map((pid, k) => {
            const src = layout.positions[pid];
            const dst = layout.positions[n.id];
            if (!src || !dst) return null;
            const key = `${pid}->${n.id}-${k}`;
            const active = hoverId === n.id || hoverId === pid;
            return (
              <line
                key={key}
                x1={src.x + src.w / 2}
                y1={src.y + src.h}
                x2={dst.x + dst.w / 2}
                y2={dst.y}
                stroke={active ? "#38bdf8" : "#334155"}
                strokeWidth={active ? 1.5 : 1}
                strokeDasharray={active ? "" : "3 3"}
              />
            );
          })
        )}
        {/* Nodes */}
        {graph.nodes.map((n) => {
          const p = layout.positions[n.id];
          const color = KIND_COLORS[n.kind] || "#475569";
          const label = KIND_LABEL[n.kind] || (n.kind || "?").replace("Node", "").toUpperCase();
          const active = hoverId === n.id;
          return (
            <g
              key={n.id}
              onMouseEnter={() => setHoverId(n.id)}
              onMouseLeave={() => setHoverId(null)}
              onClick={() => onNodeClick?.(n)}
              style={{ cursor: onNodeClick ? "pointer" : "default" }}
              data-testid={`execgraph-node-${n.id}`}
            >
              <rect
                x={p.x}
                y={p.y}
                width={p.w}
                height={p.h}
                fill={active ? "#0f172a" : "#020617"}
                stroke={color}
                strokeWidth={active ? 2 : 1}
                rx={2}
              />
              <rect x={p.x} y={p.y} width={p.w} height={16} fill={color} rx={2} />
              <text
                x={p.x + 6}
                y={p.y + 12}
                fill="#020617"
                fontSize="10"
                fontWeight="700"
                fontFamily="JetBrains Mono, monospace"
              >
                {label}
              </text>
              <text
                x={p.x + p.w - 6}
                y={p.y + 12}
                textAnchor="end"
                fill="#020617"
                fontSize="9"
                fontFamily="JetBrains Mono, monospace"
              >
                {(n.id || "").slice(0, 10)}
              </text>
              <foreignObject x={p.x + 4} y={p.y + 18} width={p.w - 8} height={p.h - 22}>
                <div
                  className="text-[10px] font-mono text-slate-400 leading-tight overflow-hidden"
                  style={{
                    display: "-webkit-box",
                    WebkitLineClamp: 3,
                    WebkitBoxOrient: "vertical",
                  }}
                >
                  {(n.reconstructed || "").slice(0, 120) || "—"}
                </div>
              </foreignObject>
            </g>
          );
        })}
      </svg>
    </div>
  );
};

export default ExecutionGraphSVG;
