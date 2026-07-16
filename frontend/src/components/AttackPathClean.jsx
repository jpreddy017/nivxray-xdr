import { useMemo, useRef, useState, useCallback } from "react";
import {
  User, Cog, FileText, HardDrive, Globe, Router, Mail, Database,
  ScrollText, Link as LinkIcon, Key, ShieldAlert, ServerCog,
  Cloud, Wifi, Camera, Download, AlertTriangle, Container, Bot,
  Crown, Target, Zap, RotateCcw,
} from "lucide-react";

/**
 * AttackPathClean — PuppyGraph-style clean L-shaped attack path.
 *
 * Renders the "primary" attack chain (longest reachable path in the
 * node/edge graph, or an in-order fallback) as filled, color-coded
 * circular nodes joined by matching accent lines. Off-path nodes are
 * shown as ghost branches from their nearest neighbour.
 *
 * Colour palette mirrors the PuppyGraph reference:
 *   orange  → infra (file / device / hash)
 *   sky     → secret / URL / domain
 *   violet  → identity (user / email / process)
 *   green   → storage / registry / bot
 *   red     → malicious / vulnerability
 */
const PALETTE = {
  infra:      "#f59e0b",  // amber-500  — VPC, gateway, subnet, NIC, file
  secret:     "#0ea5e9",  // sky-500    — URL, domain, access key, network
  identity:   "#8b5cf6",  // violet-500 — user, email, service account
  execution:  "#6366f1",  // indigo-500 — process, script
  storage:    "#22c55e",  // green-500  — registry, database, bucket
  vuln:       "#ef4444",  // red-500    — malicious / vulnerability
  neutral:    "#64748b",  // slate-500  — fallback
};

const TYPE_ICON = {
  process: Cog, file: FileText, device: HardDrive, user: User,
  url: LinkIcon, ip: Router, domain: Globe, email: Mail,
  hash: FileText, registry: Database, script: ScrollText, action: ShieldAlert,
  secret: Key, subnet: Wifi, vpc: Cloud, gateway: ServerCog, nic: Container,
  bucket: Container, bot: Bot, vulnerability: AlertTriangle,
};

const TYPE_COLOR = {
  file: "infra", device: "infra", hash: "infra",
  url: "secret", ip: "secret", domain: "secret", secret: "secret",
  user: "identity", email: "identity",
  process: "execution", script: "execution", action: "execution",
  registry: "storage", bucket: "storage", bot: "storage",
  vulnerability: "vuln",
};

function nodeColor(n) {
  if (n.malicious) return PALETTE.vuln;
  return PALETTE[TYPE_COLOR[n.type] || "neutral"];
}

function nodeIcon(n) {
  return TYPE_ICON[n.type] || Cog;
}

// -------------------------------------------------------------------
// Layout — L-shape
// -------------------------------------------------------------------
function longestPath(nodes, edges) {
  if (!nodes.length) return [];
  const idx = new Map(nodes.map((n, i) => [n.id, i]));
  const adj = new Map(nodes.map((n) => [n.id, []]));
  const indeg = new Map(nodes.map((n) => [n.id, 0]));
  for (const e of edges) {
    if (!idx.has(e.from) || !idx.has(e.to)) continue;
    adj.get(e.from).push(e.to);
    indeg.set(e.to, indeg.get(e.to) + 1);
  }
  // Kahn topological order
  const order = [];
  const q = [];
  indeg.forEach((v, k) => { if (v === 0) q.push(k); });
  while (q.length) {
    const u = q.shift();
    order.push(u);
    for (const v of adj.get(u) || []) {
      indeg.set(v, indeg.get(v) - 1);
      if (indeg.get(v) === 0) q.push(v);
    }
  }
  if (order.length !== nodes.length) {
    // Cyclic / disconnected — fall back to input order.
    return nodes.map((n) => n.id);
  }
  // Longest path via DP over topo order.
  const dist = new Map(nodes.map((n) => [n.id, 0]));
  const prev = new Map();
  for (const u of order) {
    for (const v of adj.get(u) || []) {
      if (dist.get(u) + 1 > dist.get(v)) {
        dist.set(v, dist.get(u) + 1);
        prev.set(v, u);
      }
    }
  }
  let end = order[0];
  dist.forEach((v, k) => { if (v > dist.get(end)) end = k; });
  const chain = [];
  let cur = end;
  while (cur !== undefined) {
    chain.unshift(cur);
    cur = prev.get(cur);
  }
  return chain;
}

function layoutLShape(nodes, edges) {
  const chain = longestPath(nodes, edges);
  const primary = new Set(chain);
  const off = nodes.filter((n) => !primary.has(n.id));

  const CELL = 180;                 // spacing between path nodes (extra room for labels)
  const PAD  = 60;                  // frame padding
  const BEND = Math.min(4, Math.max(2, Math.floor(chain.length / 2)));
  // First BEND nodes go vertical (down the left), rest go horizontal
  // (right along the bottom). If chain is short, it's fully vertical.
  const positions = {};
  const vertN = Math.min(BEND, chain.length);
  const horizN = chain.length - vertN;
  for (let i = 0; i < vertN; i++) {
    positions[chain[i]] = { x: PAD + 60, y: PAD + i * CELL, onPath: true };
  }
  for (let i = 0; i < horizN; i++) {
    positions[chain[vertN + i]] = {
      x: PAD + 60 + (i + 1) * CELL,
      y: PAD + (vertN - 1) * CELL + CELL,   // one row below the last vert node
      onPath: true,
    };
  }
  // Off-path nodes: hang below their first predecessor along the path.
  const nodeIdx = new Map(nodes.map((n) => [n.id, n]));
  const parentOnPath = new Map();
  for (const e of edges) {
    if (primary.has(e.from) && !primary.has(e.to)) parentOnPath.set(e.to, e.from);
    if (primary.has(e.to)   && !primary.has(e.from)) parentOnPath.set(e.from, e.to);
  }
  const usedOffsets = new Map();
  for (const n of off) {
    const anchor = parentOnPath.get(n.id);
    const base = anchor ? positions[anchor] : positions[chain[chain.length - 1]] || { x: PAD, y: PAD };
    if (!base) continue;
    const seen = usedOffsets.get(anchor) || 0;
    usedOffsets.set(anchor, seen + 1);
    positions[n.id] = {
      x: base.x + (seen + 1) * 90,
      y: base.y + 110 + (seen % 2) * 40,
      onPath: false,
    };
  }
  const width  = Math.max(900, PAD * 2 + 120 + (horizN + 1) * CELL);
  const height = Math.max(320, PAD * 2 + vertN * CELL + (off.length ? 180 : 60));
  return { positions, chain, width, height };
}

// -------------------------------------------------------------------
// Component
// -------------------------------------------------------------------
export default function AttackPathClean({ nodes = [], edges = [] }) {
  const { positions: baseLayout, chain, width, height } = useMemo(
    () => layoutLShape(nodes, edges), [nodes, edges]);
  const svgRef = useRef(null);

  // ── Drag state ────────────────────────────────────────────────
  // `overrides` stores user-moved positions per node id — merged on top
  // of the auto-layout so edges/graphics follow live.
  const [overrides, setOverrides] = useState({});
  const dragRef = useRef(null); // { id, startPtX, startPtY, origX, origY }

  // Merged effective positions.
  const positions = useMemo(() => {
    const out = {};
    for (const id of Object.keys(baseLayout)) {
      const base = baseLayout[id];
      const ov = overrides[id];
      out[id] = ov ? { ...base, x: ov.x, y: ov.y } : base;
    }
    return out;
  }, [baseLayout, overrides]);

  // Convert a pointer event's client coords into SVG user-space coords
  // (respecting any css scaling of the <svg>).
  const svgPointFromEvent = useCallback((evt) => {
    const el = svgRef.current;
    if (!el) return { x: 0, y: 0 };
    const rect = el.getBoundingClientRect();
    const scaleX = width  / rect.width;
    const scaleY = height / rect.height;
    return {
      x: (evt.clientX - rect.left) * scaleX,
      y: (evt.clientY - rect.top)  * scaleY,
    };
  }, [width, height]);

  const onNodePointerDown = (id) => (evt) => {
    evt.stopPropagation();
    evt.preventDefault();
    // Capture the pointer so subsequent move/up events fire on this element
    // even after the cursor leaves the node circle.
    try { evt.currentTarget.setPointerCapture(evt.pointerId); } catch {}
    const pt = svgPointFromEvent(evt);
    const cur = positions[id] || { x: 0, y: 0 };
    dragRef.current = {
      id,
      startPtX: pt.x, startPtY: pt.y,
      origX: cur.x,   origY: cur.y,
    };
  };

  const onSvgPointerMove = (evt) => {
    const d = dragRef.current;
    if (!d) return;
    const pt = svgPointFromEvent(evt);
    const nx = d.origX + (pt.x - d.startPtX);
    const ny = d.origY + (pt.y - d.startPtY);
    // Clamp inside canvas with a small margin so labels remain visible.
    const clampedX = Math.max(30, Math.min(width - 30,  nx));
    const clampedY = Math.max(30, Math.min(height - 30, ny));
    setOverrides((prev) => ({ ...prev, [d.id]: { x: clampedX, y: clampedY } }));
  };

  const endDrag = () => { dragRef.current = null; };

  const resetLayout = () => setOverrides({});

  if (!nodes.length) return null;

  const primary = new Set(chain);

  // ── Semantic overlays (XM Cyber concepts) ───────────────────────
  //   entry point : in-degree 0 AND on primary path (first node)
  //   crown jewel : last node on primary path
  //   choke point : any node with (in + out) degree ≥ 3
  const degree = new Map(nodes.map((n) => [n.id, { i: 0, o: 0 }]));
  for (const e of edges) {
    if (degree.has(e.from)) degree.get(e.from).o += 1;
    if (degree.has(e.to))   degree.get(e.to).i += 1;
  }
  const entryId = chain[0];
  const crownId = chain[chain.length - 1];
  const chokeIds = new Set(
    nodes
      .filter((n) => {
        const d = degree.get(n.id) || { i: 0, o: 0 };
        return (d.i + d.o) >= 3 && n.id !== entryId && n.id !== crownId;
      })
      .map((n) => n.id)
  );

  const serializeSvg = () => {
    const el = svgRef.current;
    if (!el) return null;
    const clone = el.cloneNode(true);
    clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    clone.setAttribute("style", "background:#0b1220;font-family:'Chivo',sans-serif");
    const bg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    bg.setAttribute("x", "0"); bg.setAttribute("y", "0");
    bg.setAttribute("width", String(width)); bg.setAttribute("height", String(height));
    bg.setAttribute("fill", "#0b1220");
    clone.insertBefore(bg, clone.firstChild);
    return new XMLSerializer().serializeToString(clone);
  };

  const downloadPng = () => {
    const svgStr = serializeSvg();
    if (!svgStr) return;
    const scale = 2;
    const canvas = document.createElement("canvas");
    canvas.width = width * scale;
    canvas.height = height * scale;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#0b1220";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    const img = new Image();
    img.onload = () => {
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      canvas.toBlob((blob) => {
        if (!blob) return;
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `nivxray_attack_path_${new Date().toISOString().replace(/[:.]/g, "-")}.png`;
        a.click();
        URL.revokeObjectURL(url);
      }, "image/png");
    };
    img.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svgStr);
  };

  const downloadSvg = () => {
    const svgStr = serializeSvg();
    if (!svgStr) return;
    const blob = new Blob([svgStr], { type: "image/svg+xml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nivxray_attack_path_${new Date().toISOString().replace(/[:.]/g, "-")}.svg`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const RADIUS = 26;

  return (
    <div style={{ background: "var(--inset)", border: "1px solid var(--border)" }}
         data-testid="attack-path-clean-container">
      {/* Toolbar */}
      <div style={{ display: "flex", gap: 6, padding: "6px 8px",
                    borderBottom: "1px solid var(--border)", background: "var(--bg)",
                    alignItems: "center", flexWrap: "wrap" }}>
        <span className="mono" style={{ fontSize: 9, color: "var(--text-mute)",
                                         letterSpacing: "0.18em", marginRight: 12 }}>
          KILL-CHAIN · {chain.length} on path · {nodes.length - chain.length} branches
          {Object.keys(overrides).length > 0 && (
            <span style={{ color: "#7ee3c9", marginLeft: 8 }}>
              · {Object.keys(overrides).length} MOVED
            </span>
          )}
        </span>
        {/* Semantic legend chips */}
        <span style={{ display: "inline-flex", alignItems: "center", gap: 4,
                       fontSize: 9, color: "#38bdf8", fontFamily: "'JetBrains Mono',monospace",
                       letterSpacing: "0.14em" }}>
          <Zap size={10} /> ENTRY
        </span>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 4,
                       fontSize: 9, color: "#f472b6", fontFamily: "'JetBrains Mono',monospace",
                       letterSpacing: "0.14em" }}>
          <Target size={10} /> CHOKE ({chokeIds.size})
        </span>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 4,
                       fontSize: 9, color: "#fbbf24", fontFamily: "'JetBrains Mono',monospace",
                       letterSpacing: "0.14em", marginRight: "auto" }}>
          <Crown size={10} /> CROWN JEWEL
        </span>
        <button className="nvx-btn sm ghost" onClick={resetLayout}
                disabled={!Object.keys(overrides).length}
                title="Reset all dragged positions to the auto-computed layout"
                data-testid="btn-attack-path-reset-layout">
          <RotateCcw size={11} /> RESET
        </button>
        <button className="nvx-btn sm ghost" onClick={downloadPng}
                data-testid="btn-attack-path-png">
          <Camera size={11} /> PNG
        </button>
        <button className="nvx-btn sm ghost" onClick={downloadSvg}
                data-testid="btn-attack-path-svg">
          <Download size={11} /> SVG
        </button>
      </div>

      <div style={{ overflow: "auto" }}>
        <svg ref={svgRef} width={width} height={height}
             style={{ display: "block", minWidth: "100%",
                      background: "linear-gradient(180deg, #0b1220 0%, #0f172a 100%)",
                      touchAction: "none",
                      cursor: dragRef.current ? "grabbing" : "default" }}
             data-testid="attack-path-clean-svg"
             xmlns="http://www.w3.org/2000/svg"
             onPointerMove={onSvgPointerMove}
             onPointerUp={endDrag}
             onPointerLeave={endDrag}
             onPointerCancel={endDrag}>
          {/* Dotted grid backdrop for the PuppyGraph look */}
          <defs>
            <pattern id="dotgrid" width="18" height="18" patternUnits="userSpaceOnUse">
              <circle cx="1" cy="1" r="0.7" fill="#1e293b" />
            </pattern>
            <marker id="ap-arrow" viewBox="0 0 10 10" refX="9" refY="5"
                    markerWidth="5" markerHeight="5" orient="auto">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8" />
            </marker>
          </defs>
          <rect x="0" y="0" width={width} height={height} fill="url(#dotgrid)" />

          {/* Edges */}
          {edges.map((e, i) => {
            const a = positions[e.from]; const b = positions[e.to];
            if (!a || !b) return null;
            const onChain = primary.has(e.from) && primary.has(e.to);
            const from = nodes.find((n) => n.id === e.from);
            const stroke = onChain ? nodeColor(from) : "#334155";
            const sw = onChain ? 3 : 1.4;
            // Right-angle path: horizontal-then-vertical is cleaner than diagonals for L-shape.
            const midY = onChain && Math.abs(a.y - b.y) > 20 && Math.abs(a.x - b.x) > 20
                          ? b.y : a.y;
            const d = onChain
              ? `M ${a.x} ${a.y} L ${a.x} ${midY} L ${b.x} ${midY} L ${b.x} ${b.y}`
              : `M ${a.x} ${a.y} L ${b.x} ${b.y}`;
            return (
              <path
                key={i}
                d={d}
                stroke={stroke}
                strokeWidth={sw}
                strokeLinecap="round"
                strokeLinejoin="round"
                fill="none"
                opacity={onChain ? 0.85 : 0.45}
                markerEnd={onChain ? undefined : "url(#ap-arrow)"}
              />
            );
          })}

          {/* Nodes */}
          {nodes.map((n) => {
            const p = positions[n.id];
            if (!p) return null;
            const Icon = nodeIcon(n);
            const color = nodeColor(n);
            const isPath = primary.has(n.id);
            const r = isPath ? RADIUS : RADIUS - 6;
            return (
              <g key={n.id} transform={`translate(${p.x}, ${p.y})`}
                 data-testid={`ap-node-${n.id}`}
                 onPointerDown={onNodePointerDown(n.id)}
                 style={{
                    opacity: isPath ? 1 : 0.75,
                    cursor: "grab",
                    userSelect: "none",
                    touchAction: "none",
                 }}>
                {/* Halo when on path */}
                {isPath && (
                  <circle r={r + 6} fill={color} opacity={0.15} />
                )}
                {/* Malicious warning ring */}
                {n.malicious && (
                  <circle r={r + 3} fill="none" stroke={color}
                          strokeWidth={1.5} strokeDasharray="3 3" opacity={0.9} />
                )}
                <circle r={r} fill={color} stroke="#0b1220" strokeWidth={2}
                        style={{ filter: isPath
                          ? `drop-shadow(0 4px 10px ${color}66)` : "none" }} />
                {/* Crown = critical asset (terminal on path) */}
                {n.id === crownId && (
                  <g transform={`translate(0, ${-(r + 16)})`}>
                    <circle r={9} fill="#0b1220" stroke="#fbbf24" strokeWidth={1.5} />
                    <foreignObject x={-7} y={-7} width={14} height={14}>
                      <div xmlns="http://www.w3.org/1999/xhtml"
                           style={{ color: "#fbbf24", width: 14, height: 14,
                                    display: "flex", alignItems: "center",
                                    justifyContent: "center" }}>
                        <Crown size={12} strokeWidth={2.4} />
                      </div>
                    </foreignObject>
                  </g>
                )}
                {/* Zap = entry point */}
                {n.id === entryId && (
                  <g transform={`translate(0, ${-(r + 16)})`}>
                    <circle r={9} fill="#0b1220" stroke="#38bdf8" strokeWidth={1.5} />
                    <foreignObject x={-7} y={-7} width={14} height={14}>
                      <div xmlns="http://www.w3.org/1999/xhtml"
                           style={{ color: "#38bdf8", width: 14, height: 14,
                                    display: "flex", alignItems: "center",
                                    justifyContent: "center" }}>
                        <Zap size={12} strokeWidth={2.4} />
                      </div>
                    </foreignObject>
                  </g>
                )}
                {/* Target = choke point (in+out deg >= 3) */}
                {chokeIds.has(n.id) && (
                  <g transform={`translate(${r + 8}, ${-(r - 4)})`}>
                    <circle r={8} fill="#0b1220" stroke="#f472b6" strokeWidth={1.5} />
                    <foreignObject x={-6} y={-6} width={12} height={12}>
                      <div xmlns="http://www.w3.org/1999/xhtml"
                           style={{ color: "#f472b6", width: 12, height: 12,
                                    display: "flex", alignItems: "center",
                                    justifyContent: "center" }}>
                        <Target size={10} strokeWidth={2.4} />
                      </div>
                    </foreignObject>
                  </g>
                )}                {/* White icon centred */}
                <foreignObject x={-r * 0.55} y={-r * 0.55}
                               width={r * 1.1} height={r * 1.1}>
                  <div xmlns="http://www.w3.org/1999/xhtml"
                       style={{ color: "#fff", width: "100%", height: "100%",
                                display: "flex", alignItems: "center",
                                justifyContent: "center" }}>
                    <Icon size={Math.round(r * 0.9)} strokeWidth={2.2} />
                  </div>
                </foreignObject>
                {/* Label — bold title */}
                <text x={0} y={r + 18}
                      fontSize={12} fontFamily="'Chivo',sans-serif"
                      fill="#f8fafc" textAnchor="middle" fontWeight={700}>
                  {truncate(n.label || n.id, 26)}
                </text>
                {/* Sub-label — grey uppercase type */}
                <text x={0} y={r + 33}
                      fontSize={9.5} fontFamily="'JetBrains Mono',monospace"
                      fill="#94a3b8" textAnchor="middle"
                      style={{ textTransform: "uppercase", letterSpacing: "0.14em" }}>
                  {n.type || "asset"}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

function truncate(s, n) {
  const t = String(s || "");
  return t.length > n ? t.slice(0, n - 1) + "…" : t;
}
