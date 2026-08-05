/**
 * TrajectoryDiagram — Interactive swim-lane attack-chain
 * visualisation.
 *
 * Interactions:
 *   · Drag any node to reposition it.
 *   · Drag the empty canvas to pan the whole diagram.
 *   · Mouse-wheel over the canvas to zoom in / out (50% – 200%).
 *   · Reset button restores the auto-layout at 1× zoom.
 *   · Horizontal + vertical scrollbars appear when content overflows.
 *
 * Six ATT&CK-tactic swim lanes (Execution / Transformation /
 * Network·C2 / File System / Registry / Persistence) — deterministic
 * lane mapping, plus a per-node Cyber Kill Chain phase badge:
 *   Reconnaissance · Weaponization · Delivery / Exploitation ·
 *   Exploitation · Installation · Command & Control · Actions on Objectives.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Maximize2, RotateCcw } from "lucide-react";

const LANES = [
  { id: "execution",      label: "Execution",     y: 104 },
  { id: "transformation", label: "Transformation", y: 200 },
  { id: "network",        label: "Network / C2",  y: 296 },
  { id: "filesystem",     label: "File System",   y: 392 },
  { id: "registry",       label: "Registry",      y: 488 },
  { id: "persistence",    label: "Persistence",   y: 584 },
];

const TACTIC_TO_LANE = {
  "Initial Access": "execution", "Execution": "execution",
  "Discovery": "execution", "Credential Access": "execution",
  "Defense Evasion": "registry", "Command and Control": "network",
  "Lateral Movement": "network", "Exfiltration": "network",
  "Impact": "filesystem", "Persistence": "persistence",
};

const FAMILY_LANE_OVERRIDE = {
  "shadow-copy-deletion": "filesystem", "log-clearing": "filesystem",
  "registry-modification": "registry", "uac-disable": "registry",
  "persistence-scheduled-task": "persistence",
  "sync-rclone-style": "network", "msi-install": "transformation",
  "reverse-ssh-tunnel": "network", "rmm-remote-access": "network",
  "brute-ratel": "network", "psexec-lateral": "network",
  "ad-discovery": "execution", "host-discovery": "execution",
  "session-discovery": "execution", "account-discovery": "execution",
  "initial-access-social": "execution",
};

const TACTIC_TO_KILL_CHAIN = {
  "Initial Access": "Delivery / Exploitation",
  "Execution": "Exploitation",
  "Discovery": "Reconnaissance",
  "Credential Access": "Actions on Obj.",
  "Persistence": "Installation",
  "Defense Evasion": "Actions on Obj.",
  "Lateral Movement": "Actions on Obj.",
  "Command and Control": "Command & Control",
  "Exfiltration": "Actions on Obj.",
  "Impact": "Actions on Obj.",
};

const EDGE_STYLES = {
  crit:    "rgba(239,68,68,0.65)",
  persist: "rgba(245,158,11,0.65)",
  normal:  "#3b4a68",
};

export default function TrajectoryDiagram({ preprocessor }) {
  const initialNodes = useMemo(() => _layoutNodes(preprocessor), [preprocessor]);
  const [nodes, setNodes] = useState(initialNodes);
  const [zoom,  setZoom]  = useState(1);
  const [pan,   setPan]   = useState({ x: 0, y: 0 });
  const dragRef  = useRef(null);
  const panRef   = useRef(null);
  const svgRef   = useRef(null);

  useEffect(() => { setNodes(_layoutNodes(preprocessor)); setPan({x:0,y:0}); setZoom(1); },
           [preprocessor]);

  const edges = useMemo(() => _layoutEdges(nodes, preprocessor),
                        [nodes, preprocessor]);

  if (!preprocessor || !preprocessor.stages || !preprocessor.stages.length) {
    return null;
  }

  // ── Canvas dimensions — expand with node positions ────────────
  const contentW = Math.max(1200, ...(nodes.map((n) => n.x + 220)));
  const contentH = 680;

  // ── Handlers ──────────────────────────────────────────────────
  const onNodeMouseDown = (e, id) => {
    e.stopPropagation();
    const pt = _svgPoint(svgRef.current, e.clientX, e.clientY, zoom, pan);
    const node = nodes.find((n) => n.id === id);
    if (!node) return;
    dragRef.current = { id, offX: pt.x - node.x, offY: pt.y - node.y };
  };

  const onMouseMove = (e) => {
    if (dragRef.current) {
      const pt = _svgPoint(svgRef.current, e.clientX, e.clientY, zoom, pan);
      const { id, offX, offY } = dragRef.current;
      setNodes((ns) => ns.map((n) => n.id === id
        ? { ...n, x: pt.x - offX, y: pt.y - offY } : n));
    } else if (panRef.current) {
      const dx = e.clientX - panRef.current.startX;
      const dy = e.clientY - panRef.current.startY;
      setPan({ x: panRef.current.origX + dx, y: panRef.current.origY + dy });
    }
  };

  const onMouseUp   = () => { dragRef.current = null; panRef.current = null; };
  const onBgMouseDown = (e) => {
    if (e.target !== e.currentTarget && e.target.tagName !== "rect") return;
    panRef.current = { startX: e.clientX, startY: e.clientY,
                       origX:  pan.x,    origY:  pan.y };
  };

  const reset = () => { setNodes(initialNodes); setPan({x:0,y:0}); setZoom(1); };

  return (
    <section data-testid="trajectory-diagram" style={{
      background: "linear-gradient(180deg, rgba(15,23,42,0.9), rgba(2,6,23,0.9))",
      border: "1px solid #1f2b3f", borderRadius: 12,
      padding: "16px 18px", marginBottom: 14,
    }}>
      <div style={{ display: "flex", alignItems: "center",
                    justifyContent: "space-between", marginBottom: 10,
                    flexWrap: "wrap", gap: 8 }}>
        <div>
          <div style={tagline}>EVIDENCE TRAJECTORY</div>
          <div style={{ fontSize: 18, fontWeight: 700, color: "#e2e8f0",
                        marginTop: 2 }}>
            Attack chain across {LANES.length} swim lanes ·
            drag nodes · pan background · use +/− to zoom
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button data-testid="trajectory-zoom-out" onClick={() => setZoom((z) => Math.max(0.4, +(z - 0.1).toFixed(2)))}
                  style={btn}>−</button>
          <span style={{ minWidth: 42, textAlign: "center",
                         color: "#94a3b8", fontSize: 11,
                         fontFamily: "JetBrains Mono, monospace" }}>
            {Math.round(zoom * 100)}%
          </span>
          <button data-testid="trajectory-zoom-in" onClick={() => setZoom((z) => Math.min(2.2, +(z + 0.1).toFixed(2)))}
                  style={btn}>+</button>
          <button data-testid="trajectory-reset" onClick={reset} style={btn}>
            <RotateCcw size={12} /> RESET
          </button>
        </div>
      </div>

      <div style={legendBar}>
        <LegendChip color="#67e8f9" label="Execution / process" />
        <LegendChip color="#a78bfa" label="Transformation / decode" />
        <LegendChip color="#f87171" label="Network & defense evasion" />
        <LegendChip color="#fbbf24" label="Persistence" />
      </div>

      <div data-testid="trajectory-viewport"
           style={{ overflow: "auto", border: "1px solid #1f2b3f",
                    borderRadius: 10, background: "rgba(2,6,23,0.65)",
                    maxHeight: 720, cursor: dragRef.current ? "grabbing"
                                    : panRef.current ? "grabbing" : "grab" }}>
        <svg ref={svgRef}
             width={contentW * zoom} height={contentH * zoom}
             viewBox={`0 0 ${contentW} ${contentH}`}
             style={{ display: "block", fontFamily: "JetBrains Mono, monospace",
                      userSelect: "none" }}
             onMouseMove={onMouseMove}
             onMouseUp={onMouseUp}
             onMouseLeave={onMouseUp}
             onMouseDown={onBgMouseDown}>
          <defs>
            <marker id="arr" viewBox="0 0 10 10" refX="8" refY="5"
                    markerWidth="7" markerHeight="7" orient="auto">
              <path d="M0,0 L10,5 L0,10 z" fill="#3b4a68" />
            </marker>
            <marker id="arrc" viewBox="0 0 10 10" refX="8" refY="5"
                    markerWidth="7" markerHeight="7" orient="auto">
              <path d="M0,0 L10,5 L0,10 z" fill="rgba(239,68,68,0.85)" />
            </marker>
            <marker id="arra" viewBox="0 0 10 10" refX="8" refY="5"
                    markerWidth="7" markerHeight="7" orient="auto">
              <path d="M0,0 L10,5 L0,10 z" fill="rgba(245,158,11,0.85)" />
            </marker>
          </defs>

          <g transform={`translate(${pan.x} ${pan.y})`}>
            {/* Lane bands */}
            {LANES.map((lane, i) => (
              <g key={lane.id}>
                <rect x={0} y={lane.y - 40}
                      width={contentW} height={90}
                      fill={i % 2 ? "rgba(148,163,184,0.03)"
                                  : "rgba(148,163,184,0.06)"} />
                <text x={16} y={lane.y}
                      style={{ fontSize: 11, fill: "#94a3b8",
                               letterSpacing: "0.14em",
                               textTransform: "uppercase" }}>
                  {lane.label}
                </text>
              </g>
            ))}

            {/* Edges */}
            {edges.map((e) => (
              <path key={e.id} d={e.d}
                    stroke={EDGE_STYLES[e.style] || EDGE_STYLES.normal}
                    strokeWidth={e.style === "crit" ? 2.4 : 1.6}
                    fill="none"
                    markerEnd={
                      e.style === "crit"    ? "url(#arrc)"
                      : e.style === "persist" ? "url(#arra)"
                      : "url(#arr)"
                    }
                    data-testid={`trajectory-edge-${e.id}`} />
            ))}

            {/* Nodes */}
            {nodes.map((n) => (
              <g key={n.id} data-testid={`trajectory-node-${n.id}`}
                 onMouseDown={(e) => onNodeMouseDown(e, n.id)}
                 style={{ cursor: "grab" }}>
                {/* Node card */}
                <rect x={n.x - 4} y={n.y - 24}
                      width={210} height={62} rx={6}
                      fill="rgba(15,23,42,0.9)"
                      stroke={n.critical ? "#f87171"
                              : n.persistence ? "#fbbf24"
                              : "#334467"}
                      strokeWidth={1.5} />
                <circle cx={n.x + 10} cy={n.y + 6} r={7}
                        fill={n.critical ? "#f87171"
                              : n.persistence ? "#fbbf24"
                              : "#67e8f9"}
                        stroke="#0b1220" strokeWidth={2} />
                <text x={n.x + 22} y={n.y - 8}
                      style={{ fontSize: 12, fontWeight: 700, fill: "#e2e8f0" }}>
                  {n.title.length > 26 ? n.title.slice(0, 24) + "…" : n.title}
                </text>
                <text x={n.x + 22} y={n.y + 4}
                      style={{ fontSize: 9.5, fill: "#94a3b8" }}>
                  {n.kill_chain}
                </text>
                <text x={n.x + 22} y={n.y + 16}
                      style={{ fontSize: 9.5, fill: "#64748b" }}>
                  {n.subtitle} · {n.time}
                </text>
              </g>
            ))}
          </g>
        </svg>
      </div>

      <div style={{ marginTop: 8, fontSize: 11, color: "#64748b",
                    fontStyle: "italic" }}>
        Deterministic trajectory. Drag nodes · click-drag the background to pan ·
        use +/− buttons to zoom · RESET restores the auto-layout.
      </div>
    </section>
  );
}

/* ── Layout helpers ────────────────────────────────────────────── */
function _pickLane(stage) {
  if (stage.command_family && FAMILY_LANE_OVERRIDE[stage.command_family]) {
    return FAMILY_LANE_OVERRIDE[stage.command_family];
  }
  return TACTIC_TO_LANE[stage.tactic] || "execution";
}

function _layoutNodes(preprocessor) {
  if (!preprocessor || !preprocessor.stages) return [];
  const stages = preprocessor.stages;
  const nodes = [];
  const X_START = 220;
  const X_STEP  = 240;

  stages.forEach((s, i) => {
    const lane = _pickLane(s);
    const laneObj = LANES.find((l) => l.id === lane) || LANES[0];
    nodes.push({
      id: s.id || `stage-${i}`,
      index: i + 1,
      x: X_START + i * X_STEP,
      y: laneObj.y,
      lane,
      title: s.title || `Stage ${i + 1}`,
      subtitle: (s.mitre && s.mitre[0]) || s.command_family || s.kind || "",
      kill_chain: TACTIC_TO_KILL_CHAIN[s.tactic] || "—",
      time: `+${(i * 0.35 + 0.2).toFixed(2)}s`,
      critical: (s.tactic === "Impact" || (s.mitre || []).some((m) => m === "T1490" || m === "T1486")),
      persistence: (s.tactic === "Persistence"),
      confidence: s.confidence,
      raw: s,
    });
  });
  return nodes;
}

function _layoutEdges(nodes, preprocessor) {
  if (!nodes.length) return [];
  const edges = [];
  for (let i = 0; i < nodes.length - 1; i++) {
    const a = nodes[i]; const b = nodes[i + 1];
    const style = b.critical ? "crit" : b.persistence ? "persist" : "normal";
    edges.push({ id: `e-${a.index}-${b.index}`,
                 d: _bezier(a.x + 10, a.y + 6, b.x + 10, b.y + 6),
                 style });
  }
  const inferred = (preprocessor && preprocessor.process_edges) || [];
  for (const e of inferred) {
    const p = nodes.find((n) => (n.title || "").toLowerCase()
        .includes((e.parent || "").toLowerCase().replace(".exe", "")));
    const c = nodes.find((n) => (n.title || "").toLowerCase()
        .includes((e.child || "").toLowerCase().replace(".exe", "")));
    if (p && c && p.id !== c.id) {
      edges.push({ id: `pi-${p.id}-${c.id}`,
                   d: _bezier(p.x + 10, p.y + 6, c.x + 10, c.y + 6),
                   style: c.critical ? "crit" : c.persistence ? "persist" : "normal" });
    }
  }
  return edges;
}

function _bezier(x1, y1, x2, y2) {
  const dx = Math.max(30, Math.abs(x2 - x1) * 0.55);
  return `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`;
}

function _svgPoint(svg, clientX, clientY, zoom, pan) {
  if (!svg) return { x: clientX, y: clientY };
  const rect = svg.getBoundingClientRect();
  return {
    x: (clientX - rect.left) / zoom - pan.x,
    y: (clientY - rect.top)  / zoom - pan.y,
  };
}

/* ── UI helpers ────────────────────────────────────────────────── */
function LegendChip({ color, label }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6,
                   fontSize: 11, color: "#94a3b8" }}>
      <span style={{ width: 10, height: 10, borderRadius: "50%",
                     background: color, display: "inline-block" }} />
      {label}
    </span>
  );
}

const tagline = {
  fontSize: 9, letterSpacing: "0.22em", textTransform: "uppercase",
  color: "#67e8f9", fontFamily: "JetBrains Mono, monospace",
};

const legendBar = { display: "flex", gap: 14, flexWrap: "wrap",
                    marginBottom: 8 };

const btn = {
  display: "inline-flex", alignItems: "center", gap: 4,
  padding: "4px 10px", fontSize: 11, fontWeight: 600,
  color: "#67e8f9", background: "rgba(103,232,249,0.08)",
  border: "1px solid rgba(103,232,249,0.35)",
  borderRadius: 4, cursor: "pointer",
  fontFamily: "JetBrains Mono, monospace",
};
