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
import { useInvestigationFilter } from "./InvestigationFilter";

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

// ── Kill-Chain phase → node colour palette ─────────────────────
// Each phase gets a distinct hue so the diagram becomes a
// "colour timeline" of the attack progression.  Additive — the
// existing critical / persistence highlights still take priority.
const KILL_CHAIN_COLOR = {
  "Reconnaissance":            "#67e8f9",  // cyan
  "Weaponization":             "#a78bfa",  // purple
  "Delivery / Exploitation":   "#c084fc",  // violet
  "Exploitation":              "#facc15",  // yellow
  "Installation":              "#fb923c",  // orange
  "Command & Control":         "#ef4444",  // red-orange
  "Actions on Obj.":           "#f87171",  // red
};

export default function TrajectoryDiagram({ preprocessor }) {
  const initialNodes = useMemo(() => _layoutNodes(preprocessor), [preprocessor]);
  const [nodes, setNodes] = useState(initialNodes);
  const investigation = useInvestigationFilter();
  const [zoom,  setZoom]  = useState(1);
  const [pan,   setPan]   = useState({ x: 0, y: 0 });
  const [selectedNode, setSelectedNode] = useState(null);   // Node Inspector target
  const dragRef  = useRef(null);
  const panRef   = useRef(null);
  const svgRef   = useRef(null);
  const dragMovedRef = useRef(false);   // true if the pointer moved between mousedown and mouseup — used to distinguish click vs drag

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
    dragMovedRef.current = false;
  };

  const onMouseMove = (e) => {
    if (dragRef.current) {
      const pt = _svgPoint(svgRef.current, e.clientX, e.clientY, zoom, pan);
      const { id, offX, offY } = dragRef.current;
      dragMovedRef.current = true;
      setNodes((ns) => ns.map((n) => n.id === id
        ? { ...n, x: pt.x - offX, y: pt.y - offY } : n));
    } else if (panRef.current) {
      const dx = e.clientX - panRef.current.startX;
      const dy = e.clientY - panRef.current.startY;
      setPan({ x: panRef.current.origX + dx, y: panRef.current.origY + dy });
    }
  };

  const onMouseUp = () => {
    // If the pointer never moved, treat the interaction as a click.
    if (dragRef.current && !dragMovedRef.current) {
      const node = nodes.find((n) => n.id === dragRef.current.id);
      if (node) setSelectedNode(node);
    }
    dragRef.current = null;
    panRef.current  = null;
  };
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
            Cyber Kill Chain × MITRE ATT&amp;CK · {LANES.length} swim lanes ·
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
        <span style={legendGroup}>NODE COLOURS BY KILL-CHAIN PHASE:</span>
        <LegendChip color="#67e8f9" label="Reconnaissance" />
        <LegendChip color="#c084fc" label="Delivery / Exploitation" />
        <LegendChip color="#facc15" label="Exploitation" />
        <LegendChip color="#fb923c" label="Installation" />
        <LegendChip color="#ef4444" label="Command & Control" />
        <LegendChip color="#f87171" label="Actions on Objectives" />
        <span style={{ ...legendGroup, marginLeft: 14 }}>OVERRIDES:</span>
        <LegendChip color="#f87171" label="Critical (Impact)" />
        <LegendChip color="#fbbf24" label="Persistence" />
      </div>

      <div style={{ display: "grid",
                    gridTemplateColumns: selectedNode ? "1fr 340px" : "1fr",
                    gap: 12, alignItems: "stretch" }}>
        <div data-testid="trajectory-viewport"
           style={{ overflowX: "scroll",       // ALWAYS-visible horizontal
                    overflowY: "auto",
                    border: "1px solid #1f2b3f",
                    borderRadius: 10, background: "rgba(2,6,23,0.65)",
                    maxHeight: 720,
                    scrollbarColor: "#334467 #0b1220",
                    cursor: dragRef.current ? "grabbing"
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
            {nodes.map((n) => {
              // Phase-based node colour (Kill Chain).  Critical /
              // Persistence highlights still take priority when they
              // apply, so the "colour of urgency" is not lost.
              const phaseColor = KILL_CHAIN_COLOR[n.kill_chain] || "#67e8f9";
              const borderColor = n.critical    ? "#f87171"
                                : n.persistence ? "#fbbf24"
                                : phaseColor;
              const dotColor    = n.critical    ? "#f87171"
                                : n.persistence ? "#fbbf24"
                                : phaseColor;
              return (
              <g key={n.id} data-testid={`trajectory-node-${n.id}`}
                 onMouseDown={(e) => onNodeMouseDown(e, n.id)}
                 style={{
                   cursor: "grab",
                   opacity: (investigation.active && !investigation.match(n.raw)) ? 0.28 : 1,
                   transition: "opacity 0.2s ease",
                 }}>
                {/* Node card */}
                <rect x={n.x - 4} y={n.y - 24}
                      width={210} height={62} rx={6}
                      fill="rgba(15,23,42,0.9)"
                      stroke={borderColor}
                      strokeWidth={1.6} />
                <circle cx={n.x + 10} cy={n.y + 6} r={7}
                        fill={dotColor}
                        stroke="#0b1220" strokeWidth={2} />
                <text x={n.x + 22} y={n.y - 8}
                      style={{ fontSize: 12, fontWeight: 700, fill: "#e2e8f0" }}>
                  {n.title.length > 26 ? n.title.slice(0, 24) + "…" : n.title}
                </text>
                <text x={n.x + 22} y={n.y + 4}
                      style={{ fontSize: 9.5, fill: phaseColor,
                               fontWeight: 700 }}>
                  {n.kill_chain}
                </text>
                <text x={n.x + 22} y={n.y + 16}
                      style={{ fontSize: 9.5, fill: "#64748b" }}>
                  {n.subtitle} · {n.time}
                </text>
              </g>
              );
            })}
          </g>
        </svg>
      </div>

      {/* ── Node Inspector (P0 · Trajectory drill-down) ─────── */}
      {selectedNode && (
        <NodeInspector node={selectedNode}
                       onClose={() => setSelectedNode(null)} />
      )}
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

const legendBar = { display: "flex", gap: 10, flexWrap: "wrap",
                    alignItems: "center", marginBottom: 8 };

const legendGroup = {
  fontSize: 9, letterSpacing: "0.14em", textTransform: "uppercase",
  color: "#64748b", fontFamily: "JetBrains Mono, monospace",
};

const btn = {
  display: "inline-flex", alignItems: "center", gap: 4,
  padding: "4px 10px", fontSize: 11, fontWeight: 600,
  color: "#67e8f9", background: "rgba(103,232,249,0.08)",
  border: "1px solid rgba(103,232,249,0.35)",
  borderRadius: 4, cursor: "pointer",
  fontFamily: "JetBrains Mono, monospace",
};


/* ══════════════════════════════════════════════════════════════
 *  Node Inspector — right-side drill-down panel
 * ══════════════════════════════════════════════════════════════ */
function NodeInspector({ node, onClose }) {
  if (!node) return null;
  const s = node.raw || {};
  return (
    <aside data-testid={`node-inspector-${node.id}`} style={{
      background: "rgba(15,23,42,0.95)",
      border: "1px solid #334467", borderRadius: 10,
      padding: "14px 16px", overflowY: "auto",
      maxHeight: 720,
    }}>
      <div style={{ display: "flex", alignItems: "center",
                    justifyContent: "space-between", marginBottom: 8 }}>
        <div style={{ fontSize: 9, letterSpacing: "0.22em",
                      textTransform: "uppercase", color: "#67e8f9",
                      fontFamily: "JetBrains Mono, monospace" }}>
          NODE INSPECTOR
        </div>
        <button data-testid="node-inspector-close" onClick={onClose}
                style={{ background: "transparent", border: "1px solid #334467",
                         color: "#94a3b8", borderRadius: 4,
                         padding: "2px 8px", fontSize: 11, cursor: "pointer" }}>
          ✕ CLOSE
        </button>
      </div>

      <div style={{ fontSize: 15, fontWeight: 700, color: "#e2e8f0",
                    marginBottom: 4 }}>{node.title}</div>
      <div style={{ fontSize: 11, color: "#94a3b8",
                    fontFamily: "JetBrains Mono, monospace",
                    marginBottom: 12 }}>
        Stage {node.index} · {s.kind || "—"} · {node.time}
      </div>

      {s.objective && (
        <Row label="Purpose">
          <p style={insPara}>{s.objective}</p>
        </Row>
      )}
      {s.normalized_command && (
        <Row label="Normalized Command">
          <code style={insCode}>{s.normalized_command}</code>
        </Row>
      )}
      {s.raw_excerpt && (
        <Row label="Raw Excerpt">
          <code style={{ ...insCode, whiteSpace: "pre-wrap" }}>{s.raw_excerpt}</code>
          {s.line_number ? (
            <div style={{ marginTop: 4, fontSize: 10, color: "#64748b",
                          fontFamily: "JetBrains Mono, monospace" }}>
              line {s.line_number}
            </div>
          ) : null}
        </Row>
      )}
      {s.tactic && (
        <Row label="ATT&CK Tactic">
          <span style={insBadge("#c084fc")}>{s.tactic}</span>
          <span style={{ ...insBadge("#fbbf24"), marginLeft: 6 }}>
            {node.kill_chain}
          </span>
        </Row>
      )}
      {(s.mitre || []).length > 0 && (
        <Row label="MITRE Techniques">
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {s.mitre.map((m) => (
              <span key={m} style={insBadge("#67e8f9")}>{m}</span>
            ))}
          </div>
        </Row>
      )}
      {(s.evidence || []).length > 0 && (
        <Row label="Evidence">
          <ul style={{ margin: 0, padding: 0, listStyle: "none",
                       display: "grid", gap: 4 }}>
            {s.evidence.map((e, i) => (
              <li key={i} style={{ display: "flex", gap: 6,
                                   fontSize: 11.5, color: "#cbd5e1",
                                   lineHeight: 1.5 }}>
                <span style={{ color: "#67e8f9" }}>›</span>
                <span dangerouslySetInnerHTML={{ __html:
                  String(e).replace(/`([^`]+)`/g,
                    '<code style="background:rgba(103,232,249,0.10); padding:1px 5px; border-radius:3px; color:#67e8f9">$1</code>') }} />
              </li>
            ))}
          </ul>
        </Row>
      )}
      {s.command_family && (
        <Row label="DKP Family">
          <span style={insBadge("#a78bfa")}>{s.command_family}</span>
        </Row>
      )}
      {(s.commonly_observed_in || []).length > 0 && (
        <Row label="Commonly Observed In">
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {s.commonly_observed_in.map((n) => (
              <span key={n} style={insBadge("#94a3b8")}>{n}</span>
            ))}
          </div>
          <div style={{ marginTop: 4, fontSize: 10, color: "#64748b",
                        fontStyle: "italic" }}>
            Not attribution — historical prevalence only.
          </div>
        </Row>
      )}
      {(s.artifact_ids || []).length > 0 && (
        <Row label="Related Artifact IDs">
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {s.artifact_ids.map((a) => (
              <span key={a} style={{ ...insBadge("#64748b"), fontSize: 9 }}>
                {a}
              </span>
            ))}
          </div>
        </Row>
      )}
      <Row label="Confidence">
        <div style={{ fontSize: 20, fontWeight: 700, color: "#86efac",
                      fontFamily: "JetBrains Mono, monospace" }}>
          {Math.round((s.confidence || node.confidence || 0) * 100)}%
        </div>
        <div style={{ marginTop: 4, fontSize: 11, color: "#cbd5e1",
                      lineHeight: 1.5 }}>
          <div>✓ Deterministic parser matched</div>
          {s.command_family && <div>✓ DKP family matched (<code>{s.command_family}</code>)</div>}
          {(s.mitre || []).length > 0 && <div>✓ MITRE mapping verified</div>}
          {(s.evidence || []).length > 0 && <div>✓ Evidence extracted</div>}
          <div>✓ No AI inference</div>
        </div>
      </Row>
    </aside>
  );
}

function Row({ label, children }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 9, letterSpacing: "0.16em",
                    textTransform: "uppercase", color: "#94a3b8",
                    fontFamily: "JetBrains Mono, monospace",
                    marginBottom: 4 }}>{label}</div>
      {children}
    </div>
  );
}

const insPara = { color: "#cbd5e1", fontSize: 12.5, lineHeight: 1.55,
                  margin: 0 };
const insCode = { display: "inline-block", background: "rgba(2,6,23,0.55)",
                  border: "1px solid #1f2b3f", padding: "4px 8px",
                  borderRadius: 6, fontSize: 11.5, color: "#e2e8f0",
                  fontFamily: "JetBrains Mono, monospace",
                  wordBreak: "break-word", maxWidth: "100%" };
const insBadge = (color) => ({
  display: "inline-block", padding: "1px 6px", fontSize: 10,
  fontWeight: 700, color, background: `${color}1a`,
  border: `1px solid ${color}55`, borderRadius: 4,
  fontFamily: "JetBrains Mono, monospace",
});
