/**
 * TrajectoryDiagram — Interactive swim-lane attack-chain
 * visualisation.
 *
 * Two projection modes (canonical + legacy):
 *   · CANONICAL (Rule R22 · Architecture v1.0)  — pass `behaviors`
 *     [{ label|title, mitre_tactics[], mitre_techniques[]|mitre[],
 *        kill_chain[], severity, confidence, category }, …]
 *     to render the 14-tactic ATT&CK projection.  Each behavior
 *     renders one node per entry in `mitre_tactics[]`, so a single
 *     behavior legitimately appears in multiple lanes.  Empty
 *     tactics collapse automatically.
 *   · LEGACY  — pass `preprocessor.stages` to keep the 6-lane
 *     tactic-bucket view (preserved for callers that haven't
 *     migrated to the canonical behavior graph yet).
 *
 * Interactions:
 *   · Drag any node to reposition it.
 *   · Drag the empty canvas to pan the whole diagram.
 *   · Mouse-wheel over the canvas to zoom in / out (50% – 200%).
 *   · Reset button restores the auto-layout at 1× zoom.
 *   · Horizontal + vertical scrollbars appear when content overflows.
 */
import { useCallback, useEffect, useMemo, useRef, useState, useDeferredValue } from "react";
import { Maximize2, RotateCcw } from "lucide-react";
import { useInvestigationFilter } from "./InvestigationFilter";

// ── Legacy 6-lane view (preprocessor.stages compat) ─────────────
const LANES = [
  { id: "execution",      label: "Execution",     y: 104 },
  { id: "transformation", label: "Transformation", y: 200 },
  { id: "network",        label: "Network / C2",  y: 296 },
  { id: "filesystem",     label: "File System",   y: 392 },
  { id: "registry",       label: "Registry",      y: 488 },
  { id: "persistence",    label: "Persistence",   y: 584 },
];

// ── Canonical 14-lane MITRE ATT&CK projection ───────────────────
// Rule R22 · Architecture v1.0 · The frontend is a PURE PROJECTION
// of `behavior.mitre_tactics[]` — no remapping, no inference.
// Empty tactics collapse automatically (the layout skips them).
const MITRE_LANES = [
  { id: "Reconnaissance",         label: "Reconnaissance" },
  { id: "Resource Development",   label: "Resource Development" },
  { id: "Initial Access",         label: "Initial Access" },
  { id: "Execution",              label: "Execution" },
  { id: "Persistence",            label: "Persistence" },
  { id: "Privilege Escalation",   label: "Privilege Escalation" },
  { id: "Defense Evasion",        label: "Defense Evasion" },
  { id: "Credential Access",      label: "Credential Access" },
  { id: "Discovery",              label: "Discovery" },
  { id: "Lateral Movement",       label: "Lateral Movement" },
  { id: "Collection",             label: "Collection" },
  { id: "Command and Control",    label: "Command and Control" },
  { id: "Exfiltration",           label: "Exfiltration" },
  { id: "Impact",                 label: "Impact" },
];

const MITRE_LANE_HEIGHT = 108;

// Colour per MITRE tactic — deterministic palette.  Same tactic →
// same colour every render.  Empty tactics collapse before nodes
// paint, so the palette is only ever applied to lanes that carry
// at least one behavior node.
const MITRE_LANE_COLOR = {
  "Reconnaissance":         "#67e8f9",
  "Resource Development":   "#38bdf8",
  "Initial Access":         "#a78bfa",
  "Execution":              "#facc15",
  "Persistence":            "#fbbf24",
  "Privilege Escalation":   "#f97316",
  "Defense Evasion":        "#c084fc",
  "Credential Access":      "#fb7185",
  "Discovery":              "#22d3ee",
  "Lateral Movement":       "#60a5fa",
  "Collection":             "#a3e635",
  "Command and Control":    "#ef4444",
  "Exfiltration":           "#f87171",
  "Impact":                 "#dc2626",
};

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

export default function TrajectoryDiagram({ preprocessor, behaviors }) {
  // ── Rule R23 · Visualization Isolation ─────────────────────────
  // The visualization layer MUST NEVER block the investigation
  // pipeline.  React 18 `useDeferredValue` schedules the heavy
  // 200-node SVG layout at LOW priority so user input, tab
  // switches, and text selection stay responsive even if the
  // graph takes 500 ms to lay out.  The trade-off is that on
  // heavy pastes the graph may appear a beat after the tab
  // switches — but the tab NEVER freezes.
  const deferredBehaviors  = useDeferredValue(behaviors);
  const deferredPreprocessor = useDeferredValue(preprocessor);

  // ── Rule R22 projection: canonical behaviors take priority over
  // legacy preprocessor stages.  When `behaviors` are present we
  // render the 14-tactic ATT&CK view; otherwise we fall back to
  // the legacy 6-lane tactic-bucket view.
  const isCanonical = Array.isArray(deferredBehaviors) && deferredBehaviors.length > 0;

  // Stable content fingerprint — prevents runaway recomputation
  // when the parent passes a NEW array reference on every render
  // with the SAME content (R23 · frontend guarantee #3 — progressive
  // rendering must not thrash on heavy pastes).
  const behaviorsKey = useMemo(() => {
    if (!isCanonical) return "legacy";
    const first = deferredBehaviors[0]?.id || deferredBehaviors[0]?.label || "";
    const last  = deferredBehaviors[deferredBehaviors.length - 1]?.id
                    || deferredBehaviors[deferredBehaviors.length - 1]?.label || "";
    let tacticCount = 0;
    for (const b of deferredBehaviors) tacticCount += (b?.mitre_tactics?.length || 0);
    return `${deferredBehaviors.length}:${tacticCount}:${first}:${last}`;
  }, [isCanonical, deferredBehaviors]);

  // ── Client-side telemetry (Rule R23 · guarantee #4).
  // Every render logs its layout cost + recompute count to a
  // rolling window on `window.__NIVXRAY_TRAJ_TELEM__` so ops /
  // regression tests can assert "recomputations ≤ N" without
  // instrumenting React itself.
  const _telemRef = useRef({ renders: 0, layouts: 0, lastLayoutMs: 0 });
  useEffect(() => {
    _telemRef.current.renders += 1;
    if (typeof window !== "undefined") {
      window.__NIVXRAY_TRAJ_TELEM__ = { ..._telemRef.current };
    }
  });

  // ── Full 14-lane ATT&CK matrix (2026-02-09 · scalable canvas) ─
  // Always render every MITRE tactic lane so analysts see what
  // WASN'T observed as clearly as what was.  Inactive lanes are
  // dimmed instead of removed — this makes coverage gaps visible.
  const activeLanes = useMemo(() => {
    if (!isCanonical) return LANES;
    const seen = new Set();
    for (const b of behaviors) {
      for (const t of _behaviorTactics(b)) seen.add(t);
    }
    return MITRE_LANES.map((l, i) => ({
      ...l,
      y:      80 + i * MITRE_LANE_HEIGHT,
      active: seen.has(l.id),
    }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [behaviorsKey]);

  const initialNodes = useMemo(
    () => {
      const _t0 = (typeof performance !== "undefined") ? performance.now() : 0;
      const built = isCanonical
        ? _layoutBehaviorNodes(deferredBehaviors, activeLanes)
        : _layoutNodes(deferredPreprocessor);
      _telemRef.current.layouts    += 1;
      _telemRef.current.lastLayoutMs = ((typeof performance !== "undefined") ? performance.now() : 0) - _t0;
      return built;
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [behaviorsKey, deferredPreprocessor, activeLanes],
  );
  const [nodes, setNodes] = useState(initialNodes);
  const investigation = useInvestigationFilter();
  const [zoom,  setZoom]  = useState(1);
  // ── Popout / expanded view (2026-02-09 · user request) ─────
  // When true, the entire trajectory panel renders inside a
  // fixed-position full-screen overlay so analysts can inspect
  // dense investigations without page chrome.
  const [popout, setPopout] = useState(false);
  // ESC closes the popout view — analyst-friendly muscle memory.
  useEffect(() => {
    if (!popout) return;
    const onKey = (e) => { if (e.key === "Escape") setPopout(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [popout]);
  const [pan,   setPan]   = useState({ x: 0, y: 0 });
  const [selectedNode, setSelectedNode] = useState(null);   // Node Inspector target
  const dragRef  = useRef(null);
  const panRef   = useRef(null);
  const svgRef   = useRef(null);
  const dragMovedRef = useRef(false);   // true if the pointer moved between mousedown and mouseup — used to distinguish click vs drag

  useEffect(() => {
    setNodes(isCanonical
      ? _layoutBehaviorNodes(deferredBehaviors, activeLanes)
      : _layoutNodes(deferredPreprocessor));
    setPan({x:0,y:0}); setZoom(1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [behaviorsKey, deferredPreprocessor, activeLanes]);

  const edges = useMemo(() => isCanonical
      ? _layoutBehaviorEdges(nodes)
      : _layoutEdges(nodes, deferredPreprocessor),
    [isCanonical, nodes, deferredPreprocessor]);

  // ── Per-lane stats (2026-02-09 · richer lane headers) ────────
  // For each ATT&CK tactic, aggregate:
  //   · techniques — unique T-id count across the lane's nodes
  //   · commands   — sum of node.command_count in the lane
  //   · behaviors  — number of nodes projected into the lane
  // Analysts read density at a glance without opening any node.
  // Rules-of-Hooks: this `useMemo` MUST run before any conditional
  // early return so the hook order stays stable across renders.
  const laneStats = useMemo(() => {
    const s = {};
    for (const l of MITRE_LANES) s[l.id] = { techniques: new Set(), commands: 0, behaviors: 0 };
    for (const n of nodes) {
      const bucket = s[n.tactic];
      if (!bucket) continue;
      bucket.behaviors  += 1;
      bucket.commands   += (n.command_count || 0);
      const tech = n.subtitle && n.subtitle.startsWith("T") ? n.subtitle : null;
      if (tech) bucket.techniques.add(tech);
    }
    // Coerce Sets → counts, memoize the max for the progress bar.
    let maxCmds = 0;
    const out = {};
    for (const id in s) {
      out[id] = {
        techniques: s[id].techniques.size,
        commands:   s[id].commands,
        behaviors:  s[id].behaviors,
      };
      if (out[id].commands > maxCmds) maxCmds = out[id].commands;
    }
    out.__max_commands = Math.max(1, maxCmds);
    return out;
  }, [nodes]);

  // Early empty-state return — MUST come AFTER every hook above so
  // React sees the same hook sequence on every render.
  if (isCanonical) {
    if (!nodes.length) return null;
  } else if (!deferredPreprocessor || !deferredPreprocessor.stages || !deferredPreprocessor.stages.length) {
    return null;
  }

  // ── Canvas dimensions — dynamic (2026-02-09 · scalable canvas) ─
  // Width grows linearly with the number of nodes so 5-node cases
  // fit compactly while 100-node cases get a horizontally-scrolling
  // strip.  Height is fixed at the full 14-lane matrix so ATT&CK
  // coverage is always visible.
  const NODE_STEP = 260;                                    // px between nodes
  const contentW  = Math.max(
    1400,                                                       // floor
    ...(nodes.map((n) => n.x + NODE_STEP)),
    (isCanonical ? nodes.length : 5) * NODE_STEP + 200,       // dynamic scale
  );
  const contentH = isCanonical
    ? 80 + MITRE_LANES.length * MITRE_LANE_HEIGHT + 40        // full 14 lanes
    : 900;

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

  const sectionStyle = popout ? {
      position: "fixed", inset: 0, zIndex: 1000,
      background: "linear-gradient(180deg, rgba(15,23,42,0.98), rgba(2,6,23,0.98))",
      border: "none", borderRadius: 0,
      padding: "24px 28px",
      overflow: "auto",
    } : {
      background: "linear-gradient(180deg, rgba(15,23,42,0.9), rgba(2,6,23,0.9))",
      border: "1px solid #1f2b3f", borderRadius: 12,
      padding: "16px 18px", marginBottom: 14,
      position: "relative",
    };

  return (
    <section data-testid="trajectory-diagram" style={sectionStyle}>
      <div style={{ display: "flex", alignItems: "center",
                    justifyContent: "space-between", marginBottom: 10,
                    flexWrap: "wrap", gap: 8 }}>
        <div>
          <div style={tagline}>EVIDENCE TRAJECTORY</div>
          <div style={{ fontSize: 22, fontWeight: 800, color: "#e2e8f0",
                        marginTop: 4, letterSpacing: 0.2 }}
                data-testid="trajectory-header-title">
            {isCanonical
              ? `MITRE ATT&CK`
              : `Investigation Trajectory · ${LANES.length} artifact lanes · drag nodes · pan background · use +/− to zoom`}
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
          {/* Popout / close (2026-02-09 · user request) ────────
              Expands the trajectory into a full-screen overlay so
              dense investigations get the entire viewport.  ESC or
              the × button restores the inline view. */}
          <button data-testid="trajectory-popout"
                  onClick={() => setPopout((p) => !p)}
                  style={btn}
                  title={popout ? "Restore inline view (Esc)" : "Popout · full-screen"}>
            {popout ? "× CLOSE" : "⤢ POPOUT"}
          </button>
        </div>
      </div>

      <div style={legendBar}>
        {isCanonical ? (
          <>
            <span style={legendGroup}>MITRE TACTICS PROJECTED:</span>
            {activeLanes.map((l) => (
              <LegendChip key={l.id} color={MITRE_LANE_COLOR[l.id] || "#94a3b8"} label={l.label} />
            ))}
          </>
        ) : (
          <>
            <span style={legendGroup}>NODE COLOURS BY KILL-CHAIN PHASE:</span>
            <LegendChip color="#67e8f9" label="Reconnaissance" />
            <LegendChip color="#c084fc" label="Delivery / Exploitation" />
            <LegendChip color="#facc15" label="Exploitation" />
            <LegendChip color="#fb923c" label="Installation" />
            <LegendChip color="#ef4444" label="Command & Control" />
            <LegendChip color="#f87171" label="Actions on Objectives" />
            <LegendChip color="#64748b" label="Unclassified / no phase" />
            <span style={{ ...legendGroup, marginLeft: 14 }}>OVERRIDES:</span>
            <LegendChip color="#f87171" label="Critical (Impact)" />
            <LegendChip color="#fbbf24" label="Persistence" />
          </>
        )}
      </div>

      <div style={{ display: "grid",
                    gridTemplateColumns: selectedNode ? "1fr 340px" : "1fr",
                    gap: 12, alignItems: "stretch" }}>
        <div data-testid="trajectory-viewport"
           style={{ overflowX: "scroll",       // ALWAYS-visible horizontal
                    overflowY: "auto",
                    border: "1px solid #1f2b3f",
                    borderRadius: 10, background: "rgba(2,6,23,0.65)",
                    minHeight: 560,
                    // Popout mode uses the full viewport height minus the
                    // ~180px reserved for toolbar/legend/footer.
                    maxHeight: popout ? "calc(100vh - 180px)" : 1000,
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
            {/* Lane bands — richer headers (2026-02-09 · ATT&CK
                order preserved · technique + command counts +
                density bar).  Inactive lanes render dimmed. */}
            {(isCanonical ? activeLanes : LANES).map((lane, i) => {
              const dimmed = isCanonical && lane.active === false;
              const laneColor = isCanonical
                ? (MITRE_LANE_COLOR[lane.id] || "#94a3b8")
                : "#94a3b8";
              const stats = isCanonical ? (laneStats[lane.id] || null) : null;
              const barMax = 200;
              const barW   = (stats && laneStats.__max_commands)
                                  ? Math.round(barMax * stats.commands
                                                  / laneStats.__max_commands)
                                  : 0;
              // UI-DEF-02 (ADR-0010m): empty tactic lanes stay VISUALLY
              // SILENT. Structural label + thin divider only. No dimmed
              // fill, no "— · No Evidence" suffix, no stats row, no
              // density bar. This preserves the 14-tactic scaffold while
              // preventing the visual noise the owner flagged.
              if (dimmed) {
                return (
                  <g key={lane.id}
                      data-testid={`trajectory-lane-${lane.id}`}
                      data-lane-empty="true">
                    <text x={16} y={lane.y - 22}
                          style={{ fontSize: 11,
                                   fill: "#475569",
                                   letterSpacing: "0.14em",
                                   textTransform: "uppercase",
                                   fontWeight: 500 }}>
                      {lane.label}
                    </text>
                    <line x1={16} x2={contentW - 16}
                          y1={lane.y - 8} y2={lane.y - 8}
                          stroke="rgba(148,163,184,0.10)"
                          strokeWidth={1} />
                  </g>
                );
              }
              return (
                <g key={lane.id}
                    data-testid={`trajectory-lane-${lane.id}`}
                    data-lane-empty="false">
                  <rect x={0} y={lane.y - 40}
                        width={contentW}
                        height={isCanonical ? MITRE_LANE_HEIGHT - 6 : 90}
                        fill={i % 2 ? "rgba(148,163,184,0.03)"
                                    : "rgba(148,163,184,0.06)"} />
                  {/* Lane title */}
                  <text x={16} y={lane.y - 22}
                        style={{ fontSize: 11,
                                 fill: laneColor,
                                 letterSpacing: "0.14em",
                                 textTransform: "uppercase",
                                 fontWeight: isCanonical ? 700 : 400 }}>
                    {lane.label}
                  </text>
                  {/* Lane stats (technique / command counts) */}
                  {isCanonical && stats && (
                    <>
                      <text x={16} y={lane.y - 6}
                            style={{ fontSize: 10, fill: "#94a3b8",
                                     fontFamily: "JetBrains Mono, monospace" }}>
                        {stats.techniques} technique{stats.techniques === 1 ? "" : "s"}
                        {" · "}
                        {stats.commands} command{stats.commands === 1 ? "" : "s"}
                        {" · "}
                        {stats.behaviors} behavior{stats.behaviors === 1 ? "" : "s"}
                      </text>
                      {/* Density bar — width proportional to lane's
                          command count vs the busiest lane. */}
                      <rect x={16} y={lane.y + 4}
                            width={barMax} height={4} rx={2}
                            fill="rgba(148,163,184,0.15)" />
                      <rect x={16} y={lane.y + 4}
                            width={barW} height={4} rx={2}
                            fill={laneColor}
                            fillOpacity={0.85} />
                    </>
                  )}
                </g>
              );
            })}

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
              // In canonical mode the node colour IS the tactic
              // colour — a pure projection of the SSOT.  Severity
              // shows as a small right-side pill (no reasoning
              // happens here — severity is emitted by the backend).
              // Legacy mode: colour by kill-chain phase when known;
              // fall back to a NEUTRAL slate colour when the phase is
              // undetermined (previously fell back to cyan which the
              // legend labels "Reconnaissance" — a misleading claim).
              const UNKNOWN_PHASE = "#64748b";  // slate-500 (neutral)
              const phaseColor = isCanonical
                ? (MITRE_LANE_COLOR[n.tactic] || UNKNOWN_PHASE)
                : (KILL_CHAIN_COLOR[n.kill_chain] || UNKNOWN_PHASE);
              const borderColor = isCanonical
                ? phaseColor
                : (n.critical    ? "#f87171"
                    : n.persistence ? "#fbbf24"
                    : phaseColor);
              const dotColor    = isCanonical
                ? phaseColor
                : (n.critical    ? "#f87171"
                    : n.persistence ? "#fbbf24"
                    : phaseColor);
              // ── Semantic zoom levels (2026-02-09) ─────────────
              //   zoom < 0.5 → dot only  (matrix overview)
              //   0.5..0.79 → title only (labels)
              //   >= 0.8    → full node card (all metadata)
              const zoomLevel = zoom < 0.5 ? "dot"
                                  : zoom < 0.8 ? "label" : "full";
              const cnt         = n.command_count || 0;
              // Compact-mode still shows a count so analysts don't
              // miss high-density clusters, but the ambiguous ×N
              // is dropped from FULL mode where we spell it out.
              const badgeCompact = cnt > 1 ? ` (${cnt})` : "";
              const displayTitle = (n.title.length > 24
                                          ? n.title.slice(0, 22) + "…"
                                          : n.title)
                                       + (zoomLevel === "full" ? "" : badgeCompact);

              // Dot-only mode — matrix / mini-navigation view.
              if (zoomLevel === "dot") {
                return (
                  <g key={n.id} data-testid={`trajectory-node-${n.id}`}
                     data-zoom-level="dot"
                     onMouseDown={(e) => onNodeMouseDown(e, n.id)}
                     style={{
                       cursor: "grab",
                       opacity: (investigation.active && !investigation.match(n.raw)) ? 0.28 : 1,
                     }}>
                    <circle cx={n.x + 10} cy={n.y + 6} r={9}
                            fill={dotColor}
                            stroke={borderColor} strokeWidth={2} />
                    {cnt > 1 && (
                      <text x={n.x + 10} y={n.y + 9}
                            textAnchor="middle"
                            style={{ fontSize: 9, fontWeight: 800,
                                     fill: "#0b1220", pointerEvents: "none" }}>
                        {cnt}
                      </text>
                    )}
                  </g>
                );
              }

              return (
              <g key={n.id} data-testid={`trajectory-node-${n.id}`}
                 data-zoom-level={zoomLevel}
                 onMouseDown={(e) => onNodeMouseDown(e, n.id)}
                 style={{
                   cursor: "grab",
                   opacity: (investigation.active && !investigation.match(n.raw)) ? 0.28 : 1,
                   transition: "opacity 0.2s ease",
                 }}>
                {/* Node card */}
                <rect x={n.x - 4} y={n.y - 24}
                      width={210}
                      height={zoomLevel === "label" ? 34 : 62}
                      rx={6}
                      fill="rgba(15,23,42,0.9)"
                      stroke={borderColor}
                      strokeWidth={1.6} />
                <circle cx={n.x + 10} cy={n.y + 6} r={7}
                        fill={dotColor}
                        stroke="#0b1220" strokeWidth={2} />
                <text x={n.x + 22} y={n.y - 8}
                      style={{ fontSize: 12, fontWeight: 700, fill: "#e2e8f0" }}>
                  {displayTitle}
                </text>
                {zoomLevel === "full" && (
                  <>
                    <text x={n.x + 22} y={n.y + 4}
                          style={{ fontSize: 9.5, fill: phaseColor,
                                   fontWeight: 700 }}>
                      {isCanonical ? (n.subtitle || n.tactic) : n.kill_chain}
                    </text>
                    <text x={n.x + 22} y={n.y + 16}
                          style={{ fontSize: 9.5, fill: "#64748b" }}>
                      {isCanonical
                        ? (
                            (cnt > 0 ? `${cnt} command${cnt === 1 ? "" : "s"} · ` : "")
                            + "1 behavior"
                          )
                        : (n.subtitle + " · " + n.time)}
                    </text>
                  </>
                )}
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

      {/* ── Mini-map removed 2026-02-09 · user feedback ──────────
          Overview strip was interfering with the analyst's view
          of the trajectory canvas.  Kept the code path clean —
          re-enable when a proper anchored/hideable variant lands. */}

      <div style={{ marginTop: 8, fontSize: 11, color: "#64748b",
                    fontStyle: "italic" }}>
        Deterministic trajectory. Drag nodes · click-drag the background to pan ·
        use +/− buttons to zoom · zoom out for the ATT&CK-matrix overview · RESET restores the auto-layout.
      </div>
    </section>
  );
}

/* ── Layout helpers ────────────────────────────────────────────── */

// ── Canonical 14-lane MITRE projection · behavior-driven ────────
// Rule R22: for each behavior → for each tactic in mitre_tactics[]
// → emit one node.  A single behavior with 3 tactics produces 3
// nodes (one per lane).  Empty tactics are already filtered out by
// the caller (activeLanes only contains tactics that carry ≥1
// behavior).  No inference, no remapping.
//
// Tactic sources (in priority order, per Rule R22):
//   1. `behavior.mitre_tactics[]`  (canonical, plural)
//   2. `behavior.mitre[].tactic`   (ICE-cluster shape — one entry
//                                    per technique, tactic pre-attached)
//   3. `behavior.primary_tactic`    (single fallback — ICE-cluster
//                                    shape when no MITRE technique
//                                    was mapped)
// Every extracted tactic is normalized to the canonical MITRE label
// (title-case with "and" for "&") so the 14-lane switch always
// matches.
const _TACTIC_NORMALIZE = {
  "initial access":       "Initial Access",
  "initial_access":       "Initial Access",
  "execution":            "Execution",
  "persistence":          "Persistence",
  "privilege escalation": "Privilege Escalation",
  "privilege_escalation": "Privilege Escalation",
  "defense evasion":      "Defense Evasion",
  "defense_evasion":      "Defense Evasion",
  "credential access":    "Credential Access",
  "credential_access":    "Credential Access",
  "discovery":            "Discovery",
  "lateral movement":     "Lateral Movement",
  "lateral_movement":     "Lateral Movement",
  "collection":           "Collection",
  "command and control":  "Command and Control",
  "command_and_control":  "Command and Control",
  "exfiltration":         "Exfiltration",
  "impact":               "Impact",
  "reconnaissance":       "Reconnaissance",
  "resource development": "Resource Development",
  "resource_development": "Resource Development",
};
function _canonTactic(t) {
  if (!t) return null;
  const key = String(t).trim().toLowerCase();
  return _TACTIC_NORMALIZE[key] || null;
}
function _behaviorTactics(b) {
  const out = new Set();
  for (const t of (b.mitre_tactics || [])) {
    const c = _canonTactic(t); if (c) out.add(c);
  }
  if (!out.size) {
    for (const m of (b.mitre || [])) {
      const c = _canonTactic(m && m.tactic);
      if (c) out.add(c);
    }
  }
  if (!out.size) {
    const c = _canonTactic(b.primary_tactic);
    if (c) out.add(c);
  }
  return [...out];
}

function _layoutBehaviorNodes(behaviors, activeLanes) {
  if (!Array.isArray(behaviors) || !behaviors.length) return [];
  if (!Array.isArray(activeLanes) || !activeLanes.length) return [];
  // ── Hard cap · Resource Protection Policy ────────────────────
  // Prevent runaway pastes (deeply-nested / mass-encoded inputs)
  // from producing thousands of behavior nodes that would freeze
  // the SVG renderer.  The deterministic ordering already ranks the
  // most severe / earliest kill-chain first so truncation preserves
  // the analyst's highest-signal view.
  const MAX_BEHAVIORS = 60;
  const MAX_NODES     = 200;
  // 2026-02-09 · Scalable-canvas redesign · only PLACE nodes in
  // lanes that carry behaviors.  Inactive lanes still render as
  // greyed-out swim-lane backdrops for coverage-gap visibility.
  const laneY = {};
  for (const l of activeLanes) if (l && l.id && l.active !== false) laneY[l.id] = l.y;
  const ordered = [...behaviors]
    .filter((b) => b && typeof b === "object")
    .sort((a, b) => ((a.order ?? 0) - (b.order ?? 0)))
    .slice(0, MAX_BEHAVIORS);
  const X_START = 220;
  const X_STEP  = 240;
  const nodes = [];
  // Chronological X — each behavior occupies ONE column so a
  // behavior spanning multiple tactics stacks vertically at the
  // same X.  The next behavior in chronological order advances one
  // column, so the chain reads left-to-right regardless of which
  // tactic lanes are active.
  ordered.forEach((b, i) => {
    const tactics = _behaviorTactics(b).filter((t) => t in laneY);
    if (!tactics.length) return;
    // ── Per-lane technique projection (2026-02-09 · consistency fix) ─
    // A cluster with techniques spanning multiple tactics (e.g.
    // T1053.005 Execution + T1564.003 Defense Evasion) previously
    // rendered `techniques[0]` under EVERY lane node — surfacing
    // Defense-Evasion techniques in the Execution lane and vice
    // versa.  We now split the cluster's `mitre[]` array by
    // per-technique `tactic` so each lane node only shows the
    // technique(s) that actually belong to that tactic.
    const perTactic = {};        // canonical tactic → [technique id, …]
    for (const m of (b.mitre || [])) {
      if (!m || typeof m !== "object") continue;
      const canon = _canonTactic(m.tactic);
      const tid   = m.id;
      if (!canon || !tid) continue;
      (perTactic[canon] = perTactic[canon] || []).push(tid);
    }
    // Fallback list — used ONLY when the cluster carries strings
    // in mitre_techniques[] without per-technique tactic info.
    const flatTechniques = (b.mitre_techniques && b.mitre_techniques.length
                                ? b.mitre_techniques
                                : (b.mitre || []))
      .map((m) => (m == null ? null : (typeof m === "string" ? m : m.id)))
      .filter(Boolean);
    const title = b.title || b.label || `Behavior ${i + 1}`;
    const behaviorKey = b.id || `bhv-${i}`;
    const x = X_START + i * X_STEP;
    tactics.forEach((tactic, tIdx) => {
      if (nodes.length >= MAX_NODES) return;   // hard cap SVG size
      // Prefer techniques belonging to THIS lane; fall back to the
      // flat list only when the cluster lacks per-technique tactic
      // metadata (older payload shape).
      const laneTechs = (perTactic[tactic] && perTactic[tactic].length)
                             ? perTactic[tactic]
                             : flatTechniques;
      const laneSubtitle = laneTechs[0] || b.category || "";
      const cmdCount = (b.commands || b.command_count || 0);
      nodes.push({
        id:          `${behaviorKey}--${_slug(tactic)}`,
        behaviorKey,               // stable link across sibling nodes
        order:       i,             // chronological rank
        primary:     tIdx === 0,    // first tactic listed = chain anchor
        index:       i + 1,
        x,
        y:           laneY[tactic],
        lane:        tactic,
        tactic,
        title,
        subtitle:    laneSubtitle,
        // 2026-02-09 · scalable canvas — count badge on clustered
        // behaviors so `Registry modification × 4` shows at a glance.
        command_count: (typeof cmdCount === "number" ? cmdCount
                            : (Array.isArray(cmdCount) ? cmdCount.length : 0)),
        kill_chain:  (b.kill_chain && b.kill_chain[0]) || "",
        severity:    b.severity || "medium",
        confidence:  typeof b.confidence === "number" ? b.confidence
                       : (b.confidence === "high"   ? 0.95
                         : b.confidence === "medium" ? 0.75
                         : b.confidence === "low"    ? 0.55 : 0.5),
        raw: {
          objective:      b.description,
          normalized_command: (b.commands && b.commands[0] && b.commands[0].command) || "",
          mitre:          laneTechs,        // lane-scoped provenance
          tactic,
          command_family: b.category,
          evidence:       (b.commands || []).map((c) => c.command).filter(Boolean),
          confidence:     typeof b.confidence === "number" ? b.confidence : undefined,
        },
      });
    });
  });
  return nodes;
}

// Deterministic edges for the canonical 14-lane projection.
//
// Two edge families are emitted:
//   1. Intra-behavior arcs (dashed persist style)  — connect the
//      sibling nodes of a SINGLE behavior that spans multiple
//      MITRE tactics.  Lets the analyst see “this one action
//      lives in two ATT&CK tactics.”
//   2. Chronological chain arrows (solid crit / normal)  — connect
//      behavior N's primary node (first tactic listed) to behavior
//      N+1's primary node so the attack progression reads left-to-
//      right across the diagram, jumping lanes as the tactic
//      changes.  This is the “where does the attack go next?”
//      story the analyst needs.
function _layoutBehaviorEdges(nodes) {
  if (!nodes || !nodes.length) return [];
  const edges = [];

  // ── 1. Intra-behavior vertical arcs ─────────────────────────
  const byBehavior = {};
  for (const n of nodes) {
    if (!n) continue;
    const key = n.behaviorKey || (typeof n.id === "string" ? n.id.split("--")[0] : "unknown");
    (byBehavior[key] = byBehavior[key] || []).push(n);
  }
  for (const [key, group] of Object.entries(byBehavior)) {
    const sorted = [...group].sort((a, b) => (a.y || 0) - (b.y || 0));
    for (let i = 0; i < sorted.length - 1; i++) {
      const a = sorted[i], b = sorted[i + 1];
      if (a == null || b == null) continue;
      edges.push({
        id: `be-intra-${key}-${i}`,
        d:  _bezier((a.x || 0) + 10, (a.y || 0) + 6, (b.x || 0) + 10, (b.y || 0) + 6),
        style: "persist",
      });
    }
  }

  // ── 2. Chronological attack chain — primary-node → primary-node
  const primaries = nodes
    .filter((n) => n && n.primary)
    .sort((a, b) => (a.order || 0) - (b.order || 0));
  for (let i = 0; i < primaries.length - 1; i++) {
    const a = primaries[i], b = primaries[i + 1];
    if (!a || !b) continue;
    const style = (b.tactic === "Impact") ? "crit" : "normal";
    edges.push({
      id:    `be-chain-${a.behaviorKey || a.id}-${b.behaviorKey || b.id}`,
      d:     _bezier((a.x || 0) + 10, (a.y || 0) + 6, (b.x || 0) + 10, (b.y || 0) + 6),
      style,
    });
  }

  return edges;
}

function _slug(s) {
  return String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

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
      maxHeight: 1000,
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
