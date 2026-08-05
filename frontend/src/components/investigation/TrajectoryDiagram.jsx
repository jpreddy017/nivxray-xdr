/**
 * TrajectoryDiagram — Swim-lane attack-chain visualisation matching
 * the reference NivXRay trajectory artefact.
 *
 * Six lanes (top → bottom):
 *   1. Execution
 *   2. Transformation
 *   3. Network / C2
 *   4. File System
 *   5. Registry
 *   6. Persistence
 *
 * Nodes come from `preprocessor.stages` (each stage has
 * tactic / mitre / title / objective / line_number / confidence).
 * Edges come from `preprocessor.process_edges`.  Colour code:
 *   · normal edge         → #2A3650
 *   · Impact / high-conf  → rgba(239,68,68,0.55)  (critical path)
 *   · Persistence         → rgba(245,158,11,0.55)
 *
 * Purely deterministic — no LLM, no randomness — layout is derived
 * from stage ordering and lane assignment.
 */
import { useMemo } from "react";

const LANES = [
  { id: "execution",      label: "Execution",     y: 104 },
  { id: "transformation", label: "Transformation", y: 164 },
  { id: "network",        label: "Network / C2",  y: 224 },
  { id: "filesystem",     label: "File System",   y: 284 },
  { id: "registry",       label: "Registry",      y: 344 },
  { id: "persistence",    label: "Persistence",   y: 404 },
];

// ATT&CK tactic → swim-lane id.  Deterministic mapping.
const TACTIC_TO_LANE = {
  "Initial Access":     "execution",
  "Execution":          "execution",
  "Discovery":          "execution",
  "Credential Access":  "execution",
  "Defense Evasion":    "registry",
  "Command and Control": "network",
  "Lateral Movement":   "network",
  "Exfiltration":       "network",
  "Impact":             "filesystem",
  "Persistence":        "persistence",
};

// Command-family → refinement (some families read better on a
// specific lane regardless of tactic).
const FAMILY_LANE_OVERRIDE = {
  "shadow-copy-deletion": "filesystem",
  "log-clearing":         "filesystem",
  "registry-modification": "registry",
  "uac-disable":           "registry",
  "persistence-scheduled-task": "persistence",
  "sync-rclone-style":     "network",
  "msi-install":           "transformation",
  "reverse-ssh-tunnel":    "network",
  "rmm-remote-access":     "network",
  "brute-ratel":           "network",
  "psexec-lateral":        "network",
  "ad-discovery":          "execution",
  "host-discovery":        "execution",
  "session-discovery":     "execution",
  "account-discovery":     "execution",
  "initial-access-social": "execution",
};

const EDGE_STYLES = {
  crit:    "rgba(239,68,68,0.55)",
  persist: "rgba(245,158,11,0.55)",
  normal:  "#2A3650",
};

export default function TrajectoryDiagram({ preprocessor }) {
  const nodes = useMemo(() => _layoutNodes(preprocessor), [preprocessor]);
  const edges = useMemo(() => _layoutEdges(nodes, preprocessor), [nodes, preprocessor]);

  if (!preprocessor || !preprocessor.stages || !preprocessor.stages.length) {
    return null;
  }

  // Compute canvas width from the last node.
  const width = Math.max(960, ...(nodes.map((n) => n.x + 120)));
  const height = 480;

  return (
    <section data-testid="trajectory-diagram" style={{
      background: "linear-gradient(180deg, rgba(15,23,42,0.9), rgba(2,6,23,0.9))",
      border: "1px solid #1f2b3f", borderRadius: 12,
      padding: "16px 18px", marginBottom: 14,
    }}>
      <div style={{ display: "flex", alignItems: "center",
                    justifyContent: "space-between", marginBottom: 10 }}>
        <div>
          <div style={tagline}>EVIDENCE TRAJECTORY</div>
          <div style={{ fontSize: 18, fontWeight: 700, color: "#e2e8f0",
                        marginTop: 2 }}>
            Attack chain across {LANES.length} swim lanes
          </div>
        </div>
        <div data-testid="trajectory-legend" style={legendBar}>
          <LegendChip color="#67e8f9" label="Execution / process" />
          <LegendChip color="#a78bfa" label="Transformation / decode" />
          <LegendChip color="#f87171" label="Network & defense evasion" />
          <LegendChip color="#fbbf24" label="Persistence" />
        </div>
      </div>

      <div style={{ overflowX: "auto", overflowY: "hidden",
                    border: "1px solid #1f2b3f", borderRadius: 10,
                    background: "rgba(2,6,23,0.55)" }}>
        <svg width={width} height={height}
             style={{ display: "block", fontFamily: "JetBrains Mono, monospace" }}>
          <defs>
            <marker id="arr" viewBox="0 0 10 10" refX="8" refY="5"
                    markerWidth="7" markerHeight="7" orient="auto">
              <path d="M0,0 L10,5 L0,10 z" fill="#2A3650" />
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

          {/* ── Lane bands + labels ─────────────────────────────── */}
          {LANES.map((lane, i) => (
            <g key={lane.id}>
              <rect x={0} y={lane.y - 34}
                    width={width} height={60}
                    fill={i % 2 ? "rgba(148,163,184,0.03)" : "rgba(148,163,184,0.06)"} />
              <text x={16} y={lane.y + 4}
                    style={{ fontSize: 11, fill: "#94a3b8",
                             letterSpacing: "0.12em", textTransform: "uppercase" }}>
                {lane.label}
              </text>
            </g>
          ))}

          {/* ── Edges ────────────────────────────────────────────── */}
          {edges.map((e) => (
            <path key={e.id} d={e.d}
                  stroke={EDGE_STYLES[e.style] || EDGE_STYLES.normal}
                  strokeWidth={e.style === "crit" ? 2.2 : 1.6}
                  fill="none"
                  markerEnd={
                    e.style === "crit"    ? "url(#arrc)"
                    : e.style === "persist" ? "url(#arra)"
                    : "url(#arr)"
                  }
                  data-testid={`trajectory-edge-${e.id}`} />
          ))}

          {/* ── Nodes ────────────────────────────────────────────── */}
          {nodes.map((n) => (
            <g key={n.id} data-testid={`trajectory-node-${n.id}`}>
              <circle cx={n.x} cy={n.y} r={9}
                      fill={n.critical ? "#f87171" : n.persistence ? "#fbbf24" : "#67e8f9"}
                      stroke="#0b1220" strokeWidth={2} />
              <text x={n.x + 16} y={n.y - 5}
                    style={{ fontSize: 12, fontWeight: 700, fill: "#e2e8f0" }}>
                {n.title.length > 42 ? n.title.slice(0, 39) + "…" : n.title}
              </text>
              <text x={n.x + 16} y={n.y + 9}
                    style={{ fontSize: 10, fill: "#94a3b8" }}>
                {n.subtitle}
              </text>
              <text x={n.x + 16} y={n.y + 23}
                    style={{ fontSize: 10, fill: "#64748b" }}>
                {n.time}
              </text>
            </g>
          ))}
        </svg>
      </div>

      <div style={{ marginTop: 8, fontSize: 11, color: "#64748b",
                    fontStyle: "italic" }}>
        Deterministic swim-lane trajectory generated from preprocessor stages.
        Node position reflects execution order; lane reflects ATT&CK tactic.
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
  const X_STEP  = 150;

  stages.forEach((s, i) => {
    const lane = _pickLane(s);
    const laneObj = LANES.find((l) => l.id === lane) || LANES[0];
    // Nodes advance horizontally by execution order.  Small vertical
    // jitter (± 4px) keeps duplicate-lane rows readable.
    const laneCount = stages.slice(0, i + 1).filter(
      (x, j) => j <= i && _pickLane(x) === lane).length;
    nodes.push({
      id: s.id || `stage-${i}`,
      index: i + 1,
      x: X_START + i * X_STEP,
      y: laneObj.y + ((laneCount % 2) === 0 ? 0 : 4),
      lane,
      title: s.title || `Stage ${i + 1}`,
      subtitle: (s.mitre && s.mitre[0]) || s.command_family || s.kind || "",
      time: `+${(i * 0.35 + 0.2).toFixed(3)}s`,
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
  // 1) Temporal chain — connect every consecutive stage.
  for (let i = 0; i < nodes.length - 1; i++) {
    const a = nodes[i]; const b = nodes[i + 1];
    // Determine style: if b is impact → crit; if b is persistence → persist.
    const style = b.critical ? "crit" : b.persistence ? "persist" : "normal";
    edges.push({
      id: `e-${a.index}-${b.index}`,
      d: _bezier(a.x, a.y, b.x, b.y),
      style,
    });
  }
  // 2) Explicit inferred process edges from the preprocessor (if any).
  const inferred = (preprocessor && preprocessor.process_edges) || [];
  for (const e of inferred) {
    // Try to line up parent → child by title.
    const p = nodes.find(
      (n) => (n.title || "").toLowerCase().includes((e.parent || "").toLowerCase().replace(".exe", ""))
    );
    const c = nodes.find(
      (n) => (n.title || "").toLowerCase().includes((e.child || "").toLowerCase().replace(".exe", ""))
    );
    if (p && c && p.id !== c.id) {
      edges.push({
        id: `pi-${p.id}-${c.id}`,
        d: _bezier(p.x, p.y, c.x, c.y),
        style: c.critical ? "crit" : c.persistence ? "persist" : "normal",
      });
    }
  }
  return edges;
}

function _bezier(x1, y1, x2, y2) {
  const dx = Math.max(30, (x2 - x1) * 0.55);
  const cx1 = x1 + dx;
  const cx2 = x2 - dx;
  return `M${x1},${y1} C${cx1},${y1} ${cx2},${y2} ${x2},${y2}`;
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

const legendBar = { display: "flex", gap: 14, flexWrap: "wrap" };
