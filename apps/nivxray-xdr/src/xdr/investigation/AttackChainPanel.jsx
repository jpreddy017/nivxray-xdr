/**
 * AttackChainPanel — deterministic MITRE ATT&CK Trajectory canvas.
 *
 * Full 14 ATT&CK tactic swim-lanes, always visible, projected from
 * the same canonical evidence Evidence Trajectory uses.  Technique
 * nodes are plotted in their tactic row at an x-coordinate derived
 * from the temporal order of the FIRST evidence timestamp.  Bezier
 * curves connect consecutive techniques so the attack chain is
 * visualised across rows.
 *
 * Owner-locked invariants:
 *   1. Techniques are NEVER derived from the verdict.
 *   2. Techniques with 0 evidence are NEVER rendered.
 *   3. Sequential curves are drawn temporally — they do NOT imply
 *      causality.  See relationship kinds:
 *        OBSERVED    evidence directly supports the technique
 *        SEQUENCED   temporal ordering from timestamps
 *        CORRELATED  participates in a correlation match
 *        INFERRED    analytical relationship, not directly observed
 *
 * The 14 tactics are always shown as row labels — no fabrication.
 * If a tactic has no evidence, its row is empty (honest gap).
 */
import React, { useEffect, useMemo, useRef, useState } from "react";
import { RotateCcw, Minus, Plus, X, Info, Clock } from "lucide-react";

import { KILL_CHAIN, RULE_TO_TECHNIQUE, TECHNIQUE_INDEX }
    from "@/xdr/mitre/mitreTactics";
import { useSelection } from "@/xdr/investigation/WorkspaceSelectionContext";
import api from "@/lib/api";


// Tactic accent palette (matches the base NivXRay Tool trajectory).
const TACTIC_COLOR = {
  "reconnaissance":       "#60a5fa",
  "resource-development": "#a78bfa",
  "initial-access":       "#22d3ee",
  "execution":            "#38bdf8",
  "persistence":          "#facc15",
  "privilege-escalation": "#fb923c",
  "defense-evasion":      "#c084fc",
  "credential-access":    "#f472b6",
  "discovery":            "#34d399",
  "lateral-movement":     "#818cf8",
  "collection":           "#4ade80",
  "command-and-control":  "#ef4444",
  "exfiltration":         "#f43f5e",
  "impact":               "#eab308",
};

const REL_COLOR = {
  OBSERVED:   "var(--mint)",
  SEQUENCED:  "var(--cyan)",
  CORRELATED: "#a78bfa",
  INFERRED:   "var(--faint)",
};

// Layout constants
const ROW_H         = 68;
const LANE_X        = 130;                       // width of the tactic label column
const NODE_W        = 132;
const NODE_H        = 22;
const NODE_GAP_X    = 96;
const CANVAS_HEIGHT = KILL_CHAIN.length * ROW_H + 40;


export default function AttackChainPanel({ incident }) {
  const { selection, setSelection } = useSelection();
  const [correlations, setCorrelations] = useState([]);
  const [summary, setSummary]           = useState(null);
  const [zoom, setZoom]         = useState(100);
  const [pan, setPan]           = useState({ x: 0, y: 0 });
  const [drag, setDrag]         = useState(null);
  const [nodeDrag, setNodeDrag] = useState(null);
  const [overrides, setOverrides] = useState({});   // per-node manual x/y
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!incident?.id) return;
      try {
        const r = await api.get("/xdr/correlation/matches",
                                    { params: { incident_id: incident.id }});
        if (!cancelled) setCorrelations(r?.data?.data?.matches || []);
      } catch { if (!cancelled) setCorrelations([]); }
      // Authoritative NivXRay-Tool incident summary — best-effort.
      // Feeds real ATT&CK techniques + evidence into the trajectory
      // even when the XDR incident payload alone does not carry them.
      try {
        const s = await api.get(`/incidents/${incident.id}/summary`);
        if (!cancelled) setSummary(s?.data || null);
      } catch { if (!cancelled) setSummary(null); }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  // Merge the summary's evidence + MITRE arrays into an enriched
  // incident view before deriving the trajectory.  The merge is
  // additive — never mutates the incident.
  const enrichedIncident = useMemo(() => {
    if (!summary) return incident;
    const mergedEvidence = [
      ...(incident?.verdict_stage2?.evidence || []),
      ...(summary?.suspicious_elements || []),
    ];
    const mergedMitre = [
      ...(incident?.mitre || []),
      ...(summary?.mitre  || []),
    ];
    return { ...incident,
                    verdict_stage2: { ...(incident?.verdict_stage2 || {}),
                                              evidence: mergedEvidence },
                    mitre: mergedMitre };
  }, [incident, summary]);

  const { nodes, edges, gaps, hasEvidence } = useMemo(
    () => buildTrajectory(enrichedIncident, correlations),
    [enrichedIncident, correlations]);

  const selectedTech = selection?.kind === "technique"
                                            ? selection?.ref?.technique_id : null;

  // Deterministic auto-layout with hand-drag overrides on top.
  const laidOut = useMemo(() => {
    const out = {};
    // Group nodes by tactic, order by first_seen for a stable temporal x.
    const byTactic = {};
    for (const n of nodes) {
      if (!byTactic[n.tactic]) byTactic[n.tactic] = [];
      byTactic[n.tactic].push(n);
    }
    for (const [tactic, list] of Object.entries(byTactic)) {
      list.sort((a, b) => (a.first_seen || "").localeCompare(b.first_seen || ""));
    }
    // Global temporal order for x-coordinate — every technique keeps
    // its own x based on when the FIRST evidence for it appeared.  Two
    // techniques from different tactics with adjacent timestamps end
    // up in adjacent columns, which is what the trajectory curves
    // visualise.
    const allSorted = [...nodes]
      .sort((a, b) => (a.first_seen || "").localeCompare(b.first_seen || ""));
    const xIndex = new Map();
    allSorted.forEach((n, i) => xIndex.set(n.technique_id, i));

    for (const n of nodes) {
      const rowIdx = KILL_CHAIN.findIndex((k) => k.key === n.tactic);
      const y = 20 + rowIdx * ROW_H + (ROW_H - NODE_H) / 2;
      const xCol = xIndex.get(n.technique_id) || 0;
      const x = LANE_X + 40 + xCol * NODE_GAP_X;
      const override = overrides[n.technique_id];
      out[n.technique_id] = override || { x, y };
    }
    return out;
  }, [nodes, overrides]);

  const reset = () => { setOverrides({}); setPan({ x: 0, y: 0 }); setZoom(100); };

  // Canvas width — enough to hold all nodes + margins.
  const contentWidth = Math.max(
    LANE_X + 160,
    LANE_X + 60 + (nodes.length || 1) * NODE_GAP_X);

  const onMouseDown = (e) => {
    if (nodeDrag) return;
    setDrag({ startX: e.clientX, startY: e.clientY,
                     panX: pan.x, panY: pan.y });
  };
  const onMouseMove = (e) => {
    if (nodeDrag) {
      const dx = (e.clientX - nodeDrag.startX) / (zoom / 100);
      const dy = (e.clientY - nodeDrag.startY) / (zoom / 100);
      setOverrides((cur) => ({
        ...cur,
        [nodeDrag.tid]: { x: nodeDrag.origX + dx, y: nodeDrag.origY + dy },
      }));
      return;
    }
    if (!drag) return;
    setPan({ x: drag.panX + (e.clientX - drag.startX),
                y: drag.panY + (e.clientY - drag.startY) });
  };
  const endDrag = () => { setDrag(null); setNodeDrag(null); };

  if (!hasEvidence && nodes.length === 0) {
    return (
      <section data-testid="xdr-attack-chain-panel"
                       style={{ marginTop: 14 }}>
        <Header collapsed={collapsed} setCollapsed={setCollapsed}
                        zoom={zoom} setZoom={setZoom} reset={reset}
                        techniques={0} />
        {!collapsed && (
          <>
            <TacticLegend />
            <div style={{ ...emptyBox, marginBottom: 6 }}
                        data-testid="xdr-attack-chain-empty">
              <Info size={12} style={{ marginRight: 6 }} />
              No ATT&CK-mapped evidence in this investigation.  The 14
              tactic swim-lanes remain visible as an honest empty
              trajectory — never fabricated.
            </div>
            <EmptyCanvas contentWidth={contentWidth} pan={pan}
                                  zoom={zoom} />
            <div style={helpText}>
              Deterministic trajectory · every ATT&CK tactic row is always
              rendered · techniques with 0 evidence are NEVER plotted.
            </div>
          </>
        )}
      </section>
    );
  }

  return (
    <section data-testid="xdr-attack-chain-panel"
                   style={{ marginTop: 14 }}>
      <Header collapsed={collapsed} setCollapsed={setCollapsed}
                    zoom={zoom} setZoom={setZoom} reset={reset}
                    techniques={nodes.length} />

      {!collapsed && (
        <>
          <TacticLegend />
          <div style={canvasFrame}
                     onMouseDown={onMouseDown}
                     onMouseMove={onMouseMove}
                     onMouseUp={endDrag}
                     onMouseLeave={endDrag}
                     data-testid="xdr-chain-canvas">
            <svg width="100%" height={CANVAS_HEIGHT + 20}
                     style={{ display: "block", cursor: drag ? "grabbing" : "grab" }}
                     viewBox={`0 0 ${contentWidth} ${CANVAS_HEIGHT + 20}`}
                     preserveAspectRatio="xMinYMin meet">
              <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom / 100})`}>
                {/* Swim-lane rows */}
                {KILL_CHAIN.map((k, i) => (
                  <g key={k.key} data-testid={`xdr-chain-row-${k.key}`}>
                    <rect x={0}
                                y={20 + i * ROW_H}
                                width={contentWidth}
                                height={ROW_H - 2}
                                fill={i % 2 === 0 ? "rgba(255,255,255,0.015)"
                                                                  : "transparent"} />
                    <text x={10}
                                y={20 + i * ROW_H + ROW_H / 2 - 3}
                                fill="var(--faint)"
                                fontFamily="var(--mono)"
                                fontSize={10.5}
                                fontWeight={700}
                                letterSpacing={0.4}>
                      {k.label.toUpperCase()}
                    </text>
                    <text x={10}
                                y={20 + i * ROW_H + ROW_H / 2 + 12}
                                fill="rgba(160,160,180,0.35)"
                                fontFamily="var(--mono)"
                                fontSize={8.5}>
                      technique command behavior
                    </text>
                    <line x1={LANE_X - 6} y1={20 + i * ROW_H}
                                x2={LANE_X - 6} y2={20 + i * ROW_H + ROW_H}
                                stroke="rgba(255,255,255,0.06)"
                                strokeWidth={1} />
                  </g>
                ))}

                {/* Curves between consecutive (temporally-ordered) techniques */}
                {edges.map((e) => {
                  const a = laidOut[e.from];
                  const b = laidOut[e.to];
                  if (!a || !b) return null;
                  const mx = (a.x + NODE_W + b.x) / 2;
                  const c1 = `${mx},${a.y + NODE_H / 2}`;
                  const c2 = `${mx},${b.y + NODE_H / 2}`;
                  return (
                    <path key={`${e.from}->${e.to}`}
                                data-testid={`xdr-chain-edge-${e.from}-${e.to}`}
                                d={`M ${a.x + NODE_W} ${a.y + NODE_H / 2}
                                       C ${c1} ${c2}
                                          ${b.x} ${b.y + NODE_H / 2}`}
                                fill="none"
                                stroke="rgba(200,200,220,0.28)"
                                strokeWidth={1.2} />
                  );
                })}

                {/* Technique nodes */}
                {nodes.map((n) => {
                  const p = laidOut[n.technique_id];
                  if (!p) return null;
                  const active = selectedTech === n.technique_id;
                  const color = TACTIC_COLOR[n.tactic] || "var(--cyan)";
                  return (
                    <g key={n.technique_id}
                            transform={`translate(${p.x}, ${p.y})`}
                            data-testid={`xdr-chain-tech-${n.technique_id}`}
                            style={{ cursor: "pointer" }}
                            onMouseDown={(ev) => {
                              ev.stopPropagation();
                              setNodeDrag({
                                tid: n.technique_id,
                                startX: ev.clientX, startY: ev.clientY,
                                origX: p.x, origY: p.y,
                              });
                            }}
                            onClick={(ev) => {
                              ev.stopPropagation();
                              if (nodeDrag) return;
                              setSelection({
                                kind: "technique",
                                ref: { technique_id: n.technique_id },
                                source: "attack-chain-trajectory",
                              });
                            }}>
                      <rect width={NODE_W} height={NODE_H}
                                  rx={3} ry={3}
                                  fill={active ? "rgba(56,189,248,0.22)"
                                                                : "rgba(20,25,35,0.9)"}
                                  stroke={color}
                                  strokeWidth={active ? 1.6 : 1} />
                      <circle cx={9} cy={NODE_H / 2} r={3}
                                     fill={color} />
                      <text x={20} y={NODE_H / 2 + 3.5}
                                  fill="var(--text)" fontFamily="var(--mono)"
                                  fontSize={9.5}>
                        {n.technique_id} · {truncate(n.name || "—", 14)}
                      </text>
                    </g>
                  );
                })}
              </g>
            </svg>
          </div>
          <div style={helpText}>
            Deterministic trajectory · drag nodes · click-drag background
            to pan · use −/+ buttons to zoom · RESET restores auto-layout.
            Curves are temporal, NEVER causal.  Techniques with 0 evidence
            are never rendered.
          </div>
          {gaps.length > 0 && (
            <div style={{ marginTop: 6, padding: "6px 8px", fontSize: 10.5,
                                    fontFamily: "var(--mono)",
                                    color: "var(--faint)",
                                    border: "1px dashed var(--border)", borderRadius: 3 }}
                         data-testid="xdr-chain-gaps">
              Honest gaps · {gaps.length}/14 tactics without evidence:{" "}
              {gaps.join(" · ")}
            </div>
          )}
        </>
      )}
    </section>
  );
}


function Header({ collapsed, setCollapsed, zoom, setZoom, reset,
                            techniques }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10,
                            padding: "0 4px 6px" }}>
      <div style={{ display: "flex", flexDirection: "column",
                              gap: 0, flex: 1 }}>
        <span style={{ fontSize: 9.5, color: "var(--faint)",
                                  fontFamily: "var(--mono)", fontWeight: 700,
                                  letterSpacing: 0.4, textTransform: "uppercase" }}>
          Evidence Trajectory
        </span>
        <span style={{ fontSize: 16, color: "var(--text)",
                                  fontFamily: "var(--mono)", fontWeight: 700,
                                  letterSpacing: 0.6 }}>
          MITRE ATT&CK
        </span>
      </div>
      <span style={{ padding: "1px 6px", fontSize: 9.5,
                              fontFamily: "var(--mono)", fontWeight: 700,
                              background: "var(--panel2)",
                              border: "1px solid var(--border)",
                              borderRadius: 2, color: "var(--faint)" }}>
        {techniques} technique{techniques === 1 ? "" : "s"} · 14 tactics
      </span>
      <button type="button"
                    data-testid="xdr-chain-zoom-out"
                    onClick={() => setZoom((z) => Math.max(25, z - 10))}
                    title="Zoom out"
                    style={ctrlBtn}>
        <Minus size={11} />
      </button>
      <span style={{ fontSize: 11, fontFamily: "var(--mono)",
                              minWidth: 42, textAlign: "center",
                              color: "var(--text)" }}
                   data-testid="xdr-chain-zoom-value">
        {zoom}%
      </span>
      <button type="button"
                    data-testid="xdr-chain-zoom-in"
                    onClick={() => setZoom((z) => Math.min(400, z + 10))}
                    title="Zoom in"
                    style={ctrlBtn}>
        <Plus size={11} />
      </button>
      <button type="button"
                    data-testid="xdr-chain-reset"
                    onClick={reset}
                    title="Reset layout + pan + zoom"
                    style={{ ...ctrlBtn, gap: 3 }}>
        <RotateCcw size={10} /> RESET
      </button>
      <button type="button"
                    data-testid="xdr-chain-toggle"
                    onClick={() => setCollapsed((c) => !c)}
                    title={collapsed ? "Expand" : "Collapse"}
                    style={{ ...ctrlBtn, gap: 3 }}>
        <X size={10} /> {collapsed ? "OPEN" : "CLOSE"}
      </button>
    </div>
  );
}


function TacticLegend() {
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 10,
                            padding: "0 4px 8px", alignItems: "center" }}
                data-testid="xdr-chain-legend">
      <span style={{ fontSize: 9, fontFamily: "var(--mono)",
                              color: "var(--faint)", fontWeight: 700,
                              letterSpacing: 0.4, textTransform: "uppercase" }}>
        MITRE tactics projected:
      </span>
      {KILL_CHAIN.map((k) => (
        <span key={k.key}
                    data-testid={`xdr-chain-legend-${k.key}`}
                    style={{ display: "inline-flex", alignItems: "center",
                                    gap: 4, fontSize: 10, fontFamily: "var(--mono)",
                                    color: "var(--text-dim)" }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%",
                                    background: TACTIC_COLOR[k.key] || "var(--cyan)" }} />
          {k.label}
        </span>
      ))}
    </div>
  );
}


// Empty canvas — renders the 14 tactic swim-lanes even when no
// technique has evidence.  Honest empty state INSIDE the canvas —
// never a "canvas not available" placeholder.
function EmptyCanvas({ contentWidth, pan, zoom }) {
  return (
    <div style={canvasFrame} data-testid="xdr-chain-canvas">
      <svg width="100%" height={CANVAS_HEIGHT + 20}
                style={{ display: "block" }}
                viewBox={`0 0 ${contentWidth} ${CANVAS_HEIGHT + 20}`}
                preserveAspectRatio="xMinYMin meet">
        <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom / 100})`}>
          {KILL_CHAIN.map((k, i) => (
            <g key={k.key} data-testid={`xdr-chain-row-${k.key}`}>
              <rect x={0} y={20 + i * ROW_H}
                          width={contentWidth}
                          height={ROW_H - 2}
                          fill={i % 2 === 0 ? "rgba(255,255,255,0.015)"
                                                              : "transparent"} />
              <text x={10}
                          y={20 + i * ROW_H + ROW_H / 2 - 3}
                          fill="var(--faint)"
                          fontFamily="var(--mono)"
                          fontSize={10.5}
                          fontWeight={700}
                          letterSpacing={0.4}>
                {k.label.toUpperCase()}
              </text>
              <text x={10}
                          y={20 + i * ROW_H + ROW_H / 2 + 12}
                          fill="rgba(160,160,180,0.35)"
                          fontFamily="var(--mono)"
                          fontSize={8.5}>
                technique command behavior
              </text>
              <line x1={LANE_X - 6} y1={20 + i * ROW_H}
                          x2={LANE_X - 6} y2={20 + i * ROW_H + ROW_H}
                          stroke="rgba(255,255,255,0.06)"
                          strokeWidth={1} />
            </g>
          ))}
        </g>
      </svg>
    </div>
  );
}


// ── Deterministic trajectory builder ─────────────────────────────
function buildTrajectory(incident, correlations) {
  const evs = (incident?.verdict_stage2?.evidence || incident?.evidence || []);

  const byTech = new Map();
  const seedTech = (tech, ev) => {
    if (!byTech.has(tech)) {
      const meta = TECHNIQUE_INDEX[tech] || {};
      byTech.set(tech, {
        technique_id: tech,
        name: meta.name || null,
        tactic: meta.tactic || null,
        evidence_count: 0,
        rels: new Set(),
        first_seen: null,
        last_seen: null,
      });
    }
    const cur = byTech.get(tech);
    cur.evidence_count += 1;
    cur.rels.add("OBSERVED");
    const ts = ev?.timestamp || ev?.first_seen || null;
    if (!cur.first_seen || (ts && ts < cur.first_seen)) cur.first_seen = ts;
    if (!cur.last_seen  || (ts && ts > cur.last_seen))  cur.last_seen  = ts;
  };

  // 1 · Evidence rows (Stage-2 or generic).
  for (const ev of evs) {
    const tech = ev.technique_id
              || (ev.rule_id && RULE_TO_TECHNIQUE[String(ev.rule_id).toUpperCase()]);
    if (tech) seedTech(tech, ev);
  }

  // 2 · Direct MITRE arrays surfaced by the incident payload.
  //     Accepts:
  //         incident.mitre       = [{ technique_id | id, timestamp?, count? }, …]
  //         incident.techniques  = ["T1059.001", …]  or  [{ id, timestamp? }]
  //         incident.attack_techniques = ["T1059.001", …]
  const collectDirect = (arr) => {
    for (const m of (arr || [])) {
      if (!m) continue;
      const t = typeof m === "string" ? m : (m.technique_id || m.id);
      if (!t) continue;
      const ev = typeof m === "object" ? m : {};
      for (let i = 0; i < (ev.count || 1); i++) seedTech(t, ev);
    }
  };
  collectDirect(incident?.mitre);
  collectDirect(incident?.techniques);
  collectDirect(incident?.attack_techniques);

  // 3 · SEQUENCED — mark every technique after the first as SEQUENCED.
  const sorted = Array.from(byTech.values())
      .filter((t) => t.first_seen)
      .sort((a, b) => (a.first_seen || "").localeCompare(b.first_seen || ""));
  for (let i = 1; i < sorted.length; i++) sorted[i].rels.add("SEQUENCED");

  // 4 · CORRELATED — from correlation matches.
  for (const c of correlations || []) {
    const attks = c.attack_techniques || c.techniques || [];
    for (const at of attks) {
      const cur = byTech.get(at);
      if (cur) cur.rels.add("CORRELATED");
    }
  }

  // 5 · Only techniques with a resolvable tactic can be plotted.
  const validTactics = new Set(KILL_CHAIN.map((k) => k.key));
  const nodes = Array.from(byTech.values())
    .filter((t) => t.tactic && validTactics.has(t.tactic))
    .map((t) => ({ ...t, rels: Array.from(t.rels) }));

  // 6 · Sequential edges — temporal, NOT causal.
  const edges = [];
  const sortedNodes = [...nodes]
    .sort((a, b) => (a.first_seen || "").localeCompare(b.first_seen || ""));
  for (let i = 1; i < sortedNodes.length; i++) {
    edges.push({ from: sortedNodes[i - 1].technique_id,
                          to:   sortedNodes[i].technique_id });
  }

  // 7 · Honest tactic gaps
  const covered = new Set(nodes.map((n) => n.tactic));
  const gaps = KILL_CHAIN.filter((k) => !covered.has(k.key))
                                   .map((k) => k.label);

  const hasEvidence = evs.length > 0
       || (incident?.mitre || []).length > 0
       || (incident?.techniques || []).length > 0
       || (incident?.attack_techniques || []).length > 0;

  return { nodes, edges, gaps, hasEvidence };
}


function truncate(s, n) {
  s = String(s || "");
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}


// ── styles ────────────────────────────────────────────────────────
const canvasFrame = {
  border: "1px solid var(--border)", borderRadius: 3,
  background: "var(--panel)", overflow: "hidden",
  userSelect: "none", position: "relative",
};
const helpText = {
  padding: "6px 4px", fontSize: 10, fontFamily: "var(--mono)",
  color: "var(--faint)", fontStyle: "italic",
};
const ctrlBtn = {
  padding: "3px 8px", fontSize: 10, fontWeight: 700,
  background: "var(--panel2)", border: "1px solid var(--border)",
  color: "var(--text-dim)", borderRadius: 2, cursor: "pointer",
  fontFamily: "var(--mono)", display: "inline-flex",
  alignItems: "center", letterSpacing: 0.3,
};
const emptyBox = {
  padding: "10px 12px", fontSize: 11, fontFamily: "var(--mono)",
  color: "var(--faint)", border: "1px dashed var(--border)",
  borderRadius: 3, display: "flex", alignItems: "center",
};
