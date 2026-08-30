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
import { RotateCcw, Minus, Plus, X, Info, Clock, Maximize2 } from "lucide-react";

import { KILL_CHAIN, RULE_TO_TECHNIQUE, TECHNIQUE_INDEX }
    from "@/xdr/mitre/mitreTactics";
import { useSelection } from "@/xdr/investigation/WorkspaceSelectionContext";
import api from "@/lib/api";


// Tactic accent palette (matches base NivXRay Tool trajectory colours).
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
  OBSERVED:   "#4ade80",
  SEQUENCED:  "#67e8f9",
  CORRELATED: "#a78bfa",
  INFERRED:   "#94a3b8",
};

// Layout constants — match NivXRay Tool trajectory sizing.
const ROW_H         = 74;
const LANE_X        = 148;
const NODE_W        = 210;
const NODE_H        = 42;
const NODE_GAP_X    = 130;
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
  const [popout, setPopout]       = useState(false);

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

  // Canvas width — always generous so the horizontal scrollbar
  // engages and users can drag/scroll left-to-right just like the
  // NivXRay Tool trajectory.  The floor of 2200 gives room for
  // ~12 columns of technique nodes; grows further as more nodes
  // are plotted.
  const contentWidth = Math.max(
    2200,
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
                        techniques={0}
                        popout={popout} setPopout={setPopout} />
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
                    techniques={nodes.length}
                    popout={popout} setPopout={setPopout} />

      {popout && (
        <div style={popoutBackdrop}
                   data-testid="xdr-chain-popout-modal"
                   onClick={() => setPopout(false)}>
          <div style={popoutInner}
                       onClick={(e) => e.stopPropagation()}>
            <div style={{ display: "flex", alignItems: "center",
                                    gap: 8, marginBottom: 8 }}>
              <b style={{ fontFamily: "JetBrains Mono, monospace",
                                          fontSize: 13, color: "#e2e8f0" }}>
                EVIDENCE TRAJECTORY · MITRE ATT&CK
              </b>
              <span style={{ fontSize: 11, color: "#94a3b8",
                                          fontFamily: "JetBrains Mono, monospace" }}>
                {nodes.length} technique{nodes.length === 1 ? "" : "s"} · 14 tactics
              </span>
              <span style={{ flex: 1 }} />
              <button type="button"
                            data-testid="xdr-chain-popout-close"
                            onClick={() => setPopout(false)}
                            style={ctrlBtn}>
                <X size={11} /> CLOSE
              </button>
            </div>
          <div style={canvasFramePopout}
                     onMouseDown={onMouseDown}
                     onMouseMove={onMouseMove}
                     onMouseUp={endDrag}
                     onMouseLeave={endDrag}
                     data-testid="xdr-chain-popout-canvas">
              <svg width={Math.max(contentWidth * (zoom / 100), 600)}
                       height={(CANVAS_HEIGHT + 20) * (zoom / 100)}
                       style={{ display: "block", cursor: drag ? "grabbing" : "grab" }}
                       viewBox={`0 0 ${contentWidth} ${CANVAS_HEIGHT + 20}`}
                       preserveAspectRatio="xMinYMin meet">
                <g transform={`translate(${pan.x}, ${pan.y})`}>
                  {KILL_CHAIN.map((k, i) => (
                    <g key={k.key}>
                      <rect x={0} y={20 + i * ROW_H}
                                  width={contentWidth} height={ROW_H - 2}
                                  fill={i % 2 === 0 ? "rgba(148,163,184,0.03)"
                                                                          : "transparent"} />
                      <text x={14} y={20 + i * ROW_H + ROW_H / 2 - 2}
                                  fill="#e2e8f0" fontFamily="JetBrains Mono, monospace"
                                  fontSize={11} fontWeight={700} letterSpacing={0.4}>
                        {k.label.toUpperCase()}
                      </text>
                    </g>
                  ))}
                  {edges.map((e) => {
                    const a = laidOut[e.from], b = laidOut[e.to];
                    if (!a || !b) return null;
                    const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2;
                    const x2 = b.x,          y2 = b.y + NODE_H / 2;
                    const dx = Math.max(30, Math.abs(x2 - x1) * 0.55);
                    return <path key={`p${e.from}${e.to}`}
                                                d={`M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`}
                                                fill="none" stroke="rgba(148,163,184,0.35)"
                                                strokeWidth={1.4} />;
                  })}
                  {nodes.map((n) => {
                    const p = laidOut[n.technique_id];
                    if (!p) return null;
                    const color = TACTIC_COLOR[n.tactic] || "#67e8f9";
                    return (
                      <g key={`pn${n.technique_id}`}
                              transform={`translate(${p.x}, ${p.y})`}>
                        <rect width={NODE_W} height={NODE_H} rx={6}
                                    fill="rgba(15,23,42,0.9)"
                                    stroke={color} strokeWidth={1.6} />
                        <circle cx={12} cy={NODE_H / 2} r={5.5}
                                       fill={color} stroke="#0b1220" strokeWidth={2} />
                        <text x={24} y={NODE_H / 2 - 3}
                                    fill="#e2e8f0" fontFamily="JetBrains Mono, monospace"
                                    fontSize={12} fontWeight={700}>
                          {n.technique_id}
                        </text>
                        <text x={24} y={NODE_H / 2 + 12}
                                    fill="#94a3b8" fontFamily="JetBrains Mono, monospace"
                                    fontSize={10}>
                          {truncate(n.name || "—", 24)}
                        </text>
                      </g>
                    );
                  })}
                </g>
              </svg>
            </div>
          </div>
        </div>
      )}

      {!collapsed && (
        <>
          <TacticLegend />
          <div style={canvasFrame}
                     onMouseDown={onMouseDown}
                     onMouseMove={onMouseMove}
                     onMouseUp={endDrag}
                     onMouseLeave={endDrag}
                     data-testid="xdr-chain-canvas">
            <svg width={Math.max(contentWidth * (zoom / 100), 600)}
                     height={(CANVAS_HEIGHT + 20) * (zoom / 100)}
                     style={{ display: "block", cursor: drag ? "grabbing" : "grab" }}
                     viewBox={`0 0 ${contentWidth} ${CANVAS_HEIGHT + 20}`}
                     preserveAspectRatio="xMinYMin meet">
              <g transform={`translate(${pan.x}, ${pan.y})`}>
                {/* Swim-lane rows · NivXRay Tool visual language */}
                {KILL_CHAIN.map((k, i) => (
                  <g key={k.key} data-testid={`xdr-chain-row-${k.key}`}>
                    <rect x={0}
                                y={20 + i * ROW_H}
                                width={contentWidth}
                                height={ROW_H - 2}
                                fill={i % 2 === 0 ? "rgba(148,163,184,0.03)"
                                                                  : "transparent"} />
                    <text x={14}
                                y={20 + i * ROW_H + ROW_H / 2 - 2}
                                fill="#e2e8f0"
                                fontFamily="JetBrains Mono, monospace"
                                fontSize={11}
                                fontWeight={700}
                                letterSpacing={0.4}>
                      {k.label.toUpperCase()}
                    </text>
                    <text x={14}
                                y={20 + i * ROW_H + ROW_H / 2 + 14}
                                fill="#64748b"
                                fontFamily="JetBrains Mono, monospace"
                                fontSize={9}
                                letterSpacing={0.3}>
                      technique · command · behavior
                    </text>
                    <line x1={LANE_X - 8} y1={20 + i * ROW_H}
                                x2={LANE_X - 8} y2={20 + i * ROW_H + ROW_H}
                                stroke="rgba(148,163,184,0.10)"
                                strokeWidth={1} />
                  </g>
                ))}

                {/* Bezier curves between consecutive (temporal) techniques */}
                {edges.map((e) => {
                  const a = laidOut[e.from];
                  const b = laidOut[e.to];
                  if (!a || !b) return null;
                  const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2;
                  const x2 = b.x,          y2 = b.y + NODE_H / 2;
                  const dx = Math.max(30, Math.abs(x2 - x1) * 0.55);
                  return (
                    <path key={`${e.from}->${e.to}`}
                                data-testid={`xdr-chain-edge-${e.from}-${e.to}`}
                                d={`M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`}
                                fill="none"
                                stroke="rgba(148,163,184,0.35)"
                                strokeWidth={1.4} />
                  );
                })}

                {/* Technique nodes · NivXRay Tool visual language */}
                {nodes.map((n) => {
                  const p = laidOut[n.technique_id];
                  if (!p) return null;
                  const active = selectedTech === n.technique_id;
                  const color = TACTIC_COLOR[n.tactic] || "#67e8f9";
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
                      <rect width={NODE_W} height={NODE_H} rx={6}
                                  fill="rgba(15,23,42,0.9)"
                                  stroke={active ? "#fbbf24" : color}
                                  strokeWidth={active ? 2.2 : 1.6} />
                      <circle cx={12} cy={NODE_H / 2} r={5.5}
                                     fill={color}
                                     stroke="#0b1220" strokeWidth={2} />
                      <text x={24} y={NODE_H / 2 - 3}
                                  fill="#e2e8f0"
                                  fontFamily="JetBrains Mono, monospace"
                                  fontSize={12}
                                  fontWeight={700}>
                        {n.technique_id}
                      </text>
                      <text x={24} y={NODE_H / 2 + 12}
                                  fill="#94a3b8"
                                  fontFamily="JetBrains Mono, monospace"
                                  fontSize={10}>
                        {truncate(n.name || "—", 20)}
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
                            techniques, popout, setPopout }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10,
                            padding: "0 4px 6px" }}>
      <div style={{ display: "flex", flexDirection: "column",
                              gap: 2, flex: 1 }}>
        <span style={{ fontSize: 9, letterSpacing: "0.22em",
                                  textTransform: "uppercase", color: "#67e8f9",
                                  fontFamily: "JetBrains Mono, monospace" }}>
          Evidence Trajectory
        </span>
        <span style={{ fontSize: 17, color: "#e2e8f0",
                                  fontFamily: "JetBrains Mono, monospace",
                                  fontWeight: 700, letterSpacing: 0.6 }}>
          MITRE ATT&CK
        </span>
      </div>
      <span style={{ padding: "3px 8px", fontSize: 10.5,
                              fontFamily: "JetBrains Mono, monospace",
                              fontWeight: 600, color: "#94a3b8",
                              border: "1px solid #334467",
                              borderRadius: 4 }}>
        {techniques} technique{techniques === 1 ? "" : "s"} · 14 tactics
      </span>
      <button type="button"
                    data-testid="xdr-chain-zoom-out"
                    onClick={() => setZoom((z) => Math.max(25, z - 10))}
                    title="Zoom out"
                    style={ctrlBtn}>
        <Minus size={12} />
      </button>
      <span style={{ fontSize: 12, fontFamily: "JetBrains Mono, monospace",
                              minWidth: 48, textAlign: "center",
                              color: "#e2e8f0", fontWeight: 600 }}
                   data-testid="xdr-chain-zoom-value">
        {zoom}%
      </span>
      <button type="button"
                    data-testid="xdr-chain-zoom-in"
                    onClick={() => setZoom((z) => Math.min(400, z + 10))}
                    title="Zoom in"
                    style={ctrlBtn}>
        <Plus size={12} />
      </button>
      <button type="button"
                    data-testid="xdr-chain-reset"
                    onClick={reset}
                    title="Reset layout + pan + zoom"
                    style={{ ...ctrlBtn, gap: 4 }}>
        <RotateCcw size={11} /> RESET
      </button>
      <button type="button"
                    data-testid="xdr-chain-popout"
                    onClick={() => setPopout && setPopout(true)}
                    title="Pop out to full screen"
                    style={{ ...ctrlBtn, gap: 4 }}>
        <Maximize2 size={11} /> POPOUT
      </button>
      <button type="button"
                    data-testid="xdr-chain-toggle"
                    onClick={() => setCollapsed((c) => !c)}
                    title={collapsed ? "Expand" : "Collapse"}
                    style={{ ...ctrlBtn, gap: 4 }}>
        <X size={11} /> {collapsed ? "OPEN" : "CLOSE"}
      </button>
    </div>
  );
}


function TacticLegend() {
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 12,
                            padding: "0 4px 10px", alignItems: "center" }}
                data-testid="xdr-chain-legend">
      <span style={{ fontSize: 9, letterSpacing: "0.14em",
                              textTransform: "uppercase", color: "#64748b",
                              fontFamily: "JetBrains Mono, monospace" }}>
        MITRE tactics projected:
      </span>
      {KILL_CHAIN.map((k) => (
        <span key={k.key}
                    data-testid={`xdr-chain-legend-${k.key}`}
                    style={{ display: "inline-flex", alignItems: "center",
                                    gap: 6, fontSize: 11, color: "#94a3b8",
                                    fontFamily: "JetBrains Mono, monospace" }}>
          <span style={{ width: 10, height: 10, borderRadius: "50%",
                                    background: TACTIC_COLOR[k.key] || "#67e8f9" }} />
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
      <svg width={Math.max(contentWidth * (zoom / 100), 600)}
                height={(CANVAS_HEIGHT + 20) * (zoom / 100)}
                style={{ display: "block" }}
                viewBox={`0 0 ${contentWidth} ${CANVAS_HEIGHT + 20}`}
                preserveAspectRatio="xMinYMin meet">
        <g transform={`translate(${pan.x}, ${pan.y})`}>
          {KILL_CHAIN.map((k, i) => (
            <g key={k.key} data-testid={`xdr-chain-row-${k.key}`}>
              <rect x={0} y={20 + i * ROW_H}
                          width={contentWidth}
                          height={ROW_H - 2}
                          fill={i % 2 === 0 ? "rgba(148,163,184,0.03)"
                                                              : "transparent"} />
              <text x={14}
                          y={20 + i * ROW_H + ROW_H / 2 - 2}
                          fill="#e2e8f0"
                          fontFamily="JetBrains Mono, monospace"
                          fontSize={11}
                          fontWeight={700}
                          letterSpacing={0.4}>
                {k.label.toUpperCase()}
              </text>
              <text x={14}
                          y={20 + i * ROW_H + ROW_H / 2 + 14}
                          fill="#64748b"
                          fontFamily="JetBrains Mono, monospace"
                          fontSize={9}
                          letterSpacing={0.3}>
                technique · command · behavior
              </text>
              <line x1={LANE_X - 8} y1={20 + i * ROW_H}
                          x2={LANE_X - 8} y2={20 + i * ROW_H + ROW_H}
                          stroke="rgba(148,163,184,0.10)"
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
  border: "1px solid #1f2b3f", borderRadius: 10,
  background: "rgba(2,6,23,0.65)",
  overflowX: "scroll",                     // ALWAYS-visible horizontal (NivXRay Tool parity)
  overflowY: "auto",
  userSelect: "none", position: "relative",
  minHeight: 560,
  maxHeight: 1000,
  scrollbarColor: "#334467 #0b1220",
};
const popoutBackdrop = {
  position: "fixed", inset: 0, zIndex: 200,
  background: "rgba(2,6,23,0.86)",
  padding: 24, display: "flex", alignItems: "center",
  justifyContent: "center",
};
const popoutInner = {
  width: "100%", maxWidth: 1600,
  maxHeight: "calc(100vh - 48px)",
  background: "rgba(15,23,42,0.98)",
  border: "1px solid #334467", borderRadius: 12,
  padding: 16, display: "flex", flexDirection: "column",
  overflow: "hidden",
};
const canvasFramePopout = {
  flex: 1,
  border: "1px solid #1f2b3f", borderRadius: 10,
  background: "rgba(2,6,23,0.65)",
  overflowX: "scroll", overflowY: "auto",
  userSelect: "none",
  maxHeight: "calc(100vh - 220px)",
  scrollbarColor: "#334467 #0b1220",
};
const helpText = {
  padding: "8px 4px", fontSize: 10.5,
  fontFamily: "JetBrains Mono, monospace",
  color: "#64748b", fontStyle: "italic",
  letterSpacing: 0.2,
};
const ctrlBtn = {
  padding: "4px 10px", fontSize: 11, fontWeight: 600,
  color: "#67e8f9", background: "rgba(103,232,249,0.08)",
  border: "1px solid rgba(103,232,249,0.35)",
  borderRadius: 4, cursor: "pointer",
  fontFamily: "JetBrains Mono, monospace",
  display: "inline-flex", alignItems: "center",
  letterSpacing: 0.3,
};
const emptyBox = {
  padding: "10px 12px", fontSize: 11,
  fontFamily: "JetBrains Mono, monospace",
  color: "#94a3b8", border: "1px dashed #334467",
  borderRadius: 6, display: "flex", alignItems: "center",
};
