/**
 * AttackGraphTab · Round 35.1 · Operational density rewrite.
 *
 * Same backend (Round 35 `/api/incidents/{id}/attack-graph`), tighter
 * visual language.  Defaults:
 *   - GRAPH MODE = "Attack Chain" (only observed/supported chain
 *     nodes + their techniques + their observed stages).
 *   - NOT_OBSERVED stages hidden unless the "gaps" layer is on.
 *   - Compact 180px column · 38px row · 170×30 nodes.
 *   - Primary-path nodes ringed in amber; primary-path edges thicker.
 *   - Edge labels hidden by default; revealed on hover / select.
 *   - Zoom + Fit + Reset controls + minimap.
 */
import React, { useEffect, useMemo, useRef, useState } from "react";
import { Loader2, ZoomIn, ZoomOut, Maximize2, RotateCcw,
          Play, Pause, SkipBack, SkipForward, Maximize, X, HelpCircle,
          AlertTriangle } from "lucide-react";

import api from "@/lib/api";
import { ProcessTreeView }  from "./attack_graph/ProcessTreeView";
import EvidenceInspector    from "@/xdr/components/EvidenceInspector";


// Map an Attack-Graph node (or process-tree node) to canonical
// {kind, refId} arguments for the shared EvidenceInspector.  Every
// graph tab MUST route through this so we never ship display-only
// data to the inspector (owner rule §11 + Round 38.3).
function nodeToInspectorArgs(node) {
  if (!node) return { kind: null, refId: null };
  const a = node.attrs || {};
  switch (node.kind) {
    case "technique":
      return { kind: "technique", refId: a.tid || node.label };
    case "process":
      return { kind: "process", refId: node.label };
    case "event":
      return { kind: "event", refId: a.event_id
                       || (node.label || "").replace(/^canonical:/, "") };
    case "commandline":
      return { kind: "commandline", refId: node.id };
    case "finding":
      return { kind: "finding", refId: a.finding_id || node.id };
    case "incident":
      return { kind: "incident", refId: node.label };
    case "host":     return { kind: "host",     refId: node.label };
    case "user":     return { kind: "user",     refId: node.label };
    case "ip":       return { kind: "ip",       refId: node.label };
    case "hash":     return { kind: "hash",     refId: node.label };
    case "signature":return { kind: "signature",refId: node.label };
    default:
      return { kind: node.kind, refId: node.label || node.id };
  }
}


// ─────────────────────────────────────────────────────────────────
// NivXRay XDR Attack Chain — visual language (redesign 2026-09-02).
//
// Design principles (owner-locked):
//   · Colour represents SEMANTIC STATE, not entity type.
//   · Kind is carried in a small token above the primary label so
//     nodes stay visually compact.
//   · Context entities (incident, user, host, ip, hash) MUST NOT
//     compete with actual attack activity — they recede.
//   · The selected/active attack path must be visually dominant.
//   · Edges must have semantic meaning — causal vs evidence vs
//     correlation vs gap.  Correlation MUST NOT visually imply
//     causality.
//   · Empty / low-evidence states MUST honestly say so.
// ─────────────────────────────────────────────────────────────────

// State glyph — only.  Colour comes from the role tone below.
const STATE_TONE = {
  OBSERVED:     { label: "●", fill: "#0b1220", stroke: "#94a3b8" },
  SUPPORTED:    { label: "◐", fill: "#0b1220", stroke: "#94a3b8" },
  POSSIBLE:     { label: "○", fill: "#0b1220", stroke: "#64748b" },
  NOT_OBSERVED: { label: "—", fill: "#0a0e1a", stroke: "#334155" },
};

// Semantic role of a node — drives fill / stroke / accent.
const NODE_ROLE = {
  incident:   "context",   host: "context",   user: "context",
  ip:         "context",   hash: "context",
  event:      "telemetry", event_id: "telemetry",
  signature:  "telemetry",
  process:    "activity",  commandline: "activity",
  detection:  "finding",   match: "finding",
  finding:    "finding",   capability: "finding",
  technique:  "mitre",     stage: "mitre",
  gap:        "gap",
};

// Restrained NivXRay XDR palette — fills are near-black surfaces
// so the graph never becomes a rainbow.  Accents ride on top.
const ROLE_TONE = {
  context:   { fill: "#0b1220", stroke: "#243049", accent: "#94a3b8",
                     label:  "#cbd5e1", faint: "#64748b" },
  telemetry: { fill: "#0b1a2c", stroke: "#1d3a5f", accent: "#7cb2ea",
                     label:  "#e0eefc", faint: "#64748b" },
  activity:  { fill: "#1a1408", stroke: "#4a3013", accent: "#f0b26b",
                     label:  "#fef3c7", faint: "#a3906a" },
  finding:   { fill: "#150e26", stroke: "#3a2a52", accent: "#c4a8f5",
                     label:  "#eee6ff", faint: "#8f7fb8" },
  mitre:     { fill: "#1a0f2b", stroke: "#4d2a76", accent: "#d8b4fe",
                     label:  "#f5edff", faint: "#a48fca" },
  gap:       { fill: "#0a0e1a", stroke: "#1e293b", accent: "#475569",
                     label:  "#94a3b8", faint: "#475569" },
};

// Compact kind badge glyph (3-letter mono token).
const KIND_GLYPH = {
  incident: "INC", host: "HST", user: "USR",
  ip:  "NET", hash: "HSH",
  event: "EVT", event_id: "EVT", signature: "SIG",
  process: "PRC", commandline: "CMD",
  finding: "FND", capability: "CAP",
  detection: "DET", match: "COR",
  technique: "ATT", stage: "STG", gap: "GAP",
};

// Kept for API back-compat (legend list + earlier residual code
// paths).  DO NOT reintroduce as a fill source — the new renderer
// uses ROLE_TONE.  This map only feeds the legend.
const KIND_TONE = {
  incident:    { fill: ROLE_TONE.context.fill,   stroke: ROLE_TONE.context.accent },
  host:        { fill: ROLE_TONE.context.fill,   stroke: ROLE_TONE.context.accent },
  user:        { fill: ROLE_TONE.context.fill,   stroke: ROLE_TONE.context.accent },
  ip:          { fill: ROLE_TONE.context.fill,   stroke: ROLE_TONE.context.accent },
  hash:        { fill: ROLE_TONE.context.fill,   stroke: ROLE_TONE.context.accent },
  event:       { fill: ROLE_TONE.telemetry.fill, stroke: ROLE_TONE.telemetry.accent },
  event_id:    { fill: ROLE_TONE.telemetry.fill, stroke: ROLE_TONE.telemetry.accent },
  signature:   { fill: ROLE_TONE.telemetry.fill, stroke: ROLE_TONE.telemetry.accent },
  process:     { fill: ROLE_TONE.activity.fill,  stroke: ROLE_TONE.activity.accent },
  commandline: { fill: ROLE_TONE.activity.fill,  stroke: ROLE_TONE.activity.accent },
  detection:   { fill: ROLE_TONE.finding.fill,   stroke: ROLE_TONE.finding.accent },
  match:       { fill: ROLE_TONE.finding.fill,   stroke: ROLE_TONE.finding.accent },
  finding:     { fill: ROLE_TONE.finding.fill,   stroke: ROLE_TONE.finding.accent },
  capability:  { fill: ROLE_TONE.finding.fill,   stroke: ROLE_TONE.finding.accent },
  technique:   { fill: ROLE_TONE.mitre.fill,     stroke: ROLE_TONE.mitre.accent },
  stage:       { fill: ROLE_TONE.mitre.fill,     stroke: ROLE_TONE.mitre.accent },
  gap:         { fill: ROLE_TONE.gap.fill,       stroke: ROLE_TONE.gap.stroke },
};

// Edge semantic class — controls dash, arrow, opacity, tone.
const EDGE_CLASS = {
  SPAWNED: "causal", EXECUTED: "causal", CREATED: "causal",
  WROTE: "causal", READ: "causal", MODIFIED: "causal",
  CONNECTED_TO: "causal", AUTHENTICATED_TO: "causal",
  TRIGGERED: "causal",
  DETECTED_BY: "evidence", MAPPED_TO: "evidence",
  BELONGS_TO: "evidence", SUPPORTED_BY: "evidence",
  OBSERVED_ON: "evidence",
  CORRELATED_WITH: "correlation",
  PIVOTED_TO: "gap",
};
const EDGE_TONE = {
  causal:      { stroke: "#f0b26b", dash: "0",   opacity: 0.90, arrow: true  },
  evidence:    { stroke: "#7cb2ea", dash: "0",   opacity: 0.45, arrow: false },
  correlation: { stroke: "#c4a8f5", dash: "5 3", opacity: 0.65, arrow: false },
  gap:         { stroke: "#475569", dash: "2 4", opacity: 0.40, arrow: false },
};

const KIND_COLUMN = {
  incident: 0, host: 1, user: 1, ip: 1, hash: 1,
  event: 2, event_id: 2, signature: 2,
  process: 3, commandline: 3,
  finding: 4, capability: 4,
  detection: 4, match: 4,
  technique: 5, stage: 6, gap: 7,
};

const KIND_LAYER = {
  incident: "entities",  host: "entities",  user: "entities",
  ip: "entities",        hash: "entities",
  event: "events",       event_id: "events",  signature: "events",
  process: "processes",  commandline: "processes",
  finding: "findings",   capability: "capabilities",
  detection: "findings", match: "findings",
  technique: "mitre",    stage: "mitre",
  gap: "gaps",
};

const EDGE_SEMANTICS = [
  ["SPAWNED",         "Process created another process"],
  ["EXECUTED",        "Process executed a command / action"],
  ["TRIGGERED",       "Event/signature triggered downstream activity"],
  ["DETECTED_BY",     "Evidence detected by a rule / finding"],
  ["MAPPED_TO",       "Evidence / finding mapped to ATT&CK technique"],
  ["BELONGS_TO",      "Technique belongs to ATT&CK stage / tactic"],
  ["CORRELATED_WITH", "Evidence linked to a correlation match"],
  ["SUPPORTED_BY",    "Node supported by a finding"],
  ["CONNECTED_TO",    "Process/host connected to a network endpoint"],
  ["OBSERVED_ON",     "Event observed on this entity"],
  ["AUTHENTICATED_TO","Identity authenticated to entity"],
  ["PIVOTED_TO",      "Investigation pivots toward this gap"],
];

const COL_W = 190, ROW_H = 60, NODE_W = 156, NODE_H = 46;


function nodeLabel(n) {
  const s = n.label || "";
  // The compact 156-wide node reserves 34px for the kind badge and
  // ~14px for the finding-count badge zone in the top-right, leaving
  // ~108px of usable label width at fontSize 11 — that's ~14–15
  // characters at Inter/system-ui.  Truncate hard here so we never
  // collide with the annotation badge or overflow the border.
  return s.length > 15 ? s.slice(0, 13) + "…" : s;
}


export default function AttackGraphTab({ incident }) {
  const [graph, setGraph]         = useState(null);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState(null);
  const [selId, setSelId]         = useState(null);
  const [selKind, setSelKind]     = useState(null);
  const [hoveredEdge, setHovered] = useState(null);
  const [mode, setMode]           = useState("chain"); // chain | evidence | full
  // Round 36.1 · Sub-tab selector inside the Attack Graph tab.
  //   process  → Process Tree view (default)
  //   activity → Activity / Evidence graph (SVG canvas)
  // MITRE Chain is intentionally NOT part of Attack Graph — MITRE
  // ATT&CK belongs on the MITRE and Attack Story tabs (owner rule
  // §13 of Round 38: single source of truth for ATT&CK evidence).
  const [subView, setSubView]     = useState("process");
  const [layers, setLayers]       = useState({
    entities: true, events: true, processes: true, findings: true,
    capabilities: true, mitre: true, gaps: false,
  });
  const [zoom, setZoom]           = useState(1.0);
  const [timeMax, setTimeMax]     = useState(100);
  const [playing, setPlaying]     = useState(false);
  const [popOut, setPopOut]       = useState(false);
  const [showLegend, setShowLegend] = useState(false);
  const [nodeOverrides, setNodeOverrides] = useState({}); // id → {x,y}
  const [dragState, setDragState] = useState(null); // {nodeId, ox, oy, startX, startY} | {pan:true, ...}
  // Round 41 · Timeline Replay — playback controller over the existing
  // Activity Graph walkable primary path.  No new data model.
  const [replayIdx, setReplayIdx]         = useState(-1);
  const [replayPlaying, setReplayPlaying] = useState(false);
  // Round 42 · Evidence deep-link — when the analyst clicks an
  // `evidence_refs[]` pill on an edge, we don't navigate the graph;
  // we open the existing shared <EvidenceInspector/> on the governed
  // canonical evidence object directly.  Stored as {kind, refId}.
  // Cleared when the analyst picks a new node/edge or presses "back".
  const [deepLink, setDeepLink] = useState(null);
  const scrollRef = useRef(null);

  useEffect(() => {
    if (!incident?.id) return undefined;
    let c = false;
    (async () => {
      setLoading(true); setError(null);
      try {
        const { data } = await api.get(`/incidents/${incident.id}/attack-graph`);
        if (!c) setGraph(data);
      } catch (e) { if (!c) setError(e?.message || String(e)); }
      finally { if (!c) setLoading(false); }
    })();
    return () => { c = true; };
  }, [incident?.id]);

  // Timeline playback.
  useEffect(() => {
    if (!playing) return undefined;
    const t = setInterval(() => {
      setTimeMax(v => v >= 100 ? (setPlaying(false), 100) : v + 2);
    }, 120);
    return () => clearInterval(t);
  }, [playing]);

  const primaryPath = useMemo(
    () => new Set(graph?.primary_path || []), [graph]);

  // Round 36 · Activity Graph view uses the pre-filtered projection
  // from the backend.  Other sub-views (MITRE Chain / Process Tree)
  // do not use the SVG canvas at all.
  const activeNodes = useMemo(() => {
    if (!graph) return [];
    if (subView === "activity" && graph.views?.activity_graph) {
      return graph.views.activity_graph.nodes;
    }
    return graph.nodes;
  }, [graph, subView]);

  const activeEdges = useMemo(() => {
    if (!graph) return [];
    if (subView === "activity" && graph.views?.activity_graph) {
      return graph.views.activity_graph.edges;
    }
    return graph.edges;
  }, [graph, subView]);

  // Round 41 · Ordered replay sequence.
  //
  //   Canonical Evidence → Activity Graph → Walkable Primary Path →
  //   Timeline Controller → Current Step → Existing Evidence Inspector
  //
  // We do NOT build a second timeline model.  The list is the exact
  // `graph.primary_path[]` produced by the backend walker, filtered
  // to nodes present in the current projection.  Sparse / missing
  // path elements are handled by simply omitting them.
  const replaySteps = useMemo(() => {
    if (!graph) return [];
    const path = graph.primary_path || [];
    const byId = new Map((activeNodes || []).map(n => [n.id, n]));
    return path.map(id => byId.get(id)).filter(Boolean);
  }, [graph, activeNodes]);

  const replayCurrent = replayIdx >= 0 && replayIdx < replaySteps.length
    ? replaySteps[replayIdx] : null;

  // Reset the replay when the active projection changes (e.g. sub-tab
  // switch).  Keeps state consistent with what is actually rendered.
  useEffect(() => {
    setReplayIdx(-1);
    setReplayPlaying(false);
    setDeepLink(null);  // Round 42 · sub-tab switch clears deep links
  }, [subView, incident?.id]);

  // Round 42 · Any fresh node/edge selection clears an in-flight
  // deep link so the inspector reflects what the analyst just clicked.
  useEffect(() => {
    setDeepLink(null);
  }, [selId, selKind]);

  // Wire the replay step to the shared selection so the SVG focuses
  // the current node and the shared EvidenceInspector opens for it.
  useEffect(() => {
    if (!replayCurrent) return;
    setSelId(replayCurrent.id);
    setSelKind("node");
    setDeepLink(null);           // Round 42 · replay clears any deep link
  }, [replayCurrent]);

  // Auto-advance while playing.
  useEffect(() => {
    if (!replayPlaying) return undefined;
    if (replaySteps.length === 0) { setReplayPlaying(false); return undefined; }
    const t = setInterval(() => {
      setReplayIdx(i => {
        const next = i + 1;
        if (next >= replaySteps.length) {
          setReplayPlaying(false);
          return replaySteps.length - 1;
        }
        return next;
      });
    }, 1200);
    return () => clearInterval(t);
  }, [replayPlaying, replaySteps.length]);

  // Filter nodes by mode + layers + gap policy.
  const visibleNodes = useMemo(() => {
    if (!graph) return [];
    return activeNodes.filter(n => {
      const layer = KIND_LAYER[n.kind] || "entities";
      if (!layers[layer]) return false;
      // In Attack Chain mode: hide gaps entirely, and hide
      // NOT_OBSERVED stages unless the gaps layer is explicitly on.
      if (mode === "chain") {
        if (n.kind === "gap") return false;
        if (n.kind === "stage" && n.state === "NOT_OBSERVED"
              && !layers.gaps) return false;
        if (n.kind === "finding" && n.state === "NOT_OBSERVED") return false;
      }
      // In Evidence Graph mode: also hide NOT_OBSERVED stages unless gaps on.
      if (mode === "evidence") {
        if (n.kind === "stage" && n.state === "NOT_OBSERVED"
              && !layers.gaps) return false;
      }
      return true;
    });
  }, [graph, mode, layers, activeNodes]);

  const layout = useMemo(() => {
    if (!graph || visibleNodes.length === 0) return null;
    const byCol = new Map();
    for (const n of visibleNodes) {
      const c = KIND_COLUMN[n.kind] ?? 3;
      if (!byCol.has(c)) byCol.set(c, []);
      byCol.get(c).push(n);
    }
    for (const arr of byCol.values()) {
      arr.sort((a, b) => {
        const rank = s => ({ OBSERVED: 0, SUPPORTED: 1, POSSIBLE: 2, NOT_OBSERVED: 3 }[s] ?? 9);
        return rank(a.state) - rank(b.state)
                  || (a.label || "").localeCompare(b.label || "");
      });
    }
    const cols = Array.from(byCol.keys()).sort((a, b) => a - b);
    const colIndex = new Map(cols.map((c, i) => [c, i]));
    const pos = new Map();
    for (const [col, arr] of byCol.entries()) {
      const ci = colIndex.get(col);
      arr.forEach((n, i) => {
        const base = { x: 20 + ci * COL_W, y: 20 + i * ROW_H };
        const ov = nodeOverrides[n.id];
        pos.set(n.id, ov ? { x: ov.x, y: ov.y } : base);
      });
    }
    const maxRow = Math.max(1, ...Array.from(byCol.values(), a => a.length));
    // Compute canvas bounds including overrides.
    let maxX = 20 + cols.length * COL_W + 20;
    let maxY = 20 + maxRow * ROW_H + 20;
    for (const p of pos.values()) {
      maxX = Math.max(maxX, p.x + NODE_W + 40);
      maxY = Math.max(maxY, p.y + NODE_H + 40);
    }
    return { pos, width: maxX, height: maxY };
  }, [visibleNodes, graph, nodeOverrides]);

  const timelineWindow = useMemo(() => {
    if (!graph?.timeline?.length) return null;
    const cut = Math.max(0, Math.round(graph.timeline.length * timeMax / 100));
    return new Set(graph.timeline.slice(0, cut).map(
      t => `${t.src}|${t.rel}|${t.dst}`));
  }, [graph, timeMax]);

  if (loading) return (
    <div className="rl-loading" data-testid="xdr-record-attack-graph-loading">
      <Loader2 size={12} className="rl-spin" style={{ verticalAlign: "-2px", marginRight: 6 }} />
      COMPOSING ATTACK GRAPH…
    </div>
  );
  if (error && !graph) return <div className="rl-error">{String(error)}</div>;
  if (!graph) return null;

  const nodeMap = new Map(activeNodes.map(n => [n.id, n]));
  const visibleIds = new Set(visibleNodes.map(n => n.id));
  const visibleEdges = activeEdges.filter(
    e => visibleIds.has(e.src) && visibleIds.has(e.dst));

  const selected = selId ? (selKind === "node"
    ? nodeMap.get(selId)
    : activeEdges.find(e => e.id === selId)) : null;

  const stepTimeline = (delta) => {
    if (!graph.timeline.length) return;
    const step = Math.max(1, Math.round(100 / graph.timeline.length));
    setTimeMax(v => Math.min(100, Math.max(0, v + delta * step)));
  };

  const inner = (
    <div data-testid="xdr-record-attack-graph"
          style={{ display: "grid",
                     gridTemplateColumns: popOut ? "1fr 380px" : "1fr 320px", gap: 12,
                     height: popOut ? "calc(100vh - 40px)" : "auto" }}>
      <div style={{ background: "#0b1220", border: "1px solid #1e293b",
                       borderRadius: 6, overflow: "hidden",
                       display: "flex", flexDirection: "column" }}>
        {/* Round 36 · Sub-tab switcher (MITRE / Process / Activity) */}
        <div style={{ display: "flex", gap: 2, padding: "8px 10px",
                          borderBottom: "1px solid #1e293b",
                          background: "#0a0e1a" }}
              data-testid="xdr-ag-subview-switch">
          {[["process", "Process Tree",  "Who spawned whom?"],
            ["activity","Activity Graph","How are entities connected?"]
          ].map(([k, label, hint]) => (
            <button key={k}
                     onClick={() => setSubView(k)}
                     title={hint}
                     data-testid={`xdr-ag-subview-${k}`}
                     style={{
                       padding: "6px 14px", fontSize: 11,
                       border: "1px solid " + (subView === k ? "#7c3aed" : "#1e293b"),
                       borderRadius: 3, cursor: "pointer",
                       background: subView === k ? "#4c1d95" : "transparent",
                       color: subView === k ? "#f5f3ff" : "#94a3b8",
                       fontWeight: subView === k ? 700 : 500,
                       letterSpacing: 0.3,
                       textTransform: "uppercase",
                     }}>
              {label}
            </button>
          ))}
          <div style={{ marginLeft: "auto", color: "#64748b",
                            fontSize: 10, alignSelf: "center" }}
                data-testid="xdr-ag-subview-hint">
            {subView === "process"  && "Parent → child execution lineage"}
            {subView === "activity" && "Investigation entity relationships"}
          </div>
        </div>

        {/* Process Tree view (no SVG canvas) */}
        {subView === "process" && (
          <ProcessTreeView tree={graph.views?.process_tree}
                                     onSelectProcess={(p) => {
                                       setSelId(p.id); setSelKind("node"); }}
                                     selectedId={selId} />
        )}

        {/* Activity Graph canvas · unchanged operational SVG */}
        {subView === "activity" && (
        <div style={{ display: "contents" }}>
        {/* Toolbar row 1 · counters + mode */}
        <div style={{ display: "flex", gap: 10, padding: "8px 10px",
                         borderBottom: "1px solid #1e293b", color: "#e2e8f0",
                         alignItems: "center", flexWrap: "wrap", fontSize: 11 }}>
          <div className="mono">
            <b>{visibleNodes.length}</b>/{graph.counts.nodes} nodes ·
            <b> {visibleEdges.length}</b>/{graph.counts.edges} edges ·
            <b> {graph.counts.stages_observed}</b> obs ·
            <b> {graph.counts.stages_supported}</b> sup ·
            <b> {graph.counts.gaps}</b> gaps
          </div>
          <div style={{ marginLeft: "auto", display: "flex", gap: 4,
                          background: "#0f172a", padding: 2, borderRadius: 4 }}
                data-testid="xdr-ag-mode-switch">
            {[["chain", "Attack Chain"], ["evidence", "Evidence Graph"], ["full", "Full"]].map(([k, label]) => (
              <button key={k}
                        onClick={() => setMode(k)}
                        style={{ padding: "4px 10px", fontSize: 11,
                                    border: "none", borderRadius: 3,
                                    cursor: "pointer",
                                    background: mode === k ? "#7c3aed" : "transparent",
                                    color: mode === k ? "#fff" : "#94a3b8" }}
                        data-testid={`xdr-ag-mode-${k}`}>
                {label}
              </button>
            ))}
          </div>
        </div>
        {/* Toolbar row 2 · layers + zoom */}
        <div style={{ display: "flex", gap: 12, padding: "6px 10px",
                         borderBottom: "1px solid #1e293b", color: "#94a3b8",
                         alignItems: "center", fontSize: 11 }}>
          {Object.keys(layers).map(k => (
            <label key={k} style={{ cursor: "pointer",
                                        color: layers[k] ? "#a78bfa" : "#475569" }}
                    data-testid={`xdr-ag-layer-${k}`}>
              <input type="checkbox" checked={layers[k]}
                      onChange={() => setLayers(l => ({ ...l, [k]: !l[k] }))}
                      style={{ verticalAlign: "-2px", marginRight: 4 }} />
              {k}
            </label>
          ))}
          <div style={{ marginLeft: "auto", display: "flex", gap: 6,
                            alignItems: "center" }}>
            <button onClick={() => setZoom(z => Math.max(0.5, z - 0.15))}
                      title="Zoom out" data-testid="xdr-ag-zoom-out"
                      style={btnS}><ZoomOut size={12} /></button>
            <button onClick={() => setZoom(1.0)}
                      title="Reset zoom to 100%"
                      data-testid="xdr-ag-zoom-pct"
                      style={{ ...btnS, minWidth: 44, justifyContent: "center",
                                  fontVariantNumeric: "tabular-nums", fontSize: 11 }}>
              {Math.round(zoom * 100)}%
            </button>
            <button onClick={() => setZoom(z => Math.min(1.6, z + 0.15))}
                      title="Zoom in" data-testid="xdr-ag-zoom-in"
                      style={btnS}><ZoomIn size={12} /></button>
            <button onClick={() => setZoom(1.0)}
                      title="Fit" data-testid="xdr-ag-fit"
                      style={btnS}><Maximize2 size={12} /></button>
            <button onClick={() => { setZoom(1); setSelId(null); setTimeMax(100); }}
                      title="Reset view" data-testid="xdr-ag-reset"
                      style={btnS}><RotateCcw size={12} /></button>
            <button onClick={() => setNodeOverrides({})}
                      title="Reset layout (undo manual node moves)"
                      data-testid="xdr-ag-reset-layout"
                      style={{ ...btnS, fontSize: 10, padding: "4px 8px" }}>
              Reset Layout
            </button>
            <button onClick={() => setShowLegend(v => !v)}
                      title="Edge semantics legend"
                      data-testid="xdr-ag-legend-toggle"
                      style={{ ...btnS, background: showLegend ? "#7c3aed" : "#1e293b" }}>
              <HelpCircle size={12} />
              <span style={{ marginLeft: 4, fontSize: 10 }}>Legend</span>
            </button>
            <button onClick={() => setPopOut(true)}
                      title="Pop out full-screen"
                      data-testid="xdr-ag-popout"
                      style={{ ...btnS, background: "#7c3aed", borderColor: "#8b5cf6" }}>
              <Maximize size={12} /> <span style={{ marginLeft: 4, fontSize: 10 }}>Pop Out</span>
            </button>
          </div>
        </div>
        {/* Timeline row */}
        {graph.timeline.length > 0 && (
          <div style={{ padding: "6px 10px", borderBottom: "1px solid #1e293b",
                          color: "#94a3b8", fontSize: 11, display: "flex",
                          alignItems: "center", gap: 8 }}
                data-testid="xdr-ag-timeline">
            <button onClick={() => stepTimeline(-1)} style={btnS}
                      data-testid="xdr-ag-tl-prev"><SkipBack size={11} /></button>
            <button onClick={() => setPlaying(p => !p)} style={btnS}
                      data-testid="xdr-ag-tl-play">
              {playing ? <Pause size={11} /> : <Play size={11} />}
            </button>
            <button onClick={() => stepTimeline(1)} style={btnS}
                      data-testid="xdr-ag-tl-next"><SkipForward size={11} /></button>
            <input type="range" min="0" max="100" value={timeMax}
                    onChange={e => setTimeMax(parseInt(e.target.value, 10))}
                    style={{ flex: 1 }}
                    data-testid="xdr-ag-tl-scrub" />
            <span className="mono">{timeMax}% · {timelineWindow ? timelineWindow.size : 0}</span>
          </div>
        )}
        {/* Round 41 · Timeline Replay — walkable primary-path playback.
            Pure controller over graph.primary_path[]; no new data model. */}
        <div style={{ padding: "6px 10px", borderBottom: "1px solid #1e293b",
                        color: "#e2e8f0", fontSize: 11, display: "flex",
                        alignItems: "center", gap: 8, background: "#0a0e1a" }}
              data-testid="xdr-ag-replay">
          <span style={{ color: "#a78bfa", fontWeight: 700,
                             letterSpacing: 0.6, textTransform: "uppercase",
                             fontSize: 10 }}>
            Path Replay
          </span>
          {replaySteps.length === 0 ? (
            <span style={{ color: "#64748b", fontStyle: "italic" }}
                    data-testid="xdr-ag-replay-empty">
              No walkable primary path in this projection.
            </span>
          ) : (
            <>
              <button
                data-testid="xdr-ag-replay-prev"
                style={btnS}
                disabled={replayIdx <= 0}
                title="Previous step"
                onClick={() => {
                  setReplayPlaying(false);
                  setReplayIdx(i => Math.max(0, i - 1));
                }}>
                <SkipBack size={11} />
              </button>
              <button
                data-testid="xdr-ag-replay-play"
                style={{ ...btnS,
                             background: replayPlaying ? "#7c3aed" : "#1e293b",
                             borderColor: replayPlaying ? "#8b5cf6" : "#334155" }}
                title={replayPlaying ? "Pause path replay" : "Play path replay"}
                onClick={() => {
                  if (replayIdx < 0) setReplayIdx(0);
                  setReplayPlaying(p => !p);
                }}>
                {replayPlaying ? <Pause size={11} /> : <Play size={11} />}
              </button>
              <button
                data-testid="xdr-ag-replay-next"
                style={btnS}
                disabled={replayIdx >= replaySteps.length - 1}
                title="Next step"
                onClick={() => {
                  setReplayPlaying(false);
                  setReplayIdx(i => Math.min(replaySteps.length - 1, i + 1));
                }}>
                <SkipForward size={11} />
              </button>
              <input type="range"
                      data-testid="xdr-ag-replay-scrub"
                      min="0"
                      max={Math.max(0, replaySteps.length - 1)}
                      value={Math.max(0, replayIdx)}
                      onChange={e => {
                        setReplayPlaying(false);
                        setReplayIdx(parseInt(e.target.value, 10));
                      }}
                      style={{ flex: 1 }} />
              <span className="mono"
                      data-testid="xdr-ag-replay-position"
                      style={{ color: "#cbd5e1" }}>
                {Math.max(0, replayIdx) + (replayIdx < 0 ? 0 : 1)}
                {" / "}
                {replaySteps.length}
              </span>
              {replayCurrent && (
                <span className="mono"
                        data-testid="xdr-ag-replay-current-kind"
                        title={replayCurrent.label}
                        style={{ color: "#a78bfa", fontSize: 10,
                                    textTransform: "uppercase",
                                    letterSpacing: 0.4 }}>
                  · {replayCurrent.kind}
                </span>
              )}
            </>
          )}
        </div>
        {/* Edge semantics legend (toggle) — grouped by SEMANTIC
              CLASS, not by relationship name, so the analyst learns
              the visual language rather than memorising every verb. */}
        {showLegend && (
          <div style={{ padding: "10px 12px", borderBottom: "1px solid #1e293b",
                          background: "#0a0e1a", color: "#cbd5e1",
                          fontSize: 11 }}
                data-testid="xdr-ag-legend">
            <div style={{ display: "grid",
                                  gridTemplateColumns: "auto 1fr",
                                  gap: "6px 12px", marginBottom: 8 }}>
              <LegendSwatch cls="causal"      note="Execution / spawn / created / connected — solid + arrow" />
              <LegendSwatch cls="evidence"    note="Detected · mapped · supported · observed — subtle, no arrow" />
              <LegendSwatch cls="correlation" note="Cross-lane correlation — dashed, NEVER implies causality" />
              <LegendSwatch cls="gap"         note="Pivoted-to / unknown — dotted, low emphasis" />
            </div>
            <div style={{ display: "grid",
                                  gridTemplateColumns: "repeat(2, 1fr)", gap: "4px 16px" }}>
              {EDGE_SEMANTICS.map(([k, desc]) => {
                const cls = EDGE_CLASS[k] || "evidence";
                const tone = EDGE_TONE[cls];
                return (
                  <div key={k}
                            style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
                    <span className="mono"
                                style={{ color: tone.stroke, fontWeight: 600, minWidth: 130 }}>
                      → {k}
                    </span>
                    <span style={{ color: "#94a3b8" }}>{desc}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
        {/* Attack Progression banner — the graph is a LEFT→RIGHT
              causal chain.  This banner tells the analyst so before
              they look at a single node. */}
        <div style={{ padding: "6px 12px",
                            borderBottom: "1px solid #1e293b",
                            background: "#0a0e1a", color: "#a3906a",
                            fontSize: 10, letterSpacing: 0.6,
                            textTransform: "uppercase", fontWeight: 700,
                            display: "flex", alignItems: "center", gap: 8 }}
              data-testid="xdr-ag-progression-banner">
          <span style={{ color: "#64748b" }}>Attack Progression</span>
          <span style={{ color: "#4a3013" }}>›</span>
          <span style={{ color: "#94a3b8" }}>Context</span>
          <span style={{ color: "#4a3013" }}>›</span>
          <span style={{ color: "#7cb2ea" }}>Telemetry</span>
          <span style={{ color: "#4a3013" }}>›</span>
          <span style={{ color: "#f0b26b" }}>Activity</span>
          <span style={{ color: "#4a3013" }}>›</span>
          <span style={{ color: "#c4a8f5" }}>Finding</span>
          <span style={{ color: "#4a3013" }}>›</span>
          <span style={{ color: "#d8b4fe" }}>ATT&amp;CK</span>
          <span style={{ color: "#64748b", marginLeft: "auto",
                             fontWeight: 500, textTransform: "none",
                             letterSpacing: 0.3 }}>
            Evidence-backed causal chain — correlation NEVER implies causality
          </span>
        </div>
        {/* SVG canvas with native scrollbars + drag/pan */}
        <div ref={scrollRef}
              style={{ overflow: "auto", position: "relative",
                          maxHeight: popOut ? "calc(100vh - 200px)" : 680 }}
              onMouseMove={(ev) => {
                if (!dragState) return;
                if (dragState.pan) {
                  const dx = dragState.startX - ev.clientX;
                  const dy = dragState.startY - ev.clientY;
                  scrollRef.current.scrollLeft = dragState.scrollLeft + dx;
                  scrollRef.current.scrollTop  = dragState.scrollTop + dy;
                } else {
                  const rect = scrollRef.current.getBoundingClientRect();
                  const x = (ev.clientX - rect.left + scrollRef.current.scrollLeft) / zoom
                                 - dragState.grabDx;
                  const y = (ev.clientY - rect.top  + scrollRef.current.scrollTop) / zoom
                                 - dragState.grabDy;
                  setNodeOverrides(o => ({ ...o, [dragState.nodeId]: { x, y } }));
                }
              }}
              onMouseUp={() => setDragState(null)}
              onMouseLeave={() => setDragState(null)}>
          <svg width={(layout?.width || 800) * zoom}
                height={(layout?.height || 300) * zoom}
                viewBox={`0 0 ${layout?.width || 800} ${layout?.height || 300}`}
                data-testid="xdr-ag-svg"
                style={{ display: "block", cursor: dragState?.pan ? "grabbing" : "default" }}
                onMouseDown={(ev) => {
                  // Empty-canvas drag → pan the scroll container.
                  if (ev.target === ev.currentTarget) {
                    setDragState({ pan: true,
                                       startX: ev.clientX, startY: ev.clientY,
                                       scrollLeft: scrollRef.current.scrollLeft,
                                       scrollTop:  scrollRef.current.scrollTop });
                  }
                }}>
            {/* Arrowhead markers per edge class — enables directional
                causal edges without cluttering non-causal relationships. */}
            <defs>
              <marker id="nx-arrow-causal" viewBox="0 0 10 10"
                              refX="9" refY="5" markerWidth="6" markerHeight="6"
                              orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill="#f0b26b" opacity="0.9" />
              </marker>
              <marker id="nx-arrow-primary" viewBox="0 0 10 10"
                              refX="9" refY="5" markerWidth="7" markerHeight="7"
                              orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill="#fbbf24" opacity="1" />
              </marker>
              {/* Very subtle radial glow for primary-path nodes so
                    the attack progression is visually dominant without
                    saturating colour. */}
              <filter id="nx-primary-glow" x="-20%" y="-20%"
                            width="140%" height="140%">
                <feGaussianBlur stdDeviation="2.4" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>
            {/* Edges */}
            {layout && visibleEdges.map(e => {
              const s = layout.pos.get(e.src);
              const d = layout.pos.get(e.dst);
              if (!s || !d) return null;
              const dimmed = timelineWindow && e.timestamp
                && !timelineWindow.has(`${e.src}|${e.rel}|${e.dst}`);
              const cls  = EDGE_CLASS[e.rel] || "evidence";
              const et   = EDGE_TONE[cls];
              const isPrimary = primaryPath.has(e.src) && primaryPath.has(e.dst);
              const isSelected = selId === e.id;
              const isHovered = hoveredEdge === e.id;
              const showLabel = isSelected || isHovered;
              const x1 = s.x + NODE_W, y1 = s.y + NODE_H / 2;
              const x2 = d.x,           y2 = d.y + NODE_H / 2;
              // On the primary path, force a causal look + strong
              // arrow so the attack progression is unmistakable.
              const stroke = isSelected ? "#fbbf24"
                                       : isPrimary ? "#fbbf24"
                                       : et.stroke;
              const dash = e.state === "NOT_OBSERVED" ? "1 4"
                                 : (isPrimary ? "0" : et.dash);
              const opacity = isPrimary ? 0.95 : et.opacity;
              const wantsArrow = cls === "causal" || isPrimary;
              const markerEnd = isPrimary
                ? "url(#nx-arrow-primary)"
                : (wantsArrow ? "url(#nx-arrow-causal)" : undefined);
              // Bezier control points — kept flat so the graph reads
              // as a left→right progression rather than swirls.
              const dx = Math.max(24, Math.abs(x2 - x1) * 0.35);
              return (
                <g key={e.id}
                    onClick={() => { setSelId(e.id); setSelKind("edge"); }}
                    onMouseEnter={() => setHovered(e.id)}
                    onMouseLeave={() => setHovered(null)}
                    style={{ cursor: "pointer", opacity: dimmed ? 0.10 : 1 }}
                    data-testid={`xdr-ag-edge-${e.id}`}
                    data-edge-class={cls}
                    data-edge-primary={isPrimary ? "true" : "false"}>
                  <path d={`M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`}
                         fill="none"
                         stroke={stroke}
                         strokeWidth={isSelected ? 2 : isPrimary ? 1.8 : 1}
                         strokeDasharray={dash}
                         strokeOpacity={opacity}
                         markerEnd={markerEnd} />
                  {showLabel && (
                    <text x={(x1 + x2) / 2} y={(y1 + y2) / 2 - 4}
                           fontSize={8} fontFamily="ui-monospace, monospace"
                           fill={isPrimary ? "#fbbf24" : et.stroke}
                           textAnchor="middle">
                      {e.rel}
                    </text>
                  )}
                </g>
              );
            })}
            {/* Nodes */}
            {layout && visibleNodes.map(n => {
              const p = layout.pos.get(n.id);
              if (!p) return null;
              const state    = STATE_TONE[n.state] || STATE_TONE.NOT_OBSERVED;
              const role     = NODE_ROLE[n.kind]   || "context";
              const rt       = ROLE_TONE[role];
              const glyph    = KIND_GLYPH[n.kind] || (n.kind || "").slice(0,3).toUpperCase();
              const isSel    = selId === n.id && selKind === "node";
              const isPrim   = primaryPath.has(n.id);
              const isAnchor = role === "context";
              const isReplayCurrent = replayCurrent && replayCurrent.id === n.id;
              // Context (anchor) entities recede — thinner border, no
              // fill glow, muted label — so activity/mitre nodes stay
              // visually dominant.
              const nodeFill   = rt.fill;
              const nodeStroke = isSel      ? "#fbbf24"
                                              : isPrim  ? "#fbbf24"
                                              : rt.stroke;
              const borderW    = isSel ? 1.8 : isPrim ? 1.6 : (isAnchor ? 0.8 : 1);
              const findingAnnotations = (n.annotations?.findings) || [];
              const findingCount = findingAnnotations.length;
              const evidenceCount = (n.annotations?.evidence_ids?.length) || 0
                                                    || (n.annotations?.evidence_count) || 0;
              const attckId = n.attrs?.tid;
              return (
                <g key={n.id}
                    onClick={(ev) => { ev.stopPropagation();
                                              setSelId(n.id); setSelKind("node"); }}
                    onMouseDown={(ev) => {
                      ev.stopPropagation();
                      const rect = scrollRef.current.getBoundingClientRect();
                      const px = (ev.clientX - rect.left + scrollRef.current.scrollLeft) / zoom;
                      const py = (ev.clientY - rect.top  + scrollRef.current.scrollTop) / zoom;
                      setDragState({ nodeId: n.id,
                                          grabDx: px - p.x, grabDy: py - p.y });
                    }}
                    style={{ cursor: dragState?.nodeId === n.id ? "grabbing" : "grab",
                                 opacity: isAnchor && !isPrim ? 0.82 : 1 }}
                    filter={isPrim ? "url(#nx-primary-glow)" : undefined}
                    data-testid={`xdr-ag-node-${n.id}`}
                    data-node-role={role}
                    data-node-primary={isPrim ? "true" : "false"}
                    data-node-state={n.state || "NOT_OBSERVED"}>
                  {/* Node body — sharp rectangle, minimal rounding
                        so the visual reads as forensic, not decorative. */}
                  <rect x={p.x} y={p.y} width={NODE_W} height={NODE_H} rx={3}
                         fill={nodeFill}
                         stroke={nodeStroke}
                         strokeWidth={borderW} />
                  {/* Kind glyph — small mono token in the top-left. */}
                  <rect x={p.x + 4} y={p.y + 4} width={26} height={11} rx={2}
                         fill="#000" fillOpacity={0.35}
                         stroke={rt.accent} strokeOpacity={0.5}
                         strokeWidth={0.5} />
                  <text x={p.x + 17} y={p.y + 12}
                         fontSize={7.5}
                         fontFamily="ui-monospace, monospace"
                         fontWeight={700} letterSpacing={0.5}
                         fill={rt.accent} textAnchor="middle">
                    {glyph}
                  </text>
                  {/* Primary label — the single most-important line
                        the analyst needs to read. */}
                  <text x={p.x + 34} y={p.y + 14}
                         fontSize={11} fontFamily="ui-sans-serif"
                         fill={rt.label} style={{ fontWeight: 600 }}>
                    <title>{n.label}</title>
                    {nodeLabel(n)}
                  </text>
                  {/* Footer — state dot + evidence count + ATT&CK pill.
                        These are secondary indicators; they never
                        outweigh the primary label. */}
                  <text x={p.x + 6} y={p.y + NODE_H - 6}
                         fontSize={8.5}
                         fontFamily="ui-monospace, monospace"
                         fill={rt.accent}>
                    {state.label} {(n.state || "").replace(/_/g, " ")}
                  </text>
                  {evidenceCount > 0 && (
                    <text x={p.x + 74} y={p.y + NODE_H - 6}
                            fontSize={8.5}
                            fontFamily="ui-monospace, monospace"
                            fill={rt.faint}>
                      · ev {evidenceCount > 99 ? "99+" : evidenceCount}
                    </text>
                  )}
                  {attckId && role === "mitre" && (
                    <g>
                      <rect x={p.x + NODE_W - 60} y={p.y + NODE_H - 16}
                                width={54} height={12} rx={2}
                                fill="#4d2a76" fillOpacity={0.45}
                                stroke={ROLE_TONE.mitre.accent}
                                strokeOpacity={0.5} strokeWidth={0.6} />
                      <text x={p.x + NODE_W - 33} y={p.y + NODE_H - 6}
                              fontSize={8.5}
                              fontFamily="ui-monospace, monospace"
                              fontWeight={700} letterSpacing={0.4}
                              fill={ROLE_TONE.mitre.accent}
                              textAnchor="middle">
                        {attckId}
                      </text>
                    </g>
                  )}
                  {isReplayCurrent && (
                    <rect x={p.x - 4} y={p.y - 4}
                            width={NODE_W + 8} height={NODE_H + 8} rx={5}
                            fill="none"
                            stroke="#a78bfa"
                            strokeWidth={2}
                            strokeDasharray="4 3"
                            data-testid={`xdr-ag-replay-focus-${n.id}`}>
                      <animate attributeName="stroke-opacity"
                                    values="0.4;1;0.4" dur="1.4s"
                                    repeatCount="indefinite" />
                    </rect>
                  )}
                  {findingCount > 0 && (
                    <g data-testid={`xdr-ag-finding-badge-${n.id}`}>
                      <title>
                        {findingCount} finding(s) anchored on this entity:
                        {findingAnnotations.slice(0, 5)
                                              .map(f => `\n• [${f.state}] ${f.capability || ""} · ${f.summary || f.finding_id || ""}`)
                                              .join("")}
                      </title>
                      <circle cx={p.x + NODE_W - 9} cy={p.y + 9} r={6}
                                fill="#fbbf24" stroke="#78350f" strokeWidth={0.8} />
                      <text x={p.x + NODE_W - 9} y={p.y + 12}
                              fontSize={8} fontFamily="ui-monospace, monospace"
                              fill="#78350f" textAnchor="middle"
                              style={{ fontWeight: 700 }}>
                        {findingCount > 9 ? "9+" : findingCount}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}
            {/* Empty-state — honestly say so.  Never fabricate a
                  chain.  This mirrors the owner rule for the
                  Cross-Lane Story on the backend.  Guarded on
                  `visibleNodes.length===0` ONLY — the outer
                  `layout` memo returns null in this branch, so
                  guarding on `layout &&` would make this
                  unreachable. */}
            {visibleNodes.length === 0 && (
              <g data-testid="xdr-ag-empty">
                <rect x={20} y={20}
                        width={((layout?.width) || 800) - 40}
                        height={64} rx={4}
                        fill="#0a0e1a"
                        stroke="#334155" strokeDasharray="4 4" />
                <text x={40} y={44}
                        fontSize={12} fontFamily="ui-monospace, monospace"
                        fill="#fbbf24" fontWeight={700} letterSpacing={0.6}>
                  NO EVIDENCE-BACKED ATTACK CHAIN
                </text>
                <text x={40} y={68}
                        fontSize={10} fontFamily="ui-sans-serif"
                        fill="#94a3b8">
                  Governed evidence is insufficient to plot a chain.
                  Turn on the Gaps layer to see UNKNOWN pivots, or
                  ingest more Endpoint / Identity / Cloud telemetry.
                </text>
              </g>
            )}
            {/* Top-most transparent edge hit-layer — nodes are
                  painted BEFORE this so they still visually occlude
                  edges, but the invisible strokes above give the
                  analyst a reliable click target even when a causal
                  path passes under a node rect.  Kept thin (8px)
                  so it does not shadow node clicks; the underlying
                  <g> keeps click/hover semantics identical to the
                  visible edge. */}
            {layout && visibleEdges.map(e => {
              const s = layout.pos.get(e.src);
              const d = layout.pos.get(e.dst);
              if (!s || !d) return null;
              const isPrimary = primaryPath.has(e.src) && primaryPath.has(e.dst);
              const x1 = s.x + NODE_W, y1 = s.y + NODE_H / 2;
              const x2 = d.x,           y2 = d.y + NODE_H / 2;
              const dx = Math.max(24, Math.abs(x2 - x1) * 0.35);
              return (
                <path key={`hit-${e.id}`}
                          d={`M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`}
                          fill="none"
                          stroke="transparent"
                          strokeWidth={8}
                          style={{ cursor: "pointer",
                                       pointerEvents: "stroke" }}
                          onClick={(ev) => { ev.stopPropagation();
                                                      setSelId(e.id); setSelKind("edge"); }}
                          onMouseEnter={() => setHovered(e.id)}
                          onMouseLeave={() => setHovered(null)}
                          data-testid={`xdr-ag-edge-hit-${e.id}`}
                          data-edge-primary={isPrimary ? "true" : "false"} />
              );
            })}
          </svg>
        </div>
        {/* Metrics footer */}
        <div style={{ padding: "6px 10px", borderTop: "1px solid #1e293b",
                         color: "#94a3b8", fontSize: 10,
                         display: "flex", gap: 12, flexWrap: "wrap" }}
              data-testid="xdr-ag-metrics">
          {Object.entries(graph.metrics).map(([k, v]) => (
            <span key={k}>{k.replace(/_/g, " ")}:
              <b style={{ color: "#e2e8f0", marginLeft: 4 }}>{v}%</b>
            </span>
          ))}
        </div>
        </div>)}
      </div>
      {/* Evidence Inspector · Round 38.3 shared component (owner rule §11) */}
      <div style={{ background: "#0b1220", border: "1px solid #1e293b",
                       borderRadius: 6, fontSize: 12,
                       maxHeight: 820, overflow: "auto" }}
            data-testid="xdr-ag-inspector">
        {deepLink ? (
          /* Round 42 · Evidence deep-link projection — the analyst
             clicked an evidence pill on an edge.  We reuse the exact
             same shared EvidenceInspector and canonical resolver;
             we do NOT render a second evidence-detail widget. */
          <div>
            <div style={{ padding: "8px 12px",
                             borderBottom: "1px solid #1e293b",
                             background: "#111827",
                             display: "flex", alignItems: "center",
                             gap: 8, fontSize: 11, color: "#cbd5e1" }}
                  data-testid="xdr-ag-deeplink-bar">
              <button
                data-testid="xdr-ag-deeplink-back"
                onClick={() => setDeepLink(null)}
                style={{ ...btnS, background: "#0f172a" }}
                title="Return to the edge inspector">
                ← Back
              </button>
              <span style={{ color: "#a78bfa", fontWeight: 700,
                                 letterSpacing: 0.6,
                                 textTransform: "uppercase",
                                 fontSize: 10 }}>
                Evidence Deep-Link
              </span>
              <span className="mono" style={{ fontSize: 10, opacity: 0.7 }}>
                {deepLink.kind}:{deepLink.refId}
              </span>
            </div>
            <EvidenceInspector incidentId={incident?.id}
                                        embedded
                                        kind={deepLink.kind}
                                        refId={deepLink.refId} />
          </div>
        ) : (!selected || selKind === "node") && (
          <EvidenceInspector incidentId={incident?.id}
                                       embedded
                                       {...(selected && selKind === "node"
                                             ? nodeToInspectorArgs(selected)
                                             : { kind: null, refId: null })} />
        )}
        {!deepLink && selected && selKind === "edge" && (
          <div style={{ padding: 12, color: "#e2e8f0" }}>
            <div className="mono" style={{ fontSize: 10, opacity: 0.55 }}>{selected.id}</div>
            <div style={{ fontSize: 14, fontWeight: 600, marginTop: 4 }}>{selected.rel}</div>
            <div style={{ marginTop: 6, fontSize: 11 }}>
              <div><b>State:</b> {selected.state}</div>
              <div><b>Reason:</b> {selected.reason}</div>
              {selected.timestamp   && <div><b>When:</b> {selected.timestamp}</div>}
              {selected.event_id    && <div><b>Event ID:</b> {selected.event_id}</div>}
              {selected.technique_id && <div><b>Technique:</b> {selected.technique_id}</div>}
              <div><b>Source:</b> {selected.source}</div>
            </div>
            {selected.evidence_refs.length > 0 && (
              <div style={{ marginTop: 8 }}
                    data-testid="xdr-ag-edge-evidence-refs">
                <b>Evidence refs</b>{" "}
                <span style={{ opacity: 0.5, fontSize: 10 }}>
                  (click to inspect canonical event)
                </span>
                <div style={{ display: "flex", flexWrap: "wrap",
                                 gap: 4, marginTop: 4 }}>
                  {selected.evidence_refs.slice(0, 8).map(r => (
                    <button key={r}
                             data-testid={`xdr-ag-evidence-ref-${r}`}
                             onClick={() => setDeepLink({
                               kind: "event", refId: r
                             })}
                             className="mono"
                             title={`Open canonical event ${r} in the Evidence Inspector`}
                             style={{
                               background: "#0b1220",
                               border: "1px solid #334155",
                               color: "#a5b4fc",
                               padding: "3px 8px", borderRadius: 3,
                               fontSize: 10, cursor: "pointer",
                             }}>
                      {r}
                    </button>
                  ))}
                </div>
              </div>
            )}
            {selected.finding_ids.length > 0 && (
              <div style={{ marginTop: 8 }}
                    data-testid="xdr-ag-edge-finding-refs">
                <b>Findings</b>{" "}
                <span style={{ opacity: 0.5, fontSize: 10 }}>
                  (click to inspect finding)
                </span>
                <div style={{ display: "flex", flexWrap: "wrap",
                                 gap: 4, marginTop: 4 }}>
                  {selected.finding_ids.slice(0, 8).map(r => (
                    <button key={r}
                             data-testid={`xdr-ag-finding-ref-${r}`}
                             onClick={() => setDeepLink({
                               kind: "finding", refId: r
                             })}
                             className="mono"
                             title={`Open finding ${r} in the Evidence Inspector`}
                             style={{
                               background: "#0b1220",
                               border: "1px solid #334155",
                               color: "#fde68a",
                               padding: "3px 8px", borderRadius: 3,
                               fontSize: 10, cursor: "pointer",
                             }}>
                      {r}
                    </button>
                  ))}
                </div>
              </div>
            )}
            <div style={{ marginTop: 10, borderTop: "1px solid #1e293b",
                             paddingTop: 8, fontSize: 11 }}>
              <div><b>Endpoints</b></div>
              <div>src: {nodeMap.get(selected.src)?.label}</div>
              <div>dst: {nodeMap.get(selected.dst)?.label}</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );

  if (popOut) {
    return (
      <div style={{ position: "fixed", inset: 0, zIndex: 9999,
                       background: "#020617", padding: 16,
                       display: "flex", flexDirection: "column" }}
            data-testid="xdr-ag-popout-overlay">
        <div style={{ display: "flex", alignItems: "center",
                          marginBottom: 10, color: "#e2e8f0" }}>
          <div style={{ fontWeight: 600, fontSize: 14 }}>
            NivXRay · Attack Graph · Full Investigation Canvas
          </div>
          <button onClick={() => setPopOut(false)}
                    data-testid="xdr-ag-popout-close"
                    style={{ marginLeft: "auto", ...btnS,
                                background: "#7c3aed", borderColor: "#8b5cf6" }}>
            <X size={12} /> <span style={{ marginLeft: 4, fontSize: 11 }}>Exit Pop Out</span>
          </button>
        </div>
        <div style={{ flex: 1, overflow: "hidden" }}>{inner}</div>
      </div>
    );
  }
  return inner;
}

const btnS = {
  background: "#1e293b", color: "#e2e8f0", border: "1px solid #334155",
  borderRadius: 3, padding: "4px 6px", cursor: "pointer",
  display: "inline-flex", alignItems: "center",
};


// Compact swatch used by the edge-class legend — visualises the
// dash pattern + arrowhead so the analyst learns the shape rather
// than the label.
function LegendSwatch({ cls, note }) {
  const tone = EDGE_TONE[cls];
  return (
    <>
      <span data-testid={`xdr-ag-legend-swatch-${cls}`}
                style={{ display: "inline-flex", alignItems: "center",
                            gap: 6 }}>
        <svg width={64} height={12}>
          <defs>
            <marker id={`nx-legend-arrow-${cls}`} viewBox="0 0 10 10"
                            refX="9" refY="5" markerWidth="6" markerHeight="6"
                            orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" fill={tone.stroke} />
            </marker>
          </defs>
          <line x1="2" y1="6" x2="58" y2="6"
                     stroke={tone.stroke}
                     strokeWidth="1.4"
                     strokeDasharray={tone.dash}
                     strokeOpacity={tone.opacity}
                     markerEnd={tone.arrow
                       ? `url(#nx-legend-arrow-${cls})` : undefined} />
        </svg>
        <span className="mono"
                    style={{ color: tone.stroke, fontWeight: 700,
                                letterSpacing: 0.4, minWidth: 96,
                                textTransform: "uppercase" }}>
          {cls}
        </span>
      </span>
      <span style={{ color: "#94a3b8" }}>{note}</span>
    </>
  );
}
