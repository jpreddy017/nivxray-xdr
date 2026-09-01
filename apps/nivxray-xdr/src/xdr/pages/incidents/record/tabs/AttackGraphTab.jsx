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


const STATE_TONE = {
  OBSERVED:     { fill: "#7c3aed", stroke: "#c4b5fd", label: "●" },
  SUPPORTED:    { fill: "#4c1d95", stroke: "#a78bfa", label: "◐" },
  POSSIBLE:     { fill: "#1e293b", stroke: "#94a3b8", label: "○" },
  NOT_OBSERVED: { fill: "#0f172a", stroke: "#334155", label: "—" },
};

// Per-kind fill override so the analyst can immediately identify
// what type of node they are looking at, even in dense chains.
const KIND_TONE = {
  incident:    { fill: "#831843", stroke: "#f472b6" },
  host:        { fill: "#134e4a", stroke: "#5eead4" },
  user:        { fill: "#134e4a", stroke: "#67e8f9" },
  ip:          { fill: "#083344", stroke: "#7dd3fc" },
  hash:        { fill: "#0c4a6e", stroke: "#7dd3fc" },
  event:       { fill: "#1e3a8a", stroke: "#93c5fd" },
  event_id:    { fill: "#1e3a8a", stroke: "#93c5fd" },
  signature:   { fill: "#365314", stroke: "#bef264" },
  process:     { fill: "#78350f", stroke: "#fdba74" },
  commandline: { fill: "#7c2d12", stroke: "#fca5a5" },
  detection:   { fill: "#3b0764", stroke: "#d8b4fe" },
  match:       { fill: "#4c0519", stroke: "#fda4af" },
  finding:     { fill: "#4c1d95", stroke: "#c4b5fd" },
  capability:  { fill: "#312e81", stroke: "#a5b4fc" },
  technique:   { fill: "#6d28d9", stroke: "#ddd6fe" },
  stage:       { fill: "#166534", stroke: "#86efac" },
  gap:         { fill: "#111827", stroke: "#64748b" },
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

const COL_W = 180, ROW_H = 38, NODE_W = 170, NODE_H = 30;


function nodeLabel(n) {
  const s = n.label || "";
  return s.length > 26 ? s.slice(0, 24) + "…" : s;
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
        {/* Edge semantics legend (toggle) */}
        {showLegend && (
          <div style={{ padding: "8px 10px", borderBottom: "1px solid #1e293b",
                          background: "#0f172a", color: "#cbd5e1",
                          fontSize: 11, display: "grid",
                          gridTemplateColumns: "repeat(2, 1fr)", gap: "4px 16px" }}
                data-testid="xdr-ag-legend">
            {EDGE_SEMANTICS.map(([k, desc]) => (
              <div key={k} style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
                <span className="mono" style={{ color: "#a78bfa",
                                                       fontWeight: 600,
                                                       minWidth: 130 }}>
                  → {k}
                </span>
                <span style={{ color: "#94a3b8" }}>{desc}</span>
              </div>
            ))}
          </div>
        )}
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
            {/* Edges */}
            {layout && visibleEdges.map(e => {
              const s = layout.pos.get(e.src);
              const d = layout.pos.get(e.dst);
              if (!s || !d) return null;
              const dimmed = timelineWindow && e.timestamp
                && !timelineWindow.has(`${e.src}|${e.rel}|${e.dst}`);
              const tone = STATE_TONE[e.state] || STATE_TONE.NOT_OBSERVED;
              const isPrimary = primaryPath.has(e.src) && primaryPath.has(e.dst);
              const isSelected = selId === e.id;
              const isHovered = hoveredEdge === e.id;
              const showLabel = isSelected || isHovered;
              const x1 = s.x + NODE_W, y1 = s.y + NODE_H / 2;
              const x2 = d.x,           y2 = d.y + NODE_H / 2;
              return (
                <g key={e.id}
                    onClick={() => { setSelId(e.id); setSelKind("edge"); }}
                    onMouseEnter={() => setHovered(e.id)}
                    onMouseLeave={() => setHovered(null)}
                    style={{ cursor: "pointer", opacity: dimmed ? 0.12 : 1 }}
                    data-testid={`xdr-ag-edge-${e.id}`}>
                  <path d={`M${x1},${y1} C${x1 + 30},${y1} ${x2 - 30},${y2} ${x2},${y2}`}
                         fill="none"
                         stroke={isSelected ? "#fbbf24"
                                    : isPrimary ? "#c4b5fd" : tone.stroke}
                         strokeWidth={isSelected ? 2 : isPrimary ? 1.5 : 0.8}
                         strokeDasharray={e.state === "POSSIBLE" ? "3 3"
                                              : e.state === "NOT_OBSERVED" ? "1 4" : "0"}
                         strokeOpacity={isPrimary ? 0.9 : 0.55} />
                  {showLabel && (
                    <text x={(x1 + x2) / 2} y={(y1 + y2) / 2 - 4}
                           fontSize={8} fontFamily="ui-monospace, monospace"
                           fill="#fbbf24" textAnchor="middle">
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
              const tone = STATE_TONE[n.state] || STATE_TONE.NOT_OBSERVED;
              const kindTone = KIND_TONE[n.kind];
              const nodeFill = (n.state === "OBSERVED" || n.state === "SUPPORTED")
                && kindTone ? kindTone.fill : tone.fill;
              const nodeStroke = (n.state === "OBSERVED" || n.state === "SUPPORTED")
                && kindTone ? kindTone.stroke : tone.stroke;
              const isSel = selId === n.id && selKind === "node";
              const isPrim = primaryPath.has(n.id);
              const isReplayCurrent = replayCurrent && replayCurrent.id === n.id;
              const stroke = isSel ? "#fbbf24" : isPrim ? "#fbbf24" : nodeStroke;
              const findingAnnotations = (n.annotations?.findings) || [];
              const findingCount = findingAnnotations.length;
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
                    style={{ cursor: dragState?.nodeId === n.id ? "grabbing" : "grab" }}
                    data-testid={`xdr-ag-node-${n.id}`}>
                  <rect x={p.x} y={p.y} width={NODE_W} height={NODE_H} rx={4}
                         fill={nodeFill}
                         stroke={stroke}
                         strokeWidth={isSel || isPrim ? 1.5 : 0.8} />
                  {isReplayCurrent && (
                    <rect x={p.x - 4} y={p.y - 4}
                            width={NODE_W + 8} height={NODE_H + 8} rx={6}
                            fill="none"
                            stroke="#a78bfa"
                            strokeWidth={2}
                            strokeDasharray="4 3"
                            data-testid={`xdr-ag-replay-focus-${n.id}`}>
                      <animate attributeName="stroke-opacity"
                                    values="0.4;1;0.4" dur="1.4s"
                                    repeatCount="indefinite" />
                    </rect>
                  )}                  <text x={p.x + 6} y={p.y + 11}
                         fontSize={8} fontFamily="ui-monospace, monospace"
                         fill="#e2e8f0" opacity={0.7}>
                    {tone.label} {n.kind.toUpperCase()}
                  </text>
                  <text x={p.x + 6} y={p.y + 23}
                         fontSize={10} fontFamily="ui-sans-serif"
                         fill="#f8fafc" style={{ fontWeight: 500 }}>
                    {nodeLabel(n)}
                  </text>
                  {findingCount > 0 && (
                    <g data-testid={`xdr-ag-node-annot-${n.id}`}>
                      <title>
                        {findingCount} finding(s) anchored on this entity:
                        {findingAnnotations.slice(0, 5)
                                              .map(f => `\n• [${f.state}] ${f.capability || ""} · ${f.summary || f.finding_id || ""}`)
                                              .join("")}
                      </title>
                      <circle cx={p.x + NODE_W - 8} cy={p.y + 6} r={6}
                                fill="#fbbf24" stroke="#78350f" strokeWidth={0.8} />
                      <text x={p.x + NODE_W - 8} y={p.y + 9}
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
