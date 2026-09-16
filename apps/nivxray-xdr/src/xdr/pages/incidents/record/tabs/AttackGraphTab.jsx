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
  OBSERVED:     { label: "●", fill: "var(--nx-surf-primary)", stroke: "var(--nx-muted)" },
  SUPPORTED:    { label: "◐", fill: "var(--nx-surf-primary)", stroke: "var(--nx-muted)" },
  POSSIBLE:     { label: "○", fill: "var(--nx-surf-primary)", stroke: "var(--nx-faint)" },
  NOT_OBSERVED: { label: "—", fill: "var(--nx-surf-canvas)", stroke: "var(--nx-bd-strong)" },
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
  context:   { fill: "var(--nx-surf-raised)", stroke: "var(--nx-bd-strong)", accent: "var(--nx-muted)",
                     label:  "var(--nx-text-dim)", faint: "var(--nx-faint)" },
  telemetry: { fill: "var(--nx-surf-raised)", stroke: "var(--nx-bd-strong)", accent: "var(--nx-info)",
                     label:  "var(--nx-text)", faint: "var(--nx-faint)" },
  activity:  { fill: "var(--nx-surf-raised)", stroke: "var(--nx-bd-strong)", accent: "var(--nx-high)",
                     label:  "var(--nx-text)", faint: "var(--nx-faint)" },
  finding:   { fill: "var(--nx-surf-raised)", stroke: "var(--nx-bd-strong)", accent: "var(--nx-teal)",
                     label:  "var(--nx-text)", faint: "var(--nx-faint)" },
  mitre:     { fill: "var(--nx-surf-raised)", stroke: "var(--nx-bd-strong)", accent: "var(--nx-purple)",
                     label:  "var(--nx-text)", faint: "var(--nx-faint)" },
  gap:       { fill: "var(--nx-surf-inset)", stroke: "var(--nx-rel-gap)", accent: "var(--nx-rel-gap)",
                     label:  "var(--nx-muted)", faint: "var(--nx-faint)" },
};
// Circular-node geometry.  The cell footprint stays the same so the
// column layout engine is untouched; only the presentation changes.
const NODE_R  = 21;                    // icon disc radius
const NODE_CX = 30;                    // disc centre, relative to cell x
const NODE_CY = 26;                    // disc centre, relative to cell y
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

// ── §3 RELATIONSHIP GRAMMAR · LOCKED (owner-authorised 2026-09-05) ──
// The previous implementation derived the line style from the
// relationship NAME and then FORCED every primary-path edge to a solid
// glowing amber arrow.  That asserted confirmed causality for edges the
// backend never claimed — the visual language contradicted the product's
// own epistemic contract.
//
// The class is now derived ONLY from authoritative backing carried on
// the edge itself:
//   state          — OBSERVED | SUPPORTED | POSSIBLE | NOT_OBSERVED |
//                    CONTRADICTED   (services/attack_graph)
//   evidence_refs  — canonical event ids
//   finding_ids    — engine/rule findings
//   timestamp      — the ONLY licence to draw direction
//
// No edge renders without a citation, and only OBSERVED / SUPPORTED may
// render as a continuous directional arrow.
const REL_TONE = {
  OBSERVED:     { stroke: "var(--nx-rel-observed)",     width: 1,   dash: "0",   opacity: 0.85, marker: "◆", label: "OBSERVED" },
  SUPPORTED:    { stroke: "var(--nx-rel-supported)",    width: 2,   dash: "0",   opacity: 0.95, marker: "◆", label: "SUPPORTED" },
  INFERRED:     { stroke: "var(--nx-rel-inferred)",     width: 1.2, dash: "6 4", opacity: 0.85, marker: "◇", label: "INFERRED" },
  POSSIBLE:     { stroke: "var(--nx-rel-possible)",     width: 1,   dash: "1 4", opacity: 0.70, marker: "?", label: "POSSIBLE" },
  GAP:          { stroke: "var(--nx-rel-gap)",          width: 2,   dash: "3 7", opacity: 0.55, marker: "?", label: "UNKNOWN / GAP" },
  CONTRADICTED: { stroke: "var(--nx-rel-contradicted)", width: 1.4, dash: "0",   opacity: 0.90, marker: "⊘", label: "CONTRADICTED" },
};

// Relationships that carry an intrinsic ordering fact (parent→child).
const ORDERED_RELS = new Set([
  "SPAWNED", "EXECUTED", "CREATED", "WROTE", "MODIFIED",
  "TRIGGERED", "CONNECTED_TO", "AUTHENTICATED_TO",
]);

// Resolve the epistemic relationship class of one edge from its backing.
function relClass(e) {
  const st    = String(e?.state || "").toUpperCase();
  const evRefs = Array.isArray(e?.evidence_refs) ? e.evidence_refs.filter(Boolean) : [];
  const finds  = Array.isArray(e?.finding_ids)   ? e.finding_ids.filter(Boolean)   : [];
  if (st === "CONTRADICTED") return "CONTRADICTED";
  if (st === "NOT_OBSERVED" || st === "UNKNOWN") return "GAP";
  if (st === "POSSIBLE" || st === "HYPOTHESIS") return "POSSIBLE";
  if (st === "OBSERVED") {
    // Corroborated by ≥2 distinct canonical events → SUPPORTED.
    return new Set(evRefs).size >= 2 ? "SUPPORTED" : "OBSERVED";
  }
  // Backend "SUPPORTED" = derived by a correlation/finding engine, i.e.
  // NOT directly observed.  Honest class is INFERRED, and it must cite
  // the engine finding it came from.
  if (st === "SUPPORTED") return finds.length > 0 || evRefs.length > 0 ? "INFERRED" : "POSSIBLE";
  return evRefs.length > 0 ? "OBSERVED" : "POSSIBLE";
}

// Direction may only be drawn where the backing carries ordering.
function relDirected(e, cls) {
  if (cls !== "OBSERVED" && cls !== "SUPPORTED") return false;
  return Boolean(e?.timestamp) || ORDERED_RELS.has(String(e?.rel || "").toUpperCase());
}

const REL_LEGEND = [
  ["OBSERVED",     "observed", "Both endpoints exist in canonical evidence and the edge was recorded"],
  ["SUPPORTED",    "supported", "Observed AND corroborated by ≥2 distinct canonical events"],
  ["INFERRED",     "inferred", "Derived by a rule / correlation engine — never directly observed"],
  ["POSSIBLE",     "possible", "Candidate relationship, not asserted"],
  ["GAP",          "gap", "A stage exists in the model with no evidence either way"],
  ["CONTRADICTED", "contradicted", "Negative evidence exists for this relationship"],
];

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

// Disposition is a SEPARATE axis from epistemic state: it answers
// "how bad", not "how well do we know".  It is only rendered from
// authoritative fields — never guessed from the label.
function dispositionLabel(n) {
  const d = String(n?.attrs?.disposition || n?.disposition
                     || n?.attrs?.verdict || "").toUpperCase();
  if (d) return d;
  const sev = String(n?.attrs?.severity || n?.severity || "").toUpperCase();
  return sev || "UNKNOWN";
}
function dispositionColor(n) {
  switch (dispositionLabel(n)) {
    case "MALICIOUS":  case "CRITICAL": return "var(--nx-malicious)";
    case "SUSPICIOUS": case "HIGH":     return "var(--nx-suspicious)";
    case "MEDIUM":                      return "var(--nx-medium)";
    case "BENIGN": case "CLEAN":        return "var(--nx-benign)";
    case "COMMON": case "LOW": case "INFO": return "var(--nx-info)";
    default:                            return "var(--nx-rel-gap)";
  }
}

const COL_W = 235, ROW_H = 96, NODE_W = 156, NODE_H = 52;
// Logical camera viewport (world units at zoom = 1).
const VIEW_W = 1600, VIEW_H = 620;


function nodeLabel(n) {
  const s = n.label || "";
  // The label sits BENEATH the 42px disc, centred inside a 210px
  // column.  ~18 characters at 10.5px IBM Plex Sans fits without
  // colliding with the neighbouring column, so truncate hard here.
  return s.length > 18 ? s.slice(0, 16) + "…" : s;
}


export default function AttackGraphTab({ incident, onNavigateTab }) {
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
  const [showDiag, setShowDiag]   = useState(false);
  // ── CAMERA · true pan/zoom viewport (owner: "this is not movable") ──
  // The canvas used to rely on the scroll container, which cannot pan
  // when the graph is smaller than the viewport.  The SVG now owns a
  // camera: `pan` moves it in world units, `zoom` scales it, and the
  // viewBox is derived from both.  Drag, wheel, keyboard and the
  // navigation cluster all drive the same camera.
  const [pan, setPan] = useState({ x: 0, y: 0 });
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

  // INVESTIGATE pivots — only the backend-declared, genuinely
  // implemented destinations.  Anything unavailable never reaches
  // here: the inspector renders it as CAPABILITY UNAVAILABLE.
  const runInspectorAction = (action) => {
    const target = action?.pivot?.target;
    const TAB = { "attack-graph": "attack_graph", mitre: "mitre",
                     technical: "technical" };
    if (target === "attack-graph") { setSubView("process"); return; }
    if (TAB[target] && typeof onNavigateTab === "function") {
      onNavigateTab(TAB[target]);
    }
  };

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
        const base = { x: 64 + ci * COL_W, y: 24 + i * ROW_H };
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

  // Client → world coordinates for node dragging under the camera.
  const toWorld = (clientX, clientY) => {
    const el = scrollRef.current;
    if (!el) return { x: 0, y: 0 };
    const r = el.getBoundingClientRect();
    const sc = (VIEW_W / zoom) / (r.width || 1);
    return { x: (clientX - r.left) * sc - pan.x,
                y: (clientY - r.top)  * sc - pan.y };
  };

  // Fit the whole projection into the viewport — the control an
  // analyst reaches for first when a graph runs off screen.
  const fitToView = () => {
    const w = layout?.width  || VIEW_W;
    const h = layout?.height || VIEW_H;
    const z = Math.min(2.5, Math.max(0.3,
      Math.min(VIEW_W / (w + 60), VIEW_H / (h + 60))));
    setZoom(z);
    setPan({ x: 24, y: 24 });
  };

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

  // ── LEFT NARRATIVE RAIL ─────────────────────────────────────────
  // Chronological, evidence-backed observations straight from
  // graph.timeline (fields: at / src / rel / dst / state / reason).
  // Nothing is synthesised: if the backend ordered nothing, the rail
  // says so instead of inventing a story.
  const narrative = (graph.timeline || [])
    .map((tl, i) => ({ ...tl, _i: i }))
    .sort((a, b) => String(a.at || "").localeCompare(String(b.at || "")));

  const railLabel = (id) => {
    const n = nodeMap.get(id);
    if (!n) return String(id || "").split(":")[0] || "—";
    return nodeLabel(n);
  };

  const rail = (
    <aside data-testid="xdr-ag-narrative-rail"
            style={{ background: "var(--nx-surf-primary)",
                        border: "1px solid var(--nx-bd-quiet)",
                        borderRadius: 6, overflow: "hidden",
                        display: "flex", flexDirection: "column",
                        maxHeight: popOut ? "calc(100vh - 40px)" : 640 }}>
      <div style={{ padding: "9px 12px",
                       borderBottom: "1px solid var(--nx-bd-quiet)",
                       background: "var(--nx-surf-inset)" }}>
        <div style={{ fontFamily: "var(--nx-font-display)", fontWeight: 700,
                         fontSize: 12.5, color: "var(--nx-text)",
                         letterSpacing: "-0.005em" }}>
          Attack narrative
        </div>
        <div style={{ fontFamily: "var(--nx-font-mono)", fontSize: 9.5,
                         color: "var(--nx-faint)", letterSpacing: 0.4,
                         marginTop: 2 }}>
          {narrative.length} ORDERED OBSERVATION{narrative.length === 1 ? "" : "S"}
          {" · "}SOURCE: CANONICAL EVIDENCE
        </div>
      </div>
      <div style={{ overflowY: "auto", padding: "6px 0" }}>
        {narrative.length === 0 && (
          <div className="nx-ep nx-ep--none"
                style={{ margin: 10 }}
                data-testid="xdr-ag-narrative-empty">
            ◇ NO ORDERED EVIDENCE
            <div style={{ fontFamily: "var(--nx-font-body)", fontWeight: 400,
                             textTransform: "none", letterSpacing: 0,
                             marginTop: 4, color: "var(--nx-muted)" }}>
              No relationship in this incident carries an ordering fact,
              so NivXRay will not assert a sequence.
            </div>
          </div>
        )}
        {narrative.map((tl) => {
          const key = `${tl.src}|${tl.rel}|${tl.dst}`;
          const edge = visibleEdges.find(
            e => `${e.src}|${e.rel}|${e.dst}` === key);
          const cls  = edge ? relClass(edge) : "POSSIBLE";
          const tone = REL_TONE[cls] || REL_TONE.POSSIBLE;
          const active = edge && selId === edge.id;
          return (
            <button key={key + tl._i}
                     onClick={() => { if (edge) { setSelId(edge.id); setSelKind("edge"); } }}
                     data-testid={`xdr-ag-narrative-step-${tl._i}`}
                     data-narrative-class={cls}
                     style={{
                       display: "block", width: "100%", textAlign: "left",
                       background: active ? "var(--nx-surf-selected)" : "transparent",
                       border: "none",
                       borderLeft: `2px solid ${active ? "var(--nx-focus)" : tone.stroke}`,
                       padding: "8px 12px 9px 14px",
                       cursor: edge ? "pointer" : "default",
                       transition: "background-color 150ms cubic-bezier(0.4,0,0.2,1)",
                     }}>
              <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
                <span style={{ fontFamily: "var(--nx-font-mono)", fontSize: 9.5,
                                  color: "var(--nx-muted)" }}>
                  {String(tl.at || "").replace("T", " ").slice(0, 19) || "NO TIMESTAMP"}
                </span>
                <span style={{ fontFamily: "var(--nx-font-mono)", fontSize: 8.5,
                                  fontWeight: 700, letterSpacing: 0.5,
                                  color: tone.stroke, marginLeft: "auto" }}>
                  {tone.label}
                </span>
              </div>
              <div style={{ fontFamily: "var(--nx-font-body)", fontSize: 11.5,
                               color: "var(--nx-text)", fontWeight: 600,
                               marginTop: 3, lineHeight: 1.35 }}>
                {railLabel(tl.src)}
                <span style={{ color: "var(--nx-muted)", fontWeight: 500 }}>
                  {" "}{String(tl.rel || "").toLowerCase().replace(/_/g, " ")}{" "}
                </span>
                {railLabel(tl.dst)}
              </div>
              {tl.reason && (
                <div style={{ fontFamily: "var(--nx-font-body)", fontSize: 10.5,
                                 color: "var(--nx-muted)", marginTop: 3,
                                 lineHeight: 1.45 }}>
                  {tl.reason}
                </div>
              )}
            </button>
          );
        })}
      </div>
    </aside>
  );

  const inner = (
    <div data-testid="xdr-record-attack-graph"
          style={{ display: "grid",
                     // Canvas gets the width: the rails are as narrow
                     // as their content allows so the graph can breathe.
                     gridTemplateColumns: popOut
                       ? "260px minmax(0, 1fr) 320px"
                       : "240px minmax(0, 1fr) 300px", gap: 10,
                     alignItems: "start",
                     height: popOut ? "calc(100vh - 40px)" : "auto" }}>
      {rail}
      <div style={{ background: "var(--nx-surf-primary)", border: "1px solid var(--nx-bd-quiet)",
                       borderRadius: 6, overflow: "hidden",
                       display: "flex", flexDirection: "column" }}>
        {/* Round 36 · Sub-tab switcher (MITRE / Process / Activity) */}
        <div style={{ display: "flex", gap: 2, padding: "8px 10px",
                          borderBottom: "1px solid var(--nx-bd-quiet)",
                          background: "var(--nx-surf-canvas)" }}
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
                       border: "1px solid " + (subView === k ? "var(--nx-purple)" : "var(--nx-bd-quiet)"),
                       borderRadius: 3, cursor: "pointer",
                       background: subView === k ? "var(--nx-purple)" : "transparent",
                       color: subView === k ? "var(--nx-on-accent)" : "var(--nx-muted)",
                       fontWeight: subView === k ? 700 : 500,
                       letterSpacing: 0.3,
                       textTransform: "uppercase",
                     }}>
              {label}
            </button>
          ))}
          <div style={{ marginLeft: "auto", color: "var(--nx-faint)",
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
                         borderBottom: "1px solid var(--nx-bd-quiet)", color: "var(--nx-text)",
                         alignItems: "center", flexWrap: "wrap", fontSize: 11 }}>
          <div className="mono">
            <b>{visibleNodes.length}</b>/{graph.counts.nodes} nodes ·
            <b> {visibleEdges.length}</b>/{graph.counts.edges} edges ·
            <b> {graph.counts.stages_observed}</b> obs ·
            <b> {graph.counts.stages_supported}</b> sup ·
            <b> {graph.counts.gaps}</b> gaps
          </div>
          <div style={{ marginLeft: "auto", display: "flex", gap: 4,
                          background: "var(--nx-surf-primary)", padding: 2, borderRadius: 4 }}
                data-testid="xdr-ag-mode-switch">
            {[["chain", "Attack Chain"], ["evidence", "Evidence Graph"], ["full", "Full"]].map(([k, label]) => (
              <button key={k}
                        onClick={() => setMode(k)}
                        style={{ padding: "4px 10px", fontSize: 11,
                                    border: "none", borderRadius: 3,
                                    cursor: "pointer",
                                    background: mode === k ? "var(--nx-purple)" : "transparent",
                                    color: mode === k ? "#fff" : "var(--nx-muted)" }}
                        data-testid={`xdr-ag-mode-${k}`}>
                {label}
              </button>
            ))}
          </div>
        </div>
        {/* Toolbar row 2 · layers + zoom */}
        <div style={{ display: "flex", gap: 12, padding: "6px 10px",
                         borderBottom: "1px solid var(--nx-bd-quiet)", color: "var(--nx-muted)",
                         alignItems: "center", fontSize: 11 }}>
          {Object.keys(layers).map(k => (
            <label key={k} style={{ cursor: "pointer",
                                        color: layers[k] ? "var(--nx-purple-soft)" : "var(--nx-bd-strong)" }}
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
                      style={{ ...btnS, background: showLegend ? "var(--nx-purple)" : "var(--nx-bd-quiet)" }}>
              <HelpCircle size={12} />
              <span style={{ marginLeft: 4, fontSize: 10 }}>Legend</span>
            </button>
            <button onClick={() => setPopOut(true)}
                      title="Pop out full-screen"
                      data-testid="xdr-ag-popout"
                      style={{ ...btnS, background: "var(--nx-purple)", borderColor: "var(--nx-purple-hover)" }}>
              <Maximize size={12} /> <span style={{ marginLeft: 4, fontSize: 10 }}>Pop Out</span>
            </button>
          </div>
        </div>
        {/* Timeline row */}
        {graph.timeline.length > 0 && (
          <div style={{ padding: "6px 10px", borderBottom: "1px solid var(--nx-bd-quiet)",
                          color: "var(--nx-muted)", fontSize: 11, display: "flex",
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
        <div style={{ padding: "6px 10px", borderBottom: "1px solid var(--nx-bd-quiet)",
                        color: "var(--nx-text)", fontSize: 11, display: "flex",
                        alignItems: "center", gap: 8, background: "var(--nx-surf-canvas)" }}
              data-testid="xdr-ag-replay">
          <span style={{ color: "var(--nx-purple-soft)", fontWeight: 700,
                             letterSpacing: 0.6, textTransform: "uppercase",
                             fontSize: 10 }}>
            Path Replay
          </span>
          {replaySteps.length === 0 ? (
            <span style={{ color: "var(--nx-faint)", fontStyle: "italic" }}
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
                             background: replayPlaying ? "var(--nx-purple)" : "var(--nx-bd-quiet)",
                             borderColor: replayPlaying ? "var(--nx-purple-hover)" : "var(--nx-bd-strong)" }}
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
                      style={{ color: "var(--nx-text-dim)" }}>
                {Math.max(0, replayIdx) + (replayIdx < 0 ? 0 : 1)}
                {" / "}
                {replaySteps.length}
              </span>
              {replayCurrent && (
                <span className="mono"
                        data-testid="xdr-ag-replay-current-kind"
                        title={replayCurrent.label}
                        style={{ color: "var(--nx-purple-soft)", fontSize: 10,
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
          <div style={{ padding: "10px 12px", borderBottom: "1px solid var(--nx-bd-quiet)",
                          background: "var(--nx-surf-canvas)", color: "var(--nx-text-dim)",
                          fontSize: 11 }}
                data-testid="xdr-ag-legend">
            <div style={{ display: "grid",
                                  gridTemplateColumns: "auto 1fr",
                                  gap: "6px 12px", marginBottom: 8 }}>
              <LegendSwatch cls="observed"     note="Recorded in canonical evidence — solid, 1px" />
              <LegendSwatch cls="supported"    note="Observed AND corroborated by ≥2 events — solid 2px + ◆" />
              <LegendSwatch cls="inferred"     note="Rule / correlation derived, never observed — dashed + ◇" />
              <LegendSwatch cls="possible"     note="Candidate, not asserted — dotted + ?" />
              <LegendSwatch cls="gap"          note="Stage exists, no evidence either way — broken neutral" />
              <LegendSwatch cls="contradicted" note="Negative evidence exists — struck + ⊘" />
            </div>
            <div style={{ borderTop: "1px solid var(--nx-bd-quiet)",
                                  paddingTop: 8, marginBottom: 8,
                                  color: "var(--nx-faint)", fontSize: 10 }}>
              An arrowhead is drawn ONLY where the backing evidence carries an
              ordering fact (timestamp or parent→child). Every other edge is
              undirected. Membership of the primary path changes emphasis only —
              it never upgrades an edge's class, line or direction.
            </div>
            <div style={{ display: "grid",
                                  gridTemplateColumns: "repeat(2, 1fr)", gap: "4px 16px" }}>
              {EDGE_SEMANTICS.map(([k, desc]) => {
                return (
                  <div key={k}
                            style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
                    <span className="mono"
                                style={{ color: "var(--nx-text-dim)", fontWeight: 600, minWidth: 130 }}>
                      {k.toLowerCase().replace(/_/g, " ")}
                    </span>
                    <span style={{ color: "var(--nx-muted)" }}>{desc}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
        {/* Relationship legend strip — persistent, like every
              benchmarked console.  The GRAMMAR carries the caveat, so
              the caveat stops being a caption nobody reads. */}
        <div style={{ padding: "6px 12px",
                            borderBottom: "1px solid var(--nx-bd-quiet)",
                            background: "var(--nx-surf-inset)",
                            fontSize: 10, letterSpacing: 0.4,
                            display: "flex", alignItems: "center",
                            gap: 14, flexWrap: "wrap" }}
              data-testid="xdr-ag-progression-banner">
          {REL_LEGEND.slice(0, 5).map(([key, mod]) => (
            <span key={key} className="nx-rel-row"
                      style={{ gap: 6 }}
                      data-testid={`xdr-ag-rel-legend-${mod}`}>
              <i className={`nx-rel-swatch nx-rel-swatch--${mod}`} />
              <b>{REL_TONE[key].label}</b>
            </span>
          ))}
          <span style={{ color: "var(--nx-faint)", marginLeft: "auto",
                             fontWeight: 500, textTransform: "none",
                             letterSpacing: 0.3 }}>
            Arrow = ordered evidence only · no edge renders without a citation
          </span>
        </div>
        {/* ── CANVAS · pan / zoom / keyboard navigable ───────────── */}
        <div ref={scrollRef}
              tabIndex={0}
              data-testid="xdr-ag-canvas"
              style={{ overflow: "hidden", position: "relative",
                          outline: "none",
                          background: "var(--nx-graph-bg)",
                          cursor: dragState?.pan ? "grabbing" : "grab",
                          height: popOut ? "calc(100vh - 260px)" : 620 }}
              onKeyDown={(ev) => {
                const step = 60 / zoom;
                if (ev.key === "ArrowLeft")  { setPan(v => ({ ...v, x: v.x + step })); ev.preventDefault(); }
                if (ev.key === "ArrowRight") { setPan(v => ({ ...v, x: v.x - step })); ev.preventDefault(); }
                if (ev.key === "ArrowUp")    { setPan(v => ({ ...v, y: v.y + step })); ev.preventDefault(); }
                if (ev.key === "ArrowDown")  { setPan(v => ({ ...v, y: v.y - step })); ev.preventDefault(); }
                if (ev.key === "+" || ev.key === "=") setZoom(z => Math.min(2.5, z * 1.15));
                if (ev.key === "-")                   setZoom(z => Math.max(0.3, z / 1.15));
                if (ev.key === "0")                   fitToView();
              }}
              onMouseMove={(ev) => {
                if (!dragState) return;
                if (dragState.pan) {
                  const sc = VIEW_W / zoom / (scrollRef.current.getBoundingClientRect().width || 1);
                  setPan({ x: dragState.panX + (ev.clientX - dragState.startX) * sc,
                              y: dragState.panY + (ev.clientY - dragState.startY) * sc });
                } else {
                  const w = toWorld(ev.clientX, ev.clientY);
                  setNodeOverrides(o => ({ ...o,
                    [dragState.nodeId]: { x: w.x - dragState.grabDx,
                                                y: w.y - dragState.grabDy } }));
                }
              }}
              onMouseUp={() => setDragState(null)}
              onMouseLeave={() => setDragState(null)}>
          {/* Navigation cluster · vertical icon rail on the canvas,
                the pattern every benchmarked console uses. */}
          <div style={{ position: "absolute", top: 10, left: 10, zIndex: 3,
                            display: "flex", flexDirection: "column", gap: 4 }}
                data-testid="xdr-ag-nav-cluster">
            <button style={btnS} title="Zoom in (+)" data-testid="xdr-ag-nav-zoom-in"
                     onClick={() => setZoom(z => Math.min(2.5, z * 1.15))}>
              <ZoomIn size={12} />
            </button>
            <button style={btnS} title="Zoom out (−)" data-testid="xdr-ag-nav-zoom-out"
                     onClick={() => setZoom(z => Math.max(0.3, z / 1.15))}>
              <ZoomOut size={12} />
            </button>
            <button style={btnS} title="Fit graph to view (0)" data-testid="xdr-ag-nav-fit"
                     onClick={fitToView}>
              <Maximize2 size={12} />
            </button>
            <button style={btnS} title="Reset camera and node positions"
                     data-testid="xdr-ag-nav-reset"
                     onClick={() => { setZoom(1); setPan({ x: 0, y: 0 });
                                             setNodeOverrides({}); }}>
              <RotateCcw size={12} />
            </button>
          </div>
          <div style={{ position: "absolute", bottom: 8, left: 12, zIndex: 3,
                            fontFamily: "var(--nx-font-mono)", fontSize: 9,
                            color: "var(--nx-faint)", letterSpacing: 0.4,
                            pointerEvents: "none" }}
                data-testid="xdr-ag-nav-hint">
            DRAG TO PAN · ARROWS TO NUDGE · +/− ZOOM · 0 FIT · {Math.round(zoom * 100)}%
          </div>
          <svg width="100%" height="100%"
                viewBox={`${-pan.x} ${-pan.y} ${VIEW_W / zoom} ${VIEW_H / zoom}`}
                preserveAspectRatio="xMinYMin meet"
                data-testid="xdr-ag-svg"
                style={{ display: "block" }}
                onMouseDown={(ev) => {
                  // Empty-canvas drag → pan the camera.
                  if (ev.target === ev.currentTarget
                      || ev.target.getAttribute("data-nx-pan") === "1") {
                    setDragState({ pan: true,
                                       startX: ev.clientX, startY: ev.clientY,
                                       panX: pan.x, panY: pan.y });
                  }
                }}>
              {/* Pan surface — an explicit full-bleed target so a drag
                    anywhere on the empty canvas moves the camera. */}
              <rect data-nx-pan="1"
                     x={-4000} y={-4000} width={9000} height={9000}
                     fill="transparent" />
            {/* One arrowhead, inheriting the edge's own stroke via
                `context-stroke`, so direction can never be drawn in a
                colour that contradicts the relationship class. */}
            <defs>
              <marker id="nx-arrow-rel" viewBox="0 0 10 10"
                              refX="9" refY="5" markerWidth="5.5" markerHeight="5.5"
                              orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill="context-stroke" opacity="0.95" />
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
              const cls  = relClass(e);
              const et   = REL_TONE[cls] || REL_TONE.POSSIBLE;
              const isPrimary = primaryPath.has(e.src) && primaryPath.has(e.dst);
              const isSelected = selId === e.id;
              const isHovered = hoveredEdge === e.id;
              const showLabel = isSelected || isHovered;
              // Anchor on the disc rim, not the old card edge, so an
              // edge never appears to originate from empty space.
              const x1 = s.x + NODE_CX + NODE_R + 2, y1 = s.y + NODE_CY;
              const x2 = d.x + NODE_CX - NODE_R - 3, y2 = d.y + NODE_CY;
              // §3 hard rule: membership of the primary path changes
              // EMPHASIS ONLY (width / opacity).  It can never upgrade
              // an edge's epistemic class, its line style or its
              // direction — that would fabricate causality.
              const stroke = et.stroke;
              const dash = et.dash;
              const opacity = isSelected ? 1 : (isPrimary ? Math.min(1, et.opacity + 0.1) : et.opacity);
              const directed = relDirected(e, cls);
              const markerEnd = directed ? "url(#nx-arrow-rel)" : undefined;
              // Bezier control points — kept flat so the graph reads
              // as a left→right progression rather than swirls.
              const dx = Math.max(24, Math.abs(x2 - x1) * 0.35);
              const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
              return (
                <g key={e.id}
                    onClick={() => { setSelId(e.id); setSelKind("edge"); }}
                    onMouseEnter={() => setHovered(e.id)}
                    onMouseLeave={() => setHovered(null)}
                    style={{ cursor: "pointer", opacity: dimmed ? 0.10 : 1 }}
                    data-testid={`xdr-ag-edge-${e.id}`}
                    data-edge-class={cls}
                    data-edge-directed={directed ? "true" : "false"}
                    data-edge-primary={isPrimary ? "true" : "false"}>
                  <title>
                    {`${e.rel} · ${et.label}`}
                    {`\nbacking: ${(e.evidence_refs || []).length} canonical event(s), `}
                    {`${(e.finding_ids || []).length} finding(s)`}
                    {`\ndirection: ${directed ? "ordered (timestamp / parent→child)" : "undirected — no ordering fact"}`}
                    {e.reason ? `\n${e.reason}` : ""}
                  </title>
                  <path d={`M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`}
                         fill="none"
                         style={{ stroke }}
                         strokeWidth={isSelected ? et.width + 0.8 : isPrimary ? et.width + 0.4 : et.width}
                         strokeDasharray={dash}
                         strokeOpacity={opacity}
                         strokeLinecap="round"
                         markerEnd={markerEnd} />
                  {/* CONTRADICTED · struck through — negative evidence */}
                  {cls === "CONTRADICTED" && (
                    <line x1={mx - 7} y1={my + 6} x2={mx + 7} y2={my - 6}
                           style={{ stroke }} strokeWidth={1.6} />
                  )}
                  {/* Evidence marker · only classes whose grammar
                      defines one, and only when it can cite backing. */}
                  {(cls === "SUPPORTED" || cls === "INFERRED") && (
                    <text x={mx} y={my + 3} fontSize={8.5} textAnchor="middle"
                           style={{ fill: stroke }}
                           data-testid={`xdr-ag-edge-marker-${e.id}`}>
                      {et.marker}
                    </text>
                  )}
                  {showLabel && (
                    <text x={mx} y={my - 6}
                           fontSize={8} fontFamily="ui-monospace, monospace"
                           style={{ fill: stroke }}
                           textAnchor="middle">
                      {`${e.rel.toLowerCase().replace(/_/g, " ")} · ${et.label}`}
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
              const nodeStroke = isSel      ? "var(--nx-medium)"
                                              : isPrim  ? "var(--nx-medium)"
                                              : rt.stroke;
              const borderW    = isSel ? 1.8 : isPrim ? 1.6 : (isAnchor ? 0.8 : 1);
              const findingAnnotations = (n.annotations?.findings) || [];
              const findingCount = findingAnnotations.length;
              const evidenceCount = (n.annotations?.evidence_ids?.length) || 0
                                                    || (n.annotations?.evidence_count) || 0;
              const attckId = n.attrs?.tid;
              const aggregateCount = Number(n.attrs?.count
                                                        || n.annotations?.member_count || 0);
              return (
                <g key={n.id}
                    onClick={(ev) => { ev.stopPropagation();
                                              setSelId(n.id); setSelKind("node"); }}
                    onMouseDown={(ev) => {
                      ev.stopPropagation();
                      const w = toWorld(ev.clientX, ev.clientY);
                      setDragState({ nodeId: n.id,
                                          grabDx: w.x - p.x, grabDy: w.y - p.y });
                    }}
                    style={{ cursor: dragState?.nodeId === n.id ? "grabbing" : "grab",
                                 opacity: isAnchor && !isPrim ? 0.82 : 1 }}
                    filter={isPrim ? "url(#nx-primary-glow)" : undefined}
                    data-testid={`xdr-ag-node-${n.id}`}
                    data-node-role={role}
                    data-node-primary={isPrim ? "true" : "false"}
                    data-node-state={n.state || "NOT_OBSERVED"}>
                  {/* ── EVIDENCE NODE · circular icon disc + label
                        beneath, per the NivXRay visual language.  The
                        disc carries identity (type icon), the ring
                        carries epistemic state, the top-right dot
                        carries disposition, and the badge carries
                        corroboration count.  Nothing on the node is
                        decorative. */}
                  {/* Selection halo — drawn first so it sits behind. */}
                  {isSel && (
                    <circle cx={p.x + NODE_CX} cy={p.y + NODE_CY} r={NODE_R + 6}
                             fill="none" style={{ stroke: "var(--nx-focus)" }}
                             strokeWidth={1} strokeOpacity={0.45} />
                  )}
                  <circle cx={p.x + NODE_CX} cy={p.y + NODE_CY} r={NODE_R}
                           style={{ fill: nodeFill, stroke: isSel ? "var(--nx-focus)" : nodeStroke }}
                           strokeWidth={isSel ? 2 : borderW + 0.4}
                           strokeDasharray={role === "gap" || n.state === "NOT_OBSERVED" ? "3 3" : undefined} />
                  {/* Aggregate nodes get the second ring (Defender /
                        Cisco pattern) so a collapsed set is legible as
                        a set, not mistaken for one entity. */}
                  {aggregateCount > 1 && (
                    <circle cx={p.x + NODE_CX} cy={p.y + NODE_CY} r={NODE_R - 3.5}
                             fill="none" style={{ stroke: rt.accent }}
                             strokeWidth={0.7} strokeOpacity={0.55} />
                  )}
                  {/* Type token inside the disc. */}
                  <text x={p.x + NODE_CX} y={p.y + NODE_CY + 3.5}
                         fontSize={9} fontFamily="var(--nx-font-mono)"
                         fontWeight={700} letterSpacing={0.6}
                         style={{ fill: rt.accent }} textAnchor="middle">
                    {glyph}
                  </text>
                  {/* Disposition dot · top-right of the disc. */}
                  <circle cx={p.x + NODE_CX + 15} cy={p.y + NODE_CY - 15} r={4}
                           style={{ fill: dispositionColor(n),
                                       stroke: "var(--nx-surf-canvas)" }}
                           strokeWidth={1.4}
                           data-testid={`xdr-ag-node-disposition-${n.id}`}>
                    <title>{`disposition: ${dispositionLabel(n)}`}</title>
                  </circle>
                  {/* Primary label · BENEATH the disc, centred and
                        truncated — the analyst reads the shape first,
                        then the name. */}
                  <text x={p.x + NODE_CX} y={p.y + NODE_CY + NODE_R + 13}
                         fontSize={10.5} fontFamily="var(--nx-font-body)"
                         style={{ fill: rt.label, fontWeight: 600 }}
                         textAnchor="middle">
                    <title>{n.label}</title>
                    {nodeLabel(n)}
                  </text>
                  {/* Epistemic state line · locked vocabulary. */}
                  <text x={p.x + NODE_CX} y={p.y + NODE_CY + NODE_R + 25}
                         fontSize={8.5} fontFamily="var(--nx-font-mono)"
                         letterSpacing={0.5}
                         style={{ fill: "var(--nx-muted)" }} textAnchor="middle">
                    {state.label} {(n.state || "UNKNOWN").replace(/_/g, " ")}
                    {evidenceCount > 0
                      ? ` · ev ${evidenceCount > 99 ? "99+" : evidenceCount}` : ""}
                  </text>
                  {attckId && role === "mitre" && (
                    <text x={p.x + NODE_CX} y={p.y + NODE_CY + NODE_R + 36}
                            fontSize={8.5} fontFamily="var(--nx-font-mono)"
                            fontWeight={700} letterSpacing={0.4}
                            style={{ fill: ROLE_TONE.mitre.accent }}
                            textAnchor="middle">
                      {attckId}
                    </text>
                  )}
                  {role === "gap" && (
                    <text x={p.x + NODE_CX} y={p.y + NODE_CY + NODE_R + 36}
                            fontSize={8} fontFamily="var(--nx-font-mono)"
                            fontWeight={700} letterSpacing={0.6}
                            style={{ fill: "var(--nx-rel-gap)" }}
                            textAnchor="middle"
                            data-testid={`xdr-ag-gap-pill-${n.id}`}>
                      GAP · NO EVIDENCE EITHER WAY
                    </text>
                  )}
                  {isReplayCurrent && (
                    <circle cx={p.x + NODE_CX} cy={p.y + NODE_CY} r={NODE_R + 9}
                            fill="none"
                            style={{ stroke: "var(--nx-purple)" }}
                            strokeWidth={1.6}
                            strokeDasharray="4 3"
                            data-testid={`xdr-ag-replay-focus-${n.id}`}>
                      <animate attributeName="stroke-opacity"
                                    values="0.35;1;0.35" dur="1.4s"
                                    repeatCount="indefinite" />
                    </circle>
                  )}
                  {/* Corroboration / finding count badge · bottom-left
                        of the disc (Cortex pattern). */}
                  {findingCount > 0 && (
                    <g data-testid={`xdr-ag-finding-badge-${n.id}`}>
                      <title>
                        {findingCount} finding(s) anchored on this entity:
                        {findingAnnotations.slice(0, 5)
                                              .map(f => `\n• [${f.state}] ${f.capability || ""} · ${f.summary || f.finding_id || ""}`)
                                              .join("")}
                      </title>
                      <circle cx={p.x + NODE_CX - 15} cy={p.y + NODE_CY - 15} r={7}
                                style={{ fill: "var(--nx-surf-canvas)",
                                            stroke: "var(--nx-high)" }} strokeWidth={1} />
                      <text x={p.x + NODE_CX - 15} y={p.y + NODE_CY - 12}
                              fontSize={8} fontFamily="var(--nx-font-mono)"
                              style={{ fill: "var(--nx-high)", fontWeight: 700 }}
                              textAnchor="middle">
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
                        style={{ fill: "var(--nx-surf-canvas)",
                                    stroke: "var(--nx-bd-strong)" }}
                        strokeDasharray="4 4" />
                <text x={40} y={44}
                        fontSize={12} fontFamily="ui-monospace, monospace"
                        style={{ fill: "var(--nx-medium)" }} fontWeight={700} letterSpacing={0.6}>
                  NO EVIDENCE-BACKED ATTACK CHAIN
                </text>
                <text x={40} y={68}
                        fontSize={10} fontFamily="ui-sans-serif"
                        style={{ fill: "var(--nx-muted)" }}>
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
              // Anchor on the disc rim, not the old card edge, so an
              // edge never appears to originate from empty space.
              const x1 = s.x + NODE_CX + NODE_R + 2, y1 = s.y + NODE_CY;
              const x2 = d.x + NODE_CX - NODE_R - 3, y2 = d.y + NODE_CY;
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
        {/* ── COVERAGE DIAGNOSTICS · progressive disclosure ────────
              Diagnostics describe the QUALITY of the projection, not
              the incident, so they must never lead the view.  The two
              figures an analyst actually triages on stay visible; the
              rest live one click away. */}
        <div className="nx-drawer" data-testid="xdr-ag-metrics">
          <button className="nx-drawer__toggle"
                   onClick={() => setShowDiag(v => !v)}
                   data-testid="xdr-ag-metrics-toggle"
                   aria-expanded={showDiag ? "true" : "false"}>
            <span>{showDiag ? "▾" : "▸"} Coverage diagnostics</span>
            <span style={{ marginLeft: "auto", display: "flex", gap: 16,
                               textTransform: "none", letterSpacing: 0 }}>
              <span style={{ color: "var(--nx-muted)", fontWeight: 500 }}>
                evidence{" "}
                <b style={{ color: "var(--nx-ep-present)",
                                fontFamily: "var(--nx-font-mono)" }}>
                  {graph.metrics?.evidence_coverage ?? 0}%
                </b>
              </span>
              <span style={{ color: "var(--nx-muted)", fontWeight: 500 }}>
                telemetry{" "}
                <b style={{ color: "var(--nx-info)",
                                fontFamily: "var(--nx-font-mono)" }}>
                  {graph.metrics?.telemetry_coverage ?? 0}%
                </b>
              </span>
            </span>
          </button>
          {showDiag && (
            <div className="nx-drawer__body">
              {Object.entries(graph.metrics).map(([k, v]) => (
                <div className="nx-metric" key={k}
                      data-testid={`xdr-ag-metric-${k}`}>
                  <span className="nx-metric__k">{k.replace(/_/g, " ")}</span>
                  <span className="nx-metric__v"
                          style={{ color: Number(v) === 0
                            ? "var(--nx-faint)" : "var(--nx-text)" }}>
                    {v}%
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
        </div>)}
      </div>
      {/* Evidence Inspector · Round 38.3 shared component (owner rule §11) */}
      <div style={{ background: "var(--nx-surf-primary)", border: "1px solid var(--nx-bd-quiet)",
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
                             borderBottom: "1px solid var(--nx-bd-quiet)",
                             background: "var(--nx-surf-primary)",
                             display: "flex", alignItems: "center",
                             gap: 8, fontSize: 11, color: "var(--nx-text-dim)" }}
                  data-testid="xdr-ag-deeplink-bar">
              <button
                data-testid="xdr-ag-deeplink-back"
                onClick={() => setDeepLink(null)}
                style={{ ...btnS, background: "var(--nx-surf-primary)" }}
                title="Return to the edge inspector">
                ← Back
              </button>
              <span style={{ color: "var(--nx-purple-soft)", fontWeight: 700,
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
                                        onAction={runInspectorAction}
                                        kind={deepLink.kind}
                                        refId={deepLink.refId} />
          </div>
        ) : (!selected || selKind === "node") && (
          <EvidenceInspector incidentId={incident?.id}
                                       embedded
                                       onAction={runInspectorAction}
                                       {...(selected && selKind === "node"
                                             ? nodeToInspectorArgs(selected)
                                             : { kind: null, refId: null })} />
        )}
        {!deepLink && selected && selKind === "edge" && (
          <div style={{ padding: 12, color: "var(--nx-text)" }}>
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
                               background: "var(--nx-surf-primary)",
                               border: "1px solid var(--nx-bd-strong)",
                               color: "var(--nx-purple-soft)",
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
                               background: "var(--nx-surf-primary)",
                               border: "1px solid var(--nx-bd-strong)",
                               color: "var(--nx-medium-bd)",
                               padding: "3px 8px", borderRadius: 3,
                               fontSize: 10, cursor: "pointer",
                             }}>
                      {r}
                    </button>
                  ))}
                </div>
              </div>
            )}
            <div style={{ marginTop: 10, borderTop: "1px solid var(--nx-bd-quiet)",
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
                          marginBottom: 10, color: "var(--nx-text)" }}>
          <div style={{ fontWeight: 600, fontSize: 14 }}>
            NivXRay · Attack Graph · Full Investigation Canvas
          </div>
          <button onClick={() => setPopOut(false)}
                    data-testid="xdr-ag-popout-close"
                    style={{ marginLeft: "auto", ...btnS,
                                background: "var(--nx-purple)", borderColor: "var(--nx-purple-hover)" }}>
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
  background: "var(--nx-surf-raised)", color: "var(--nx-text)",
  border: "1px solid var(--nx-bd-strong)",
  borderRadius: 3, padding: "4px 6px", cursor: "pointer",
  display: "inline-flex", alignItems: "center",
};


// Compact swatch for the RELATIONSHIP GRAMMAR legend — visualises the
// line weight, dash pattern, marker and arrowhead licence so the
// analyst learns the shape rather than memorising a label.
function LegendSwatch({ cls, note }) {
  const key  = String(cls).toUpperCase();
  const tone = REL_TONE[key] || REL_TONE.POSSIBLE;
  const directed = key === "OBSERVED" || key === "SUPPORTED";
  return (
    <>
      <span data-testid={`xdr-ag-legend-swatch-${cls}`}
                style={{ display: "inline-flex", alignItems: "center",
                            gap: 6 }}>
        <svg width={64} height={14}>
          <defs>
            <marker id={`nx-legend-arrow-${cls}`} viewBox="0 0 10 10"
                            refX="9" refY="5" markerWidth="6" markerHeight="6"
                            orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" fill="context-stroke" />
            </marker>
          </defs>
          <line x1="2" y1="7" x2="56" y2="7"
                     style={{ stroke: tone.stroke }}
                     strokeWidth={tone.width}
                     strokeDasharray={tone.dash}
                     strokeOpacity={tone.opacity}
                     strokeLinecap="round"
                     markerEnd={directed
                       ? `url(#nx-legend-arrow-${cls})` : undefined} />
          {key === "CONTRADICTED" && (
            <line x1="23" y1="12" x2="35" y2="2"
                       style={{ stroke: tone.stroke }} strokeWidth={1.4} />
          )}
          {(key === "SUPPORTED" || key === "INFERRED") && (
            <text x={29} y={5.5} fontSize={8} textAnchor="middle"
                       style={{ fill: tone.stroke }}>{tone.marker}</text>
          )}
        </svg>
        <span className="mono"
                    style={{ color: tone.stroke, fontWeight: 700,
                                letterSpacing: 0.4, minWidth: 110,
                                textTransform: "uppercase" }}>
          {tone.label}
        </span>
      </span>
      <span style={{ color: "var(--nx-muted)" }}>{note}</span>
    </>
  );
}
