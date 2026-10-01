/*
 * IRGWorkspace — Investigation Relationship Graph tab.
 *
 * Layout mirrors DeviceTrajectoryV2 (two aligned cards):
 *   • TOP     · CardToolbar (shared) + TimeRangeBox (shared)
 *   • BOTTOM  · Attack Chain (left) | IRGGraphCanvas (center) | Evidence (right)
 *
 * All three panels bind to the same viewport / selected-event state so the
 * IRG tab and Device Trajectory tab share the same investigation surface.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import api from "@/lib/api";
import Header from "@/components/Header";
import { T } from "../theme";
import IRGGraphCanvas from "../canvas_engine/IRGGraphCanvas";
import {
  CardToolbar, TimeRangeBox, AttackChainSidebar, EvidencePane, StatusBar,
} from "./DeviceTrajectoryV2";

export default function IRGWorkspace() {
  const { caseId = "case_dfir_bumblebee_akira_2026" } = useParams() || {};
  const [graph,    setGraph]    = useState({ nodes: [], edges: [] });
  const [traj,     setTraj]     = useState(null);
  const [err,      setErr]      = useState(null);
  const [selected, setSelected] = useState(null);   // iid of a node
  const [selectedEventId, setSelectedEventId] = useState(null);
  const [selectedStageIdx, setSelectedStageIdx] = useState(null);
  const [rightTab, setRightTab] = useState("evidence");
  const [viewport, setViewport] = useState(null);
  const [reportedVp, setReportedVp] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");

  // Fetch both IRG + trajectory (trajectory is needed for stages + evidence).
  useEffect(() => {
    (async () => {
      try {
        const [g, t] = await Promise.all([
          api.get(`/v2/cases/${encodeURIComponent(caseId)}/irg?limit=1000`),
          api.get(`/v2/cases/${encodeURIComponent(caseId)}/trajectory/device?limit=1000`),
        ]);
        setGraph({ nodes: g.data.nodes || [], edges: g.data.edges || [] });
        setTraj(t.data);
      } catch (e) {
        setErr(e?.response?.data?.detail || e.message);
      }
    })();
  }, [caseId]);

  // Rows + events + stages from trajectory (reused by Attack Chain + Evidence).
  const frames = useMemo(() => traj?.frames || [], [traj]);
  const events = useMemo(() => framesToEvents(frames), [frames]);
  const stages = useMemo(() => framesToStages(frames), [frames]);

  // Map of entity IID → friendly name, so the Evidence pane can resolve
  // parent.iid to a human-readable process/file/registry name.
  const nameByIid = useMemo(() => {
    const m = {};
    for (const f of frames) {
      const e = f.entity;
      if (e?.iid && e?.name) m[e.iid] = e.name;
    }
    return m;
  }, [frames]);

  const caseBounds = useMemo(() => {
    let lo = Infinity, hi = -Infinity;
    for (const n of graph.nodes) {
      const a = tsMs(n.first_seen), b = tsMs(n.last_seen);
      if (a != null && a < lo) lo = a;
      if (b != null && b > hi) hi = b;
    }
    if (!Number.isFinite(lo)) return { start: 0, end: 1 };
    if (lo === hi) hi = lo + 1;
    return { start: lo, end: hi };
  }, [graph]);

  const selEvent = useMemo(
    () => events.find(e => e.id === selectedEventId) || null,
    [events, selectedEventId],
  );

  const handleStageSelect = useCallback((idx) => {
    if (idx === selectedStageIdx) { setSelectedStageIdx(null); setViewport(null); return; }
    setSelectedStageIdx(idx);
    const s = stages[idx];
    if (!s) return;
    const pad = Math.max(1, (s.lastTs - s.firstTs) * 0.10);
    setViewport({ start: s.firstTs - pad, end: s.lastTs + pad });
  }, [selectedStageIdx, stages]);

  const handleRangeChange = useCallback((range) => {
    if (range === "all") { setViewport(null); return; }
    const ms = { "24h": 24*3600e3, "7d": 7*24*3600e3, "30d": 30*24*3600e3, "90d": 90*24*3600e3 }[range];
    if (!ms) return;
    setViewport({ start: caseBounds.end - ms, end: caseBounds.end });
  }, [caseBounds]);

  // When a node is clicked, also select the first event on that entity.
  const handleNodeSelect = useCallback((node) => {
    setSelected(node.iid);
    const ev = events.find(e => e.meta?.entity?.iid === node.iid);
    if (ev) setSelectedEventId(ev.id);
    else    setSelectedEventId(null);
  }, [events]);

  // Keyboard shortcuts — mirror Device Trajectory.
  useEffect(() => {
    const handler = (e) => {
      if (e.target && /INPUT|TEXTAREA/.test(e.target.tagName)) return;
      if (e.key === "Escape") { setSelected(null); setSelectedEventId(null); setSelectedStageIdx(null); setViewport(null); return; }
      if (e.key.toLowerCase() === "f") { setViewport(null); return; }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  const cardStyle = {
    background: T.cardGradient,
    border: `1px solid ${T.line}`,
    borderRadius: 12,
    boxShadow: "inset 0 1px 0 rgba(255,255,255,0.04), 0 8px 32px -8px rgba(0,0,0,0.65)",
    backdropFilter: "blur(14px)",
    WebkitBackdropFilter: "blur(14px)",
    overflow: "hidden",
  };
  const caseMeta = traj?.case || {};
  const compromiseCount = stages.filter(s => s.malicious).length;
  const rows = [];

  // ── Search-driven filtering (matches Device Trajectory behaviour) ──
  const q = (searchQuery || "").trim().toLowerCase();
  const matchedIids = useMemo(() => {
    if (!q) return null;
    const out = new Set();
    for (const n of graph.nodes) {
      const hay = `${n.name || ""} ${n.iid || ""} ${n.type || ""}`.toLowerCase();
      if (hay.includes(q)) out.add(n.iid);
    }
    return out;
  }, [q, graph.nodes]);

  // When a query is active, keep only nodes that either match directly
  // OR are connected (source/target) to a matched node, so the analyst
  // sees the neighbourhood of the search hit, not an empty canvas.
  const { visibleNodes, visibleEdges } = useMemo(() => {
    if (!matchedIids || matchedIids.size === 0) {
      return { visibleNodes: graph.nodes, visibleEdges: graph.edges };
    }
    const keep = new Set(matchedIids);
    for (const e of graph.edges) {
      if (matchedIids.has(e.source) || matchedIids.has(e.target)) {
        keep.add(e.source); keep.add(e.target);
      }
    }
    const nodes = graph.nodes.filter(n => keep.has(n.iid));
    const edges = graph.edges.filter(e => keep.has(e.source) && keep.has(e.target));
    return { visibleNodes: nodes, visibleEdges: edges };
  }, [graph, matchedIids]);

  const visibleStages = useMemo(() => {
    if (!matchedIids || matchedIids.size === 0) return stages;
    return stages.filter(s =>
      (s.frames || []).some(f =>
        matchedIids.has(f.entity?.iid) || matchedIids.has(f.parent?.iid),
      ),
    );
  }, [stages, matchedIids]);

  // Auto-select first matched entity so the Evidence pane populates.
  useEffect(() => {
    if (!matchedIids || matchedIids.size === 0) return;
    if (selected && matchedIids.has(selected)) return;
    const first = [...matchedIids][0];
    setSelected(first);
    const ev = events.find(e => e.meta?.entity?.iid === first);
    if (ev) setSelectedEventId(ev.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [matchedIids]);

  return (
    <div className="flex flex-col"
         style={{ minHeight: "100vh", background: T.bg, color: T.ink }}>
      <Header />
    <div data-testid="irg-workspace"
         className="w-full overflow-hidden flex flex-col p-3 gap-3"
         style={{ flex: "1 1 0", minHeight: 0, height: "calc(100vh - 56px)", background: T.bg, color: T.ink }}>
      {/* Top card · toolbar + time range */}
      <div className="flex-shrink-0 flex flex-col" style={cardStyle}>
        <CardToolbar caseId={caseId} meta={caseMeta}
                     activeTab="irg"
                     onRangeChange={handleRangeChange}
                     reportedVp={reportedVp}
                     caseBounds={caseBounds}
                     searchQuery={searchQuery}
                     onSearch={setSearchQuery} />
        <TimeRangeBox stages={stages}
                      selectedStageIdx={selectedStageIdx}
                      onSelectStage={handleStageSelect}
                      caseBounds={caseBounds}
                      reportedVp={reportedVp}
                      setViewport={setViewport} />
      </div>

      {/* Bottom card · attack chain · IRG graph · evidence */}
      <div className="flex-1 min-h-0 flex flex-col" style={cardStyle}>
        <div className="grid flex-1 min-h-0"
             style={{ gridTemplateColumns: "232px 1fr 340px" }}>
          <AttackChainSidebar stages={visibleStages}
                              selectedIdx={selectedStageIdx}
                              onSelect={handleStageSelect} />
          <div className="relative flex flex-col min-h-0"
               style={{ background: T.paper,
                        borderLeft: `1px solid ${T.line}`,
                        borderRight: `1px solid ${T.line}` }}>
            <div className="px-4 py-2 text-[10px] tracking-[2px] font-bold flex-shrink-0"
                 style={{ color: T.inkMute, borderBottom: `1px solid ${T.line}` }}>
              IRG · {visibleNodes.length} ENTITIES · {visibleEdges.length} RELATIONSHIPS
              {matchedIids && matchedIids.size > 0 && (
                <span className="ml-2" style={{ color: T.amber }}>
                  · filtered by &quot;{searchQuery}&quot;
                </span>
              )}
            </div>
            <div className="relative flex-1 min-h-0">
              {err && <Banner err={err} />}
              {!err && !graph.nodes.length && <Banner msg="Loading investigation relationship graph…" />}
              {!err && graph.nodes.length > 0 && visibleNodes.length === 0 && (
                <Banner msg={`No entities match "${searchQuery}". Clear the search to see the full graph.`} />
              )}
              {!err && visibleNodes.length > 0 && (
                <IRGGraphCanvas nodes={visibleNodes} edges={visibleEdges}
                                selected={selected}
                                focusRange={viewport}
                                onViewportChange={setReportedVp}
                                onSelect={handleNodeSelect} />
              )}
            </div>
          </div>
          <EvidencePane event={selEvent} tab={rightTab} onTab={setRightTab}
                        nameByIid={nameByIid}
                        onFocusParent={(pIid) => {
                          setSelected(pIid);
                          const ev = events.find(e => e.meta?.entity?.iid === pIid);
                          if (ev) setSelectedEventId(ev.id);
                        }} />
        </div>
        <StatusBar rows={rows} events={events}
                   selectedStageIdx={selectedStageIdx}
                   compromiseCount={compromiseCount} />
      </div>
    </div>
    </div>
  );
}

function Banner({ err, msg }) {
  return (
    <div className="absolute inset-0 flex items-center justify-center"
         style={{ color: T.inkMute, fontSize: 12 }}
         data-testid="irg-banner">
      {err ? `Failed to load IRG: ${err}` : (msg || "…")}
    </div>
  );
}

function tsMs(ts) {
  if (ts == null) return null;
  if (typeof ts === "number") return ts > 1e12 ? ts : ts * 1000;
  const s = String(ts).endsWith("Z") ? ts : ts + "Z";
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

// Minimal projections from trajectory frames — same shape the shared
// EvidencePane / AttackChainSidebar / TimeRangeBox already expect.
function friendlyLabel(f) {
  const raw = String(f.label || "").trim();
  const action = String(f.action || "").trim();
  if (raw) {
    const parts = raw.split(/\s+·\s+/);
    if (parts.length === 3 && parts[0] === parts[2]) {
      return `${parts[0]} · ${parts[1]}`;
    }
    return raw;
  }
  const ent = f.entity?.name || "event";
  return action ? `${ent} · ${action}` : ent;
}
function framesToEvents(frames) {
  return frames.map((f, i) => ({
    id:      f.frame_iid || f.event?.iid || `f${i}`,
    ts:      tsMs(f.ts) || 0,
    rowKey:  (f.entity?.iid || f.parent?.iid || "unknown"),
    kind:    f.lane || "process",
    verdict: f.verdict || "benign",
    label:   friendlyLabel(f),
    mitre:   f.mitre || [],
    meta:    f,
  }));
}
function framesToStages(frames) {
  const by = new Map();
  for (const f of frames) {
    for (const m of (f.mitre || [])) {
      const tactic = tacticOf(m) || "OTHER";
      const s = by.get(tactic) || { tactic, first: null, last: null, malicious: false, count: 0, techniques: new Set(), frames: [] };
      const t = tsMs(f.ts);
      if (t != null) {
        s.first = s.first == null ? t : Math.min(s.first, t);
        s.last  = s.last  == null ? t : Math.max(s.last,  t);
      }
      s.count++;
      s.techniques.add(m);
      s.frames.push(f);
      if ((f.verdict || "") === "malicious") s.malicious = true;
      by.set(tactic, s);
    }
  }
  const arr = [...by.values()];
  arr.sort((a, b) => (a.first || 0) - (b.first || 0));
  return arr.map((s, i) => ({
    index:      i + 1,
    tactic:     s.tactic,
    firstTs:    s.first || 0,
    lastTs:     s.last  || 0,
    malicious:  s.malicious,
    count:      s.count,
    techniques: [...s.techniques],
    frames:     s.frames,
  }));
}
function tacticOf(t) {
  const m = String(t || "").match(/^T(\d+)/);
  const id = m ? parseInt(m[1], 10) : 0;
  if (id === 1059 || id === 1218) return "EXECUTION";
  if (id === 1087 || id === 1082) return "DISCOVERY";
  if (id === 1003)                return "CREDENTIAL ACCESS";
  if (id === 1218 || id === 1027) return "DEFENSE EVASION";
  if (id === 1486 || id === 1490) return "IMPACT";
  return "OTHER";
}
