/**
 * EvidenceFirstInvestigationWorkspace
 *
 * The Investigation Canvas is a real, evidence-backed graph — NOT a
 * decorative sketch.  Nodes are minted only from data that already
 * exists on the canonical incident payload:
 *
 *   • incident.assets.hosts / .users           → host / identity nodes
 *   • incident.iocs.{hash, ip, domain, url}    → indicator nodes
 *   • incident.verdict_stage2.evidence[]       → evidence nodes
 *   • incident.evidence[].rule_id/technique_id → MITRE relations
 *   • Response Engine executions (from Base
 *     `/api/xdr/response-evidence`)            → response nodes
 *
 * If the base payload does not carry a value we render nothing
 * (never a "phantom" node) and surface an explicit
 * `no_matching_evidence` badge so the analyst knows this is an
 * evidence gap, not a rendering quirk.
 *
 * Owner-locked:
 *   – No fake relationships.  Edges only exist when there is a
 *     concrete referent (same host, same user, same IOC value,
 *     rule → technique from the authoritative RULE_TO_TECHNIQUE
 *     table).
 *   – Response actions must appear IN the investigation, not as
 *     an isolated SOAR blob.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Search, Zap, Cpu, Server, User, Globe, FileDigit, Hash,
  ShieldAlert, GitBranch, X, Copy, ExternalLink, ChevronRight,
  Filter, Maximize2, RotateCcw, Map as MapIcon, Layers, Clock,
  Boxes, MinusSquare, PlusSquare, ListTree,
} from "lucide-react";

import { RULE_TO_TECHNIQUE, TECHNIQUE_INDEX } from "@/xdr/mitre/mitreTactics";
import api from "@/lib/api";
import { XdrIocEnrichmentPanel, XdrProcessCausalityPanel,
  XdrBehaviorRegistryPanel, fetchCorrelationEdges } from "@/xdr/adopt/consumerPanels";

// ── Node type palette (single restrained accent per kind) ─────────
const NODE_TYPE = {
  incident:  { color: "#f87171", icon: ShieldAlert, label: "INCIDENT",  shape: "hex" },
  host:      { color: "#38bdf8", icon: Server,      label: "HOST",      shape: "square" },
  user:      { color: "#c084fc", icon: User,        label: "IDENTITY",  shape: "circle" },
  process:   { color: "#a78bfa", icon: Cpu,         label: "PROCESS",   shape: "circle" },
  file:      { color: "#e5e7eb", icon: FileDigit,   label: "FILE",      shape: "diamond" },
  ip:        { color: "#22d3ee", icon: Globe,       label: "IP",        shape: "diamond" },
  domain:    { color: "#22d3ee", icon: Globe,       label: "DOMAIN",    shape: "diamond" },
  hash:      { color: "#facc15", icon: Hash,        label: "HASH",      shape: "diamond" },
  url:       { color: "#22d3ee", icon: Globe,       label: "URL",       shape: "diamond" },
  evidence:  { color: "#fbbf24", icon: FileDigit,   label: "EVIDENCE",  shape: "circle" },
  technique: { color: "#f472b6", icon: GitBranch,   label: "MITRE",     shape: "hex" },
  verdict:   { color: "#f87171", icon: ShieldAlert, label: "VERDICT",   shape: "hex" },
  response:  { color: "#34d399", icon: Zap,         label: "RESPONSE",  shape: "square" },
  cluster:   { color: "#7c8494", icon: Boxes,       label: "CLUSTER",   shape: "square" },
};

const EDGE_KIND = {
  // Semantic edge taxonomy — every edge on the canvas must be one of
  // these.  Never a generic "connected".  If the incident payload does
  // not support a semantic relationship, we do NOT draw an edge.
  parent_of:    { color: "#c084fc", dashed: false, label: "parent_of",    weight: 1.6 },
  created:      { color: "#facc15", dashed: false, label: "created",      weight: 1.4 },
  executed:     { color: "#a78bfa", dashed: false, label: "executed",     weight: 1.4 },
  connected_to: { color: "#22d3ee", dashed: false, label: "connected_to", weight: 1.2 },
  resolved_to:  { color: "#22d3ee", dashed: true,  label: "resolved_to",  weight: 1.0 },
  mapped_to:    { color: "#f472b6", dashed: true,  label: "mapped_to",    weight: 1.0 },
  responded:    { color: "#34d399", dashed: false, label: "responded",    weight: 1.6 },
  produced:     { color: "#34d399", dashed: true,  label: "produced",     weight: 1.2 },
  // legacy fallbacks (kept for older callers)
  observed:     { color: "rgba(160,160,180,.55)", dashed: false, label: "observed" },
  derived:      { color: "rgba(160,160,180,.32)", dashed: true,  label: "derived"  },
};


// Filter chips — chosen kinds narrow both the canvas and the timeline
// via the same predicate.  "all" means no filter.
const FILTERS = [
  { key: "all",      label: "All",       types: null },
  { key: "evidence", label: "Evidence",  types: ["evidence"] },
  { key: "process",  label: "Process",   types: ["process", "host", "cluster"] },
  { key: "network",  label: "Network",   types: ["ip", "domain", "url"] },
  { key: "identity", label: "Identity",  types: ["user"] },
  { key: "mitre",    label: "MITRE",     types: ["technique"] },
  { key: "response", label: "Response",  types: ["response"] },
];


export default function EvidenceFirstInvestigationWorkspace({ incident }) {
  // Base-backend backfill of response executions.  We fetch by
  // incident_id so response nodes appear on the canvas even when the
  // incident payload does not embed them.  If the endpoint isn't
  // available (older base) we silently fall back to
  // ``incident.response_executions`` — the graph builder tolerates
  // an empty array.
  const [responseExecutions, setRespExec] = useState(null);
  const [corrEdges, setCorrEdges] = useState([]);   // authoritative causality
  useEffect(() => {
    let cancelled = false;
    if (!incident?.id) return;
    (async () => {
      try {
        const r = await api.get(
          `/api/xdr/incidents/${encodeURIComponent(incident.id)}/response-executions`,
          { params: incident.tenant_id ? { tenant_id: incident.tenant_id } : {} });
        if (!cancelled) setRespExec(r.data?.executions || []);
      } catch {
        if (!cancelled) setRespExec(null);
      }
      // Correlation consumer — layout XDR-owned, causality NivXRay-owned.
      try {
        const cr = await fetchCorrelationEdges(incident.id);
        if (!cancelled && cr.ok) setCorrEdges(cr.edges || []);
      } catch { /* stay silent — canvas legend shows nothing invented */ }
    })();
    return () => { cancelled = true; };
  }, [incident?.id, incident?.tenant_id]);

  // Enrich the incident with the fetched executions so buildGraph
  // sees them in a single place.  Prefer server-authoritative data
  // over any embedded payload copies.
  const enrichedIncident = useMemo(() => {
    if (!incident) return incident;
    if (responseExecutions == null) return incident;
    return { ...incident, response_executions: responseExecutions };
  }, [incident, responseExecutions]);

  // 1 · Build the graph deterministically from the incident payload.
  const raw = useMemo(() => buildGraph(enrichedIncident),
                                [enrichedIncident]);

  // Cluster expansion state — expanded clusters re-inject their
  // hidden children so the analyst can drill in without leaving the
  // canvas.
  const [expandedClusters, setExpandedClusters] = useState(() => new Set());
  const { nodes, edges } = useMemo(
    () => {
      const g = expandClusters(raw, expandedClusters, enrichedIncident);
      // Merge authoritative correlation edges (never overwriting real
      // XDR edges that already exist between the same endpoints).
      if (corrEdges.length) {
        const existing = new Set(g.edges.map((e) => `${e.source}->${e.target}#${e.kind}`));
        for (const ce of corrEdges) {
          const key = `${ce.source}->${ce.target}#${ce.kind}`;
          if (existing.has(key)) continue;
          // Only draw when BOTH endpoints exist as canvas nodes; never
          // fabricate a floating edge.
          if (g.nodes.find((n) => n.id === ce.source)
                && g.nodes.find((n) => n.id === ce.target)) {
            g.edges.push({ id: key, ...ce });
          }
        }
      }
      return g;
    },
    [raw, expandedClusters, enrichedIncident, corrEdges],
  );

  const [selected, setSelected]   = useState(null);
  const [hovered, setHovered]     = useState(null);
  const [highlight, setHighlight] = useState(null); // { technique_id? | evidence_id? }
  const [pivot, setPivot]         = useState(null); // {x,y,node}
  const [zoom, setZoom]           = useState(1);
  const [pan,  setPan]            = useState({ x: 0, y: 0 });
  const [filter, setFilter]       = useState("all");
  const [showMinimap, setShowMinimap] = useState(true);
  const [showTimeline, setShowTimeline] = useState(true);
  const dragRef = useRef({ dragging: false, ox: 0, oy: 0 });
  const canvasRef = useRef(null);

  const filterFn = useMemo(() => {
    const f = FILTERS.find((x) => x.key === filter);
    if (!f || !f.types) return () => true;
    return (n) => f.types.includes(n.type) || n.type === "incident";
  }, [filter]);

  // Auto-select the incident node on first load.
  useEffect(() => {
    if (!selected && nodes.length) {
      const inc = nodes.find((n) => n.type === "incident");
      if (inc) setSelected(inc.id);
    }
  }, [nodes, selected]);

  const onCanvasMouseDown = useCallback((e) => {
    if (e.button !== 0) return;
    dragRef.current = { dragging: true, ox: e.clientX, oy: e.clientY,
                            px: pan.x, py: pan.y };
    setPivot(null);
  }, [pan]);
  const onCanvasMouseMove = useCallback((e) => {
    if (!dragRef.current.dragging) return;
    setPan({ x: dragRef.current.px + (e.clientX - dragRef.current.ox),
                y: dragRef.current.py + (e.clientY - dragRef.current.oy) });
  }, []);
  const onCanvasMouseUp   = useCallback(() => { dragRef.current.dragging = false; }, []);
  // Wheel / touchpad-pinch zoom disabled per owner directive — zoom is
  // driven only by the on-screen −/+ buttons on the canvas toolbar.
  const onWheel = useCallback(() => {}, []);

  const openPivot = useCallback((e, node) => {
    e.preventDefault();
    setPivot({ x: e.clientX, y: e.clientY, node });
    setSelected(node.id);
  }, []);
  useEffect(() => {
    const close = () => setPivot(null);
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, []);

  // ── Toolbar actions ─
  const doFitView = useCallback(() => {
    if (!nodes.length || !canvasRef.current) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const xs = nodes.map((n) => n.x), ys = nodes.map((n) => n.y);
    const minX = Math.min(...xs), maxX = Math.max(...xs);
    const minY = Math.min(...ys), maxY = Math.max(...ys);
    const gw = Math.max(1, maxX - minX), gh = Math.max(1, maxY - minY);
    // Reserve 80px of padding around the graph bounds.
    const scale = Math.min(1.8, Math.max(0.4,
      Math.min((rect.width  - 160) / gw,
                  (rect.height - 160) / gh)));
    setZoom(scale);
    setPan({
      x: rect.width  / 2 - ((minX + maxX) / 2) * scale,
      y: rect.height / 2 - ((minY + maxY) / 2) * scale,
    });
  }, [nodes]);

  const doReset = useCallback(() => {
    setZoom(1); setPan({ x: 0, y: 0 });
    setSelected(null); setHighlight(null);
    setFilter("all");
    setExpandedClusters(new Set());
  }, []);

  const onNodeClick = useCallback((e, node) => {
    e.stopPropagation();
    if (node.type === "cluster") {
      setExpandedClusters((s) => new Set([...s, node.id]));
      setSelected(null);
      return;
    }
    setSelected(node.id);
  }, []);
  const collapseCluster = useCallback((clusterId) => {
    setExpandedClusters((s) => {
      const n = new Set(s); n.delete(clusterId); return n;
    });
  }, []);

  const selectedNode = nodes.find((n) => n.id === selected) || null;

  return (
    <div data-testid="xdr-investigation-workspace"
            style={{ display: "grid",
                        gridTemplateColumns: "1fr 340px",
                        gridTemplateRows: "auto 1fr auto",
                        gap: 12, height: 780 }}>
      {/* Investigation Toolbar (spans full width) */}
      <div style={{ gridColumn: "1 / 3", gridRow: 1 }}>
        <InvestigationToolbar
          nodeCount={nodes.length} edgeCount={edges.length}
          filter={filter} onFilter={setFilter}
          onFit={doFitView} onReset={doReset}
          showMinimap={showMinimap} onToggleMinimap={() => setShowMinimap((v) => !v)}
          showTimeline={showTimeline} onToggleTimeline={() => setShowTimeline((v) => !v)}
        />
        <TacticRibbon
          nodes={nodes}
          highlight={highlight}
          onSelectTactic={(k) => setHighlight(highlight?.tactic === k
                                                                          ? null : { tactic: k })}
          onSelectTechnique={(tid) => setHighlight({ technique_id: tid })}
          onClear={() => setHighlight(null)}
        />
      </div>

      {/* Canvas */}
      <section ref={canvasRef} className="panel"
                  style={{ position: "relative", overflow: "hidden",
                              background: "linear-gradient(160deg, #0a0d14 0%, #0e131c 100%)",
                              borderRadius: 6, gridRow: 2 }}
                  data-testid="xdr-investigation-canvas"
                  onMouseDown={onCanvasMouseDown}
                  onMouseMove={onCanvasMouseMove}
                  onMouseUp={onCanvasMouseUp}
                  onMouseLeave={onCanvasMouseUp}>
        <CanvasToolbar
          incidentId={incident?.id}
          nodeCount={nodes.length} edgeCount={edges.length}
          zoom={zoom} onZoom={setZoom}
          highlight={highlight} onClearHighlight={() => setHighlight(null)}
        />
        <svg width="100%" height="100%"
                style={{ position: "absolute", inset: 0, cursor: dragRef.current.dragging ? "grabbing" : "grab" }}>
          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* Edges first so nodes sit on top */}
            {edges.map((e) => {
              const s = nodes.find((n) => n.id === e.source);
              const t = nodes.find((n) => n.id === e.target);
              if (!s || !t) return null;
              const dimByFilter = !(filterFn(s) || filterFn(t));
              const dimByHl = highlight && !_edgeMatches(e, s, t, highlight);
              const dim = dimByFilter || dimByHl;
              const meta = EDGE_KIND[e.kind] || EDGE_KIND.observed;
              return (
                <g key={e.id} opacity={dim ? 0.12 : 1}>
                  <line
                    x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                    stroke={meta.color}
                    strokeWidth={meta.weight || 1.4}
                    strokeDasharray={meta.dashed ? "4 4" : "none"} />
                  {/* small semantic tag mid-edge for legibility on hover */}
                  {(selected === s.id || selected === t.id
                        || hovered === s.id || hovered === t.id) && (
                    <text
                      x={(s.x + t.x) / 2} y={(s.y + t.y) / 2 - 4}
                      textAnchor="middle" fill={meta.color}
                      fontSize={9} fontFamily="ui-monospace, monospace"
                      style={{ pointerEvents: "none" }}>
                      {meta.label}
                    </text>
                  )}
                </g>
              );
            })}
            {nodes.map((n) => (
              <NodeGlyph key={n.id} node={n}
                              selected={selected === n.id}
                              hovered={hovered === n.id}
                              dimmed={(highlight && !_nodeMatches(n, highlight))
                                          || !filterFn(n)}
                              onClick={(e) => onNodeClick(e, n)}
                              onContextMenu={(e) => openPivot(e, n)}
                              onMouseEnter={() => setHovered(n.id)}
                              onMouseLeave={() => setHovered(null)} />
            ))}
          </g>
        </svg>
        {/* Minimap removed per owner directive — Evidence Trajectory
                MITRE ATT&CK view is the primary spatial reference. */}
        <CanvasLegend />
        {/* Selected-cluster hint to collapse */}
        {selectedNode?.type === "cluster" && (
          <button className="btn ghost"
                    onClick={() => collapseCluster(selectedNode.id)}
                    data-testid="xdr-canvas-cluster-collapse"
                    style={{ position: "absolute", top: 44, right: 12,
                                padding: "3px 10px", fontSize: 10.5,
                                zIndex: 4 }}>
            <MinusSquare size={11} /> Collapse cluster
          </button>
        )}
      </section>

      {/* Right-side stack: Inspector on top, Process Chain, Attack Story below */}
      <aside style={{ display: "flex", flexDirection: "column", gap: 10,
                          overflow: "hidden", gridRow: 2 }}>
        <EntityInspector
          node={selectedNode} incident={incident}
          onPivotHighlight={setHighlight}
          onOpenPivot={(e) => selectedNode && openPivot(e, selectedNode)}
        />
        <ProcessChainPanel
          nodes={nodes} edges={edges}
          selectedId={selected} onSelect={setSelected}
        />
        <AttackStoryPanel
          incident={incident}
          selectedNodeId={selected}
          onHighlightTechnique={(t) => setHighlight({ technique_id: t })}
          onHighlightEvidence={(rid) => setHighlight({ rule_id: rid })}
          onFocusNode={(nid) => setSelected(nid)}
        />
      </aside>

      {/* Synchronized Timeline strip — one investigation surface */}
      {showTimeline && (
        <div style={{ gridColumn: "1 / 3", gridRow: 3 }}>
          <SynchronizedTimeline
            incident={enrichedIncident} nodes={nodes}
            selectedId={selected}
            highlight={highlight}
            onSelect={setSelected}
            onHighlight={setHighlight}
          />
        </div>
      )}

      {/* Pivot context menu */}
      {pivot && (
        <PivotMenu x={pivot.x} y={pivot.y} node={pivot.node}
                        incident={incident}
                        onClose={() => setPivot(null)}
                        onHighlight={setHighlight} />
      )}
    </div>
  );
}


/* ───────────────────────────── graph builder ─────────────────────── */
function buildGraph(incident) {
  const nodes = [];
  const edges = [];
  if (!incident) return { nodes, edges };

  const push = (n) => {
    const existing = nodes.find((x) => x.id === n.id);
    if (existing) {
      // Merge badge counters across duplicate refs.
      existing.badges = _mergeBadges(existing.badges, n.badges);
      return existing;
    }
    n.badges = n.badges || {};
    nodes.push(n);
    return n;
  };
  const edge = (source, target, kind = "connected_to") => {
    if (!source || !target || source === target) return;
    if (!edges.find((e) =>
        e.source === source && e.target === target && e.kind === kind))
      edges.push({ id: `${source}->${target}#${kind}`,
                       source, target, kind });
  };

  // Layout (deterministic; d3-force is P1).
  const cx = 480, cy = 220;

  const incidentNode = push({
    id: `inc:${incident.id}`, type: "incident",
    title: incident.name || incident.number || "Incident",
    subtitle: incident.severity || "",
    badges: { severity: incident.severity },
    x: cx, y: cy,
  });

  // ── Hosts + their processes (executed edges + parent_of within tree) ─
  const hosts = incident.assets?.hosts || incident.hosts || [];
  const hostIndex = {};
  hosts.forEach((h, i) => {
    const hostKey = h.host_id || h.id || h.name || i;
    const id = `host:${hostKey}`;
    push({ id, type: "host",
              title: h.host_id || h.name || h.id || "host",
              subtitle: h.os || h.ip || "",
              raw: h, badges: { ip: h.ip },
              x: cx - 220 - (i % 3) * 80, y: cy - 60 + i * 42 });
    edge(`inc:${incident.id}`, id, "connected_to");
    hostIndex[hostKey] = id;
  });

  // ── Identities ─
  const users = incident.assets?.users || incident.users || [];
  users.forEach((u, i) => {
    const id = `user:${u.user_id || u.id || u.email || i}`;
    push({ id, type: "user",
              title: u.email || u.user_id || u.name || "user",
              subtitle: u.role || u.department || "",
              raw: u, x: cx + 240 + (i % 2) * 60, y: cy - 60 + i * 42 });
    edge(`inc:${incident.id}`, id, "connected_to");
  });

  // ── Processes (executed / parent_of edges) ─
  const processes = _extractProcesses(incident);
  processes.forEach((p, i) => {
    const id = `proc:${p.pid || p.name || i}`;
    push({ id, type: "process",
              title: p.name || `pid:${p.pid || "?"}`,
              subtitle: p.command_line ? _short(p.command_line, 42) : "",
              raw: p,
              badges: { pid: p.pid },
              x: cx - 30 + (i - processes.length / 2) * 90, y: cy + 70 });
    if (p.host_id && hostIndex[p.host_id])
      edge(hostIndex[p.host_id], id, "executed");
    if (p.parent_pid) {
      const parentId = `proc:${p.parent_pid}`;
      if (nodes.find((n) => n.id === parentId)) edge(parentId, id, "parent_of");
    }
  });

  // ── IOCs (typed indicators + resolved_to / connected_to edges) ─
  const iocs = incident.iocs || {};
  const iocKinds = [
    ["hash",   iocs.hash,   "created"],
    ["ip",     iocs.ip,     "connected_to"],
    ["domain", iocs.domain, "resolved_to"],
    ["url",    iocs.url,    "connected_to"],
  ];
  let iocRow = 0;
  iocKinds.forEach(([kind, values, semantic]) => {
    (values || []).forEach((v, i) => {
      const val = typeof v === "string" ? v : v.value || i;
      const id  = `${kind}:${val}`;
      push({ id, type: kind,
                title: _short(String(val), 22),
                subtitle: typeof v === "object" ? v.provider || v.source || "" : "",
                raw: v, badges: {},
                x: cx - 250 + (i % 3) * 70,
                y: cy + 160 + iocRow * 48 });
      // Attribute the IOC to a real producing process if the payload
      // links them; otherwise attach to the host (never to nothing).
      const linkedProc = typeof v === "object" && v.process
        ? nodes.find((n) => n.id === `proc:${v.process}`) : null;
      const linkedHost = typeof v === "object" && v.host_id
        ? hostIndex[v.host_id] : null;
      if (linkedProc) edge(linkedProc.id, id, semantic);
      else if (linkedHost) edge(linkedHost, id, semantic);
    });
    if ((values || []).length) iocRow++;
  });

  // ── Evidence (produced / mapped_to edges + MITRE technique nodes) ─
  const stage2 = incident.verdict_stage2 || {};
  const evList = (stage2.evidence || incident.evidence || []).slice(0, 24);
  evList.forEach((ev, i) => {
    const id = `evid:${ev.rule_id || ev.id || i}`;
    push({ id, type: "evidence",
              title: ev.rule_id || ev.title || `evidence #${i}`,
              subtitle: ev.detected_by || ev.engine || "",
              raw: ev,
              badges: { weight: ev.weight },
              x: cx + 130 + (i % 3) * 80,
              y: cy + 150 + Math.floor(i / 3) * 48 });
    // Prefer attaching evidence to the specific process/host it names.
    const evHostId = ev.entity?.host_id ? hostIndex[ev.entity.host_id] : null;
    const evProcId = ev.entity?.pid ? `proc:${ev.entity.pid}` : null;
    const proc     = evProcId && nodes.find((n) => n.id === evProcId);
    if (proc)         edge(proc.id, id, "produced");
    else if (evHostId) edge(evHostId, id, "produced");
    else              edge(`inc:${incident.id}`, id, "produced");
    // Bump the parent's evidence-count badge.
    const owner = proc ? proc : evHostId ? nodes.find((n) => n.id === evHostId) : incidentNode;
    if (owner) owner.badges.evidence_count = (owner.badges.evidence_count || 0) + 1;

    // Rule → MITRE mapping (from the authoritative RULE_TO_TECHNIQUE table).
    const rid  = String(ev.rule_id || "").toUpperCase();
    const tech = ev.technique_id || RULE_TO_TECHNIQUE[rid];
    if (tech) {
      const tid = `tech:${tech}`;
      push({ id: tid, type: "technique",
                title: tech,
                subtitle: TECHNIQUE_INDEX[tech]?.name || "",
                raw: TECHNIQUE_INDEX[tech] || { technique_id: tech },
                badges: {},
                x: cx + 80 + (i % 4) * 90, y: cy + 300 });
      edge(id, tid, "mapped_to");
      if (owner) owner.badges.technique_count = (owner.badges.technique_count || 0) + 1;
    }
  });

  // ── Response executions (responded + produced edges to evidence) ─
  const responses = incident.response_executions || incident.responses || [];
  responses.slice(0, 10).forEach((r, i) => {
    const id = `resp:${r.execution_id || i}`;
    push({ id, type: "response",
              title: r.action_id || "response",
              subtitle: r.state || r.status || "",
              raw: r,
              badges: { state: r.state || r.status },
              x: cx + 320, y: cy - 40 + i * 46 });
    edge(`inc:${incident.id}`, id, "responded");
    // Response → its evidence node (real ref from base backend).
    if (r.evidence_ref) {
      const evId = `evid:${r.evidence_ref}`;
      if (!nodes.find((n) => n.id === evId)) {
        push({ id: evId, type: "evidence",
                  title: _short(r.evidence_ref, 18),
                  subtitle: "response evidence",
                  raw: { evidence_ref: r.evidence_ref },
                  badges: { via_response: true },
                  x: cx + 220, y: cy - 40 + i * 46 });
      }
      edge(id, evId, "produced");
    }
    // Response → host / user it targeted (real target from parameters).
    const tgtHostId = r.parameters?.host_id ? hostIndex[r.parameters.host_id] : null;
    if (tgtHostId) edge(id, tgtHostId, "responded");
    const tgtUser  = r.parameters?.user_id || r.parameters?.user;
    if (tgtUser) {
      const uId = `user:${tgtUser}`;
      if (nodes.find((n) => n.id === uId)) edge(id, uId, "responded");
    }
    incidentNode.badges.response_count = (incidentNode.badges.response_count || 0) + 1;
  });

  // ── Cluster collapse — hosts with > CLUSTER_THRESHOLD child processes
  // fold into a single node the analyst can expand.  Keeps the canvas
  // legible without hiding data (expansion is a click away).
  return _foldClusters({ nodes, edges }, { threshold: 4 });
}


function _foldClusters({ nodes, edges }, { threshold = 4 } = {}) {
  // Group processes by their executed-parent host.
  const byHost = {};
  for (const e of edges) {
    if (e.kind !== "executed") continue;
    (byHost[e.source] = byHost[e.source] || []).push(e.target);
  }
  const collapsed = [];
  const droppedNodeIds = new Set();
  for (const [hostId, procIds] of Object.entries(byHost)) {
    if (procIds.length < threshold) continue;
    const hostNode = nodes.find((n) => n.id === hostId);
    if (!hostNode) continue;
    // Mark procs as clusterable; the toolbar / node click can expand.
    const clusterId = `cluster:${hostId}`;
    if (nodes.find((n) => n.id === clusterId)) continue;
    nodes.push({
      id: clusterId, type: "cluster",
      title: `${procIds.length} processes`,
      subtitle: hostNode.title,
      badges: { count: procIds.length, parent_host: hostId },
      collapsed: true, contains: procIds,
      x: hostNode.x + 90, y: hostNode.y + 40,
    });
    for (const pid of procIds) droppedNodeIds.add(pid);
    collapsed.push(clusterId);
  }
  if (droppedNodeIds.size === 0) return { nodes, edges };
  const keepNodes = nodes.filter((n) => !droppedNodeIds.has(n.id));
  const keepEdges = edges.filter((e) =>
    !droppedNodeIds.has(e.source) && !droppedNodeIds.has(e.target));
  // Re-attach a cluster→host edge for each collapsed group.
  for (const cid of collapsed) {
    const cluster = keepNodes.find((n) => n.id === cid);
    if (!cluster) continue;
    keepEdges.push({ id: `${cluster.badges.parent_host}->${cid}#executed`,
                          source: cluster.badges.parent_host,
                          target: cid, kind: "executed" });
  }
  return { nodes: keepNodes, edges: keepEdges,
             _hiddenNodes: [...droppedNodeIds] };
}


function _mergeBadges(a = {}, b = {}) {
  const out = { ...a };
  for (const [k, v] of Object.entries(b)) {
    if (typeof v === "number") out[k] = (out[k] || 0) + v;
    else if (out[k] == null)   out[k] = v;
  }
  return out;
}


// Given the folded graph, put the child nodes back for any cluster
// the analyst has opened.  We rebuild those child nodes from the
// incident payload so the semantic edges reappear correctly.
function expandClusters(raw, expandedIds, incident) {
  if (!expandedIds || expandedIds.size === 0) return raw;
  const nodes = raw.nodes.filter((n) =>
    n.type !== "cluster" || !expandedIds.has(n.id));
  const edges = raw.edges.filter((e) => !expandedIds.has(e.target));
  // Re-inject the child processes that were folded away.
  for (const cid of expandedIds) {
    const cluster = raw.nodes.find((n) => n.id === cid);
    if (!cluster) continue;
    const hostId = cluster.badges.parent_host;
    const host   = raw.nodes.find((n) => n.id === hostId);
    const baseX  = host ? host.x + 90 : cluster.x;
    const baseY  = host ? host.y + 30 : cluster.y;
    (cluster.contains || []).forEach((pid, i) => {
      const proc = _rebuildProcess(pid, incident);
      if (!proc) return;
      nodes.push({
        ...proc, x: baseX + (i % 3) * 80, y: baseY + Math.floor(i / 3) * 40,
      });
      if (host) edges.push({ id: `${hostId}->${pid}#executed`,
                                    source: hostId, target: pid, kind: "executed" });
    });
  }
  return { nodes, edges };
}


function _rebuildProcess(procId, incident) {
  // procId like `proc:<pid|name|index>`.
  const key = procId.slice(5);
  const procs = _extractProcesses(incident);
  const match = procs.find((p) => String(p.pid) === key ||
                                              String(p.name) === key);
  if (!match) return null;
  return {
    id: procId, type: "process",
    title: match.name || `pid:${match.pid || "?"}`,
    subtitle: match.command_line ? _short(match.command_line, 42) : "",
    raw: match, badges: { pid: match.pid },
  };
}

function _extractProcesses(incident) {
  const acc = [];
  const seen = new Set();
  const evs = (incident?.verdict_stage2?.evidence || incident?.evidence || []);
  for (const ev of evs) {
    const e = ev.entity || ev.process || {};
    const name = e.image || e.process || e.name;
    const key  = `${name}|${e.pid || ""}`;
    if (!name || seen.has(key)) continue;
    seen.add(key);
    acc.push({ name, pid: e.pid, command_line: e.command_line || e.cmdline,
                  host_id: e.host_id || (incident?.assets?.hosts || [])[0]?.host_id });
  }
  return acc.slice(0, 6);
}


/* ───────────────────────────── SVG glyph ─────────────────────────── */
function NodeGlyph({ node, selected, hovered, dimmed,
                          onClick, onContextMenu, onMouseEnter, onMouseLeave }) {
  const meta = NODE_TYPE[node.type] || NODE_TYPE.evidence;
  const Icon = meta.icon;
  const r    = selected ? 22 : hovered ? 20 : 18;
  const badges = _renderBadges(node);
  const isCluster = node.type === "cluster";
  return (
    <g transform={`translate(${node.x}, ${node.y})`}
          opacity={dimmed ? 0.22 : 1}
          onClick={onClick} onContextMenu={onContextMenu}
          onMouseEnter={onMouseEnter} onMouseLeave={onMouseLeave}
          data-testid={`xdr-node-${node.id}`}
          style={{ cursor: "pointer" }}>
      {selected && (
        <ShapePath shape={meta.shape} r={r + 6} fill="none"
                          stroke={meta.color} strokeOpacity={0.35}
                          strokeWidth={2} />
      )}
      <ShapePath shape={meta.shape} r={r}
                        fill={_hexA(meta.color, selected ? 0.28 : 0.14)}
                        stroke={meta.color}
                        strokeWidth={selected ? 2 : 1.2} />
      <foreignObject x={-9} y={-9} width={18} height={18}
                          style={{ pointerEvents: "none" }}>
        <div style={{ color: meta.color, display: "flex",
                          alignItems: "center", justifyContent: "center",
                          width: 18, height: 18 }}>
          <Icon size={14} />
        </div>
      </foreignObject>
      {isCluster && (
        <foreignObject x={r - 4} y={-r - 4} width={16} height={16}
                              style={{ pointerEvents: "none" }}>
          <div style={{ color: meta.color, display: "flex",
                            alignItems: "center", justifyContent: "center",
                            width: 16, height: 16 }}>
            <PlusSquare size={12} />
          </div>
        </foreignObject>
      )}
      <text y={r + 12} textAnchor="middle"
              fill="#e6e9f2" fontSize={10.5}
              fontFamily="Inter, system-ui" fontWeight={600}
              style={{ pointerEvents: "none" }}>
        {_short(node.title, 24)}
      </text>
      {node.subtitle && (
        <text y={r + 24} textAnchor="middle"
                fill="#7c8494" fontSize={9}
                fontFamily="ui-monospace, SFMono-Regular, monospace"
                style={{ pointerEvents: "none" }}>
          {_short(node.subtitle, 32)}
        </text>
      )}
      {/* Badges — small semantic chips (evidence count / MITRE count /
              severity / response state).  Each badge is minted only from
              a real datum. */}
      {badges.map((b, i) => (
        <g key={i} transform={`translate(${r - 4 + i * 14}, ${-(r + 6)})`}
              style={{ pointerEvents: "none" }}>
          <rect x={-6} y={-6} width={12} height={12} rx={2}
                    fill={b.bg} stroke={b.fg} strokeWidth={0.7} />
          <text x={0} y={2.5} textAnchor="middle"
                    fill={b.fg} fontSize={7.5} fontWeight={800}
                    fontFamily="ui-monospace, monospace">
            {b.label}
          </text>
        </g>
      ))}
    </g>
  );
}


// Small SVG-path helper so nodes can be rendered as different shapes
// (hex for INCIDENT/MITRE/VERDICT, square for HOST/RESPONSE, diamond
// for indicators/FILE, circle otherwise).  Deliberately compact.
function ShapePath({ shape, r, ...rest }) {
  if (shape === "hex") {
    const pts = [];
    for (let i = 0; i < 6; i++) {
      const a = (Math.PI / 3) * i - Math.PI / 6;
      pts.push([r * Math.cos(a), r * Math.sin(a)]);
    }
    return <polygon points={pts.map(([x, y]) => `${x},${y}`).join(" ")} {...rest} />;
  }
  if (shape === "square") {
    return <rect x={-r} y={-r} width={2 * r} height={2 * r} rx={4} {...rest} />;
  }
  if (shape === "diamond") {
    const p = `0,${-r} ${r},0 0,${r} ${-r},0`;
    return <polygon points={p} {...rest} />;
  }
  return <circle r={r} {...rest} />;
}


function _renderBadges(node) {
  const b = node.badges || {};
  const out = [];
  const chip = (label, fg, bg) => out.push({ label, fg, bg });
  // Severity for incident + inherited to owners with heavy evidence.
  if (node.type === "incident" && b.severity) {
    chip(String(b.severity)[0].toUpperCase(),
            _sevFg(b.severity), _hexA(_sevFg(b.severity), 0.22));
  }
  if (typeof b.evidence_count === "number" && b.evidence_count > 0) {
    chip(String(b.evidence_count), "#fbbf24", "rgba(251,191,36,.22)");
  }
  if (typeof b.technique_count === "number" && b.technique_count > 0) {
    chip("T" + b.technique_count, "#f472b6", "rgba(244,114,182,.22)");
  }
  if (b.state && node.type === "response") {
    const isOk = b.state === "SUCCEEDED";
    chip(isOk ? "✓" : "!",
            isOk ? "#34d399" : "#ff9494",
            isOk ? "rgba(52,211,153,.22)" : "rgba(255,148,148,.22)");
  }
  if (typeof b.count === "number" && node.type === "cluster") {
    chip(String(b.count), "#e5e7eb", "rgba(160,160,180,.24)");
  }
  return out.slice(0, 3);   // never crowd the node
}
function _sevFg(sev) {
  const s = String(sev || "").toLowerCase();
  return s.startsWith("crit") ? "#f87171"
       : s.startsWith("high") ? "#fb923c"
       : s.startsWith("med")  ? "#facc15"
       : s.startsWith("low")  ? "#38bdf8"
       : "#94a3b8";
}


// P1 · Contextual entity actions.  Each pill deep-links into an
// existing NivXRay capability — none of them fabricate an action.
// When a linked feature doesn't exist for a given entity, we simply
// don't render the pill.
function EntityActions({ node, incident, onPivotHighlight }) {
  const actions = useMemo(() => _entityActions(node, incident,
                                                             onPivotHighlight),
                                 [node, incident, onPivotHighlight]);
  if (!actions.length) return null;
  return (
    <div data-testid="xdr-inspector-entity-actions"
            style={{ display: "flex", flexWrap: "wrap", gap: 4,
                        marginTop: 10 }}>
      {actions.map((a, i) => (
        <button key={i} className="btn ghost"
                  onClick={a.onClick}
                  data-testid={`xdr-inspector-action-${a.key}`}
                  title={a.title}
                  style={{ padding: "2px 8px", fontSize: 10,
                              border: "1px solid var(--border)",
                              borderRadius: 3 }}>
          {a.label}
        </button>
      ))}
    </div>
  );
}
function _entityActions(node, incident, onPivotHighlight) {
  if (!node) return [];
  const raw = node.raw || {};
  const push = (arr, key, label, onClick, title) =>
    arr.push({ key, label, onClick, title });
  const open = (u) => window.open(u, "_blank", "noopener,noreferrer");
  const actions = [];
  const encId = incident?.id ? encodeURIComponent(incident.id) : "";

  // "Investigate" is the default action — always jump back to the
  // incident detail (that IS the investigation surface).
  push(actions, "investigate", "Investigate",
        () => open(`/xdr/incidents/${encId}`),
        "Open incident investigation");

  if (node.type === "host") {
    push(actions, "trajectory", "Trajectory",
          () => open(`/xdr/endpoints/${encodeURIComponent(raw.host_id || node.title)}/trajectory`),
          "Device trajectory");
    push(actions, "related",    "Related Incidents",
          () => open(`/xdr/incidents?q=${encodeURIComponent(raw.host_id || node.title)}`));
  }
  if (node.type === "user") {
    push(actions, "user-incidents", "User Incidents",
          () => open(`/xdr/incidents?q=${encodeURIComponent(raw.email || raw.user_id || node.title)}`));
  }
  if (node.type === "process") {
    push(actions, "process-tree", "Process Tree",
          () => open(`/edr/process-tree?incident=${encId}`),
          "Open process tree");
  }
  if (["hash", "ip", "domain", "url"].includes(node.type)) {
    push(actions, "ti", "Threat Intel",
          () => open(`/xdr/intelligence/iocs?ioc=${encodeURIComponent(node.title)}`),
          "Threat intel enrichment");
    push(actions, "ioc-related", "Related",
          () => open(`/xdr/incidents?q=${encodeURIComponent(node.title)}`));
  }
  if (node.type === "evidence") {
    push(actions, "raw", "Raw Evidence",
          () => open(`/xdr/incidents/${encId}?tab=investigation&evidence=${encodeURIComponent(raw.rule_id || node.title)}`));
    const tech = raw.technique_id || (raw.rule_id && RULE_TO_TECHNIQUE[String(raw.rule_id).toUpperCase()]);
    if (tech) push(actions, "mitre-focus", "MITRE",
                            () => onPivotHighlight({ technique_id: tech }));
  }
  if (node.type === "technique") {
    push(actions, "heatmap", "Heatmap",
          () => open(`/xdr/intelligence/mitre?technique=${encodeURIComponent(node.title)}`));
    push(actions, "filter",  "Filter graph",
          () => onPivotHighlight({ technique_id: node.title }),
          "Filter to this technique on the canvas");
    push(actions, "tech-related", "Related Incidents",
          () => open(`/xdr/incidents?technique=${encodeURIComponent(node.title)}`));
  }
  if (node.type === "response") {
    push(actions, "resp-chain", "Response Chain",
          () => open(`/xdr/evidence/${encodeURIComponent(raw.execution_id || "")}`),
          "Full response chain");
  }
  return actions;
}


/* ───────────────────────────── inspector ─────────────────────────── */
function EntityInspector({ node, incident, onPivotHighlight, onOpenPivot }) {
  if (!node) {
    return (
      <div className="panel" data-testid="xdr-inspector-empty"
              style={{ padding: 12, fontSize: 11, color: "var(--faint)" }}>
        Click a node in the canvas to inspect.  Right-click any node for
        the pivot menu.
      </div>
    );
  }
  const meta = NODE_TYPE[node.type] || NODE_TYPE.evidence;
  const Icon = meta.icon;
  const raw  = node.raw || {};

  return (
    <div className="panel" data-testid={`xdr-inspector-${node.type}`}
            style={{ padding: 12, flex: 1, minHeight: 260,
                        display: "flex", flexDirection: "column" }}>
      <header style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
        <span style={{ color: meta.color, display: "inline-flex" }}>
          <Icon size={14} />
        </span>
        <b className="mono" style={{ color: meta.color, fontSize: 10.5,
                                                letterSpacing: ".3px" }}>
          {meta.label}
        </b>
        <span style={{ flex: 1 }} />
        <button className="btn ghost" onClick={onOpenPivot}
                  data-testid="xdr-inspector-pivot-btn"
                  style={{ padding: "2px 6px", fontSize: 10 }}>
          Pivot <ChevronRight size={10} />
        </button>
      </header>
      <div style={{ fontSize: 12.5, fontWeight: 700, color: "var(--text)",
                        wordBreak: "break-all" }}>
        {node.title}
      </div>
      {node.subtitle && (
        <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 2 }}>
          {node.subtitle}
        </div>
      )}

      {/* Contextual entity actions strip (P1) */}
      <EntityActions node={node} incident={incident}
                            onPivotHighlight={onPivotHighlight} />

      <div style={{ marginTop: 10, overflow: "auto", flex: 1 }}>
        {node.type === "evidence" && (
          <>
            <Row k="Rule ID"      v={raw.rule_id || node.title} copy />
            <Row k="Detected by"  v={raw.detected_by || raw.engine} />
            <Row k="Weight"       v={raw.weight != null ? `+${raw.weight}` : "—"} />
            <Row k="Timestamp"    v={raw.timestamp || raw.at} />
            <Row k="Host"         v={raw.entity?.host_id || raw.host_id} />
            <Row k="Command line" v={raw.entity?.command_line || raw.command_line} mono />
            <Row k="Provenance"   v={raw.provenance} mono small />
            {raw.technique_id && (
              <Row k="MITRE" v={
                <span onClick={() => onPivotHighlight({ technique_id: raw.technique_id })}
                         style={{ color: "#f472b6", cursor: "pointer",
                                    textDecoration: "underline" }}>
                  {raw.technique_id} · {TECHNIQUE_INDEX[raw.technique_id]?.name || "—"}
                </span>
              } />
            )}
            {raw.rule_id && (
              <XdrBehaviorRegistryPanel ruleId={raw.rule_id} />
            )}
          </>
        )}
        {node.type === "response" && (
          <>
            <Row k="Action"        v={raw.action_id} copy />
            <Row k="State"         v={raw.state || raw.status}
                    color={raw.state === "SUCCEEDED" ? "var(--mint)" : "#ff9494"} />
            <Row k="Execution ID"  v={raw.execution_id} mono copy />
            <Row k="Evidence Ref"  v={raw.evidence_ref} mono copy />
            <Row k="Audit Ref"     v={raw.audit_ref} mono copy />
            <Row k="Timeline Ref"  v={raw.timeline_ref} mono copy />
            <Row k="Invoker"       v={raw.invoker?.id || raw.invoker?.kind} />
            <Row k="Approved by"   v={raw.approval?.approved_by} />
            {raw.execution_id && (
              <div style={{ marginTop: 8 }}>
                <a href={`/xdr/evidence/${encodeURIComponent(raw.execution_id)}`}
                      target="_blank" rel="noreferrer"
                      style={{ color: "var(--cyan)", fontSize: 10.5 }}
                      data-testid="xdr-inspector-response-deeplink">
                  Open full response chain <ExternalLink size={10} />
                </a>
              </div>
            )}
          </>
        )}
        {node.type === "host" && (
          <>
            <Row k="Host ID"  v={raw.host_id || raw.id || raw.name} copy />
            <Row k="OS"       v={raw.os || raw.operating_system} />
            <Row k="IP"       v={raw.ip} copy />
            <Row k="Domain"   v={raw.domain} />
            <Row k="Last seen" v={raw.last_seen} />
          </>
        )}
        {node.type === "user" && (
          <>
            <Row k="User"     v={raw.user_id || raw.email || raw.id} copy />
            <Row k="Role"     v={raw.role} />
            <Row k="Dept"     v={raw.department} />
            <Row k="MFA"      v={raw.mfa_enabled != null ? String(raw.mfa_enabled) : "—"} />
          </>
        )}
        {node.type === "process" && (
          <>
            <Row k="Image"      v={raw.name || raw.image} copy />
            <Row k="PID"        v={raw.pid} />
            <Row k="Host"       v={raw.host_id} />
            <Row k="Command"    v={raw.command_line} mono />
            <XdrProcessCausalityPanel
              pid={raw.pid}
              hostId={raw.host_id}
              incidentId={incident?.id} />
          </>
        )}
        {(node.type === "ip" || node.type === "domain" || node.type === "hash"
              || node.type === "url") && (
          <>
            <Row k="Indicator" v={typeof raw === "string" ? raw : raw.value} mono copy />
            <Row k="Source"    v={typeof raw === "object" ? (raw.source || raw.provider) : "—"} />
            <Row k="Verdict"   v={typeof raw === "object" ? raw.verdict : "—"} />
            <XdrIocEnrichmentPanel
              value={typeof raw === "string" ? raw : (raw.value || node.title)}
              kind={node.type} />
          </>
        )}
        {node.type === "technique" && (
          <>
            <Row k="Technique"  v={node.title} copy />
            <Row k="Name"       v={TECHNIQUE_INDEX[node.title]?.name} />
            <Row k="Tactic"     v={TECHNIQUE_INDEX[node.title]?.tactic} />
            <div style={{ marginTop: 8 }}>
              <a href={`https://attack.mitre.org/techniques/${node.title.replace(".", "/")}/`}
                    target="_blank" rel="noreferrer"
                    style={{ color: "var(--cyan)", fontSize: 10.5 }}>
                Open on attack.mitre.org <ExternalLink size={10} />
              </a>
            </div>
          </>
        )}
        {node.type === "incident" && (
          <>
            <Row k="Incident"  v={incident.number || incident.id} copy />
            <Row k="State"     v={incident.state} />
            <Row k="Severity"  v={incident.severity} />
            <Row k="Assignee"  v={incident.assignee || "unassigned"} />
            <Row k="Sources"   v={(incident.sources || []).join(", ") || "—"} />
          </>
        )}
      </div>
    </div>
  );
}


/* ───────────────────────────── attack story ──────────────────────── */
function AttackStoryPanel({ incident, selectedNodeId,
                                    onHighlightTechnique, onHighlightEvidence,
                                    onFocusNode }) {
  const sentences = useMemo(() => buildAttackStory(incident), [incident]);
  return (
    <div className="panel" data-testid="xdr-attack-story"
            style={{ padding: 12, maxHeight: 260, overflow: "auto" }}>
      <div className="section-title" style={{ marginBottom: 6 }}>
        Attack Story
      </div>
      {sentences.length === 0 && (
        <div style={{ fontSize: 11, color: "var(--faint)" }}>
          No evidence-backed story yet.  The narrative appears once the
          incident carries Stage-2 evidence.
        </div>
      )}
      {sentences.map((s, i) => {
        const isSelected = selectedNodeId
          && ((s.rule_id && selectedNodeId === `evid:${s.rule_id}`) ||
                (s.technique && selectedNodeId === `tech:${s.technique}`) ||
                (s.response && selectedNodeId === `resp:${s.response}`));
        return (
          <div key={i}
                  style={{ fontSize: 11.5,
                              color: isSelected ? "var(--text)" : "var(--text-dim)",
                              padding: "5px 6px",
                              borderLeft: isSelected ? "2px solid var(--purple)"
                                                                : "2px solid transparent",
                              background: isSelected ? "rgba(155,123,240,.06)" : "transparent",
                              borderBottom: "1px solid var(--border)",
                              cursor: "pointer" }}
                  onClick={() => {
                    if (s.response) onFocusNode(`resp:${s.response}`);
                    else if (s.rule_id) { onFocusNode(`evid:${s.rule_id}`);
                                                   onHighlightEvidence(s.rule_id); }
                    else if (s.technique) { onFocusNode(`tech:${s.technique}`);
                                                     onHighlightTechnique(s.technique); }
                  }}
                  data-testid={`xdr-attack-story-sentence-${i}`}>
            <span className="mono" style={{ color: "var(--faint)", fontSize: 10 }}>
              {String(i + 1).padStart(2, "0")}.
            </span>{" "}
            {s.text}
            {s.technique && (
              <span className="mono"
                       style={{ marginLeft: 4, color: "#f472b6", fontSize: 9.5 }}>
                [{s.technique}]
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}

function buildAttackStory(incident) {
  const out = [];
  if (!incident) return out;
  const evs = (incident.verdict_stage2?.evidence || incident.evidence || []).slice(0, 12);
  for (const ev of evs) {
    const rid  = String(ev.rule_id || "").toUpperCase();
    const tech = ev.technique_id || RULE_TO_TECHNIQUE[rid];
    const who  = ev.entity?.image || ev.entity?.process || ev.image || "an entity";
    const host = ev.entity?.host_id || ev.host_id || (incident.assets?.hosts || [])[0]?.host_id;
    const verb = ev.title || ev.rule_id || "matched a detection rule";
    let text = `${who}${host ? " on " + host : ""} ${verb.replace(/_/g, " ").toLowerCase()}.`;
    if (ev.entity?.command_line) {
      text += ` Command line: ${_short(ev.entity.command_line, 90)}.`;
    }
    out.push({ text, rule_id: ev.rule_id, technique: tech });
  }
  const rs = incident.response_executions || incident.responses || [];
  for (const r of rs.slice(0, 4)) {
    out.push({
      text: `Response · ${r.action_id || "action"} executed ` +
              `(state: ${r.state || r.status || "?"}) by ${r.invoker?.id || r.invoker?.kind || "system"}.`,
      response: r.execution_id,
    });
  }
  return out;
}


/* ───────────────────────────── synchronized timeline ────────────── */
/**
 * Timeline strip below the canvas that stays in lockstep with every
 * other panel.  Selecting a marker updates the canvas + inspector;
 * highlighting a technique dims non-related markers; selecting a
 * canvas node scrolls the corresponding marker into view.
 *
 * Markers are minted strictly from real data — evidence timestamps,
 * response `completed_at`, and the incident opened-at.  No decorative
 * beats.
 */
function SynchronizedTimeline({ incident, nodes, selectedId, highlight,
                                          onSelect, onHighlight }) {
  const markers = useMemo(() => buildMarkers(incident), [incident]);
  const scrollerRef = useRef(null);
  useEffect(() => {
    if (!selectedId || !scrollerRef.current) return;
    const el = scrollerRef.current.querySelector(
      `[data-marker-node="${selectedId}"]`);
    if (el) el.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
  }, [selectedId]);

  if (markers.length === 0) return null;

  return (
    <div className="panel" data-testid="xdr-timeline-strip"
            style={{ padding: "8px 12px" }}>
      <div style={{ display: "flex", alignItems: "center",
                        marginBottom: 6, gap: 8 }}>
        <span className="section-title">Timeline</span>
        <span className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
          {markers.length} events · {markers[0].label_short} → {markers[markers.length - 1].label_short}
        </span>
      </div>
      <div ref={scrollerRef}
              style={{ display: "flex", alignItems: "flex-end", gap: 4,
                          overflowX: "auto", padding: "8px 4px 4px" }}>
        {markers.map((m, i) => {
          const isSel = selectedId === m.node_id;
          const dim   = highlight && !_markerMatches(m, highlight);
          const meta  = NODE_TYPE[m.type] || NODE_TYPE.evidence;
          return (
            <div key={i}
                    data-marker-node={m.node_id}
                    data-testid={`xdr-timeline-marker-${i}`}
                    onClick={() => onSelect(m.node_id)}
                    onMouseEnter={() => onHighlight(
                      m.type === "technique" ? { technique_id: m.technique_id }
                        : m.type === "evidence" && m.rule_id ? { rule_id: m.rule_id }
                        : null)}
                    onMouseLeave={() => onHighlight(null)}
                    style={{ cursor: "pointer", flex: "0 0 auto",
                                display: "flex", flexDirection: "column",
                                alignItems: "center",
                                opacity: dim ? 0.3 : 1,
                                minWidth: 90, padding: 4,
                                borderTop: isSel ? `2px solid ${meta.color}` : "2px solid transparent",
                                background: isSel ? _hexA(meta.color, 0.08) : "transparent",
                                transition: "opacity 200ms ease" }}>
              <div style={{ height: 24, display: "flex", alignItems: "flex-end" }}>
                <div style={{ width: 3, height: (m.weight || 0.5) * 24 + 4,
                                  background: meta.color, borderRadius: 1,
                                  boxShadow: isSel
                                                ? `0 0 6px ${_hexA(meta.color, 0.9)}`
                                                : "none" }} />
              </div>
              <div className="mono"
                      style={{ fontSize: 9, color: meta.color,
                                  fontWeight: 700, letterSpacing: ".3px",
                                  marginTop: 3 }}>
                {meta.label}
              </div>
              <div className="mono"
                      style={{ fontSize: 9.5, color: "var(--text-dim)",
                                  marginTop: 1, whiteSpace: "nowrap",
                                  maxWidth: 90, overflow: "hidden",
                                  textOverflow: "ellipsis" }}>
                {m.title}
              </div>
              <div className="mono"
                      style={{ fontSize: 9, color: "var(--faint)",
                                  marginTop: 1 }}>
                {m.label_short}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function buildMarkers(incident) {
  const rows = [];
  if (!incident) return rows;

  const pushMarker = (m) => {
    if (!m.at) return;
    const t = new Date(m.at).getTime();
    if (Number.isNaN(t)) return;
    rows.push({ ...m, ts: t });
  };

  pushMarker({
    at: incident.created_at || incident.opened_at,
    type: "incident", title: incident.name || "Incident opened",
    node_id: `inc:${incident.id}`, weight: 0.75,
  });

  const evs = incident.verdict_stage2?.evidence || incident.evidence || [];
  evs.slice(0, 40).forEach((ev, i) => {
    const rid  = String(ev.rule_id || "").toUpperCase();
    const tech = ev.technique_id || RULE_TO_TECHNIQUE[rid];
    pushMarker({
      at: ev.timestamp || ev.at,
      type: "evidence", title: ev.rule_id || `evidence ${i + 1}`,
      node_id: `evid:${ev.rule_id || ev.id || i}`,
      rule_id: ev.rule_id, technique_id: tech,
      weight: Math.min(1, (ev.weight || 30) / 60),
    });
  });

  const rs = incident.response_executions || incident.responses || [];
  rs.slice(0, 20).forEach((r, i) => {
    pushMarker({
      at: r.completed_at || r.started_at,
      type: "response", title: r.action_id || `response ${i + 1}`,
      node_id: `resp:${r.execution_id || i}`,
      weight: r.state === "SUCCEEDED" ? 0.9 : 0.6,
    });
  });

  rows.sort((a, b) => a.ts - b.ts);
  for (const r of rows) r.label_short = _shortTime(r.at);
  return rows;
}

function _shortTime(iso) {
  try {
    const d = new Date(iso);
    return d.toISOString().slice(11, 19) + "Z";
  } catch { return String(iso || "").slice(11, 19); }
}
function _markerMatches(m, h) {
  if (!h) return true;
  if (h.technique_id) {
    return m.technique_id === h.technique_id || m.type === "incident";
  }
  if (h.rule_id) {
    return m.rule_id === h.rule_id || m.type === "incident";
  }
  return true;
}


/* ───────────────────────────── pivot menu ────────────────────────── */
function PivotMenu({ x, y, node, incident, onClose, onHighlight }) {
  const items = useMemo(() => buildPivotItems(node, incident), [node, incident]);
  const style = {
    position: "fixed", left: Math.min(x, window.innerWidth - 240),
    top: Math.min(y, window.innerHeight - 320),
    background: "#0e131c", border: "1px solid #22293a",
    borderRadius: 5, minWidth: 220, padding: "5px 0",
    boxShadow: "0 6px 24px rgba(0,0,0,.55)",
    zIndex: 100, fontSize: 11.5,
  };
  return (
    <div style={style} data-testid="xdr-pivot-menu"
            onClick={(e) => e.stopPropagation()}>
      <div style={{ padding: "4px 10px", color: "var(--faint)",
                        fontFamily: "var(--mono)", fontSize: 10,
                        textTransform: "uppercase", letterSpacing: ".3px" }}>
        {(NODE_TYPE[node.type] || {}).label} PIVOT
      </div>
      {items.map((it, i) =>
        it.divider ? (
          <div key={i} style={{ height: 1, background: "#1c2230", margin: "4px 0" }} />
        ) : (
          <button key={i} className="btn ghost"
                     onClick={() => { it.action?.({ onHighlight }); onClose(); }}
                     data-testid={`xdr-pivot-${it.key}`}
                     style={{ width: "100%", textAlign: "left",
                                 padding: "5px 12px", borderRadius: 0,
                                 background: "transparent",
                                 color: "var(--text-dim)", fontSize: 11.5 }}>
            {it.label}
          </button>
        )
      )}
    </div>
  );
}
function buildPivotItems(node, incident) {
  const raw   = node.raw || {};
  const base  = [];
  const encId = incident?.id ? encodeURIComponent(incident.id) : "";

  const open = (url) => window.open(url, "_blank", "noopener,noreferrer");
  const copy = (val) => navigator.clipboard?.writeText(String(val || ""));

  base.push({ key: "copy-title", label: "Copy value",
                 action: () => copy(node.title) });

  if (node.type === "host") {
    base.push({ key: "trajectory", label: "Show device trajectory",
                    action: () => open(`/xdr/endpoints/${encodeURIComponent(raw.host_id || node.title)}/trajectory`) });
    base.push({ key: "search-host", label: "Search related incidents",
                    action: () => open(`/xdr/incidents?q=${encodeURIComponent(raw.host_id || node.title)}`) });
  }
  if (node.type === "user") {
    base.push({ key: "pivot-user", label: "Search related incidents",
                    action: () => open(`/xdr/incidents?q=${encodeURIComponent(raw.email || raw.user_id || node.title)}`) });
  }
  if (node.type === "process") {
    base.push({ key: "process-tree", label: "Open process tree",
                    action: () => open(`/edr/process-tree?incident=${encId}`) });
  }
  if (["hash", "ip", "domain", "url"].includes(node.type)) {
    base.push({ key: "ioc-search",  label: `Search this ${node.type.toUpperCase()}`,
                    action: () => open(`/xdr/incidents?q=${encodeURIComponent(node.title)}`) });
    base.push({ key: "ioc-ti",      label: "Threat intel enrichment",
                    action: () => open(`/xdr/intelligence/iocs?ioc=${encodeURIComponent(node.title)}`) });
  }
  if (node.type === "evidence") {
    base.push({ key: "evidence-open", label: "Open in incident investigation",
                    action: () => open(`/xdr/incidents/${encId}?tab=investigation&evidence=${encodeURIComponent(raw.rule_id || node.title)}`) });
  }
  if (node.type === "technique") {
    base.push({ key: "tech-heatmap",  label: "Highlight on MITRE heatmap",
                    action: () => open(`/xdr/intelligence/mitre?technique=${encodeURIComponent(node.title)}`) });
    base.push({ key: "tech-filter",   label: "Filter this technique on canvas",
                    action: ({ onHighlight }) => onHighlight({ technique_id: node.title }) });
    base.push({ key: "tech-incidents", label: "Incidents with this technique",
                    action: () => open(`/xdr/incidents?technique=${encodeURIComponent(node.title)}`) });
  }
  if (node.type === "response") {
    base.push({ key: "resp-detail",  label: `Open response chain (${_short(raw.execution_id || "", 12)})`,
                    action: () => open(`/xdr/evidence/${encodeURIComponent(raw.execution_id || "")}`) });
    if (raw.evidence_ref) {
      base.push({ key: "resp-evidence-copy", label: "Copy evidence_ref",
                      action: () => copy(raw.evidence_ref) });
    }
  }

  base.push({ divider: true });
  base.push({ key: "add-to-case", label: "Add to case notes",
                 action: () => copy(`Investigation pivot: ${node.type}=${node.title}`) });
  base.push({ key: "automation",  label: "Create automation rule",
                 action: () => open(`/xdr/respond/automation-rules`) });
  base.push({ key: "respond",     label: "Run response action…",
                 action: () => open(`/xdr/incidents/${encId}?respond=1`) });
  return base;
}


/* ───────────────────────────── ancillary ─────────────────────────── */
function InvestigationToolbar({
  nodeCount, edgeCount, filter, onFilter,
  onFit, onReset, showMinimap, onToggleMinimap,
  showTimeline, onToggleTimeline,
}) {
  return (
    <div className="panel" data-testid="xdr-investigation-toolbar"
            style={{ padding: "6px 10px",
                        display: "flex", alignItems: "center",
                        gap: 6, flexWrap: "wrap" }}>
      <ToolbarBtn label="Fit view" icon={Maximize2}
                        testid="xdr-toolbar-fit" onClick={onFit} />
      <ToolbarBtn label="Reset"    icon={RotateCcw}
                        testid="xdr-toolbar-reset" onClick={onReset} />
      <ToolbarBtn label="Timeline" icon={Clock}
                        testid="xdr-toolbar-timeline"
                        active={showTimeline}
                        onClick={onToggleTimeline} />
      <span style={{ width: 1, height: 20, background: "var(--border)",
                        margin: "0 4px" }} />
      <span className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                    marginRight: 4,
                                                    textTransform: "uppercase",
                                                    letterSpacing: ".3px" }}>
        <Filter size={10} style={{ verticalAlign: "middle",
                                                marginRight: 3 }} />
        Filter
      </span>
      {FILTERS.map((f) => (
        <button key={f.key}
                  className="btn ghost"
                  data-testid={`xdr-toolbar-filter-${f.key}`}
                  onClick={() => onFilter(f.key)}
                  style={{ padding: "3px 9px",
                              background: filter === f.key
                                              ? "rgba(155,123,240,.18)" : "transparent",
                              color: filter === f.key
                                        ? "var(--text)" : "var(--text-dim)",
                              fontSize: 10.5, borderRadius: 4,
                              fontWeight: filter === f.key ? 700 : 500 }}>
          {f.label}
        </button>
      ))}
      <span style={{ flex: 1 }} />
      <span className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
        {nodeCount} nodes · {edgeCount} edges
      </span>
    </div>
  );
}
function ToolbarBtn({ icon: Icon, label, testid, onClick, active }) {
  return (
    <button className="btn ghost" onClick={onClick}
              data-testid={testid}
              style={{ padding: "3px 8px", fontSize: 10.5,
                          background: active ? "rgba(155,123,240,.18)" : "transparent",
                          color: active ? "var(--text)" : "var(--text-dim)",
                          display: "inline-flex", alignItems: "center", gap: 4 }}>
      <Icon size={11} /> {label}
    </button>
  );
}


// Overview minimap — projects the full graph into a tiny viewport
// with a red frame showing the current pan/zoom.  Clicking a spot
// on the minimap does NOT recenter yet (kept simple); this is a
// legibility aid for large investigations.
function Minimap({ nodes, pan, zoom, selectedId, canvasRef }) {
  const size = { w: 140, h: 90 };
  const layout = useMemo(() => {
    if (!nodes.length) return null;
    const xs = nodes.map((n) => n.x), ys = nodes.map((n) => n.y);
    const minX = Math.min(...xs) - 40, maxX = Math.max(...xs) + 40;
    const minY = Math.min(...ys) - 40, maxY = Math.max(...ys) + 40;
    const sx = size.w / Math.max(1, maxX - minX);
    const sy = size.h / Math.max(1, maxY - minY);
    return { minX, minY, sx, sy };
  }, [nodes]);
  if (!layout) return null;
  const project = (x, y) => ({
    x: (x - layout.minX) * layout.sx,
    y: (y - layout.minY) * layout.sy,
  });

  // Compute the viewport rectangle in graph coords → minimap coords.
  const rect = canvasRef.current?.getBoundingClientRect();
  const vp = rect
    ? {
        x1: (-pan.x) / zoom, y1: (-pan.y) / zoom,
        x2: (rect.width  - pan.x) / zoom,
        y2: (rect.height - pan.y) / zoom,
      }
    : null;
  const vpProj = vp && {
    p1: project(vp.x1, vp.y1), p2: project(vp.x2, vp.y2),
  };

  return (
    <div data-testid="xdr-canvas-minimap"
            style={{
              position: "absolute", right: 10, bottom: 40, zIndex: 5,
              width: size.w, height: size.h,
              background: "rgba(10,13,20,.85)",
              border: "1px solid #22293a", borderRadius: 4,
              boxShadow: "0 4px 14px rgba(0,0,0,.5)",
              padding: 3,
            }}>
      <svg width={size.w - 6} height={size.h - 6}
              style={{ display: "block" }}>
        {nodes.map((n) => {
          const p = project(n.x, n.y);
          const meta = NODE_TYPE[n.type] || NODE_TYPE.evidence;
          return (
            <circle key={n.id} cx={p.x} cy={p.y}
                        r={selectedId === n.id ? 3 : 1.8}
                        fill={meta.color}
                        opacity={selectedId === n.id ? 1 : 0.6} />
          );
        })}
        {vpProj && (
          <rect
            x={Math.max(0, Math.min(size.w, vpProj.p1.x))}
            y={Math.max(0, Math.min(size.h, vpProj.p1.y))}
            width={Math.max(0,
                     Math.min(size.w, vpProj.p2.x) -
                     Math.max(0, vpProj.p1.x))}
            height={Math.max(0,
                      Math.min(size.h, vpProj.p2.y) -
                      Math.max(0, vpProj.p1.y))}
            fill="none" stroke="#f87171"
            strokeWidth={1} strokeDasharray="2 2" />
        )}
      </svg>
    </div>
  );
}


function CanvasToolbar({ incidentId, nodeCount, edgeCount,
                                zoom, onZoom, highlight, onClearHighlight }) {
  return (
    <div style={{
      position: "absolute", top: 8, left: 10, right: 10, zIndex: 3,
      display: "flex", alignItems: "center", gap: 8,
      pointerEvents: "none",
    }}>
      <div className="mono" style={{ color: "var(--faint)", fontSize: 10,
                                                pointerEvents: "auto" }}>
        {nodeCount} nodes · {edgeCount} edges
      </div>
      <span style={{ flex: 1 }} />
      {highlight && (
        <button className="btn ghost" onClick={onClearHighlight}
                  data-testid="xdr-canvas-clear-highlight"
                  style={{ padding: "2px 8px", fontSize: 10,
                              pointerEvents: "auto" }}>
          <X size={10} /> Clear highlight
        </button>
      )}
      <div className="mono" style={{ color: "var(--faint)", fontSize: 10,
                                                pointerEvents: "auto" }}>
        <button className="btn ghost" style={{ padding: "2px 6px" }}
                  onClick={() => onZoom(Math.max(0.35, zoom - 0.15))}
                  data-testid="xdr-canvas-zoom-out">−</button>
        <span style={{ padding: "0 6px" }}>{Math.round(zoom * 100)}%</span>
        <button className="btn ghost" style={{ padding: "2px 6px" }}
                  onClick={() => onZoom(Math.min(2.4, zoom + 0.15))}
                  data-testid="xdr-canvas-zoom-in">+</button>
      </div>
    </div>
  );
}


function CanvasLegend() {
  // Semantic edge legend + node type legend.  Every symbol on the
  // canvas has a corresponding entry here — no mystery glyphs.
  const nodeKinds = ["host", "user", "process", "evidence", "response",
                        "technique", "ip", "hash"];
  const edgeKinds = ["parent_of", "executed", "created", "connected_to",
                        "resolved_to", "mapped_to", "responded", "produced"];
  return (
    <div data-testid="xdr-canvas-legend"
            style={{
              position: "absolute", bottom: 8, left: 10, zIndex: 2,
              display: "flex", gap: 16, alignItems: "flex-end",
              maxWidth: "70%",
            }}>
      <div>
        <div className="mono" style={{ fontSize: 9, color: "var(--faint)",
                                                    textTransform: "uppercase",
                                                    letterSpacing: ".3px",
                                                    marginBottom: 3 }}>
          Entities
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
          {nodeKinds.map((k) => {
            const meta = NODE_TYPE[k];
            return (
              <span key={k}
                       style={{ display: "inline-flex", alignItems: "center",
                                   gap: 3, padding: "1px 5px", borderRadius: 3,
                                   border: `1px solid ${meta.color}`,
                                   background: _hexA(meta.color, 0.08),
                                   fontSize: 9, color: meta.color,
                                   fontFamily: "var(--mono)",
                                   letterSpacing: ".3px" }}>
                {meta.label}
              </span>
            );
          })}
        </div>
      </div>
      <div>
        <div className="mono" style={{ fontSize: 9, color: "var(--faint)",
                                                    textTransform: "uppercase",
                                                    letterSpacing: ".3px",
                                                    marginBottom: 3 }}>
          Relationships
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
          {edgeKinds.map((k) => {
            const meta = EDGE_KIND[k];
            return (
              <span key={k}
                       style={{ display: "inline-flex", alignItems: "center",
                                   gap: 4, padding: "1px 5px",
                                   fontSize: 9, color: meta.color,
                                   fontFamily: "var(--mono)",
                                   letterSpacing: ".3px" }}>
                <span style={{ display: "inline-block", width: 12,
                                    borderTop: `${meta.dashed ? "dashed" : "solid"} 1.4px ${meta.color}`,
                                    height: 0 }} />
                {meta.label}
              </span>
            );
          })}
        </div>
      </div>
    </div>
  );
}
function Row({ k, v, mono, copy, small, color }) {
  if (v == null || v === "") return null;
  const style = {
    color: color || "var(--text-dim)",
    fontFamily: mono ? "var(--mono)" : "inherit",
    fontSize: small ? 10.5 : 11,
    wordBreak: "break-all",
  };
  return (
    <div style={{ display: "flex", justifyContent: "space-between",
                    gap: 6, padding: "3px 0",
                    borderBottom: "1px solid var(--border)" }}>
      <span style={{ color: "var(--faint)", fontSize: 10.5,
                        textTransform: "uppercase", letterSpacing: ".3px" }}>{k}</span>
      <span style={style}>
        {v}
        {copy && typeof v === "string" && (
          <button className="btn ghost" style={{ padding: 2, marginLeft: 4 }}
                    onClick={() => navigator.clipboard?.writeText(v)}
                    title="Copy">
            <Copy size={9} />
          </button>
        )}
      </span>
    </div>
  );
}


/* ───────────────────────────── helpers ───────────────────────────── */
function _short(s, n = 24) {
  s = String(s || "");
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
function _hexA(hex, a) {
  // Small alpha helper for arbitrary named or hex color inputs.
  if (hex?.startsWith?.("#") && hex.length === 7) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgba(${r},${g},${b},${a})`;
  }
  return hex;
}
function _nodeMatches(node, h) {
  if (!h) return true;
  if (h.tactic) {
    // Match technique nodes whose tactic == h.tactic; and evidence /
    // response nodes whose technique_id resolves to that tactic.
    if (node.type === "technique") {
      const tid = node.title;
      const meta = TECHNIQUE_INDEX[tid];
      return meta?.tactic === h.tactic;
    }
    if (node.type === "evidence" || node.type === "response") {
      const rid = String(node.raw?.rule_id || "").toUpperCase();
      const tid = node.raw?.technique_id || RULE_TO_TECHNIQUE[rid];
      if (!tid) return false;
      return TECHNIQUE_INDEX[tid]?.tactic === h.tactic;
    }
    if (node.type === "incident") return true;
    return false;
  }
  if (h.technique_id && node.type === "technique") return node.title === h.technique_id;
  if (h.technique_id && node.type === "evidence") {
    const rid = String(node.raw?.rule_id || "").toUpperCase();
    return (node.raw?.technique_id === h.technique_id) ||
              (RULE_TO_TECHNIQUE[rid] === h.technique_id);
  }
  if (h.rule_id && node.type === "evidence")
    return String(node.raw?.rule_id || "") === String(h.rule_id || "");
  // Response nodes that produced evidence with this rule_id count too.
  if (h.rule_id && node.type === "response") {
    return String(node.raw?.rule_id || "") === String(h.rule_id || "");
  }
  if (h.technique_id && node.type === "incident") return true;
  if (h.rule_id      && node.type === "incident") return true;
  return false;
}
function _edgeMatches(edge, s, t, h) {
  return _nodeMatches(s, h) || _nodeMatches(t, h);
}


// ═══════════════════════════════════════════════════════════════════
// TacticRibbon — evidence-driven MITRE ATT&CK tactic filter strip.
// Sits directly above the Evidence Trajectory canvas.
//
// Rule per owner directive:
//   Evidence → Observed technique → ATT&CK mapping → Tactic
//   The ribbon is NEVER derived from the verdict.
// ═══════════════════════════════════════════════════════════════════
function TacticRibbon({ nodes, highlight, onSelectTactic, onClear,
                                                onSelectTechnique }) {
  const activeKey = highlight?.tactic || null;
  const [openTactic, setOpenTactic] = React.useState(null);
  // Aggregate evidence-linked technique observations per tactic.
  // We track per-technique metadata deterministically from the graph:
  //   evidenceCount, hosts, users, processes, ruleIds, firstSeen, lastSeen.
  //   NEVER derived from the verdict.
  const stats = React.useMemo(() => {
    // techId → {tactic, name, evidence, hosts, users, processes,
    //           ruleIds:Set, firstSeen, lastSeen}
    const byTech = new Map();
    for (const n of (nodes || [])) {
      let tid = null;
      if (n.type === "technique") tid = n.title;
      else if (n.type === "evidence" || n.type === "response") {
        const rid = String(n.raw?.rule_id || "").toUpperCase();
        tid = n.raw?.technique_id || RULE_TO_TECHNIQUE[rid] || null;
      } else continue;
      if (!tid) continue;
      const meta = TECHNIQUE_INDEX[tid];
      const tactic = meta?.tactic;
      if (!tactic) continue;
      const row = byTech.get(tid) || {
        technique_id: tid, name: meta?.technique_name || tid, tactic,
        evidence: 0, hosts: new Set(), users: new Set(), processes: new Set(),
        ruleIds: new Set(), firstSeen: null, lastSeen: null,
      };
      // Count only rows that are actual EVIDENCE observations — a bare
      // ATT&CK-knowledge technique node without evidence should NOT
      // inflate the evidence count.
      if (n.type === "evidence" || n.type === "response") {
        row.evidence += 1;
        const rid = n.raw?.rule_id;
        if (rid) row.ruleIds.add(String(rid));
        const ts = n.raw?.first_seen || n.raw?.timestamp || n.raw?.ts;
        if (ts) {
          if (!row.firstSeen || ts < row.firstSeen) row.firstSeen = ts;
          if (!row.lastSeen  || ts > row.lastSeen)  row.lastSeen  = ts;
        }
      }
      const h = n.raw?.host || n.raw?.hostname;
      if (h) row.hosts.add(h);
      const u = n.raw?.user || n.raw?.username;
      if (u) row.users.add(u);
      const p = n.raw?.process || n.raw?.process_name;
      if (p) row.processes.add(p);
      byTech.set(tid, row);
    }
    // Bucket per tactic and sort by evidence count desc.
    const byTactic = {};
    for (const row of byTech.values()) {
      // ANTI-FABRICATION invariant: a technique with 0 evidence is only
      // kept when it appeared as a first-class technique node — never
      // manufacture entries from rule mappings alone.
      const hasEvidence = row.evidence > 0
              || (nodes || []).some(
                    (n) => n.type === "technique" && n.title === row.technique_id);
      if (!hasEvidence) continue;
      (byTactic[row.tactic] = byTactic[row.tactic] || []).push(row);
    }
    for (const k of Object.keys(byTactic)) {
      byTactic[k].sort((a, b) => b.evidence - a.evidence);
    }
    return byTactic;
  }, [nodes]);

  const counts = React.useMemo(() => {
    const c = {};
    for (const k of Object.keys(stats)) {
      c[k] = stats[k].reduce((s, r) => s + r.evidence, 0)
                || stats[k].length;
    }
    return c;
  }, [stats]);

  return (
    <div data-testid="xdr-tactic-ribbon"
              style={{ marginTop: 8, padding: "6px 10px",
                              background: "var(--panel)",
                              border: "1px solid var(--border)",
                              borderRadius: 4,
                              display: "flex", alignItems: "center", gap: 8,
                              flexWrap: "wrap", position: "relative" }}>
      <span style={{ fontFamily: "var(--mono)", fontSize: 9,
                              color: "var(--faint)", fontWeight: 700,
                              textTransform: "uppercase", letterSpacing: ".4px" }}>
        Tactics
      </span>
      {KILL_CHAIN.map((t) => {
        const n = counts[t.key] || 0;
        const active   = activeKey === t.key;
        const touched  = n > 0;
        const color    = touched
          ? (active ? "var(--cyan)" : "var(--text)")
          : "var(--faint)";
        return (
          <div key={t.key} style={{ position: "relative" }}>
            <button data-testid={`xdr-tactic-ribbon-${t.key}`}
                          disabled={!touched}
                          onClick={() => {
                            onSelectTactic(t.key);
                            setOpenTactic((cur) => cur === t.key ? null : t.key);
                          }}
                          title={touched ? `${n} evidence-linked technique(s) — click for breakdown`
                                                      : "No evidence for this tactic in this investigation"}
                          style={{
                            padding: "3px 8px", borderRadius: 3,
                            border: `1px solid ${active
                                                                ? "var(--cyan)"
                                                                : (touched ? "var(--border)"
                                                                                  : "transparent")}`,
                            background: touched ? "var(--panel2)" : "transparent",
                            color, cursor: touched ? "pointer" : "default",
                            opacity: touched ? 1 : 0.45,
                            fontFamily: "var(--mono)", fontSize: 10,
                            fontWeight: 700, letterSpacing: ".3px" }}>
              {t.label}{touched && ` · ${n}`}
            </button>
            {openTactic === t.key && touched && (
              <TechniqueBreakdown
                tactic={t}
                rows={stats[t.key] || []}
                onSelectTechnique={(tid) => {
                  onSelectTechnique(tid);
                  setOpenTactic(null);
                }}
                onClose={() => setOpenTactic(null)}
              />
            )}
          </div>
        );
      })}
      {activeKey && (
        <button data-testid="xdr-tactic-ribbon-clear"
                      onClick={() => { onClear(); setOpenTactic(null); }}
                      style={{ marginLeft: "auto",
                                      padding: "3px 8px", borderRadius: 3,
                                      border: "1px solid var(--amber)",
                                      color: "var(--amber)",
                                      background: "transparent",
                                      cursor: "pointer",
                                      fontFamily: "var(--mono)", fontSize: 10,
                                      fontWeight: 700 }}>
          Clear filter
        </button>
      )}
    </div>
  );
}


function TechniqueBreakdown({ tactic, rows, onSelectTechnique, onClose }) {
  const [showAll, setShowAll] = React.useState(false);
  const visible = showAll ? rows : rows.slice(0, 8);
  return (
    <div data-testid={`xdr-technique-breakdown-${tactic.key}`}
              onClick={(e) => e.stopPropagation()}
              style={{
                position: "absolute", top: "calc(100% + 4px)", left: 0,
                minWidth: 320, maxWidth: 420, zIndex: 40,
                background: "var(--panel)",
                border: "1px solid var(--cyan)",
                borderRadius: 4,
                boxShadow: "0 6px 20px rgba(0,0,0,.35)",
                padding: 8, fontFamily: "var(--mono)", fontSize: 10.5 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6,
                              marginBottom: 6,
                              borderBottom: "1px solid var(--border)",
                              paddingBottom: 4 }}>
        <b style={{ color: "var(--cyan)", fontSize: 10.5,
                            textTransform: "uppercase", letterSpacing: ".3px" }}>
          {tactic.label}
        </b>
        <span style={{ color: "var(--faint)" }}>
          · {rows.length} technique{rows.length === 1 ? "" : "s"}
        </span>
        <span style={{ flex: 1 }} />
        <button onClick={onClose}
                      data-testid={`xdr-technique-breakdown-close-${tactic.key}`}
                      style={{ background: "transparent", border: 0,
                                      color: "var(--faint)", cursor: "pointer",
                                      fontSize: 12 }}>×</button>
      </div>
      {rows.length === 0 && (
        <div style={{ color: "var(--faint)" }}>
          No evidence-linked techniques observed.
        </div>
      )}
      {visible.map((r) => (
        <div key={r.technique_id}
                    data-testid={`xdr-technique-row-${r.technique_id}`}
                    onClick={() => onSelectTechnique(r.technique_id)}
                    style={{ padding: "4px 6px", cursor: "pointer",
                                    borderRadius: 2,
                                    display: "grid",
                                    gridTemplateColumns: "auto 1fr auto",
                                    columnGap: 8, alignItems: "baseline",
                                    borderBottom: "1px dashed var(--border)" }}>
          <span style={{ color: "var(--cyan)", fontWeight: 700 }}>
            {r.technique_id}
          </span>
          <span style={{ color: "var(--text)", overflow: "hidden",
                                  textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {r.name}
          </span>
          <span style={{ color: "var(--faint)" }}>
            {r.evidence} evidence
          </span>
          <span />
          <span style={{ color: "var(--faint)", fontSize: 9.5,
                                    gridColumn: "2 / span 2" }}>
            {r.hosts.size    ? `hosts=${r.hosts.size} `        : ""}
            {r.users.size    ? `users=${r.users.size} `        : ""}
            {r.processes.size? `procs=${r.processes.size} `    : ""}
            {r.ruleIds.size  ? `rules=${r.ruleIds.size} `      : ""}
            {r.firstSeen     ? `first=${String(r.firstSeen).slice(11,19)}Z ` : ""}
            {r.lastSeen      ? `last=${String(r.lastSeen).slice(11,19)}Z`    : ""}
          </span>
        </div>
      ))}
      {rows.length > 8 && !showAll && (
        <button data-testid={`xdr-technique-breakdown-view-all-${tactic.key}`}
                      onClick={() => setShowAll(true)}
                      style={{ marginTop: 6, width: "100%",
                                      padding: "3px 6px", borderRadius: 2,
                                      background: "var(--panel2)",
                                      border: "1px solid var(--border)",
                                      color: "var(--text-dim)", cursor: "pointer",
                                      fontFamily: "var(--mono)", fontSize: 10 }}>
          View all techniques ({rows.length})
        </button>
      )}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════
// ProcessChainPanel — parent → child process ancestry.
// Reads directly from the investigation graph (process nodes +
// parent_of edges).  Never fabricates a process; if there are no
// process nodes, the panel renders an honest empty state.
// ═══════════════════════════════════════════════════════════════════
function ProcessChainPanel({ nodes, edges, selectedId, onSelect }) {
  const trees = React.useMemo(() => {
    const procs = (nodes || []).filter((n) => n.type === "process");
    if (!procs.length) return [];
    const byId = new Map(procs.map((p) => [p.id, p]));
    const parentEdges = (edges || []).filter((e) => e.kind === "parent_of");
    const parentOf = new Map();   // childId → parentId
    const childrenOf = new Map(); // parentId → [childId]
    for (const e of parentEdges) {
      if (byId.has(e.source) && byId.has(e.target)) {
        parentOf.set(e.target, e.source);
        const arr = childrenOf.get(e.source) || [];
        arr.push(e.target);
        childrenOf.set(e.source, arr);
      }
    }
    const roots = procs.filter((p) => !parentOf.has(p.id));
    const build = (id, depth) => {
      const kids = (childrenOf.get(id) || [])
        .map((cid) => build(cid, depth + 1));
      return { node: byId.get(id), depth, children: kids };
    };
    return roots.map((r) => build(r.id, 0));
  }, [nodes, edges]);

  return (
    <div className="panel" data-testid="xdr-process-chain-panel"
              style={{ display: "flex", flexDirection: "column",
                              minHeight: 0, maxHeight: 240 }}>
      <div style={{ padding: "6px 10px",
                              borderBottom: "1px solid var(--border)",
                              fontFamily: "var(--mono)", fontSize: 10.5,
                              fontWeight: 700, color: "var(--text-dim)",
                              textTransform: "uppercase", letterSpacing: ".4px" }}>
        Process Chain (parent → child)
      </div>
      <div style={{ overflow: "auto", padding: "6px 10px",
                              fontFamily: "var(--mono)", fontSize: 11,
                              lineHeight: 1.55 }}>
        {trees.length === 0 && (
          <div style={{ color: "var(--faint)", fontSize: 10.5 }}>
            No process evidence in this investigation.
          </div>
        )}
        {trees.map((root) => (
          <ProcessNodeRow key={root.node.id} tree={root}
                                        selectedId={selectedId}
                                        onSelect={onSelect} />
        ))}
      </div>
    </div>
  );
}


function ProcessNodeRow({ tree, selectedId, onSelect, isLast = true,
                                                prefix = "" }) {
  const { node, children } = tree;
  const isSel = selectedId === node.id;
  const connector = prefix === "" ? "" : (isLast ? "└─ " : "├─ ");
  return (
    <>
      <div data-testid={`xdr-process-chain-${node.id}`}
                onClick={() => onSelect(node.id)}
                style={{ cursor: "pointer",
                                color: isSel ? "var(--cyan)" : "var(--text)",
                                whiteSpace: "nowrap",
                                background: isSel ? "rgba(56,189,248,.08)"
                                                                  : "transparent",
                                padding: "1px 2px", borderRadius: 2 }}>
        <span style={{ color: "var(--faint)" }}>{prefix}{connector}</span>
        <span style={{ fontWeight: 700 }}>{node.title || node.id}</span>
        {node.raw?.pid && (
          <span style={{ color: "var(--faint)", marginLeft: 6 }}>
            pid={node.raw.pid}
          </span>
        )}
      </div>
      {children.map((c, i) => (
        <ProcessNodeRow key={c.node.id} tree={c}
                                      selectedId={selectedId} onSelect={onSelect}
                                      isLast={i === children.length - 1}
                                      prefix={prefix + (isLast ? "   " : "│  ")} />
      ))}
    </>
  );
}
