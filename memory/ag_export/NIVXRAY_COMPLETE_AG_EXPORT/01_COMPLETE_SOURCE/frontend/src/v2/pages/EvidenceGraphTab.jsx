/**
 * EvidenceGraphTab — Interactive causality graph over the Investigation
 * Knowledge Graph (IKG).
 *
 * Three modes:
 *   1. Causality (default)     — top-to-bottom chain: subject → action → target
 *   2. Entity Relationship     — subject centered; artifacts branch outward
 *   3. Time Overlay            — nodes fade by age; edges labelled with timestamps
 *
 * Features:
 *   - Zoom (wheel) / Pan (drag) / Fit / Reset
 *   - Search box (matches name / iid)
 *   - Node type filters (process / file / network / registry / service / user)
 *   - Edge type filters (spawned / created / modified / deleted / contacted / loaded)
 *   - SelectionContext synchronization (click → selects across every tab)
 *   - Legend (colour codes)
 *
 * Data model:
 *   IKG delivers `nodes` (process, file, network, event, verdict, technique,
 *   incident, device) and `edges` (executed_by, spawned, modified, contacted,
 *   deleted, maps_to, contributes_to, rollup_of, hosted_on, part_of).
 *
 *   We project the IKG into an entity-only graph by joining
 *     event.executed_by --> process   (the actor)
 *     event.(modified|contacted|deleted|spawned) --> target
 *   producing synthetic entity-to-entity edges labelled by the event's
 *   action (spawned / modified / contacted / deleted / …).
 *
 *   Standalone process-to-process `spawned` edges are preserved as-is.
 */
import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import {
  Search, Radar, Cpu, File as FileIcon, Database, Globe, User,
  Terminal, Cog, ZoomIn, ZoomOut, Maximize2, RefreshCw, GitBranch,
  Network as NetIcon, Layers,
} from "lucide-react";
import { T } from "../theme";
import { useSelection } from "./SelectionContext";

// ─── Theme mapping ──────────────────────────────────────────────
const NODE_COLOR = {
  process:  { fill: "#1E293B", stroke: "#94A3B8",  text: "#F1F5F9", icon: Cpu     },
  file:     { fill: "#0C2A46", stroke: "#38BDF8",  text: "#E0F2FE", icon: FileIcon},
  registry: { fill: "#3B1E5B", stroke: "#C084FC",  text: "#F3E8FF", icon: Database},
  network:  { fill: "#0F3730", stroke: "#34D399",  text: "#D1FAE5", icon: Globe   },
  service:  { fill: "#3A2E10", stroke: "#EAB308",  text: "#FEF3C7", icon: Cog     },
  user:     { fill: "#2A2A2A", stroke: "#A1A1AA",  text: "#F4F4F5", icon: User    },
  command:  { fill: "#1A1A1A", stroke: "#EF4444",  text: "#FEE2E2", icon: Terminal},
  event:    { fill: "#0F1729", stroke: "#64748B",  text: "#94A3B8", icon: Radar   },
};
const EDGE_COLOR = {
  spawned:   "#F59E0B",  // amber
  created:   "#22C55E",  // green
  modified:  "#3B82F6",  // blue
  deleted:   "#EF4444",  // red
  loaded:    "#A855F7",  // violet
  injected:  "#EC4899",  // pink
  contacted: "#14B8A6",  // teal
  resolved:  "#0EA5E9",  // sky
  executed:  "#F59E0B",  // amber (alias of spawned)
  persisted: "#8B5CF6",  // purple
  default:   "#64748B",  // slate
};

// Mapping from event.action → canonical edge label.
function actionToEdge(action) {
  const a = String(action || "").toLowerCase();
  if (/(spawn|process[_ ]create|launch|invoke|run)/.test(a)) return "spawned";
  if (/(create|write|drop|add|new|persist|install)/.test(a)) return "created";
  if (/(modify|change|edit|rename)/.test(a))                return "modified";
  if (/(delete|remove|purge|wipe)/.test(a))                 return "deleted";
  if (/(load|import|dll)/.test(a))                          return "loaded";
  if (/(inject|hollow)/.test(a))                            return "injected";
  if (/(connect|beacon|http|dns|network|c2|contact)/.test(a)) return "contacted";
  if (/(resolve|dns)/.test(a))                              return "resolved";
  if (/(execute|exec|ran)/.test(a))                         return "executed";
  return "executed";  // safe fallback
}

// Map raw IKG edge type → user-visible edge type.
const EDGE_TYPE_ALIAS = {
  spawned: "spawned", modified: "modified", contacted: "contacted",
  deleted: "deleted", created: "created", loaded: "loaded",
  injected: "injected", resolved: "resolved", persisted: "persisted",
};

// ═══════════════════════════════════════════════════════════════════
export default function EvidenceGraphTab({ inv }) {
  const { selection, setSelection } = useSelection();
  const nodesRaw = inv?.ikg?.nodes || [];
  const edgesRaw = inv?.ikg?.edges || [];

  // ─── Project IKG into entity-to-entity causality graph ──────────
  const { entities, causalEdges, tsBounds } = useMemo(() => {
    const eventById = new Map();
    const entityById = new Map();
    for (const n of nodesRaw) {
      if (n.type === "event") eventById.set(n.id, n);
      else if (["process","file","registry","network","service","user","command"].includes(n.type)) {
        entityById.set(n.id, n);
      }
    }
    // For each event, find its actor (executed_by) and its target(s).
    const actorOf = new Map();     // event id → actor process id
    const targetsOf = new Map();   // event id → [{ target, type }]
    for (const e of edgesRaw) {
      if (e.type === "executed_by") {
        // event → process
        actorOf.set(e.source, e.target);
      }
    }
    // Any edge whose source is an event AND target is an entity is a
    // "target" relationship. Also treat direct process→process spawned
    // as a standalone causal edge.
    const causal = [];
    for (const e of edgesRaw) {
      const alias = EDGE_TYPE_ALIAS[e.type];
      if (!alias) continue;
      const srcIsEvent  = eventById.has(e.source);
      const tgtIsEntity = entityById.has(e.target);
      if (srcIsEvent && tgtIsEntity) {
        const actor = actorOf.get(e.source);
        if (actor && entityById.has(actor)) {
          const evNode = eventById.get(e.source);
          causal.push({
            source:  actor,
            target:  e.target,
            edgeType: alias,
            ts: evNode?.attrs?.ts || null,
            eventId: e.source,
            action: evNode?.attrs?.action,
            mitre: evNode?.attrs?.mitre || [],
          });
        }
      }
      // Direct process→process spawned edge (no event pivot).
      if (!srcIsEvent && entityById.has(e.source) && entityById.has(e.target)) {
        causal.push({
          source: e.source, target: e.target,
          edgeType: alias, ts: null,
        });
      }
    }
    // Also derive `executed` edges for events that have no target
    // (e.g. process_create without extra rel). Actor spawned a temp
    // process — surface actor→actor edge would loop; skip. But if the
    // event has a `mitre` chain that implies a distinct child process,
    // fall back to actionToEdge(event.action).
    // Compute case time bounds from every entity's first_seen.
    let lo = Infinity, hi = -Infinity;
    for (const [, n] of entityById) {
      const t = tsMs(n.attrs?.first_seen);
      if (t != null) { if (t < lo) lo = t; if (t > hi) hi = t; }
    }
    for (const c of causal) {
      const t = tsMs(c.ts);
      if (t != null) { if (t < lo) lo = t; if (t > hi) hi = t; }
    }
    if (!Number.isFinite(lo)) { lo = 0; hi = 1; }
    if (lo === hi) hi = lo + 1;
    return {
      entities: [...entityById.values()],
      causalEdges: causal,
      tsBounds: { lo, hi },
    };
  }, [nodesRaw, edgesRaw]);

  // ─── UI state ────────────────────────────────────────────────
  const [mode, setMode] = useState("causality");
  const [zoom, setZoom] = useState(1);
  const [pan, setPan]   = useState({ x: 0, y: 0 });
  const [query, setQuery] = useState("");
  const [nodeFilter, setNodeFilter] = useState({
    process: true, file: true, registry: true, network: true,
    service: true, user: true, command: true,
  });
  const [edgeFilter, setEdgeFilter] = useState({
    spawned: true, created: true, modified: true, deleted: true,
    loaded: true, injected: true, contacted: true, resolved: true,
    executed: true, persisted: true,
  });
  const [timeRange, setTimeRange] = useState(1.0);  // 0..1 = fraction of case span from start

  const svgWrapRef = useRef(null);
  const [size, setSize] = useState({ w: 900, h: 620 });
  useEffect(() => {
    if (!svgWrapRef.current) return;
    const el = svgWrapRef.current;
    const update = () => setSize({ w: el.clientWidth, h: Math.max(400, el.clientHeight) });
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // ─── Filter entities + edges by search / type / time ─────────
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const maxTs = tsBounds.lo + (tsBounds.hi - tsBounds.lo) * timeRange;
    const passesTime = (t) => {
      if (t == null) return true;
      const ms = tsMs(t);
      return ms == null || ms <= maxTs;
    };
    const matchQ = (n) => {
      if (!q) return true;
      const hay = `${n.label || ""} ${n.id || ""} ${n.type || ""}`.toLowerCase();
      return hay.includes(q);
    };
    const nodesById = new Map(entities.map(n => [n.id, n]));
    const survivingEdges = causalEdges.filter(e => {
      if (edgeFilter[e.edgeType] === false) return false;
      if (!passesTime(e.ts)) return false;
      const s = nodesById.get(e.source), t = nodesById.get(e.target);
      if (!s || !t) return false;
      if (nodeFilter[s.type] === false || nodeFilter[t.type] === false) return false;
      // Search widens the neighbourhood: an edge survives if either
      // endpoint matches the query.
      if (q && !(matchQ(s) || matchQ(t))) return false;
      return true;
    });
    // Keep nodes that survive filter AND are attached to a surviving
    // edge, OR nodes that directly match the query.
    const attached = new Set();
    for (const e of survivingEdges) { attached.add(e.source); attached.add(e.target); }
    const survivingNodes = entities.filter(n => {
      if (nodeFilter[n.type] === false) return false;
      const t = tsMs(n.attrs?.first_seen);
      if (t != null && t > maxTs) return false;
      if (q) return matchQ(n) || attached.has(n.id);
      return attached.has(n.id) || causalEdges.length === 0;
    });
    return { nodes: survivingNodes, edges: survivingEdges };
  }, [entities, causalEdges, query, nodeFilter, edgeFilter, timeRange, tsBounds]);

  // ─── Layout (depends on mode) ────────────────────────────────
  const positioned = useMemo(() => {
    if (mode === "entity_rel") return layoutEntityRelationship(filtered);
    if (mode === "time_overlay") return layoutTimeOverlay(filtered, tsBounds);
    return layoutCausality(filtered);
  }, [filtered, mode, tsBounds]);

  // ─── Zoom / pan handlers ─────────────────────────────────────
  const onWheel = (e) => {
    e.preventDefault();
    const factor = e.deltaY > 0 ? 0.9 : 1.1;
    setZoom(z => clamp(z * factor, 0.15, 6));
  };
  const dragRef = useRef(null);
  const onMouseDown = (e) => {
    if (e.button !== 0) return;
    if (e.target && (e.target.dataset?.role === "node")) return;  // let node click through
    dragRef.current = { x: e.clientX, y: e.clientY, ox: pan.x, oy: pan.y };
  };
  const onMouseMove = (e) => {
    if (!dragRef.current) return;
    setPan({
      x: dragRef.current.ox + (e.clientX - dragRef.current.x),
      y: dragRef.current.oy + (e.clientY - dragRef.current.y),
    });
  };
  const onMouseUp   = () => { dragRef.current = null; };
  useEffect(() => {
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const doFit = useCallback(() => {
    if (!positioned.nodes.length) { setZoom(1); setPan({x:0, y:0}); return; }
    let lo = { x: Infinity, y: Infinity }, hi = { x: -Infinity, y: -Infinity };
    for (const n of positioned.nodes) {
      lo.x = Math.min(lo.x, n.x); lo.y = Math.min(lo.y, n.y);
      hi.x = Math.max(hi.x, n.x); hi.y = Math.max(hi.y, n.y);
    }
    const w = Math.max(1, hi.x - lo.x + 260);
    const h = Math.max(1, hi.y - lo.y + 160);
    const z = clamp(Math.min(size.w / w, size.h / h), 0.15, 3);
    setZoom(z);
    setPan({
      x: (size.w - (lo.x + hi.x) * z) / 2,
      y: (size.h - (lo.y + hi.y) * z) / 2,
    });
  }, [positioned.nodes, size]);
  useEffect(() => { doFit(); }, [mode, doFit]);

  // ─── SelectionContext sync ───────────────────────────────────
  const selectedId = selection?.id || selection?.process_iid || selection?.frame_iid || null;
  const handleNodeClick = (n) => {
    if (n.type === "process") {
      setSelection({ kind: "process", id: n.id, process_iid: n.id, source: "graph" });
    } else {
      setSelection({ kind: "event", id: n.id, source: "graph" });
    }
  };

  // ─── Render ──────────────────────────────────────────────────
  const modes = [
    { key: "causality",    label: "Causality",    icon: GitBranch },
    { key: "entity_rel",   label: "Entity Rel.",  icon: NetIcon   },
    { key: "time_overlay", label: "Time Overlay", icon: Layers    },
  ];
  const nodeStats = countBy(filtered.nodes, "type");
  const edgeStats = countBy(filtered.edges, "edgeType");

  return (
    <div className="flex flex-col min-h-0" data-testid="evidence-graph-tab"
         style={{ background: T.bg, color: T.ink, height: "calc(100vh - 260px)" }}>
      {/* Toolbar */}
      <div className="flex items-center gap-3 px-4 py-2 flex-shrink-0"
           style={{ borderBottom: `1px solid ${T.line}`, background: T.paper }}>
        <div className="flex items-center rounded overflow-hidden"
             style={{ background: T.paper2, border: `1px solid ${T.line}` }}
             data-testid="graph-mode-tabs">
          {modes.map(m => (
            <button key={m.key}
                    data-testid={`graph-mode-${m.key}`}
                    onClick={() => setMode(m.key)}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-semibold"
                    style={{
                      color: mode === m.key ? "#05080F" : T.inkDim,
                      background: mode === m.key ? T.amber : "transparent",
                    }}>
              <m.icon size={12} /> {m.label}
            </button>
          ))}
        </div>
        <div className="relative flex-1 max-w-sm">
          <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2"
                  style={{ color: T.inkFaint }} />
          <input type="text" placeholder="Search entities"
                 data-testid="graph-search-input"
                 value={query} onChange={(e) => setQuery(e.target.value)}
                 onKeyDown={(e) => { if (e.key === "Escape") setQuery(""); }}
                 className="w-full pl-7 pr-7 py-1 rounded text-[11px] outline-none"
                 style={{ background: T.paper2, border: `1px solid ${T.line}`, color: T.ink }} />
          {query && (
            <button data-testid="graph-search-clear"
                    onClick={() => setQuery("")}
                    className="absolute right-1 top-1/2 -translate-y-1/2 w-4 h-4 rounded-full text-[10px] font-bold"
                    style={{ background: T.paper, color: T.inkDim, border: `1px solid ${T.line}` }}>
              ×
            </button>
          )}
        </div>
        <div className="text-[10px] font-mono flex items-center gap-3" style={{ color: T.inkMute }}>
          <span data-testid="graph-node-count">{filtered.nodes.length} nodes</span>
          <span data-testid="graph-edge-count">{filtered.edges.length} edges</span>
        </div>
        <div className="flex items-center gap-1">
          <IconBtn onClick={() => setZoom(z => clamp(z * 1.2, 0.15, 6))} label="Zoom in"  icon={ZoomIn}     testId="graph-zoom-in"  />
          <IconBtn onClick={() => setZoom(z => clamp(z / 1.2, 0.15, 6))} label="Zoom out" icon={ZoomOut}    testId="graph-zoom-out" />
          <IconBtn onClick={doFit}                                       label="Fit"      icon={Maximize2}  testId="graph-fit"      />
          <IconBtn onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }} label="Reset" icon={RefreshCw}  testId="graph-reset"    />
        </div>
      </div>

      {/* Body — canvas + left rail */}
      <div className="flex flex-1 min-h-0">
        {/* Filters rail */}
        <aside className="w-52 flex-shrink-0 overflow-y-auto p-3 space-y-4"
               data-testid="graph-filter-rail"
               style={{ background: T.paper, borderRight: `1px solid ${T.line}` }}>
          <FilterGroup label="Node types" testIdPrefix="node-filter"
                       items={Object.keys(NODE_COLOR).filter(t => t !== "event")}
                       values={nodeFilter} setValues={setNodeFilter}
                       counts={nodeStats} colorMap={(t) => NODE_COLOR[t]?.stroke} />
          <FilterGroup label="Edge types" testIdPrefix="edge-filter"
                       items={["spawned","created","modified","deleted","loaded","injected","contacted","resolved","executed","persisted"]}
                       values={edgeFilter} setValues={setEdgeFilter}
                       counts={edgeStats} colorMap={(t) => EDGE_COLOR[t] || EDGE_COLOR.default} />
          <div>
            <div className="text-[10px] tracking-[1.4px] font-bold mb-2"
                 style={{ color: T.inkMute }}>TIME FILTER</div>
            <input type="range" min="0" max="1" step="0.01"
                   data-testid="graph-time-range"
                   value={timeRange}
                   onChange={(e) => setTimeRange(parseFloat(e.target.value))}
                   className="w-full" />
            <div className="text-[9px] font-mono mt-1" style={{ color: T.inkFaint }}>
              up to +{fmtRel((tsBounds.hi - tsBounds.lo) * timeRange)}
              <span className="ml-2" style={{ color: timeRange < 1 ? T.amber : T.inkFaint }}>
                {timeRange < 1 ? "focused" : "all time"}
              </span>
            </div>
          </div>
          <div>
            <div className="text-[10px] tracking-[1.4px] font-bold mb-1"
                 style={{ color: T.inkMute }}>LEGEND</div>
            <div className="text-[10px] space-y-1" style={{ color: T.inkDim }}>
              <div>• Solid pill = entity</div>
              <div>• Line colour = relationship</div>
              <div>• Amber ring = selected</div>
              <div>• Red border = malicious</div>
              <div>• Click any node to sync every tab</div>
            </div>
          </div>
        </aside>

        {/* SVG canvas */}
        <div ref={svgWrapRef}
             className="relative flex-1 min-h-0 overflow-hidden select-none"
             onWheel={onWheel} onMouseDown={onMouseDown}
             data-testid="graph-canvas-wrap"
             style={{ background: T.paper, cursor: dragRef.current ? "grabbing" : "grab" }}>
          <svg width={size.w} height={size.h}
               data-testid="graph-canvas-svg"
               style={{ display: "block" }}>
            <defs>
              {Object.entries(EDGE_COLOR).map(([k, c]) => (
                <marker key={k} id={`arr-${k}`} viewBox="0 0 10 10" refX="9" refY="5"
                        markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill={c} />
                </marker>
              ))}
            </defs>
            <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
              {/* Edges */}
              {positioned.edges.map((e, i) => (
                <EdgePath key={`ed-${i}`} e={e} mode={mode}
                          selectedId={selectedId} tsBounds={tsBounds} />
              ))}
              {/* Nodes */}
              {positioned.nodes.map(n => (
                <NodeGroup key={n.id} node={n} mode={mode}
                           selected={selectedId === n.id}
                           onClick={() => handleNodeClick(n)}
                           tsBounds={tsBounds} />
              ))}
            </g>
          </svg>
          {positioned.nodes.length === 0 && (
            <div className="absolute inset-0 flex items-center justify-center text-[12px]"
                 style={{ color: T.inkMute }}
                 data-testid="graph-empty">
              {query
                ? `No entities match "${query}". Clear the search or widen the filters.`
                : "No causal relationships in the current filter. Enable more node/edge types."}
            </div>
          )}
          <div className="absolute bottom-2 right-3 text-[9px] font-mono"
               style={{ color: T.inkFaint }}>
            zoom {(zoom * 100).toFixed(0)}% · scroll = zoom · drag = pan
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Sub-components ─────────────────────────────────────────────
function IconBtn({ icon: Icon, label, onClick, testId }) {
  return (
    <button onClick={onClick} title={label} data-testid={testId}
            className="w-7 h-7 rounded flex items-center justify-center"
            style={{ background: T.paper2, border: `1px solid ${T.line}`, color: T.ink }}>
      <Icon size={12} />
    </button>
  );
}

function FilterGroup({ label, items, values, setValues, counts, colorMap, testIdPrefix }) {
  const toggle = (k) => setValues(v => ({ ...v, [k]: !v[k] }));
  return (
    <div>
      <div className="text-[10px] tracking-[1.4px] font-bold mb-2" style={{ color: T.inkMute }}>
        {label.toUpperCase()}
      </div>
      <div className="space-y-1">
        {items.map(k => (
          <label key={k}
                 data-testid={`${testIdPrefix}-${k}`}
                 className="flex items-center gap-2 text-[11px] cursor-pointer"
                 style={{ color: values[k] ? T.ink : T.inkFaint }}>
            <input type="checkbox" checked={!!values[k]} onChange={() => toggle(k)} />
            <span className="w-2 h-2 rounded-full"
                  style={{ background: colorMap(k) || T.gray }} />
            <span className="flex-1 font-mono">{k}</span>
            <span className="text-[9px]" style={{ color: T.inkFaint }}>{counts[k] || 0}</span>
          </label>
        ))}
      </div>
    </div>
  );
}

function NodeGroup({ node, mode, selected, onClick, tsBounds }) {
  const c = NODE_COLOR[node.type] || NODE_COLOR.event;
  const Icon = c.icon;
  const label = (node.label || node.id || "").slice(0, 22);
  const ts = tsMs(node.attrs?.first_seen);
  // Fade by age in time-overlay mode.
  let opacity = 1;
  if (mode === "time_overlay" && ts != null) {
    const frac = (ts - tsBounds.lo) / Math.max(1, tsBounds.hi - tsBounds.lo);
    opacity = 0.4 + frac * 0.6;
  }
  const malicious = /malicious|critical/i.test(node.attrs?.verdict || "");
  const stroke = malicious ? "#F87171" : (selected ? "#F59E0B" : c.stroke);
  const strokeW = selected ? 2.5 : (malicious ? 2 : 1);
  return (
    <g transform={`translate(${node.x},${node.y})`}
       style={{ cursor: "pointer", opacity }}
       onClick={onClick}
       data-testid={`graph-node-${node.id}`}>
      <rect x={-70} y={-16} width={140} height={32} rx={16}
            fill={c.fill} stroke={stroke} strokeWidth={strokeW}
            data-role="node" />
      <foreignObject x={-62} y={-10} width={20} height={20} style={{ pointerEvents: "none" }}>
        <div style={{ color: c.stroke }}>
          <Icon size={14} />
        </div>
      </foreignObject>
      <text x={-38} y={4} fontSize={11} fontFamily="Inter, sans-serif"
            fontWeight={600} fill={c.text} style={{ pointerEvents: "none" }}>
        {label}
      </text>
      <text x={-70} y={28} fontSize={8}
            fontFamily="'IBM Plex Mono', monospace"
            fill="#64748B" style={{ pointerEvents: "none" }}>
        {node.type}
      </text>
    </g>
  );
}

function EdgePath({ e, mode, selectedId, tsBounds }) {
  const color = EDGE_COLOR[e.edgeType] || EDGE_COLOR.default;
  const a = e.__src, b = e.__tgt;
  if (!a || !b) return null;
  const dx = b.x - a.x, dy = b.y - a.y;
  const mx = a.x + dx / 2, my = a.y + dy / 2;
  // Bezier control point offset to give causality graph a nice arc.
  const curl = mode === "entity_rel" ? 0 : 30;
  const path = `M ${a.x} ${a.y + 16} Q ${mx} ${my + curl} ${b.x} ${b.y - 16}`;
  const highlight = selectedId && (selectedId === e.source || selectedId === e.target);
  const ts = tsMs(e.ts);
  const showLabel = mode === "time_overlay" && ts != null;
  return (
    <g data-testid={`graph-edge-${e.source}-${e.target}-${e.edgeType}`}>
      <path d={path}
            fill="none" stroke={color}
            strokeWidth={highlight ? 2.4 : 1.4}
            opacity={highlight ? 0.95 : 0.55}
            markerEnd={`url(#arr-${e.edgeType})`} />
      <text x={mx} y={my + (curl / 2)} textAnchor="middle"
            fontSize={9} fill={color}
            fontFamily="'IBM Plex Mono', monospace" opacity={0.75}>
        {e.edgeType}
      </text>
      {showLabel && (
        <text x={mx} y={my + (curl / 2) + 12} textAnchor="middle"
              fontSize={8} fill="#94A3B8"
              fontFamily="'IBM Plex Mono', monospace" opacity={0.9}>
          {fmtTsShort(ts, tsBounds.lo)}
        </text>
      )}
    </g>
  );
}

// ─── Layout algorithms ──────────────────────────────────────────
function layoutCausality(g) {
  // Compute depth: root = nodes with no incoming spawn/create edge; then
  // BFS assigning depth = max(depth(parents)) + 1. Layout top-to-bottom.
  const nodes = g.nodes.map(n => ({ ...n }));
  const idToNode = new Map(nodes.map(n => [n.id, n]));
  const incoming = new Map();
  for (const e of g.edges) {
    if (!incoming.has(e.target)) incoming.set(e.target, []);
    incoming.get(e.target).push(e.source);
  }
  const depth = new Map();
  const assign = (id, d, seen = new Set()) => {
    if (seen.has(id)) return;
    seen.add(id);
    depth.set(id, Math.max(depth.get(id) || 0, d));
    for (const e of g.edges) if (e.source === id) assign(e.target, d + 1, seen);
  };
  for (const n of nodes) if (!(incoming.get(n.id)?.length)) assign(n.id, 0);
  for (const n of nodes) if (!depth.has(n.id)) depth.set(n.id, 0);
  // Group by depth then time (first_seen).
  const byDepth = new Map();
  for (const n of nodes) {
    const d = depth.get(n.id) || 0;
    if (!byDepth.has(d)) byDepth.set(d, []);
    byDepth.get(d).push(n);
  }
  for (const list of byDepth.values()) {
    list.sort((a, b) => (tsMs(a.attrs?.first_seen) || 0) - (tsMs(b.attrs?.first_seen) || 0));
  }
  const ROW_H = 110, COL_W = 200;
  for (const [d, list] of byDepth.entries()) {
    list.forEach((n, i) => {
      n.x = 120 + i * COL_W;
      n.y = 80 + d * ROW_H;
    });
  }
  return attachEndpoints({ nodes, edges: g.edges }, idToNode);
}

function layoutEntityRelationship(g) {
  // Put processes on a vertical spine (center column). Attach files /
  // registry / network artefacts radially to the right / left.
  const nodes = g.nodes.map(n => ({ ...n }));
  const idToNode = new Map(nodes.map(n => [n.id, n]));
  const procs = nodes.filter(n => n.type === "process");
  const others = nodes.filter(n => n.type !== "process");
  procs.sort((a, b) => (tsMs(a.attrs?.first_seen) || 0) - (tsMs(b.attrs?.first_seen) || 0));
  procs.forEach((n, i) => { n.x = 500; n.y = 80 + i * 110; });
  // For each other node, attach to its first process-neighbour.
  const parentOf = new Map();
  for (const e of g.edges) {
    if (idToNode.get(e.source)?.type === "process" &&
        idToNode.get(e.target)?.type !== "process") {
      if (!parentOf.has(e.target)) parentOf.set(e.target, e.source);
    }
  }
  const buckets = new Map();
  for (const n of others) {
    const p = parentOf.get(n.id);
    if (!buckets.has(p)) buckets.set(p, []);
    buckets.get(p).push(n);
  }
  for (const [pid, list] of buckets.entries()) {
    const proc = idToNode.get(pid);
    if (!proc) continue;
    list.forEach((n, i) => {
      const side = i % 2 === 0 ? 1 : -1;
      const dist = 220 + Math.floor(i / 2) * 30;
      n.x = proc.x + side * dist;
      n.y = proc.y + (i % 2 === 0 ? -12 : 12);
    });
  }
  // Orphans (no parent process) → placed to the far left top.
  let ox = 100, oy = 80;
  for (const n of others) {
    if (!parentOf.has(n.id)) { n.x = ox; n.y = oy; oy += 60; }
  }
  return attachEndpoints({ nodes, edges: g.edges }, idToNode);
}

function layoutTimeOverlay(g, tsBounds) {
  const nodes = g.nodes.map(n => ({ ...n }));
  const idToNode = new Map(nodes.map(n => [n.id, n]));
  const span = Math.max(1, tsBounds.hi - tsBounds.lo);
  const laneY = { process: 200, file: 340, registry: 460, network: 560,
                  service: 640, user: 720, command: 800 };
  const CANVAS_W = 1400;
  const perLaneCount = {};
  for (const n of nodes) {
    const ts = tsMs(n.attrs?.first_seen);
    const frac = ts != null ? (ts - tsBounds.lo) / span : 0;
    n.x = 120 + frac * (CANVAS_W - 200);
    // avoid vertical overlap by staggering within lane
    const k = n.type;
    perLaneCount[k] = (perLaneCount[k] || 0);
    const bump = (perLaneCount[k] % 3) * 26;
    n.y = (laneY[k] || 720) + bump;
    perLaneCount[k]++;
  }
  return attachEndpoints({ nodes, edges: g.edges }, idToNode);
}

// Attach __src/__tgt pointers to each edge for renderer.
function attachEndpoints({ nodes, edges }, idMap) {
  const decorated = edges.map(e => ({
    ...e,
    __src: idMap.get(e.source),
    __tgt: idMap.get(e.target),
  }));
  return { nodes, edges: decorated };
}

// ─── Utilities ──────────────────────────────────────────────────
function tsMs(ts) {
  if (ts == null) return null;
  if (typeof ts === "number") return ts > 1e12 ? ts : ts * 1000;
  const s = String(ts);
  const t = Date.parse(s.endsWith("Z") ? s : s + "Z");
  return Number.isFinite(t) ? t : null;
}
function fmtRel(ms) {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3600_000) return `${(ms / 60_000).toFixed(1)}m`;
  return `${(ms / 3600_000).toFixed(1)}h`;
}
function fmtTsShort(ts, lo) { return `+${fmtRel(ts - lo)}`; }
function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }
function countBy(arr, key) {
  const out = {};
  for (const x of arr) { const k = x[key]; out[k] = (out[k] || 0) + 1; }
  return out;
}
