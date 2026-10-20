/**
 * ProcessGraphCanvas — reference-locked investigation workspace for the
 * NivXForge EDR Process Tree (Task 1B).
 *
 * Composition, geometry and styling follow the owner-supplied reference
 * screenshot 1:1 (alerts rail · circular segmented-ring graph · red
 * "Process creation" connectors · right process-details panel).
 * EVERY value is driven by the existing tenant-scoped projection from
 * `GET /api/edr/process-tree` plus `GET /api/edr/endpoint-detections`:
 *   · ring colour reflects attached detections / unobserved lineage only;
 *   · a parent referenced but never observed stays GREY + dashed, never a
 *     confirmed edge;
 *   · a counter with no telemetry behind it renders "—", never a number.
 */
import React, { useEffect, useMemo, useRef, useState } from "react";
import { Cog, Minus, Plus, ChevronDown, ChevronRight } from "lucide-react";
import { listEndpointDetections } from "@/nivxforge/edrApi";

/* ---- reference geometry (baseline 1715 × 864) ---------------------- */
const R = 28;                 // node radius
const RING = 4;               // ring thickness
const COL = 290;              // horizontal distance between depths
const ROWGAP = 128;           // vertical distance between rows
const ALERTS_W = 170;
const RIGHT_W = 804;

const C = {
  shellBg: "#0E1420",
  graphBg: "#1A1F2B",
  panelBg: "#141A26",
  alertsBg: "#141926",
  line: "#242B3A",
  text: "#E7EAF2",
  dim: "#8C93A6",
  faint: "#5C6476",
  red: "#B4514F",
  redBright: "#D4605C",
  magenta: "#E85FA8",
  purple: "#9B6BE0",
  blue: "#4FA8E8",
  grey: "#6B7384",
  capsule: "#0A0E16",
};

const fmt = (iso) => {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()} `
       + `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
};
const label = (n) => `${n.pid ?? "?"}:${n.process || "unobserved"}`;

/* Ring segments: evidence → colour. Malicious = detections attached by the
   backend. Unknown = never observed. Nothing else is asserted. */
function ringOf(node) {
  if ((node.detections || []).length)
    return { arcs: [C.magenta, C.magenta, C.purple, C.red], kind: "malicious" };
  if (node.observed === false)
    return { arcs: [C.grey, C.grey, C.grey, C.grey], kind: "unknown" };
  if (node.lineage_state && node.lineage_state !== "PARENT_OBSERVED")
    return { arcs: [C.purple, C.grey, C.blue, C.grey], kind: "unknown" };
  return { arcs: [C.blue, C.purple, C.magenta, C.grey], kind: "observed" };
}

function layout(nodes, roots, collapsed = new Set()) {
  const key = (n) => n.process_iid || n.entity_id;
  const byId = new Map(nodes.map((n) => [key(n), n]));
  const placed = [];
  const seen = new Set();
  let row = 0;
  const walk = (id, depth) => {
    if (seen.has(id)) return;
    seen.add(id);
    const n = byId.get(id);
    if (!n) return;
    placed.push({ ...n, _id: id, _cx: 120 + depth * COL, _cy: 110 + row * ROWGAP });
    row += 1;
    if (!collapsed.has(id))
      for (const c of (n.child_ids || [])) walk(c, depth + 1);
  };
  for (const r of (roots || [])) walk(r, 0);
  // Only TRUE orphans (a parent the projection never emitted) are re-rooted.
  // A node hidden because an ancestor is collapsed must stay hidden.
  const hidden = new Set();
  const hide = (id) => {
    const n = byId.get(id);
    if (!n) return;
    for (const c of (n.child_ids || [])) { hidden.add(c); hide(c); }
  };
  for (const id of collapsed) hide(id);
  for (const n of nodes) {
    const id = key(n);
    if (seen.has(id) || hidden.has(id)) continue;
    const parent = n.parent_iid || n.parent_entity_id;
    if (parent && byId.has(parent)) continue;
    walk(id, 0);
  }
  const pos = new Map(placed.map((p) => [p._id, p]));
  const links = [];
  for (const p of placed) {
    const pid = p.parent_iid || p.parent_entity_id;
    const from = pid ? pos.get(pid) : null;
    if (!from) continue;
    links.push({ id: `${pid}->${p._id}`, from, to: p,
                 proven: from.observed !== false && p.observed !== false });
  }
  return { placed, links };
}

/** All descendant process creations of a node, newest-first — the right
 *  panel's event list is literally this evidence, nothing synthesised. */
function descendants(node, byId) {
  const out = [];
  const stack = [...(node.child_ids || [])];
  const seen = new Set();
  while (stack.length) {
    const id = stack.pop();
    if (seen.has(id)) continue;
    seen.add(id);
    const n = byId.get(id);
    if (!n) continue;
    out.push(n);
    for (const c of (n.child_ids || [])) stack.push(c);
  }
  return out.sort((a, b) => String(b.first_seen || "").localeCompare(String(a.first_seen || "")));
}

/* ---- node ---------------------------------------------------------- */
const NodeGlyph = ({ p, active, onClick, onToggle, collapsedHere }) => {
  const ring = ringOf(p);
  const circ = 2 * Math.PI * (R - RING / 2);
  const seg = circ / 4;
  return (
    <g data-testid={`edr-processgraph-node-${p._id}`}
       data-kind={ring.kind}
       transform={`translate(${p._cx},${p._cy})`}
       style={{ cursor: "pointer" }} onClick={() => onClick(p._id)}>
      {ring.arcs.map((col, i) => (
        <circle key={i} r={R - RING / 2} fill="none" stroke={col}
                strokeWidth={RING} strokeLinecap="butt"
                strokeDasharray={`${seg - 7} ${circ - seg + 7}`}
                strokeDashoffset={-i * seg}
                transform="rotate(-96)" opacity={0.95} />
      ))}
      {active && (
        <circle r={R + 6} fill="none" stroke={ring.arcs[0]} strokeWidth="1.3"
                opacity="0.65" />
      )}
      <circle r={R - RING - 2}
              fill={ring.kind === "malicious" ? "#2A1A22" : "#1E2330"}
              stroke="#0B0F18" strokeWidth="1" />
      <foreignObject x={-11} y={-11} width="22" height="22">
        <Cog size={21} color={ring.kind === "unknown" ? C.dim : "#C9CFDD"}
             strokeWidth={1.6} />
      </foreignObject>
      {(p.child_ids || []).length > 0 && (
        <g transform={`translate(${R - 6},${-R + 4})`}
           data-testid={`edr-processgraph-toggle-${p._id}`}
           onClick={(e) => { e.stopPropagation(); onToggle(p._id); }}>
          <circle r="10" fill="#0B0F18" stroke={ring.arcs[0]} strokeWidth="1.2" />
          <text y="4" textAnchor="middle" fontSize="13" fill="#D7DCE8">
            {collapsedHere ? "+" : "−"}
          </text>
        </g>)}
      <g transform={`translate(0,${R + 24})`}>
        <rect x={-(label(p).length * 3.5 + 38)} y="-13"
              width={label(p).length * 7 + 76} height="26" rx="6"
              fill={C.capsule} opacity="0.95" />
        <text x="0" y="5" textAnchor="middle" fill={C.text} fontSize="12.5"
              fontFamily="Inter, system-ui, sans-serif">
          {`Process: ${label(p)}`}
        </text>
      </g>
    </g>
  );
};

/* ---- right-hand process details ------------------------------------ */
const Tab = ({ children, count, active, onClick, testid }) => (
  <button onClick={onClick} data-testid={testid} data-active={!!active}
          style={{ background: "none", border: "none", cursor: "pointer",
                   padding: "6px 2px", marginRight: 22, color: active ? "#8FB8FF" : C.dim,
                   fontSize: 12.5, display: "inline-flex", alignItems: "center",
                   gap: 7, borderBottom: active ? "2px solid #4F7DD6" : "2px solid transparent" }}>
    {children}
    {count !== undefined && (
      <span style={{ fontSize: 11, color: active ? "#8FB8FF" : C.faint,
                     background: "rgba(255,255,255,.05)", borderRadius: 4,
                     padding: "0 5px" }}>{count}</span>)}
  </button>
);

const EventRow = ({ n }) => (
  <div data-testid={`edr-processgraph-event-${n.process_iid || n.entity_id}`}
       style={{ display: "flex", alignItems: "center", gap: 14,
                padding: "7px 22px 7px 14px",
                borderBottom: `1px solid ${C.line}` }}>
    <span style={{ width: 3, height: 15, borderRadius: 2, flexShrink: 0,
                   background: (n.detections || []).length ? C.redBright
                              : n.observed === false ? C.grey : "#4F7DD6" }} />
    <span style={{ width: 190, fontSize: 12.5, color: C.text }}>ProcessCreation</span>
    <span style={{ flex: 1, fontSize: 12.5, color: "#86A5CF" }}>{label(n)}</span>
    <span style={{ fontSize: 12.5, color: "#A9B2C6" }}>{fmt(n.first_seen)}</span>
  </div>
);

/* ---- workspace ------------------------------------------------------ */
export default function ProcessGraphCanvas({
  nodes = [], roots = [], meta = {}, endpointId = null, hostname = null,
  onShowList = null, hours = 24, onHours = null, counts = null,
}) {
  const [collapsed, setCollapsed] = useState(() => new Set());
  const { placed, links } = useMemo(
    () => layout(nodes, roots, collapsed), [nodes, roots, collapsed]);
  const byId = useMemo(
    () => new Map(nodes.map((n) => [n.process_iid || n.entity_id, n])), [nodes]);
  const [selected, setSelected] = useState(null);
  const [openTabs, setOpenTabs] = useState([]);
  const [tab, setTab] = useState("processes");
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [det, setDet] = useState(null);
  const drag = useRef(null);
  const viewport = useRef(null);
  const fitted = useRef(null);

  useEffect(() => {
    if (!endpointId) return;
    let dead = false;
    listEndpointDetections(endpointId, meta.window_hours || 24)
      .then((d) => { if (!dead) setDet(d); })
      .catch(() => { if (!dead) setDet({ detections: [], count: 0, error: true }); });
    return () => { dead = true; };
  }, [endpointId, meta.window_hours]);

  // fit the whole lineage into the viewport once per dataset — the
  // reference shows the full graph, not a corner of it.
  useEffect(() => {
    const el = viewport.current;
    if (!el || !placed.length) return;
    const sig = placed.map((p) => p._id).join("|");
    if (fitted.current === sig) return;
    const w = el.clientWidth, h = el.clientHeight;
    if (!w || !h) return;
    const minX = Math.min(...placed.map((p) => p._cx)) - R - 20;
    const maxX = Math.max(...placed.map((p) => p._cx)) + R + 130;
    const minY = Math.min(...placed.map((p) => p._cy)) - R - 20;
    const maxY = Math.max(...placed.map((p) => p._cy)) + R + 52;
    const raw = Math.min(1, (w - 40) / (maxX - minX), (h - 40) / (maxY - minY));
    const z = Math.max(0.92, +raw.toFixed(2));   // reference renders nodes 1:1
    setZoom(z);
    setPan({ x: 24 - minX * z, y: 20 - minY * z });
    fitted.current = sig;
  }, [placed]);

  useEffect(() => {
    if (!selected && placed.length) {
      const first = placed.find((p) => (p.detections || []).length) || placed[0];
      setSelected(first._id);
      setOpenTabs([first._id]);
    }
  }, [placed, selected]);

  const node = selected ? placed.find((p) => p._id === selected) : null;
  const kids = node ? descendants(node, byId) : [];

  const pick = (id) => {
    setSelected(id);
    setOpenTabs((t) => (t.includes(id) ? t : [...t, id]));
  };
  const closeTab = (id) => {
    setOpenTabs((t) => t.filter((x) => x !== id));
    if (selected === id) setSelected(null);
  };

  const onDown = (e) => { drag.current = { x: e.clientX - pan.x, y: e.clientY - pan.y }; };
  const onMove = (e) => {
    if (!drag.current) return;
    setPan({ x: e.clientX - drag.current.x, y: e.clientY - drag.current.y });
  };
  const onUp = () => { drag.current = null; };

  /* alerts rail — detections the backend attached to THIS endpoint's
     evidence; the graph's own rule hits when the detection fabric has not
     evaluated the raw events. */
  const alerts = useMemo(() => {
    const fromFabric = (det?.detections || []).map((d) => ({
      id: d.detection_id || d.rule_id || JSON.stringify(d).slice(0, 24),
      rule: d.rule_id || d.rule || "detection",
      source: d.process || d.image || hostname || endpointId,
      files: d.file_name ? [d.file_name] : [],
    }));
    if (fromFabric.length) return fromFabric;
    return nodes.filter((n) => (n.detections || []).length).map((n) => ({
      id: n.process_iid || n.entity_id, rule: n.detections.join(" · "),
      source: label(n), files: n.path ? [n.path.split("\\").pop()] : [],
    }));
  }, [det, nodes, hostname, endpointId]);

  if (!placed.length) {
    return (
      <div className="x-empty" data-testid="edr-processgraph-empty">
        No process evidence in this window — an absence of telemetry, not an
        absence of activity.
      </div>
    );
  }

  const malicious = placed.filter((p) => (p.detections || []).length).length;
  const unknown = placed.filter((p) => p.observed === false).length;

  return (
    <div data-testid="edr-processgraph"
         style={{ display: "flex", height: "calc(100vh - 96px)", minHeight: 700,
                  background: C.shellBg, margin: "6px -18px -18px",
                  borderTop: `1px solid ${C.line}`,
                  overflow: "hidden", fontFamily: "Inter, system-ui, sans-serif" }}>

      {/* ── alerts rail ─────────────────────────────────────────────── */}
      <aside data-testid="edr-processgraph-alerts"
             style={{ width: ALERTS_W, flexShrink: 0, background: C.alertsBg,
                      borderRight: `1px solid ${C.line}`, overflowY: "auto" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 10,
                      padding: "18px 16px 12px" }}>
          <h2 style={{ margin: 0, fontSize: 17, fontWeight: 600, color: C.text }}>
            Alerts
          </h2>
          <span style={{ fontSize: 12, color: C.dim }}>Active</span>
          <span style={{ fontSize: 11, color: C.text, background: "#2A3346",
                         borderRadius: 4, padding: "1px 6px" }}
                data-testid="edr-processgraph-alert-count">{alerts.length}</span>
        </div>
        <div style={{ margin: "0 12px 12px", padding: "9px 10px",
                      background: "#0E131F", border: `1px solid ${C.line}`,
                      borderRadius: 5, fontSize: 11.5, color: "#9FB4D6",
                      fontFamily: "ui-monospace, Menlo, monospace" }}>
          endpoint_id: "{endpointId || "—"}"
          <div style={{ color: C.faint, marginTop: 4 }}>
            {meta.window_hours || 24}h · {placed.length} processes
            {counts ? ` · ${counts.observed} observed · ${counts.roots} root(s)` : ""}
          </div>
          {counts && counts.ghost_parents > 0 && (
            <div style={{ color: "#E0B84A", marginTop: 4 }}
                 data-testid="edr-processgraph-ghost-count">
              {counts.ghost_parents} ghost parent(s) — a visibility gap, not an
              absent process
            </div>)}
        </div>
        {alerts.length === 0 && (
          <div style={{ margin: "0 12px", fontSize: 11.5, color: C.dim,
                        lineHeight: 1.6 }}
               data-testid="edr-processgraph-alerts-empty">
            No detection derivations on this endpoint's raw events
            {det && det.events_not_evaluated
              ? ` · ${det.events_not_evaluated} event(s) not evaluated — a detection gap, not an all-clear.`
              : " in this window."}
          </div>)}
        {alerts.map((a) => (
          <div key={a.id} data-testid={`edr-processgraph-alert-${a.id}`}
               style={{ margin: "0 0 2px", padding: "12px 16px",
                        borderLeft: `3px solid ${C.redBright}`,
                        background: "#161C2A" }}>
            <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
              <span style={{ fontSize: 10.5, color: C.redBright,
                             border: `1px solid rgba(212,96,92,.5)`,
                             borderRadius: 3, padding: "1px 6px" }}>Detected</span>
              <span style={{ fontSize: 10.5, color: C.dim }}>Related in graph</span>
            </div>
            <div style={{ fontSize: 11, color: C.faint, marginBottom: 4 }}>Source</div>
            <div style={{ fontSize: 11.5, color: C.text, background: "#1E2433",
                          borderRadius: 4, padding: "3px 7px", marginBottom: 6,
                          wordBreak: "break-all" }}>{a.source}</div>
            <div style={{ fontSize: 11, color: C.faint, marginBottom: 4 }}>Rule</div>
            <div style={{ fontSize: 11.5, color: "#D8A0A0", wordBreak: "break-all" }}>
              {a.rule}
            </div>
          </div>))}
      </aside>

      {/* ── graph ──────────────────────────────────────────────────── */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column",
                    minWidth: 0 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 26,
                    height: 44, padding: "0 22px", background: C.shellBg,
                    borderBottom: `1px solid ${C.line}` }}
           data-testid="edr-processgraph-header">
        <span style={{ fontSize: 16.5, fontWeight: 600, color: C.text }}>
          Endpoint
        </span>
        <span style={{ fontSize: 14, color: C.dim }}>Investigation</span>
      </div>
      <div ref={viewport}
           style={{ flex: 1, position: "relative", background: C.graphBg,
                    cursor: drag.current ? "grabbing" : "grab" }}
           data-testid="edr-processgraph-canvas"
           onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp}
           onMouseLeave={onUp}>
        {/* window control — the reference has no such row, so it sits as a
            compact overlay instead of a page-level toolbar */}
        <div style={{ position: "absolute", top: 14, left: 18, zIndex: 2,
                      display: "flex", alignItems: "center", gap: 6 }}
             data-testid="edr-processgraph-window">
          {[1, 24, 72, 168, 720].map((h) => (
            <button key={h} data-testid={`edr-processgraph-window-${h}`}
                    data-active={h === hours}
                    onClick={() => onHours && onHours(h)}
                    style={{ cursor: "pointer", fontSize: 11.5, borderRadius: 4,
                             padding: "4px 10px",
                             background: h === hours ? "#2A3346" : "#1A2030",
                             border: `1px solid ${C.line}`,
                             color: h === hours ? C.text : C.dim }}>
              {h < 24 ? `${h}h` : `${h / 24}d`}
            </button>))}
        </div>

        {/* legend */}
        <div style={{ position: "absolute", top: 14, right: 18, display: "flex",
                      gap: 8, zIndex: 2 }}
             data-testid="edr-processgraph-legend">
          <span style={{ display: "inline-flex", alignItems: "center", gap: 7,
                         background: "#1E2433", borderRadius: 14,
                         padding: "4px 12px", fontSize: 12, color: C.text }}>
            <i style={{ width: 7, height: 7, borderRadius: 7,
                        background: C.redBright, display: "inline-block" }} />
            Malicious <b style={{ color: C.dim, fontWeight: 500 }}>{malicious}</b>
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 7,
                         background: "#1E2433", borderRadius: 14,
                         padding: "4px 12px", fontSize: 12, color: C.text }}>
            <i style={{ width: 7, height: 7, borderRadius: 7,
                        background: C.blue, display: "inline-block" }} />
            Unknown <b style={{ color: C.dim, fontWeight: 500 }}>{unknown}</b>
          </span>
        </div>
        {/* zoom */}
        <div style={{ position: "absolute", top: 54, right: 18, display: "flex",
                      alignItems: "center", gap: 8, zIndex: 2 }}>
          <span style={{ fontSize: 12.5, color: C.text }}
                data-testid="edr-processgraph-zoom-level">
            Current zoom: {(zoom * 7.11).toFixed(2)}
          </span>
          <button data-testid="edr-processgraph-zoom-out" aria-label="Zoom out"
                  onClick={() => setZoom((z) => Math.max(0.3, +(z - 0.12).toFixed(2)))}
                  style={{ width: 26, height: 26, borderRadius: 13, cursor: "pointer",
                           background: "#1E2433", border: `1px solid ${C.line}`,
                           color: C.text, display: "grid", placeItems: "center" }}>
            <Minus size={13} />
          </button>
          <button data-testid="edr-processgraph-zoom-in" aria-label="Zoom in"
                  onClick={() => setZoom((z) => Math.min(2.4, +(z + 0.12).toFixed(2)))}
                  style={{ width: 26, height: 26, borderRadius: 13, cursor: "pointer",
                           background: "#1E2433", border: `1px solid ${C.line}`,
                           color: C.text, display: "grid", placeItems: "center" }}>
            <Plus size={13} />
          </button>
        </div>

        <svg width="100%" height="100%" role="img" aria-label="process graph">
          <defs>
            <marker id="nvf-arrow" markerWidth="5.2" markerHeight="5.2" refX="3.1"
                    refY="2.6" orient="auto">
              <path d="M0,0 L0,5.2 L5.2,2.6 z" fill={C.red} />
            </marker>
            <marker id="nvf-arrow-grey" markerWidth="5.2" markerHeight="5.2"
                    refX="3.1" refY="2.6" orient="auto">
              <path d="M0,0 L0,5.2 L5.2,2.6 z" fill={C.grey} />
            </marker>
          </defs>
          <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
            {links.map((l) => {
              const sx = l.from._cx + R + 4;
              const sy = l.from._cy;
              const ex = l.to._cx - R - 10;
              const ey = l.to._cy;
              const mid = sx + (ex - sx) * 0.5;
              const d = Math.abs(ey - sy) < 4
                ? `M${sx},${sy} L${ex},${ey}`
                : `M${sx},${sy} L${mid - 34},${sy} Q${mid},${sy} ${mid},${sy + Math.sign(ey - sy) * 34} `
                  + `L${mid},${ey - Math.sign(ey - sy) * 34} Q${mid},${ey} ${mid + 34},${ey} L${ex},${ey}`;
              return (
                <g key={l.id}
                   data-testid={`edr-processgraph-edge-${l.proven ? "proven" : "unproven"}`}>
                  <path d={d} fill="none"
                        stroke={l.proven ? C.red : C.grey} strokeWidth="7"
                        strokeLinecap="round" strokeLinejoin="round"
                        strokeDasharray={l.proven ? "0" : "12 9"}
                        markerEnd={l.proven ? "url(#nvf-arrow)" : "url(#nvf-arrow-grey)"}
                        opacity={l.proven ? 0.9 : 0.75} />
                  <g transform={`translate(${(sx + ex) / 2},${ey})`}>
                    <rect x="-52" y="-11" width="104" height="22" rx="4"
                          fill={l.proven ? "#5E2F32" : "#2A2F3C"} />
                    <text y="4.5" textAnchor="middle" fontSize="11.5"
                          fill={l.proven ? "#F0C9C7" : C.dim}>
                      {l.proven ? "Process creation" : "Parent not observed"}
                    </text>
                  </g>
                </g>);
            })}
            {placed.map((p) => (
              <NodeGlyph key={p._id} p={p} active={p._id === selected} onClick={pick}
                         collapsedHere={collapsed.has(p._id)}
                         onToggle={(id) => setCollapsed((c) => {
                           const next = new Set(c);
                           if (next.has(id)) next.delete(id); else next.add(id);
                           return next;
                         })} />
            ))}
          </g>
        </svg>

        {/* bottom-centre view switch */}
        <div style={{ position: "absolute", bottom: 18, left: "50%",
                      transform: "translateX(-50%)", display: "flex",
                      background: "#1A2030", border: `1px solid ${C.line}`,
                      borderRadius: 6, padding: 3, zIndex: 2 }}
             data-testid="edr-processgraph-viewswitch">
          <span style={{ padding: "6px 16px", borderRadius: 4, fontSize: 12.5,
                         background: "#2A3346", color: C.text }}
                data-testid="edr-processgraph-view-graph">Graph view</span>
          <button onClick={() => onShowList && onShowList()}
                  data-testid="edr-processgraph-view-tree"
                  style={{ padding: "6px 16px", borderRadius: 4, fontSize: 12.5,
                           background: "none", border: "none", color: C.dim,
                           cursor: "pointer" }}>Process tree</button>
        </div>
      </div>
      </div>

      {/* ── process details ────────────────────────────────────────── */}
      <aside data-testid="edr-processgraph-detail"
             style={{ width: RIGHT_W, flexShrink: 0, background: C.panelBg,
                      borderLeft: `1px solid ${C.line}`, display: "flex",
                      flexDirection: "column" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 2,
                      borderBottom: `1px solid ${C.line}`, padding: "0 10px",
                      overflowX: "auto" }}>
          <span style={{ padding: "13px 12px", fontSize: 12.5, color: C.dim }}>
            Overview
          </span>
          <span style={{ padding: "13px 12px", fontSize: 12.5, color: C.dim,
                         display: "inline-flex", gap: 7, alignItems: "center" }}
                data-testid="edr-processgraph-host-tab">
            {hostname || endpointId || "endpoint"}
          </span>
          {openTabs.map((id) => {
            const t = placed.find((p) => p._id === id);
            if (!t) return null;
            return (
              <span key={id} data-testid={`edr-processgraph-tab-${id}`}
                    onClick={() => setSelected(id)}
                    style={{ padding: "13px 10px", fontSize: 12.5, cursor: "pointer",
                             color: id === selected ? C.text : C.dim,
                             borderBottom: id === selected ? "2px solid #4F7DD6" : "none",
                             display: "inline-flex", gap: 8, alignItems: "center",
                             whiteSpace: "nowrap" }}>
                <Cog size={13} color={id === selected ? "#8FB8FF" : C.faint} />
                {label(t)}
                <i onClick={(e) => { e.stopPropagation(); closeTab(id); }}
                   style={{ fontStyle: "normal", color: C.faint }}>×</i>
              </span>);
          })}
        </div>

        {!node ? (
          <div style={{ padding: 22, fontSize: 12.5, color: C.dim }}>
            Select a process in the graph to open its evidence.
          </div>
        ) : (
          <>
            <div style={{ display: "flex", alignItems: "flex-start",
                          padding: "18px 20px 10px" }}>
              <div style={{ flex: 1 }}>
                <h2 style={{ margin: 0, fontSize: 22, fontWeight: 600, color: C.text }}
                    data-testid="edr-processgraph-detail-title">{label(node)}</h2>
                <div style={{ fontSize: 12.5, color: C.dim, marginTop: 3 }}>
                  Process details
                </div>
              </div>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 7,
                             background: "#232B3C", border: `1px solid ${C.line}`,
                             borderRadius: 5, padding: "6px 12px", fontSize: 12.5,
                             color: C.text }}
                    data-testid="edr-processgraph-manage">
                Manage <ChevronDown size={13} />
              </span>
            </div>

            <div style={{ display: "flex", alignItems: "center",
                          padding: "0 20px", borderBottom: `1px solid ${C.line}` }}>
              <Tab testid="edr-processgraph-tab-info" active={tab === "info"}
                   onClick={() => setTab("info")}>Info</Tab>
              <Tab testid="edr-processgraph-tab-processes" active={tab === "processes"}
                   count={kids.length} onClick={() => setTab("processes")}>Processes</Tab>
              <Tab testid="edr-processgraph-tab-files" count="—"
                   active={tab === "files"} onClick={() => setTab("files")}>Files</Tab>
              <Tab testid="edr-processgraph-tab-registry" count="—"
                   active={tab === "registry"} onClick={() => setTab("registry")}>Registry</Tab>
              <Tab testid="edr-processgraph-tab-network" count="—"
                   active={tab === "network"} onClick={() => setTab("network")}>Network</Tab>
              <Tab testid="edr-processgraph-tab-winobj" active={tab === "winobj"}
                   onClick={() => setTab("winobj")}>winObj</Tab>
            </div>

            <div style={{ flex: 1, overflowY: "auto" }}>
              {tab === "processes" && (kids.length ? kids.map((k) => (
                <EventRow key={k.process_iid || k.entity_id} n={k} />
              )) : (
                <div style={{ padding: 18, fontSize: 12.5, color: C.dim }}
                     data-testid="edr-processgraph-no-children">
                  No child process creations observed under this process.
                </div>))}

              {tab === "info" && (
                <div style={{ padding: "4px 20px 20px" }}
                     data-testid="edr-processgraph-info">
                  {[["Lineage", node.lineage_state],
                    ["PID / PPID", `${node.pid ?? "—"} / ${node.ppid ?? "—"}`],
                    ["User", node.user], ["Command line", node.command_line],
                    ["Image path", node.path], ["SHA256", node.sha256],
                    ["First seen", node.first_seen ? fmt(node.first_seen) : null],
                    ["Last seen", node.last_seen ? fmt(node.last_seen) : null],
                    ["Detections", (node.detections || []).join(", ")],
                    ["Evidence records", (node.event_iids || []).length],
                    ["Process identity", node._id]].map(([k, v]) => (
                      <div key={k} style={{ padding: "9px 0",
                                            borderBottom: `1px solid ${C.line}` }}>
                        <div style={{ fontSize: 10.5, letterSpacing: ".4px",
                                      textTransform: "uppercase", color: C.faint }}>{k}</div>
                        <div style={{ fontSize: 12.5, color: C.text, marginTop: 3,
                                      wordBreak: "break-all" }}>
                          {v === null || v === undefined || v === "" ? "—" : String(v)}
                        </div>
                      </div>))}
                  {node.observed === false && (
                    <p style={{ fontSize: 11.5, color: "#E0B84A", marginTop: 14,
                                border: "1px solid rgba(224,184,74,.35)",
                                background: "rgba(224,184,74,.06)", padding: 10,
                                borderRadius: 4 }}
                       data-testid="edr-processgraph-ghost-note">
                      {node.note || "Referenced as a parent by observed evidence but never observed itself. Nothing about it is claimed."}
                    </p>)}
                </div>)}

              {["files", "registry", "network", "winobj"].includes(tab) && (
                <div style={{ padding: 18, fontSize: 12.5, color: C.dim, lineHeight: 1.7 }}
                     data-testid={`edr-processgraph-gap-${tab}`}>
                  <b style={{ color: "#E0B84A" }}>NOT PROJECTED</b> — this sensor's
                  canonical evidence carries process lineage only. File, registry,
                  network and object activity for a single process is not projected
                  by `/api/edr/process-tree`, so no count is shown rather than a
                  fabricated one.
                </div>)}
            </div>

            <div style={{ borderTop: `1px solid ${C.line}`, padding: "9px 20px",
                          fontSize: 11, color: C.faint,
                          display: "flex", gap: 8, alignItems: "center" }}>
              <ChevronRight size={12} />
              SSOT · {meta.source || "v2_shadow_observations"} · canonical
              process_iid / parent_iid
            </div>
          </>)}
      </aside>
    </div>
  );
}
