/**
 * ProcessGraphCanvas — evidence-backed process graph for the NivXForge EDR
 * console. Same renderer contract as the list view below it: it consumes the
 * EXISTING `GET /api/edr/process-tree` projection (nodes[] + child_ids +
 * roots[]), identity-linked by `process_iid`/`parent_iid`, never by pid alone.
 *
 * Nothing here infers a relationship:
 *   · a parent referenced but never observed renders as a GHOST node, its
 *     edge dashed and labelled unproven;
 *   · `lineage_state` is rendered verbatim;
 *   · a field with no evidence shows "—", never a guess.
 *
 * No Tailwind in this app — styling is inline + the console's CSS vars.
 */
import React, { useMemo, useRef, useState } from "react";
import {
  Terminal, FileCode2, Shield, ShieldAlert, Ghost, ChevronRight,
  ZoomIn, ZoomOut, Crosshair, Cpu,
} from "lucide-react";

const NODE_W = 236;
const NODE_H = 88;
const GAP_X = 104;
const GAP_Y = 26;
const CANVAS_H = 540;

const SHELLS = /^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|bash|sh)\b/i;

const truncate = (s, n) => (String(s).length > n ? `${String(s).slice(0, n - 1)}…` : String(s));

function iconFor(node) {
  if (node.observed === false) return Ghost;
  const n = (node.process || "").toLowerCase();
  if (SHELLS.test(n)) return Terminal;
  if (n.endsWith(".dll")) return FileCode2;
  if ((node.detections || []).length) return ShieldAlert;
  if (node.signer) return Shield;
  return Cpu;
}

/** Suspicion is a RENDERING of evidence, not a new verdict: it reacts only to
 *  detections the backend already attached, or to an unproven lineage. */
function tone(node) {
  if ((node.detections || []).length) return "#F87171";
  if (node.observed === false) return "#7C8798";
  if (node.lineage_state && node.lineage_state !== "PARENT_OBSERVED")
    return "#F5A34C";
  return "#5FD3B2";
}

/** Deterministic tidy layout: depth → column, pre-order → row. */
function layout(nodes, roots) {
  const key = (n) => n.process_iid || n.entity_id;
  const byId = new Map(nodes.map((n) => [key(n), n]));
  const placed = [];
  const seen = new Set();
  let row = 0;
  const walk = (id, depth) => {
    if (seen.has(id)) return;              // pid-reuse / cyclic-claim guard
    seen.add(id);
    const node = byId.get(id);
    if (!node) return;
    placed.push({
      ...node,
      _id: id,
      _x: depth * (NODE_W + GAP_X),
      _y: row * (NODE_H + GAP_Y),
    });
    row += 1;
    for (const child of [...(node.child_ids || [])]) walk(child, depth + 1);
  };
  for (const r of (roots || [])) walk(r, 0);
  for (const n of nodes) if (!seen.has(key(n))) walk(key(n), 0);

  const pos = new Map(placed.map((p) => [p._id, p]));
  const edges = [];
  for (const p of placed) {
    const parent = p.parent_iid || p.parent_entity_id;
    const from = parent ? pos.get(parent) : null;
    if (!from) continue;
    edges.push({
      id: `${parent}->${p._id}`,
      x1: from._x + NODE_W, y1: from._y + NODE_H / 2,
      x2: p._x, y2: p._y + NODE_H / 2,
      proven: from.observed !== false && p.observed !== false,
    });
  }
  return { placed, edges };
}

const Field = ({ label, value, mono }) => (
  <div style={{ padding: "7px 0", borderBottom: "1px solid rgba(255,255,255,.06)" }}>
    <div style={{ fontSize: 9.5, letterSpacing: ".4px", fontWeight: 800,
                  textTransform: "uppercase", color: "#7C8798" }}>{label}</div>
    <div className={mono ? "mono" : ""}
         style={{ fontSize: mono ? 11 : 12, color: "#E6EDF3",
                  wordBreak: "break-all", marginTop: 2 }}>
      {value === null || value === undefined || value === "" ? "—" : String(value)}
    </div>
  </div>
);

const ToolBtn = ({ testid, label, onClick, children }) => (
  <button className="btn" data-testid={testid} aria-label={label} title={label}
          onClick={onClick} style={{ padding: "4px 7px" }}>
    {children}
  </button>
);

export default function ProcessGraphCanvas({ nodes = [], roots = [], meta = {} }) {
  const { placed, edges } = useMemo(() => layout(nodes, roots), [nodes, roots]);
  const [selected, setSelected] = useState(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 28, y: 24 });
  const drag = useRef(null);

  const node = selected ? placed.find((p) => p._id === selected) : null;
  const ghosts = placed.filter((p) => p.observed === false).length;

  const onDown = (e) => { drag.current = { x: e.clientX - pan.x, y: e.clientY - pan.y }; };
  const onMove = (e) => {
    if (!drag.current) return;
    setPan({ x: e.clientX - drag.current.x, y: e.clientY - drag.current.y });
  };
  const onUp = () => { drag.current = null; };

  if (!placed.length) {
    return (
      <div className="x-empty" data-testid="edr-processgraph-empty">
        <Ghost size={14} style={{ verticalAlign: "middle", marginRight: 6 }} />
        No process evidence in this window — an absence of telemetry, not an
        absence of activity.
      </div>
    );
  }

  return (
    <div className="panel" data-testid="edr-processgraph"
         style={{ padding: 0, overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                    padding: "8px 12px",
                    borderBottom: "1px solid rgba(255,255,255,.08)" }}>
        <span className="mono" style={{ fontSize: 10.5, color: "#C3CDD6" }}
              data-testid="edr-processgraph-count">
          {placed.length} process{placed.length === 1 ? "" : "es"}
        </span>
        <span style={{ color: "#48555F" }}>·</span>
        <span className="mono" style={{ fontSize: 10.5,
                                        color: ghosts ? "#C9A227" : "#7C8798" }}
              data-testid="edr-processgraph-ghosts">
          {ghosts} unobserved parent{ghosts === 1 ? "" : "s"}
        </span>
        {meta.window_hours ? (
          <>
            <span style={{ color: "#48555F" }}>·</span>
            <span className="mono" style={{ fontSize: 10.5, color: "#7C8798" }}>
              {meta.window_hours}h window
            </span>
          </>) : null}
        <div style={{ flex: 1 }} />
        <ToolBtn testid="edr-processgraph-zoom-out" label="Zoom out"
                 onClick={() => setZoom((z) => Math.max(0.4, +(z - 0.15).toFixed(2)))}>
          <ZoomOut size={12} />
        </ToolBtn>
        <span className="mono" style={{ fontSize: 10, color: "#7C8798", width: 34,
                                        textAlign: "center" }}
              data-testid="edr-processgraph-zoom-level">
          {Math.round(zoom * 100)}%
        </span>
        <ToolBtn testid="edr-processgraph-zoom-in" label="Zoom in"
                 onClick={() => setZoom((z) => Math.min(2, +(z + 0.15).toFixed(2)))}>
          <ZoomIn size={12} />
        </ToolBtn>
        <ToolBtn testid="edr-processgraph-reset" label="Reset view"
                 onClick={() => { setZoom(1); setPan({ x: 28, y: 24 }); }}>
          <Crosshair size={12} />
        </ToolBtn>
      </div>

      <div style={{ display: "flex" }}>
        <div data-testid="edr-processgraph-canvas"
             style={{ position: "relative", flex: 1, height: CANVAS_H,
                      cursor: drag.current ? "grabbing" : "grab",
                      background: "radial-gradient(circle at 18% 0%, rgba(95,211,178,.08), transparent 55%), #080C12" }}
             onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp}
             onMouseLeave={onUp}>
          <svg width="100%" height="100%" role="img" aria-label="process graph">
            <defs>
              <marker id="pg-arrow" markerWidth="9" markerHeight="9" refX="8"
                      refY="3" orient="auto" markerUnits="strokeWidth">
                <path d="M0,0 L0,6 L8,3 z" fill="#4A5A6B" />
              </marker>
            </defs>
            <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
              {edges.map((e) => (
                <path key={e.id}
                      data-testid={`edr-processgraph-edge-${e.proven ? "proven" : "unproven"}`}
                      d={`M${e.x1},${e.y1} C${e.x1 + GAP_X / 2},${e.y1} ${e.x2 - GAP_X / 2},${e.y2} ${e.x2},${e.y2}`}
                      fill="none" stroke={e.proven ? "#3E5162" : "#7C8798"}
                      strokeWidth={1.4}
                      strokeDasharray={e.proven ? "0" : "5 4"}
                      markerEnd="url(#pg-arrow)" />
              ))}
              {placed.map((p) => {
                const Icon = iconFor(p);
                const accent = tone(p);
                const active = p._id === selected;
                const dets = (p.detections || []).length;
                return (
                  <g key={p._id} data-testid={`edr-processgraph-node-${p._id}`}
                     transform={`translate(${p._x},${p._y})`}
                     style={{ cursor: "pointer" }}
                     onClick={() => setSelected(p._id)}>
                    <rect width={NODE_W} height={NODE_H} rx="10"
                          fill={active ? "#111A24" : "#0D141C"}
                          stroke={active ? accent : "rgba(255,255,255,.09)"}
                          strokeWidth={active ? 1.8 : 1} />
                    <rect width="3" height={NODE_H} rx="1.5" fill={accent} />
                    <foreignObject x="13" y="12" width="18" height="18">
                      <Icon size={15} style={{ color: accent }} />
                    </foreignObject>
                    <text x="36" y="25" fill="#E6EDF3" fontSize="12.5"
                          fontWeight="700">
                      {truncate(p.process || "unobserved parent", 24)}
                    </text>
                    <text x="36" y="42" fill="#7C8798" fontSize="10"
                          fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace">
                      {`pid ${p.pid ?? "—"}${p.user ? ` · ${p.user}` : ""}`}
                    </text>
                    {p.command_line ? (
                      <text x="36" y="57" fill="#56636F" fontSize="9.5"
                            fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace">
                        {truncate(p.command_line, 30)}
                      </text>) : null}
                    {dets ? (
                      <text x="36" y="71" fill="#F87171" fontSize="9"
                            fontWeight="800" letterSpacing="0.4">
                        {`${dets} DETECTION${dets === 1 ? "" : "S"}`}
                      </text>
                    ) : p.observed === false ? (
                      <text x="36" y="71" fill="#C9A227" fontSize="9"
                            fontWeight="800" letterSpacing="0.4">
                        ◇ NEVER OBSERVED
                      </text>
                    ) : null}
                  </g>
                );
              })}
            </g>
          </svg>
        </div>

        <aside data-testid="edr-processgraph-detail"
               style={{ width: 320, flexShrink: 0, height: CANVAS_H,
                        overflowY: "auto", padding: 14,
                        borderLeft: "1px solid rgba(255,255,255,.08)",
                        background: "#0A1016" }}>
          {!node ? (
            <p style={{ fontSize: 11.5, color: "#7C8798" }}>
              Select a process to see the evidence behind it.
            </p>
          ) : (
            <>
              <div style={{ display: "flex", alignItems: "center", gap: 6,
                            marginBottom: 8 }}>
                <ChevronRight size={14} style={{ color: tone(node) }} />
                <h3 style={{ margin: 0, fontSize: 13.5, fontWeight: 800,
                             color: "#E6EDF3" }}>
                  {node.process || "unobserved parent"}
                </h3>
              </div>
              {node.observed === false && (
                <p data-testid="edr-processgraph-ghost-note"
                   style={{ fontSize: 10.5, color: "#E0B84A", marginTop: 0,
                            border: "1px solid rgba(201,162,39,.35)", padding: 8,
                            borderRadius: 4, background: "rgba(201,162,39,.06)" }}>
                  {node.note || "Referenced as a parent by observed evidence but never observed itself. Nothing about it is claimed."}
                </p>
              )}
              <Field label="lineage" value={node.lineage_state} />
              <Field label="pid / ppid" value={`${node.pid ?? "—"} / ${node.ppid ?? "—"}`} mono />
              <Field label="user" value={node.user} />
              <Field label="command line" value={node.command_line} mono />
              <Field label="image path" value={node.path} mono />
              <Field label="sha256" value={node.sha256} mono />
              <Field label="first seen" value={node.first_seen} mono />
              <Field label="last seen" value={node.last_seen} mono />
              <Field label="detections"
                     value={(node.detections || []).length ? node.detections.join(", ") : null} />
              <Field label="evidence records" value={(node.event_iids || []).length} />
              <Field label="process identity" value={node._id} mono />
            </>
          )}
        </aside>
      </div>
    </div>
  );
}
