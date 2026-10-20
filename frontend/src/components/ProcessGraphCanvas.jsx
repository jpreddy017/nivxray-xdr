/**
 * ProcessGraphCanvas — the shared evidence-backed process graph renderer.
 *
 * Consumes the EXISTING projection from `GET /api/edr/process-tree`
 * (nodes[], edges[], roots[]) — identity-linked by `process_iid` /
 * `parent_iid`, never by pid alone. Nothing here infers a relationship:
 *   * a parent referenced but never observed renders as a GHOST node and
 *     its edge is dashed + labelled, not solid;
 *   * `lineage_state` is rendered verbatim, so PARENT_NOT_OBSERVED stays
 *     visibly unproven instead of silently becoming a tree edge;
 *   * a node with no evidence for a field shows "—", never a guess.
 */
import { useMemo, useRef, useState } from "react";
import {
  Terminal, FileCode2, Shield, ShieldAlert, Ghost, ChevronRight,
  ZoomIn, ZoomOut, Crosshair, Cpu,
} from "lucide-react";

const NODE_W = 232;
const NODE_H = 76;
const GAP_X = 96;
const GAP_Y = 28;

const SHELLS = /^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|bash|sh)\b/i;

function iconFor(node) {
  if (!node.observed) return Ghost;
  const n = (node.process || "").toLowerCase();
  if (SHELLS.test(n)) return Terminal;
  if (n.endsWith(".dll")) return FileCode2;
  if (node.detections?.length) return ShieldAlert;
  if (node.signer) return Shield;
  return Cpu;
}

/** Suspicion is a RENDERING of evidence, not a verdict: it only reacts to
 *  detections the backend already attached, or to an unproven lineage. */
function tone(node) {
  if (node.detections?.length) return "#F87171";
  if (!node.observed) return "#64748B";
  if (node.lineage_state && node.lineage_state !== "PARENT_OBSERVED")
    return "#F5A34C";
  return "#7DB1D6";
}

/** Deterministic tidy layout: depth → column, pre-order → row. */
function layout(nodes, roots) {
  const byId = new Map(nodes.map((n) => [n.process_iid, n]));
  const placed = [];
  const seen = new Set();
  let row = 0;
  const walk = (id, depth) => {
    if (seen.has(id)) return;              // PID reuse / cyclic claim guard
    seen.add(id);
    const node = byId.get(id);
    if (!node) return;
    placed.push({ ...node, _x: depth * (NODE_W + GAP_X), _y: row * (NODE_H + GAP_Y), _depth: depth });
    row += 1;
    for (const child of [...(node.child_ids || [])].sort()) walk(child, depth + 1);
  };
  for (const r of [...(roots || [])].sort()) walk(r, 0);
  for (const n of nodes) if (!seen.has(n.process_iid)) walk(n.process_iid, 0);
  const pos = new Map(placed.map((p) => [p.process_iid, p]));
  const edges = [];
  for (const p of placed) {
    if (!p.parent_iid) continue;
    const from = pos.get(p.parent_iid);
    if (!from) continue;
    edges.push({
      id: `${p.parent_iid}->${p.process_iid}`,
      x1: from._x + NODE_W, y1: from._y + NODE_H / 2,
      x2: p._x, y2: p._y + NODE_H / 2,
      proven: from.observed && p.observed,
    });
  }
  return { placed, edges };
}

const Field = ({ label, value, mono }) => (
  <div className="py-1.5 border-b border-white/5 last:border-0">
    <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
    <div className={`text-sm text-slate-200 break-all ${mono ? "font-mono text-xs" : ""}`}>
      {value === null || value === undefined || value === "" ? "—" : String(value)}
    </div>
  </div>
);

export const ProcessGraphCanvas = ({ nodes = [], roots = [], meta = {} }) => {
  const { placed, edges } = useMemo(() => layout(nodes, roots), [nodes, roots]);
  const [selected, setSelected] = useState(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 24, y: 24 });
  const drag = useRef(null);

  const w = placed.length ? Math.max(...placed.map((p) => p._x)) + NODE_W + 48 : 640;
  const h = placed.length ? Math.max(...placed.map((p) => p._y)) + NODE_H + 48 : 240;
  const node = selected ? placed.find((p) => p.process_iid === selected) : null;

  const onDown = (e) => { drag.current = { x: e.clientX - pan.x, y: e.clientY - pan.y }; };
  const onMove = (e) => {
    if (!drag.current) return;
    setPan({ x: e.clientX - drag.current.x, y: e.clientY - drag.current.y });
  };
  const onUp = () => { drag.current = null; };

  if (!placed.length) {
    return (
      <div data-testid="process-graph-empty"
           className="rounded-xl border border-white/10 bg-[#0B0F17] p-10 text-center">
        <Ghost className="mx-auto mb-3 h-6 w-6 text-slate-600" />
        <p className="text-sm text-slate-400">
          No process evidence in this window. Nothing is drawn, because nothing
          was observed — this is an absence of telemetry, not an absence of activity.
        </p>
      </div>
    );
  }

  return (
    <div data-testid="process-graph" className="rounded-xl border border-white/10 bg-[#0B0F17] overflow-hidden">
      <div className="flex items-center justify-between border-b border-white/10 px-4 py-2.5">
        <div className="flex items-center gap-3 text-xs text-slate-400">
          <span data-testid="process-graph-count" className="text-slate-300">
            {placed.length} process{placed.length === 1 ? "" : "es"}
          </span>
          <span className="text-slate-600">·</span>
          <span data-testid="process-graph-ghosts">
            {placed.filter((p) => !p.observed).length} unobserved parent(s)
          </span>
          {meta.window_hours ? (
            <><span className="text-slate-600">·</span><span>{meta.window_hours}h window</span></>
          ) : null}
        </div>
        <div className="flex items-center gap-1">
          <button data-testid="process-graph-zoom-out" aria-label="zoom out"
                  onClick={() => setZoom((z) => Math.max(0.4, +(z - 0.15).toFixed(2)))}
                  className="rounded-md p-1.5 text-slate-400 transition-colors hover:bg-white/5 hover:text-slate-200">
            <ZoomOut className="h-4 w-4" />
          </button>
          <button data-testid="process-graph-zoom-in" aria-label="zoom in"
                  onClick={() => setZoom((z) => Math.min(2, +(z + 0.15).toFixed(2)))}
                  className="rounded-md p-1.5 text-slate-400 transition-colors hover:bg-white/5 hover:text-slate-200">
            <ZoomIn className="h-4 w-4" />
          </button>
          <button data-testid="process-graph-reset" aria-label="reset view"
                  onClick={() => { setZoom(1); setPan({ x: 24, y: 24 }); }}
                  className="rounded-md p-1.5 text-slate-400 transition-colors hover:bg-white/5 hover:text-slate-200">
            <Crosshair className="h-4 w-4" />
          </button>
        </div>
      </div>

      <div className="flex">
        <div className="relative flex-1 cursor-grab active:cursor-grabbing"
             style={{ height: 520, background:
               "radial-gradient(circle at 20% 0%, rgba(125,177,214,.07), transparent 55%), #0B0F17" }}
             onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={onUp}>
          <svg width="100%" height="100%" role="img" aria-label="process graph">
            <defs>
              <marker id="pg-arrow" markerWidth="9" markerHeight="9" refX="8" refY="3"
                      orient="auto" markerUnits="strokeWidth">
                <path d="M0,0 L0,6 L8,3 z" fill="#475569" />
              </marker>
            </defs>
            <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
              {edges.map((e) => (
                <path key={e.id} data-testid={`process-edge-${e.proven ? "proven" : "unproven"}`}
                      d={`M${e.x1},${e.y1} C${e.x1 + GAP_X / 2},${e.y1} ${e.x2 - GAP_X / 2},${e.y2} ${e.x2},${e.y2}`}
                      fill="none" stroke={e.proven ? "#475569" : "#64748B"}
                      strokeWidth={1.4} strokeDasharray={e.proven ? "0" : "5 4"}
                      markerEnd="url(#pg-arrow)" />
              ))}
              {placed.map((p) => {
                const Icon = iconFor(p);
                const accent = tone(p);
                const active = p.process_iid === selected;
                return (
                  <g key={p.process_iid} data-testid={`process-node-${p.process_iid}`}
                     transform={`translate(${p._x},${p._y})`} style={{ cursor: "pointer" }}
                     onClick={() => setSelected(p.process_iid)}>
                    <rect width={NODE_W} height={NODE_H} rx="10"
                          fill={active ? "#141B26" : "#0F1620"}
                          stroke={active ? accent : "rgba(255,255,255,.08)"}
                          strokeWidth={active ? 1.8 : 1} />
                    <rect width="3" height={NODE_H} rx="1.5" fill={accent} />
                    <foreignObject x="14" y="10" width={NODE_W - 24} height={NODE_H - 16}>
                      <div className="flex items-start gap-2">
                        <Icon className="mt-0.5 h-4 w-4 shrink-0" style={{ color: accent }} />
                        <div className="min-w-0">
                          <div className="truncate text-sm font-medium text-slate-100">
                            {p.process || "unobserved parent"}
                          </div>
                          <div className="truncate font-mono text-[11px] text-slate-500">
                            pid {p.pid ?? "—"}{p.user ? ` · ${p.user}` : ""}
                          </div>
                          {p.detections?.length ? (
                            <div className="truncate text-[10px] font-semibold uppercase tracking-wide text-rose-300">
                              {p.detections.length} detection{p.detections.length === 1 ? "" : "s"}
                            </div>
                          ) : null}
                        </div>
                      </div>
                    </foreignObject>
                  </g>
                );
              })}
            </g>
          </svg>
        </div>

        <aside data-testid="process-node-detail"
               className="w-80 shrink-0 border-l border-white/10 bg-[#0C1118] p-4 overflow-y-auto"
               style={{ height: 520 }}>
          {!node ? (
            <p className="text-sm text-slate-500">
              Select a process to see the evidence behind it.
            </p>
          ) : (
            <>
              <div className="mb-3 flex items-center gap-2">
                <ChevronRight className="h-4 w-4" style={{ color: tone(node) }} />
                <h3 className="truncate text-base font-semibold text-slate-100">
                  {node.process || "unobserved parent"}
                </h3>
              </div>
              {!node.observed && (
                <p data-testid="process-node-ghost-note"
                   className="mb-3 rounded-md border border-slate-700/60 bg-slate-800/40 p-2 text-xs text-slate-300">
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
                     value={node.detections?.length ? node.detections.join(", ") : null} />
              <Field label="evidence records" value={node.event_iids?.length ?? 0} />
              <Field label="process identity" value={node.process_iid} mono />
            </>
          )}
        </aside>
      </div>
    </div>
  );
};

export default ProcessGraphCanvas;
