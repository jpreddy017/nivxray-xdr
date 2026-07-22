/**
 * Process Ancestry Panel · v2 · R1.2
 *
 * Shows the spawn-chain graph rooted at a specific process for a case.
 * Backend: GET /api/v2/cases/{caseId}/ancestry/process/{processIid}
 *
 * Same design tokens as Device Trajectory (Amber-on-Graphite, IBM Plex).
 * Nodes render as a vertical waterfall — ancestors above the root,
 * descendants below. Edges are drawn as SVG connectors with a small
 * arrowhead. Selecting a node opens the same-style evidence drawer
 * used on the trajectory page.
 */
import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  Activity, ArrowLeft, ChevronRight, Radar, Shield, ShieldAlert,
  ShieldCheck, X,
} from "lucide-react";
import { isObservable } from "../flags";
import api from "@/lib/api";

const VERDICT = {
  benign:     { color: "#22C55E", label: "OBSERVATION", Icon: ShieldCheck },
  suspicious: { color: "#F59E0B", label: "SUSPICIOUS",  Icon: Shield      },
  malicious:  { color: "#E11D48", label: "MALICIOUS",   Icon: ShieldAlert },
};

const ROLE_META = {
  ancestor:   { label: "ANCESTOR",   color: "#71717A" },
  root:       { label: "ROOT",       color: "#F59E0B" },
  descendant: { label: "DESCENDANT", color: "#8B5CF6" },
};

const NODE_W = 260;
const NODE_H = 68;
const ROW_GAP = 42;

export default function ProcessAncestry() {
  const navigate = useNavigate();
  const { caseId, processIid } = useParams();
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [selectedKey, setSelectedKey] = useState(null);
  const enabled = isObservable("TRAJECTORY_ENGINE") || isObservable("CASE_ENGINE");

  useEffect(() => {
    if (!enabled || !caseId || !processIid) return;
    let cancelled = false;
    (async () => {
      try {
        const r = await api.get(
          `/v2/cases/${encodeURIComponent(caseId)}/ancestry/process/${encodeURIComponent(processIid)}`,
        );
        if (!cancelled) setData(r.data);
      } catch (e) {
        if (!cancelled) setErr(e?.response?.data?.detail || e.message);
      }
    })();
    return () => { cancelled = true; };
  }, [caseId, processIid, enabled]);

  // Layout: three rows — ancestors (top), root, descendants (bottom).
  const layout = useMemo(() => {
    if (!data?.nodes) return { rows: [], w: 800, h: 240 };
    const anc  = data.nodes.filter(n => n.role === "ancestor");
    const root = data.nodes.filter(n => n.role === "root");
    const desc = data.nodes.filter(n => n.role === "descendant");
    const rows = [anc, root, desc].filter(r => r.length > 0);
    const maxCols = Math.max(1, ...rows.map(r => r.length));
    const w = maxCols * (NODE_W + 40) + 40;
    const h = rows.length * (NODE_H + ROW_GAP) + 40;
    // Compute (x,y) for each node
    const pos = {};
    rows.forEach((row, ri) => {
      row.forEach((n, ci) => {
        const rowW = row.length * (NODE_W + 40);
        const offset = (w - rowW) / 2;
        pos[n.key] = {
          x: offset + ci * (NODE_W + 40),
          y: 20 + ri * (NODE_H + ROW_GAP),
        };
      });
    });
    return { rows, w, h, pos };
  }, [data]);

  const selectedNode = useMemo(
    () => data?.nodes?.find(n => n.key === selectedKey) || null,
    [data, selectedKey],
  );
  const selectedEvents = useMemo(
    () => (selectedKey && data?.events ? data.events[selectedKey] || [] : []),
    [data, selectedKey],
  );

  if (!enabled) {
    return (
      <div className="min-h-screen bg-zinc-950 text-zinc-500 p-6 text-xs"
           style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
        Trajectory engine disabled.
      </div>
    );
  }

  return (
    <div data-testid="v2-process-ancestry"
         className="flex flex-col h-screen overflow-hidden bg-zinc-950 text-zinc-100"
         style={{ fontFamily: "'IBM Plex Sans', sans-serif" }}>

      {/* Header */}
      <header className="h-14 shrink-0 flex items-center gap-4 border-b border-zinc-800 bg-zinc-950 px-4 z-20">
        <button
          data-testid="ancestry-back"
          onClick={() => navigate(`/v2/trajectory/${encodeURIComponent(caseId)}`)}
          className="w-8 h-8 flex items-center justify-center rounded-sm border border-zinc-800
                     text-zinc-400 hover:text-amber-500 hover:border-amber-500/40 transition-colors duration-150"
        >
          <ArrowLeft size={14} />
        </button>
        <div className="flex items-center gap-3">
          <div className="w-7 h-7 flex items-center justify-center rounded-sm bg-amber-500/10
                          border border-amber-500/30">
            <Activity className="text-amber-500" size={14} />
          </div>
          <div>
            <div className="text-[9px] tracking-[0.28em] text-zinc-500 uppercase font-semibold">
              NIVXRAY · V2 · R1.2
            </div>
            <h1 className="text-base font-semibold text-zinc-100 tracking-tight leading-none mt-0.5">
              Process Ancestry
            </h1>
          </div>
        </div>
        <div className="hidden md:flex items-center gap-2 pl-4 ml-2 border-l border-zinc-800 h-8">
          <span className="text-[10px] tracking-widest uppercase text-zinc-500 font-semibold">Case</span>
          <code className="text-[11px] text-amber-500"
                style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
            {caseId}
          </code>
          <span className="text-zinc-700 mx-1">·</span>
          <span className="text-[10px] tracking-widest uppercase text-zinc-500 font-semibold">Root</span>
          <code className="text-[11px] text-zinc-200"
                style={{ fontFamily: "'IBM Plex Mono', monospace" }}
                data-testid="ancestry-root-label">
            {data?.root_label ?? processIid}
          </code>
        </div>
        <div className="flex-1" />
        {data?.stats && (
          <div className="flex items-center gap-3 text-[10px] text-zinc-500 tracking-widest"
               style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
            <span data-testid="stat-ancestors">ANCESTORS <span className="text-zinc-200">{data.stats.ancestor_count}</span></span>
            <span data-testid="stat-descendants">DESCENDANTS <span className="text-zinc-200">{data.stats.descendant_count}</span></span>
            <span data-testid="stat-events">EVENTS <span className="text-zinc-200">{data.stats.total_events}</span></span>
          </div>
        )}
      </header>

      {err && (
        <div className="px-4 py-2 border-b border-rose-900/40 bg-rose-950/30 text-rose-400 text-xs"
             style={{ fontFamily: "'IBM Plex Mono', monospace" }} data-testid="ancestry-error">
          {String(err)}
        </div>
      )}

      <div className="flex flex-1 min-h-0">
        {/* Graph canvas */}
        <div className="flex-1 min-w-0 overflow-auto p-6">
          {!data && !err && (
            <div className="text-[11px] text-zinc-600"
                 style={{ fontFamily: "'IBM Plex Mono', monospace" }} data-testid="ancestry-loading">
              loading ancestry graph…
            </div>
          )}
          {data && data.nodes && (
            <div className="relative" style={{ width: layout.w, height: layout.h }}>
              {/* SVG edges */}
              <svg width={layout.w} height={layout.h}
                   className="absolute top-0 left-0 pointer-events-none">
                <defs>
                  <marker id="arrow-anc" markerWidth="10" markerHeight="10"
                          refX="8" refY="3" orient="auto">
                    <path d="M 0 0 L 8 3 L 0 6 z" fill="#71717A" />
                  </marker>
                </defs>
                {data.edges.map((e, i) => {
                  const from = layout.pos[e.parent];
                  const to = layout.pos[e.child];
                  if (!from || !to) return null;
                  const x1 = from.x + NODE_W / 2;
                  const y1 = from.y + NODE_H;
                  const x2 = to.x + NODE_W / 2;
                  const y2 = to.y;
                  const my = (y1 + y2) / 2;
                  return (
                    <path key={i}
                          d={`M ${x1} ${y1} L ${x1} ${my} L ${x2} ${my} L ${x2} ${y2 - 6}`}
                          stroke="#52525B" strokeWidth="1" strokeDasharray="3 3"
                          fill="none" markerEnd="url(#arrow-anc)" />
                  );
                })}
              </svg>

              {/* Nodes */}
              {data.nodes.map(n => (
                <NodeCard key={n.key} node={n}
                          x={layout.pos[n.key]?.x || 0}
                          y={layout.pos[n.key]?.y || 0}
                          selected={selectedKey === n.key}
                          onSelect={() => setSelectedKey(n.key)} />
              ))}
            </div>
          )}
        </div>

        {/* Right drawer */}
        <aside className="w-[380px] shrink-0 border-l border-zinc-800 bg-zinc-950/95 flex flex-col overflow-hidden"
               data-testid="ancestry-drawer">
          {selectedNode ? (
            <NodeDetail node={selectedNode} events={selectedEvents}
                        onClose={() => setSelectedKey(null)} />
          ) : (
            <div className="p-5" style={{ fontFamily: "'IBM Plex Sans', sans-serif" }}>
              <div className="flex items-center gap-2 mb-1">
                <Activity size={13} className="text-amber-500" />
                <span className="text-[10px] tracking-[0.24em] font-semibold text-zinc-400 uppercase">
                  Ancestry Overview
                </span>
              </div>
              <div className="text-[11px] text-zinc-500 mb-4"
                   style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                Click any node in the graph to inspect its events, MITRE mappings, and rule provenance.
              </div>
              <div className="text-[10px] text-zinc-500 mb-2 tracking-widest uppercase">Legend</div>
              <div className="space-y-1.5">
                {Object.entries(ROLE_META).map(([role, m]) => (
                  <div key={role} className="flex items-center gap-2">
                    <span className="w-3 h-3 rounded-sm border"
                          style={{ borderColor: m.color, background: m.color + "22" }} />
                    <span className="text-[10px] tracking-widest text-zinc-400">{m.label}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Node card (in the graph)
// ═══════════════════════════════════════════════════════════════════
function NodeCard({ node, x, y, selected, onSelect }) {
  const rMeta = ROLE_META[node.role] || ROLE_META.descendant;
  const vMeta = VERDICT[node.verdict] || VERDICT.benign;
  return (
    <button
      data-testid={`ancestry-node-${node.key}`}
      onClick={onSelect}
      className="absolute rounded-sm bg-zinc-900 border text-left outline-none focus-visible:ring-2
                 focus-visible:ring-amber-500 transition-transform duration-150 hover:-translate-y-[2px]"
      style={{
        left: x, top: y, width: NODE_W, height: NODE_H,
        borderColor: selected ? "#F59E0B" : (rMeta.color + "66"),
        borderLeftColor: rMeta.color, borderLeftWidth: 3,
        boxShadow: selected
          ? "0 0 0 1px #F59E0B, 0 6px 24px -8px rgba(245,158,11,0.35)"
          : `0 4px 16px -8px ${vMeta.color}44`,
      }}
    >
      <div className="p-2 flex flex-col gap-1 h-full">
        <div className="flex items-center gap-1.5">
          <span className="text-[9px] font-bold tracking-widest px-1 py-[1px] rounded-sm border"
                style={{ color: rMeta.color, borderColor: rMeta.color + "66",
                         background: rMeta.color + "14" }}>
            {rMeta.label}
          </span>
          <span className="inline-flex items-center gap-1 text-[9px] font-bold tracking-widest px-1 py-[1px] rounded-sm border"
                style={{ color: vMeta.color, borderColor: vMeta.color + "66",
                         background: vMeta.color + "14" }}>
            <vMeta.Icon size={9} /> {vMeta.label}
          </span>
          <div className="flex-1" />
          <span className="text-[9px] text-zinc-500 tabular-nums"
                style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
            {node.event_count} evt
          </span>
        </div>
        <div className="text-[12px] text-zinc-200 truncate"
             style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
          {node.label}
        </div>
        {node.mitre.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {node.mitre.slice(0, 4).map(t => (
              <span key={t}
                    className="text-[8px] px-1 py-[1px] border border-zinc-700 rounded-sm
                               bg-zinc-950 text-zinc-400"
                    style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                {t}
              </span>
            ))}
            {node.mitre.length > 4 && (
              <span className="text-[8px] text-zinc-600">+{node.mitre.length - 4}</span>
            )}
          </div>
        )}
      </div>
    </button>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Right-drawer node detail
// ═══════════════════════════════════════════════════════════════════
function NodeDetail({ node, events, onClose }) {
  const vMeta = VERDICT[node.verdict] || VERDICT.benign;
  return (
    <div className="flex-1 flex flex-col overflow-hidden" data-testid="ancestry-node-detail">
      <div className="px-5 pt-5 pb-4 border-b border-zinc-900 relative">
        <div className="absolute top-0 left-0 right-0 h-[3px]" style={{ background: vMeta.color }} />
        <div className="flex items-center gap-2 mb-2">
          <Activity size={13} className="text-amber-500" />
          <span className="text-[10px] tracking-[0.24em] font-semibold text-zinc-400 uppercase">
            {ROLE_META[node.role]?.label || node.role}
          </span>
          <div className="flex-1" />
          <button data-testid="ancestry-detail-close" onClick={onClose}
                  className="text-zinc-600 hover:text-zinc-300"><X size={14} /></button>
        </div>
        <span className="inline-flex items-center gap-1 text-[9px] font-bold tracking-[0.2em] px-1.5 py-0.5 rounded-sm border"
              style={{ color: vMeta.color, borderColor: vMeta.color + "66",
                       background: vMeta.color + "14" }}>
          <vMeta.Icon size={10} /> {vMeta.label}
        </span>
        <div className="mt-3 text-[13px] text-zinc-100 break-all"
             style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
          {node.label}
        </div>
        <div className="mt-2 text-[10px] text-zinc-500 tabular-nums"
             style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
          {node.event_count} event(s) · {node.first_ts || "—"} → {node.last_ts || "—"}
        </div>
      </div>

      {node.mitre.length > 0 && (
        <div className="px-5 py-3 border-b border-zinc-900">
          <div className="text-[9px] tracking-[0.24em] font-semibold text-zinc-500 uppercase mb-2">
            MITRE ATT&CK
          </div>
          <div className="flex flex-wrap gap-1">
            {node.mitre.map(t => (
              <span key={t}
                    className="text-[10px] px-1.5 py-0.5 border border-rose-500/30 rounded-sm
                               text-rose-400 bg-rose-500/5"
                    style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                {t}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="flex-1 overflow-y-auto">
        <div className="px-5 py-3 sticky top-0 bg-zinc-950/95 border-b border-zinc-900">
          <div className="text-[9px] tracking-[0.24em] font-semibold text-zinc-500 uppercase">
            Events ({events.length})
          </div>
        </div>
        {events.map((e, i) => (
          <div key={e.frame_iid || i}
               data-testid={`ancestry-event-${e.frame_iid || i}`}
               className="px-5 py-2 border-b border-zinc-900/70">
            <div className="flex items-center gap-2 text-[10px] text-zinc-500 mb-1"
                 style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
              <ChevronRight size={10} className="text-zinc-600" />
              <span className="tabular-nums">{new Date(e.ts).toISOString().slice(11, 19)}</span>
              <span className="text-zinc-700">·</span>
              <span className="uppercase tracking-widest">{e.lane || "—"}</span>
              <span className="text-zinc-700">·</span>
              <span>{e.action}</span>
            </div>
            <div className="text-[11px] text-zinc-200 break-words"
                 style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
              {e.label}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
