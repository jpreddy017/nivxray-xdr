/**
 * Device Trajectory · v2 · Process-timeline redesign.
 *
 * Adopted pattern (per user reference — Cisco Secure Endpoint Device
 * Trajectory, Black Hat Asia 2023 XDR NOC blog):
 *   - One row per process (not per event category)
 *   - Each row has a horizontal LIFELINE spanning first→last event
 *   - Event glyphs sit ON the lifeline (icon per event kind, halo per verdict)
 *   - Vertical dashed SPAWN ARCS connect parent → child process rows
 *   - Top strip is a mini HISTOGRAM SCRUBBER of event density over time
 *   - Right-side EVENT DETAILS panel appears on selection
 *
 * Visuals (design_guidelines.json — "Amber-on-Graphite / Tactical Surveillance"):
 *   - zinc-950 base, zinc-800 borders, IBM Plex Sans + Mono
 *   - Amber #F59E0B as the ONE hero accent (V2 badge, zoom active, selection)
 *   - Per-lane accents kept small: violet SYSTEM, rose PROCESS, amber FILES,
 *     indigo NETWORK, orange REGISTRY — used to tint event glyphs
 *   - Verdict halos: emerald (observation) · amber (suspicious) · rose (malicious)
 *   - No cyan/teal anywhere. No copied Cisco chrome.
 *
 * Feature-flag gated on TRAJECTORY_ENGINE. No RC5 imports.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  Cpu, Activity, FileCode, Globe, Database,
  Search, Shield, ShieldAlert, ShieldCheck, ChevronRight, ChevronDown,
  Clock, PenSquare, Radar, Play, AlertTriangle, X, Filter, HelpCircle,
  FolderOpen, Sparkles,
} from "lucide-react";
import { isObservable } from "../flags";
import api from "@/lib/api";

// LocalStorage key for the "new since last view" badge
const LAST_VIEWED_KEY = (caseId) => `nivx.trajectory.lastViewed.${caseId}`;
// Confidence tiers used by the evidence badge
function confidenceTierOf(frame) {
  const c = Number(frame.provenance?.confidence ?? frame.confidence ?? 0);
  if (c >= 0.8 || frame.rule_id) return { key: "high",   label: "HIGH",   color: "#22C55E" };
  if (c >= 0.5 || (frame.mitre || []).length > 0)
                                 return { key: "medium", label: "MED",    color: "#F59E0B" };
  return                                { key: "low",    label: "LOW",    color: "#71717A" };
}

// ═══════════════════════════════════════════════════════════════════
// Lane metadata (accents applied to event glyphs, NOT full-row bands)
// ═══════════════════════════════════════════════════════════════════
const LANE_META = {
  system:   { label: "SYSTEM",   accent: "#8B5CF6", Icon: Cpu      },
  process:  { label: "PROCESS",  accent: "#E11D48", Icon: Activity },
  file:     { label: "FILES",    accent: "#F59E0B", Icon: FileCode },
  network:  { label: "NETWORK",  accent: "#4F46E5", Icon: Globe    },
  registry: { label: "REGISTRY", accent: "#EA580C", Icon: Database },
};
const LANE_ORDER = ["system", "process", "file", "network", "registry"];

const VERDICT = {
  benign:     { color: "#22C55E", label: "OBSERVATION",  Icon: ShieldCheck },
  suspicious: { color: "#F59E0B", label: "SUSPICIOUS",   Icon: Shield      },
  malicious:  { color: "#E11D48", label: "MALICIOUS",    Icon: ShieldAlert },
};
function verdictFor(f) {
  const hasMitre = (f.mitre || []).length > 0;
  const rule = (f.rule_id || f.provenance?.rule_id || "").toLowerCase();
  if (hasMitre && rule) return "malicious";
  if (hasMitre) return "suspicious";
  return "benign";
}

// Graph-paper track backdrop
const TRACK_BG =
  "url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='48' height='48'>" +
  "<path d='M48 0H0v48' fill='none' stroke='%2327272A' stroke-opacity='0.35' stroke-width='0.5'/>" +
  "<path d='M12 0v48M24 0v48M36 0v48M0 12h48M0 24h48M0 36h48' fill='none' stroke='%2327272A' stroke-opacity='0.18' stroke-width='0.5'/>" +
  "</svg>\")";

// Layout constants
const ROW_H = 34;                 // per-process row height in canvas
const LEFT_RAIL_W = 232;          // width of the process-label rail
const CANVAS_PAD_X = 24;          // horizontal padding inside the track
const SCRUBBER_H = 56;            // top histogram scrubber height

// Extract a readable process-name label from a frame
function processLabelOf(frame) {
  const raw = frame.label || frame.action || "";
  const m = raw.match(/([A-Za-z0-9_.-]+\.(?:exe|dll|msi|ps1|bat|cmd|sys|com))/i);
  if (m) return m[1];
  const p = (frame.process?.iid || frame.parent?.iid || "").split(/[:/\\]/).pop();
  return p || (frame.action || "event");
}
// Group key: prefer readable process name so that N events from the same
// binary collapse to ONE lifeline (Cisco Device Trajectory pattern). The
// shadow adapter mints a unique `proc_shadow_xxxx` iid per event, which
// would otherwise explode into one row per event.
function processKeyOf(frame) {
  const label = processLabelOf(frame);
  if (label && /\.(exe|dll|msi|ps1|bat|cmd|sys|com)$/i.test(label)) {
    return `bin:${label.toLowerCase()}`;
  }
  return frame.process?.iid || frame.parent?.iid || `sys:${frame.lane}`;
}

// ═══════════════════════════════════════════════════════════════════
// Root component
// ═══════════════════════════════════════════════════════════════════
export default function DeviceTrajectory() {
  const navigate = useNavigate();
  const { caseId = "case_dfir_bumblebee_akira_2026" } = useParams() || {};
  const [data, setData] = useState(null);
  const [err, setErr]   = useState(null);
  const [selected, setSelected] = useState(null);
  const [zoom, setZoom] = useState("Fit");
  const [query, setQuery] = useState("");
  const searchRef = useRef(null);
  const canvasRef = useRef(null);
  const [canvasW, setCanvasW] = useState(1200);
  // R1.1 · Filter chips
  const [verdictFilter, setVerdictFilter] = useState("all"); // all | benign | suspicious | malicious
  const [laneFilter, setLaneFilter]       = useState("all"); // all | system | process | file | network | registry
  const [mitreFilter, setMitreFilter]     = useState(null);  // null | "TXXXX"
  // R1.1 · Case selector
  const [cases, setCases]           = useState(null);
  const [caseMenuOpen, setCaseMenu] = useState(false);
  const [legendOpen, setLegendOpen] = useState(false);
  // R1.1 · New-since-last-view badge
  const [lastViewed, setLastViewed] = useState(null);

  const enabled = isObservable("TRAJECTORY_ENGINE") || isObservable("CASE_ENGINE");

  // Fetch
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    (async () => {
      try {
        const r = await api.get(
          `/v2/cases/${encodeURIComponent(caseId)}/trajectory/device?limit=1000`,
        );
        if (!cancelled) setData(r.data);
      } catch (e) {
        if (!cancelled) setErr(e?.response?.data?.detail || e.message);
      }
    })();
    return () => { cancelled = true; };
  }, [caseId, enabled]);

  // R1.1 · Load case list for the selector (best-effort — 401/404 → keep null)
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    (async () => {
      try {
        const r = await api.get("/v2/cases?limit=100");
        if (!cancelled) setCases(Array.isArray(r.data) ? r.data : []);
      } catch (_) {
        if (!cancelled) setCases([]);
      }
    })();
    return () => { cancelled = true; };
  }, [enabled]);

  // R1.1 · Read the "last viewed" timestamp for this case, then bump it.
  useEffect(() => {
    if (!enabled) return;
    try {
      const prev = localStorage.getItem(LAST_VIEWED_KEY(caseId));
      setLastViewed(prev ? Number(prev) : null);
      localStorage.setItem(LAST_VIEWED_KEY(caseId), String(Date.now()));
    } catch (_) { /* localStorage disabled — ignore */ }
  }, [caseId, enabled]);

  // Observe canvas resize so nodes stay pixel-precise across viewports
  useEffect(() => {
    if (!canvasRef.current) return;
    const el = canvasRef.current;
    const ro = new ResizeObserver(entries => {
      for (const ent of entries) setCanvasW(ent.contentRect.width);
    });
    ro.observe(el);
    setCanvasW(el.clientWidth);
    return () => ro.disconnect();
  }, [enabled]);

  // Filtered frames (search + verdict + lane + mitre chip)
  const frames = useMemo(() => {
    if (!data?.frames) return [];
    let out = data.frames;
    if (verdictFilter !== "all")
      out = out.filter(f => verdictFor(f) === verdictFilter);
    if (laneFilter !== "all")
      out = out.filter(f => f.lane === laneFilter);
    if (mitreFilter)
      out = out.filter(f => (f.mitre || []).includes(mitreFilter));
    if (query) {
      const q = query.toLowerCase();
      out = out.filter(f =>
        (f.label || "").toLowerCase().includes(q) ||
        (f.action || "").toLowerCase().includes(q) ||
        processLabelOf(f).toLowerCase().includes(q) ||
        (f.mitre || []).some(t => t.toLowerCase().includes(q)),
      );
    }
    return out;
  }, [data, query, verdictFilter, laneFilter, mitreFilter]);

  // R1.1 · Count of frames newer than the last-viewed timestamp
  const newSinceCount = useMemo(() => {
    if (!lastViewed || !data?.frames) return 0;
    return data.frames.filter(f => {
      const ing = new Date(f.provenance?.ingested_at || f.ts).getTime();
      return ing > lastViewed;
    }).length;
  }, [data, lastViewed]);

  // Time domain + x mapper
  const { xForTs, minTs, maxTs, tickTimes } = useMemo(() => {
    if (!frames.length) return { xForTs: () => 0, minTs: 0, maxTs: 1, tickTimes: [] };
    const times = frames.map(f => new Date(f.ts).getTime());
    let lo = Math.min(...times), hi = Math.max(...times);
    if (hi === lo) hi = lo + 1000;
    const span = hi - lo;
    const usableW = Math.max(canvasW - CANVAS_PAD_X * 2, 200);
    const ticks = Array.from({ length: 9 }, (_, i) => lo + (span * i) / 8);
    return {
      xForTs: (ts) => CANVAS_PAD_X + ((new Date(ts).getTime() - lo) / span) * usableW,
      minTs: lo, maxTs: hi, tickTimes: ticks,
    };
  }, [frames, canvasW]);

  // Build the per-process rows
  const rows = useMemo(() => {
    const byKey = new Map();
    frames.forEach(f => {
      const key = processKeyOf(f);
      if (!byKey.has(key)) {
        byKey.set(key, {
          key,
          label: processLabelOf(f),
          type: (f.process?.iid ? "PROC" : (f.parent?.iid ? "PROC" : "SYS")),
          events: [],
          firstTs: new Date(f.ts).getTime(),
          lastTs: new Date(f.ts).getTime(),
          parentKey: f.parent?.iid || null,
          worstVerdict: "benign",
        });
      }
      const r = byKey.get(key);
      r.events.push(f);
      const ts = new Date(f.ts).getTime();
      if (ts < r.firstTs) r.firstTs = ts;
      if (ts > r.lastTs)  r.lastTs  = ts;
      const v = verdictFor(f);
      if (v === "malicious" || (v === "suspicious" && r.worstVerdict !== "malicious")) {
        r.worstVerdict = v;
      }
    });
    // Sort by first-seen ts so lifelines cascade
    return [...byKey.values()].sort((a, b) =>
      a.firstTs !== b.firstTs ? a.firstTs - b.firstTs : a.label.localeCompare(b.label)
    );
  }, [frames]);

  const rowIndex = useMemo(() => {
    const m = new Map();
    rows.forEach((r, i) => m.set(r.key, i));
    return m;
  }, [rows]);

  // Spawn edges (parent → child)
  const spawnEdges = useMemo(() => {
    const edges = [];
    rows.forEach(child => {
      if (!child.parentKey) return;
      if (!rowIndex.has(child.parentKey)) return;
      edges.push({ parent: child.parentKey, child: child.key });
    });
    return edges;
  }, [rows, rowIndex]);

  // Histogram buckets (top scrubber)
  const histogram = useMemo(() => {
    const B = 48;
    const arr = new Array(B).fill(0);
    if (!frames.length) return arr;
    const span = maxTs - minTs || 1;
    frames.forEach(f => {
      const t = new Date(f.ts).getTime();
      const i = Math.min(B - 1, Math.max(0, Math.floor(((t - minTs) / span) * B)));
      arr[i] += 1;
    });
    return arr;
  }, [frames, minTs, maxTs]);

  // Overview (drawer empty state)
  const overview = useMemo(() => {
    const mitreCount = new Map();
    const laneCount = Object.fromEntries(LANE_ORDER.map(l => [l, 0]));
    frames.forEach(f => {
      (f.mitre || []).forEach(t => mitreCount.set(t, (mitreCount.get(t) || 0) + 1));
      if (laneCount[f.lane] != null) laneCount[f.lane] += 1;
    });
    return {
      mitre: [...mitreCount.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6),
      lanes: LANE_ORDER.map(l => [l, laneCount[l]]),
      processes: rows.length,
      malicious: frames.filter(f => verdictFor(f) === "malicious").length,
      suspicious: frames.filter(f => verdictFor(f) === "suspicious").length,
    };
  }, [frames, rows]);

  // Keyboard nav
  useEffect(() => {
    if (!enabled) return;
    const handler = (e) => {
      if (e.key === "/" && document.activeElement?.tagName !== "INPUT") {
        e.preventDefault(); searchRef.current?.focus(); return;
      }
      if (e.key === "Escape") { setSelected(null); return; }
      if (!frames.length) return;
      if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
      const idx = selected ? frames.findIndex(f => f.frame_iid === selected.frame_iid) : -1;
      const nextIdx = e.key === "ArrowRight"
        ? Math.min(idx + 1, frames.length - 1)
        : Math.max(idx - 1, 0);
      setSelected(frames[nextIdx]);
      e.preventDefault();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [enabled, frames, selected]);

  const onPickEvent = useCallback((f) => setSelected(f), []);

  if (!enabled) {
    return (
      <div data-testid="v2-trajectory-disabled"
           className="min-h-screen bg-zinc-950 text-zinc-500 p-6 text-xs"
           style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
        Device Trajectory is disabled. Set{" "}
        <code className="text-amber-500">REACT_APP_NIVX_FLAG_TRAJECTORY_ENGINE=shadow</code>{" "}or{" "}
        <code className="text-amber-500">REACT_APP_NIVX_FLAG_CASE_ENGINE=shadow</code>.
      </div>
    );
  }

  // Total canvas height for absolute-positioned children
  const canvasH = rows.length * ROW_H + 16;

  return (
    <div data-testid="v2-device-trajectory"
         className="flex flex-col h-screen overflow-hidden bg-zinc-950 text-zinc-100"
         style={{ fontFamily: "'IBM Plex Sans', sans-serif" }}>
      <Header
        caseId={caseId} count={data?.count} totalRows={rows.length}
        query={query} setQuery={setQuery}
        zoom={zoom} setZoom={setZoom}
        searchRef={searchRef}
        cases={cases}
        caseMenuOpen={caseMenuOpen} setCaseMenu={setCaseMenu}
        onPickCase={(id) => navigate(`/v2/trajectory/${encodeURIComponent(id)}`)}
        legendOpen={legendOpen} setLegendOpen={setLegendOpen}
        newSinceCount={newSinceCount}
      />

      {err && (
        <div className="px-4 py-2 border-b border-rose-900/40 bg-rose-950/30 text-rose-400 text-xs"
             style={{ fontFamily: "'IBM Plex Mono', monospace" }}
             data-testid="v2-trajectory-error">
          {String(err)}
        </div>
      )}

      {/* Top two-tier scrubber */}
      <Scrubber histogram={histogram} minTs={minTs} maxTs={maxTs} frames={frames} />

      {/* R1.1 · Filter chips row */}
      <FilterChips
        verdictFilter={verdictFilter} setVerdictFilter={setVerdictFilter}
        laneFilter={laneFilter} setLaneFilter={setLaneFilter}
        mitreFilter={mitreFilter} setMitreFilter={setMitreFilter}
        topMitre={overview.mitre}
        counts={{
          malicious:  overview.malicious,
          suspicious: overview.suspicious,
          benign:     (data?.count ?? 0) - overview.malicious - overview.suspicious,
        }}
        laneCounts={Object.fromEntries(overview.lanes)}
        totalShown={frames.length}
        totalAll={data?.count ?? 0}
      />

      {/* Main work area */}
      <div className="flex flex-1 min-h-0">
        <div className="flex-1 flex flex-col min-w-0 relative">
          {/* Row layout (left rail + track canvas) */}
          <div className="flex-1 flex overflow-auto">
            <ProcessRail rows={rows} selectedKey={selected ? processKeyOf(selected) : null}
                         onPickRow={(r) => onPickEvent(r.events[0])} />

            <div
              ref={canvasRef}
              className="flex-1 relative overflow-hidden"
              style={{ backgroundImage: TRACK_BG, backgroundSize: "48px 48px" }}
              data-testid="trajectory-canvas"
            >
              <div className="relative" style={{ height: canvasH }}>
                {/* Row separators */}
                {rows.map((r, i) => (
                  <div key={r.key + ":sep"} className="absolute inset-x-0 border-b border-zinc-900/70"
                       style={{ top: (i + 1) * ROW_H - 1, height: 1 }} />
                ))}

                {/* SVG overlay: lifelines + spawn arcs */}
                <svg width={canvasW} height={canvasH}
                     className="absolute top-0 left-0 pointer-events-none">
                  {/* Lifelines — dashed, matching Cisco Device Trajectory pattern */}
                  {rows.map((r, i) => {
                    const y = i * ROW_H + ROW_H / 2;
                    const x1 = xForTs(r.firstTs);
                    const x2 = xForTs(r.lastTs);
                    const isSel = selected && processKeyOf(selected) === r.key;
                    const stroke = r.worstVerdict === "malicious"
                      ? VERDICT.malicious.color
                      : r.worstVerdict === "suspicious"
                        ? "#A16207" // muted amber
                        : "#3F3F46"; // zinc-700
                    return (
                      <g key={r.key + ":line"}>
                        <line x1={x1 - 4} y1={y} x2={x2 + 4} y2={y}
                              stroke={stroke} strokeWidth={isSel ? 1.5 : 1}
                              strokeDasharray="2 3"
                              strokeOpacity={isSel ? 0.95 : 0.55} />
                      </g>
                    );
                  })}
                  {/* Spawn arcs: dashed L-shaped connector parent → child */}
                  {spawnEdges.map(({ parent, child }, i) => {
                    const pi = rowIndex.get(parent), ci = rowIndex.get(child);
                    if (pi == null || ci == null) return null;
                    const py = pi * ROW_H + ROW_H / 2;
                    const cy = ci * ROW_H + ROW_H / 2;
                    const childRow = rows[ci];
                    const cx = xForTs(childRow.firstTs);
                    return (
                      <path key={`spawn-${i}`}
                            d={`M ${cx} ${py} L ${cx} ${cy - 6}`}
                            stroke="#52525B" strokeWidth="1" strokeDasharray="3 3"
                            fill="none" opacity="0.75" />
                    );
                  })}
                </svg>

                {/* Selected row highlight band */}
                {selected && (() => {
                  const idx = rowIndex.get(processKeyOf(selected));
                  if (idx == null) return null;
                  return (
                    <div className="absolute inset-x-0 pointer-events-none"
                         style={{ top: idx * ROW_H, height: ROW_H,
                                  background: "linear-gradient(90deg, rgba(245,158,11,0.10), rgba(245,158,11,0.04))",
                                  borderTop: "1px solid rgba(245,158,11,0.35)",
                                  borderBottom: "1px solid rgba(245,158,11,0.35)" }} />
                  );
                })()}

                {/* Event glyphs */}
                {frames.map(f => {
                  const key = processKeyOf(f);
                  const i = rowIndex.get(key);
                  if (i == null) return null;
                  const x = xForTs(f.ts);
                  const y = i * ROW_H + ROW_H / 2;
                  const isSel = selected?.frame_iid === f.frame_iid;
                  return (
                    <EventGlyph key={f.frame_iid || `${key}-${x}`}
                                frame={f} x={x} y={y} selected={isSel}
                                onSelect={onPickEvent} />
                  );
                })}
              </div>

              {/* Empty hint */}
              {!frames.length && !err && (
                <div className="absolute inset-0 flex items-center justify-center text-zinc-600 pointer-events-none"
                     style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                  <div className="text-xs tracking-wider text-center">
                    <Radar className="mx-auto mb-2 text-zinc-700" size={22} />
                    NO TRAJECTORY FRAMES · seed observations via{" "}
                    <code className="text-amber-500">POST /api/v2/cases/{caseId}/observations</code>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Bottom ruler */}
          <TimeRuler ticks={tickTimes} zoom={zoom} minTs={minTs} maxTs={maxTs}
                     total={frames.length} rows={rows.length} />
        </div>

        <Drawer selected={selected} onClose={() => setSelected(null)}
                overview={overview} totalEvents={data?.count ?? 0} caseId={caseId}
                frames={frames} onPickEvent={onPickEvent} />
      </div>

      {/* Floating Training Note CTA */}
      <button
        data-testid="training-note-cta"
        className="fixed bottom-6 right-[404px] bg-amber-500 text-amber-950 px-3 py-1.5 rounded-sm
                   font-semibold text-[11px] tracking-wider shadow-lg hover:bg-amber-400
                   border border-amber-300/60 flex items-center gap-2 z-40
                   transition-colors duration-150"
      >
        <PenSquare size={12} /> TRAINING NOTE
      </button>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Header
// ═══════════════════════════════════════════════════════════════════
function Header({
  caseId, count, totalRows, query, setQuery, zoom, setZoom, searchRef,
  cases, caseMenuOpen, setCaseMenu, onPickCase,
  legendOpen, setLegendOpen, newSinceCount,
}) {
  return (
    <header className="h-14 shrink-0 flex items-center gap-4 border-b border-zinc-800 bg-zinc-950 px-4 z-20 relative">
      <div className="flex items-center gap-3">
        <div className="w-7 h-7 flex items-center justify-center rounded-sm bg-amber-500/10
                        border border-amber-500/30 shadow-[0_0_8px_rgba(245,158,11,0.15)]">
          <Radar className="text-amber-500" size={14} />
        </div>
        <div>
          <div className="text-[9px] tracking-[0.28em] text-zinc-500 uppercase font-semibold">
            NIVXRAY · V2 · SHADOW
          </div>
          <h1 className="text-base font-semibold text-zinc-100 tracking-tight leading-none mt-0.5">
            Device Trajectory
          </h1>
        </div>
      </div>

      {/* Case selector dropdown */}
      <div className="hidden md:flex items-center gap-2 pl-4 ml-2 border-l border-zinc-800 h-8 relative">
        <span className="text-[10px] tracking-widest uppercase text-zinc-500 font-semibold">Case</span>
        <button
          data-testid="case-selector-trigger"
          onClick={() => setCaseMenu(!caseMenuOpen)}
          className="flex items-center gap-1.5 px-2 py-1 rounded-sm border border-zinc-800
                     hover:border-amber-500/40 hover:bg-amber-500/5 transition-colors duration-150"
        >
          <FolderOpen size={11} className="text-amber-500/70" />
          <code className="text-[11px] text-amber-500 max-w-[240px] truncate"
                style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
            {caseId}
          </code>
          {newSinceCount > 0 && (
            <span
              data-testid="new-since-badge"
              className="ml-1 text-[9px] font-bold tracking-wider px-1.5 py-0.5 rounded-sm
                         bg-amber-500 text-amber-950 flex items-center gap-1"
              title={`${newSinceCount} new events since last visit`}
            >
              <Sparkles size={9} /> {newSinceCount} NEW
            </span>
          )}
          <ChevronDown size={11} className={"text-zinc-500 transition-transform duration-150 " +
                                             (caseMenuOpen ? "rotate-180" : "")} />
        </button>

        {caseMenuOpen && cases && (
          <div
            data-testid="case-selector-menu"
            className="absolute top-full mt-1 left-16 w-96 max-h-80 overflow-y-auto z-40
                       bg-zinc-950 border border-zinc-800 rounded-sm shadow-2xl"
          >
            {cases.length === 0 && (
              <div className="p-3 text-[11px] text-zinc-600"
                   style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                no cases indexed · use POST /api/v2/cases to seed
              </div>
            )}
            {cases.map(c => {
              const id = c.case_id || c._id || c.id;
              const isActive = id === caseId;
              return (
                <button
                  key={id}
                  data-testid={`case-option-${id}`}
                  onClick={() => { onPickCase(id); setCaseMenu(false); }}
                  className={"w-full text-left px-3 py-2 border-b border-zinc-900 last:border-b-0 " +
                             "transition-colors duration-100 " +
                             (isActive ? "bg-amber-500/10" : "hover:bg-zinc-900/50")}
                >
                  <div className={"text-[11px] " + (isActive ? "text-amber-400" : "text-zinc-200")}
                       style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                    {id}
                  </div>
                  {c.title && (
                    <div className="text-[10px] text-zinc-500 mt-0.5">{c.title}</div>
                  )}
                </button>
              );
            })}
          </div>
        )}

        <span className="text-zinc-700 mx-1">·</span>
        <span className="text-[10px] tracking-widest uppercase text-zinc-500 font-semibold">Events</span>
        <span className="text-[11px] text-zinc-200 tabular-nums"
              style={{ fontFamily: "'IBM Plex Mono', monospace" }}
              data-testid="event-count-label">
          {count ?? "—"}
        </span>
        <span className="text-zinc-700 mx-1">·</span>
        <span className="text-[10px] tracking-widest uppercase text-zinc-500 font-semibold">Procs</span>
        <span className="text-[11px] text-zinc-200 tabular-nums"
              style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
          {totalRows}
        </span>
      </div>

      <div className="flex-1" />

      {/* Legend button */}
      <div className="relative">
        <button
          data-testid="glyph-legend-trigger"
          onClick={() => setLegendOpen(!legendOpen)}
          className="w-8 h-8 flex items-center justify-center rounded-sm border border-zinc-800
                     text-zinc-400 hover:text-amber-500 hover:border-amber-500/40 transition-colors duration-150"
          title="Symbol legend"
        >
          <HelpCircle size={14} />
        </button>
        {legendOpen && <GlyphLegend onClose={() => setLegendOpen(false)} />}
      </div>

      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-600" size={12} />
        <input
          ref={searchRef}
          data-testid="trajectory-search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="search process / command / mitre"
          className="pl-8 pr-8 py-1.5 w-72 bg-zinc-900 border border-zinc-700 rounded-sm
                     text-xs text-zinc-200 placeholder-zinc-600 outline-none
                     focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors duration-150"
          style={{ fontFamily: "'IBM Plex Mono', monospace" }}
        />
        <kbd className="absolute right-2 top-1/2 -translate-y-1/2 text-[9px] text-zinc-600
                        border border-zinc-700 rounded px-1 bg-zinc-950 pointer-events-none">/</kbd>
      </div>

      <div className="flex items-center gap-1 border border-zinc-800 rounded-sm p-0.5" role="tablist">
        {["Fit", "1h", "24h", "7d", "30d"].map(z => (
          <button key={z}
            data-testid={`zoom-${z}`}
            onClick={() => setZoom(z)}
            className={
              "px-2.5 py-1 text-[10px] font-semibold tracking-wider rounded-sm transition-colors duration-150 " +
              (zoom === z
                ? "bg-amber-500/15 text-amber-500 border border-amber-500/40 shadow-[0_0_8px_rgba(245,158,11,0.12)]"
                : "text-zinc-500 hover:text-zinc-300 border border-transparent")
            }
            style={{ fontFamily: "'IBM Plex Mono', monospace" }}
          >
            {z.toUpperCase()}
          </button>
        ))}
      </div>
    </header>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Filter chips row (R1.1 · Analyst Experience)
// ═══════════════════════════════════════════════════════════════════
function FilterChips({
  verdictFilter, setVerdictFilter,
  laneFilter, setLaneFilter,
  mitreFilter, setMitreFilter,
  topMitre, counts, laneCounts, totalShown, totalAll,
}) {
  const hasFilter = verdictFilter !== "all" || laneFilter !== "all" || mitreFilter;
  return (
    <div className="shrink-0 border-b border-zinc-800 bg-zinc-950/95 px-4 py-2
                    flex items-center gap-2 flex-wrap"
         data-testid="filter-chips">
      <div className="flex items-center gap-1.5">
        <Filter size={11} className="text-zinc-600" />
        <span className="text-[9px] tracking-[0.24em] text-zinc-500 uppercase font-semibold">
          Filter
        </span>
      </div>

      {/* Verdict pills */}
      <ChipGroup>
        <Chip active={verdictFilter === "all"} onClick={() => setVerdictFilter("all")}
              tid="chip-verdict-all">
          All
        </Chip>
        <Chip active={verdictFilter === "malicious"} onClick={() => setVerdictFilter("malicious")}
              tid="chip-verdict-malicious" color="#E11D48">
          <ShieldAlert size={10} /> Malicious
          <span className="tabular-nums opacity-70">{counts.malicious}</span>
        </Chip>
        <Chip active={verdictFilter === "suspicious"} onClick={() => setVerdictFilter("suspicious")}
              tid="chip-verdict-suspicious" color="#F59E0B">
          <Shield size={10} /> Suspicious
          <span className="tabular-nums opacity-70">{counts.suspicious}</span>
        </Chip>
        <Chip active={verdictFilter === "benign"} onClick={() => setVerdictFilter("benign")}
              tid="chip-verdict-benign" color="#22C55E">
          <ShieldCheck size={10} /> Observation
          <span className="tabular-nums opacity-70">{counts.benign}</span>
        </Chip>
      </ChipGroup>

      <span className="w-px h-4 bg-zinc-800 mx-1" />

      {/* Lane pills */}
      <ChipGroup>
        <Chip active={laneFilter === "all"} onClick={() => setLaneFilter("all")}
              tid="chip-lane-all">All lanes</Chip>
        {LANE_ORDER.map(l => {
          const meta = LANE_META[l];
          return (
            <Chip key={l} active={laneFilter === l} onClick={() => setLaneFilter(l)}
                  tid={`chip-lane-${l}`} color={meta.accent}>
              <meta.Icon size={10} /> {meta.label}
              <span className="tabular-nums opacity-70">{laneCounts[l] || 0}</span>
            </Chip>
          );
        })}
      </ChipGroup>

      {topMitre.length > 0 && (
        <>
          <span className="w-px h-4 bg-zinc-800 mx-1" />
          <ChipGroup>
            {topMitre.slice(0, 4).map(([tid, n]) => (
              <Chip key={tid}
                    active={mitreFilter === tid}
                    onClick={() => setMitreFilter(mitreFilter === tid ? null : tid)}
                    tid={`chip-mitre-${tid}`}
                    color="#F87171">
                {tid}
                <span className="tabular-nums opacity-70">{n}</span>
              </Chip>
            ))}
          </ChipGroup>
        </>
      )}

      <div className="flex-1" />

      {/* Result count + clear */}
      <div className="flex items-center gap-2 text-[10px] text-zinc-500"
           style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
        <span className="text-zinc-200 tabular-nums">{totalShown}</span>
        <span className="text-zinc-600">/</span>
        <span className="tabular-nums">{totalAll}</span>
        <span>shown</span>
        {hasFilter && (
          <button
            data-testid="filter-clear"
            onClick={() => { setVerdictFilter("all"); setLaneFilter("all"); setMitreFilter(null); }}
            className="ml-2 flex items-center gap-1 text-amber-500 hover:text-amber-400
                       border border-amber-500/40 rounded-sm px-1.5 py-0.5 transition-colors duration-150"
          >
            <X size={9} /> clear
          </button>
        )}
      </div>
    </div>
  );
}
function ChipGroup({ children }) {
  return <div className="flex items-center gap-1">{children}</div>;
}
function Chip({ active, onClick, tid, color, children }) {
  const style = active && color ? {
    color, borderColor: color + "66", background: color + "1F",
  } : undefined;
  return (
    <button
      data-testid={tid}
      onClick={onClick}
      className={
        "flex items-center gap-1 px-2 py-0.5 rounded-sm border text-[10px] tracking-wider " +
        "transition-colors duration-100 " +
        (active
          ? (color ? "" : "border-amber-500/50 text-amber-400 bg-amber-500/10")
          : "border-zinc-800 text-zinc-500 hover:text-zinc-300 hover:border-zinc-700")
      }
      style={{ fontFamily: "'IBM Plex Sans', sans-serif", ...(style || {}) }}
    >
      {children}
    </button>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Glyph legend (popover)
// ═══════════════════════════════════════════════════════════════════
function GlyphLegend({ onClose }) {
  const items = [
    { kind: "create",     label: "Create"     },
    { kind: "copy",       label: "Copy"       },
    { kind: "move",       label: "Move"       },
    { kind: "execute",    label: "Execute"    },
    { kind: "open",       label: "Open"       },
    { kind: "network",    label: "Network"    },
    { kind: "exploit",    label: "Exploit prevention" },
    { kind: "restore",    label: "Restore"    },
    { kind: "detect",     label: "Scan detection" },
    { kind: "compromise", label: "Compromise" },
    { kind: "scan",       label: "Scan"       },
    { kind: "reboot",     label: "Reboot"     },
  ];
  return (
    <div
      data-testid="glyph-legend"
      className="absolute top-full mt-1 right-0 w-[420px] z-40 bg-zinc-950 border border-zinc-800
                 rounded-sm shadow-2xl p-4"
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-[10px] tracking-[0.24em] font-semibold text-zinc-400 uppercase">
          Symbol legend
        </span>
        <button onClick={onClose} className="text-zinc-600 hover:text-zinc-300">
          <X size={12} />
        </button>
      </div>
      <div className="grid grid-cols-2 gap-2">
        {items.map(({ kind, label }) => (
          <div key={kind} className="flex items-center gap-2 py-1">
            <svg width={22} height={22} viewBox="0 0 22 22">
              <circle cx="11" cy="11" r="9" fill="#0B0B0E" stroke="#71717A" strokeWidth="1.5" />
              <ActivityMark kind={kind} color="#E4E4E7" />
            </svg>
            <span className="text-[11px] text-zinc-300"
                  style={{ fontFamily: "'IBM Plex Sans', sans-serif" }}>{label}</span>
          </div>
        ))}
      </div>
      <div className="mt-3 pt-3 border-t border-zinc-900 grid grid-cols-3 gap-2">
        <LegendVerdict color="#22C55E" label="Observation" />
        <LegendVerdict color="#F59E0B" label="Suspicious"  />
        <LegendVerdictHex label="Malicious" />
      </div>
    </div>
  );
}
function LegendVerdict({ color, label }) {
  return (
    <div className="flex items-center gap-2">
      <svg width={20} height={20} viewBox="0 0 20 20">
        <circle cx="10" cy="10" r="8" fill="#0B0B0E" stroke={color} strokeWidth="1.6" />
      </svg>
      <span className="text-[10px] text-zinc-300">{label}</span>
    </div>
  );
}
function LegendVerdictHex({ label }) {
  return (
    <div className="flex items-center gap-2">
      <svg width={20} height={20} viewBox="0 0 20 20">
        <polygon points="10,1 19,6 19,14 10,19 1,14 1,6"
                 fill="#450A0A" stroke="#E11D48" strokeWidth="1.5" />
      </svg>
      <span className="text-[10px] text-zinc-300">{label}</span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Two-tier top scrubber — day-of-month strip + hour-of-day strip, both
// with hatched "outside window" zones (Cisco Device Trajectory pattern
// adopted; visuals are ours).
// ═══════════════════════════════════════════════════════════════════
function Scrubber({ histogram, minTs, maxTs, frames }) {
  const total = frames.length;
  const hasData = total > 0 && maxTs > minTs;

  // Build a 31-day month strip anchored on maxTs
  const monthDays = useMemo(() => {
    const anchor = hasData ? maxTs : Date.now();
    const end = new Date(anchor); end.setUTCHours(0, 0, 0, 0);
    const out = [];
    for (let i = 30; i >= 0; i--) {
      const d = new Date(end); d.setUTCDate(end.getUTCDate() - i);
      out.push(d);
    }
    return out;
  }, [hasData, maxTs]);

  // Which days have any events?
  const eventDayKeys = useMemo(() => {
    const s = new Set();
    frames.forEach(f => {
      const d = new Date(f.ts); d.setUTCHours(0, 0, 0, 0);
      s.add(d.toISOString().slice(0, 10));
    });
    return s;
  }, [frames]);

  // Which hours have events on the active day (= day of first event)?
  const activeDayKey = hasData
    ? new Date(minTs).toISOString().slice(0, 10)
    : monthDays[monthDays.length - 1].toISOString().slice(0, 10);
  const activeHours = useMemo(() => {
    const s = new Set();
    if (!hasData) return s;
    frames.forEach(f => {
      const d = new Date(f.ts);
      const key = d.toISOString().slice(0, 10);
      if (key === activeDayKey) s.add(d.getUTCHours());
    });
    return s;
  }, [frames, hasData, activeDayKey]);

  const spanLabel = hasData ? `spanning ${formatDuration(maxTs - minTs)}` : "no window";

  return (
    <div className="shrink-0 border-b border-zinc-800 bg-zinc-950/95 px-4 py-2"
         data-testid="scrubber">
      {/* Header line */}
      <div className="flex items-center gap-3 mb-1">
        <div>
          <div className="text-[9px] tracking-[0.24em] text-zinc-500 uppercase font-semibold">
            Timeline
          </div>
          <div className="text-[10px] text-zinc-400"
               style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
            <span className="text-zinc-200 tabular-nums">{total}</span> compromise events · {spanLabel}
          </div>
        </div>
        <div className="flex-1" />
        {/* Density histogram sparkline on the right */}
        <div className="w-64 h-6 flex items-end gap-[2px]">
          {histogram.map((n, i) => {
            const max = Math.max(1, ...histogram);
            const pct = n / max;
            return (
              <div key={i}
                   className={"flex-1 rounded-[1px] " + (n === 0 ? "bg-zinc-900" : "bg-amber-500/70")}
                   style={{ height: `${Math.max(pct * 100, n === 0 ? 12 : 18)}%` }} />
            );
          })}
        </div>
      </div>

      {/* Tier 1 · Month day strip */}
      <div className="flex items-stretch gap-[1px] h-8 mt-1" data-testid="scrubber-month">
        {monthDays.map((d, i) => {
          const iso = d.toISOString().slice(0, 10);
          const has = eventDayKeys.has(iso);
          const isActive = iso === activeDayKey;
          const isFirst = i === 0 || d.getUTCDate() === 1;
          return (
            <div key={iso}
                 className={"flex-1 relative border-t border-b border-zinc-800/70 " +
                            (has ? "bg-zinc-900" : "bg-zinc-950")}
                 title={iso}>
              {isActive && (
                <span className="absolute top-1 left-1/2 -translate-x-1/2 w-2 h-2 rounded-full bg-amber-500
                                 shadow-[0_0_8px_rgba(245,158,11,0.9)]" />
              )}
              <span className={"absolute bottom-0.5 left-1/2 -translate-x-1/2 text-[9px] tabular-nums " +
                              (isActive ? "text-amber-400" : "text-zinc-500")}
                    style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                {d.getUTCDate()}
              </span>
              {isFirst && (
                <span className="absolute -top-3 left-0 text-[9px] uppercase tracking-widest text-zinc-600 font-semibold">
                  {d.toLocaleString("en-US", { month: "short", timeZone: "UTC" })}
                </span>
              )}
            </div>
          );
        })}
      </div>

      {/* Tier 2 · Hour-of-day strip for the active day */}
      <div className="flex items-stretch gap-[1px] h-6 mt-2" data-testid="scrubber-hour">
        {Array.from({ length: 24 }, (_, h) => {
          const has = activeHours.has(h);
          return (
            <div key={h}
                 className={"flex-1 relative border-t border-b border-zinc-800/70 " +
                            (has ? "bg-amber-500/25" : "bg-zinc-950")}
                 style={!has ? {
                   backgroundImage:
                     "repeating-linear-gradient(135deg, transparent, transparent 3px, rgba(63,63,70,0.5) 3px, rgba(63,63,70,0.5) 4px)"
                 } : undefined}
                 title={`${h}:00`}>
              {(h % 3 === 0) && (
                <span className={"absolute bottom-0 left-1/2 -translate-x-1/2 text-[8px] tabular-nums " +
                                (has ? "text-amber-400" : "text-zinc-600")}
                      style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                  {h.toString().padStart(2, "0")}
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Process left rail (one row per process)
// ═══════════════════════════════════════════════════════════════════
function ProcessRail({ rows, selectedKey, onPickRow }) {
  return (
    <div className="shrink-0 border-r border-zinc-800 bg-zinc-950/60"
         style={{ width: LEFT_RAIL_W }}
         data-testid="process-rail">
      <div className="h-8 flex items-center px-3 border-b border-zinc-900">
        <span className="text-[9px] tracking-[0.24em] uppercase font-semibold text-zinc-500">
          Files & Processes
        </span>
      </div>
      <div>
        {rows.map((r, i) => {
          const isSel = selectedKey === r.key;
          const vc = r.worstVerdict === "malicious" ? VERDICT.malicious.color
                   : r.worstVerdict === "suspicious" ? VERDICT.suspicious.color
                   : "#3F3F46";
          return (
            <button key={r.key}
              data-testid={`row-${r.key}`}
              onClick={() => onPickRow(r)}
              className={"w-full h-[34px] flex items-center gap-2 pl-3 pr-2 border-b border-zinc-900/70 " +
                "text-right outline-none transition-colors duration-100 " +
                (isSel ? "bg-amber-500/8" : "hover:bg-zinc-900/50")}
              style={{ borderLeft: `2px solid ${vc}66` }}
            >
              <span className={"flex-1 truncate text-[11px] " + (isSel ? "text-amber-400" : "text-zinc-300")}
                    style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                {r.label}
              </span>
              <span className="text-[9px] tracking-widest text-zinc-600 font-semibold">
                [{r.type}]
              </span>
              <span className="text-[9px] text-zinc-500 tabular-nums w-6 text-right"
                    style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                {r.events.length}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Action → activity-glyph mapping (Cisco Secure Endpoint vocabulary).
// Each frame's action is classified into one of these buckets. The
// disposition (verdict) is drawn as an outer ring on the disc, and for
// MALICIOUS the whole disc is replaced by a red hexagon shield.
// ═══════════════════════════════════════════════════════════════════
const ACTIVITY = {
  CREATE:    "create",     // +
  COPY:      "copy",       // ∧
  MOVE:      "move",       // →
  EXECUTE:   "execute",    // ▷
  OPEN:      "open",       // ○
  NETWORK:   "network",    // ⇌
  EXPLOIT:   "exploit",    // ⚡
  RESTORE:   "restore",    // ↻
  DETECT:    "detect",     // ✕
  COMPROMISE:"compromise", // !?
  SCAN:      "scan",       // 🔍
  REBOOT:    "reboot",     // |
};

function activityOf(frame) {
  const a = (frame.action || "").toLowerCase();
  const lane = frame.lane;
  // Explicit high-signal keywords first
  if (/(ransom|locker|encrypt|removed_volume|volume_shadow)/.test(a)) return ACTIVITY.COMPROMISE;
  if (/(dumped_lsass|dumped|stolen|ntds|credential)/.test(a))         return ACTIVITY.DETECT;
  if (/(reverse_tunnel|c2|beacon|exfil)/.test(a))                     return ACTIVITY.NETWORK;
  if (/(connect|tunnel|dns|network|http|beacon)/.test(a))             return ACTIVITY.NETWORK;
  if (/(exploit|prevention|blocked)/.test(a))                         return ACTIVITY.EXPLOIT;
  if (/(restore|rollback|revert)/.test(a))                            return ACTIVITY.RESTORE;
  if (/(reboot|restart)/.test(a))                                     return ACTIVITY.REBOOT;
  if (/(scan|inspect|audit)/.test(a))                                 return ACTIVITY.SCAN;
  if (/(copy|clone)/.test(a))                                         return ACTIVITY.COPY;
  if (/(move|rename)/.test(a))                                        return ACTIVITY.MOVE;
  if (/(install|drop|create|add|new|write|persist|backup)/.test(a))   return ACTIVITY.CREATE;
  if (/(open|read|query|enumerate|export|discover|list)/.test(a))     return ACTIVITY.OPEN;
  if (/(execute|launch|spawn|ran|run|invoke|started)/.test(a))        return ACTIVITY.EXECUTE;
  // Fall back per lane
  if (lane === "file")     return ACTIVITY.CREATE;
  if (lane === "network")  return ACTIVITY.NETWORK;
  if (lane === "registry") return ACTIVITY.CREATE;
  if (lane === "system")   return ACTIVITY.SCAN;
  return ACTIVITY.EXECUTE;
}

// SVG activity-mark drawings, centered in a 22×22 viewBox
function ActivityMark({ kind, color }) {
  const c = 11; // center
  switch (kind) {
    case ACTIVITY.CREATE: return (
      <g>
        <line x1={c - 4} y1={c} x2={c + 4} y2={c}
              stroke={color} strokeWidth="1.8" strokeLinecap="round" />
        <line x1={c} y1={c - 4} x2={c} y2={c + 4}
              stroke={color} strokeWidth="1.8" strokeLinecap="round" />
      </g>
    );
    case ACTIVITY.COPY: return (
      <path d={`M ${c - 4} ${c + 2} L ${c} ${c - 3} L ${c + 4} ${c + 2}`}
            fill="none" stroke={color} strokeWidth="1.8"
            strokeLinecap="round" strokeLinejoin="round" />
    );
    case ACTIVITY.MOVE: return (
      <g>
        <line x1={c - 4} y1={c} x2={c + 3.5} y2={c}
              stroke={color} strokeWidth="1.7" strokeLinecap="round" />
        <path d={`M ${c + 1.5} ${c - 3} L ${c + 4} ${c} L ${c + 1.5} ${c + 3}`}
              fill="none" stroke={color} strokeWidth="1.7"
              strokeLinecap="round" strokeLinejoin="round" />
      </g>
    );
    case ACTIVITY.EXECUTE: return (
      <polygon points={`${c - 3},${c - 4} ${c - 3},${c + 4} ${c + 4},${c}`}
               fill={color} />
    );
    case ACTIVITY.OPEN: return (
      <circle cx={c} cy={c} r="3.4" fill="none" stroke={color} strokeWidth="1.6" />
    );
    case ACTIVITY.NETWORK: return (
      <g>
        <path d={`M ${c - 4} ${c - 2} L ${c + 3} ${c - 2}`}
              fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" />
        <path d={`M ${c + 1} ${c - 4.2} L ${c + 3.5} ${c - 2} L ${c + 1} ${c - 0.2}`}
              fill="none" stroke={color} strokeWidth="1.5"
              strokeLinecap="round" strokeLinejoin="round" />
        <path d={`M ${c + 4} ${c + 2} L ${c - 3} ${c + 2}`}
              fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" />
        <path d={`M ${c - 1} ${c + 4.2} L ${c - 3.5} ${c + 2} L ${c - 1} ${c - 0.2}`}
              fill="none" stroke={color} strokeWidth="1.5"
              strokeLinecap="round" strokeLinejoin="round" />
      </g>
    );
    case ACTIVITY.EXPLOIT: return (
      <path d={`M ${c + 1} ${c - 4.5} L ${c - 3} ${c + 0.5} L ${c} ${c + 0.5}
                 L ${c - 1} ${c + 4.5} L ${c + 3} ${c - 0.5} L ${c} ${c - 0.5} Z`}
            fill={color} />
    );
    case ACTIVITY.RESTORE: return (
      <path d={`M ${c + 4} ${c - 1}
                 A 4 4 0 1 0 ${c - 3} ${c + 3}
                 M ${c + 4} ${c - 3} L ${c + 4} ${c - 1} L ${c + 2} ${c - 1}`}
            fill="none" stroke={color} strokeWidth="1.5"
            strokeLinecap="round" strokeLinejoin="round" />
    );
    case ACTIVITY.DETECT: return (
      <g stroke={color} strokeWidth="1.9" strokeLinecap="round">
        <line x1={c - 3.5} y1={c - 3.5} x2={c + 3.5} y2={c + 3.5} />
        <line x1={c - 3.5} y1={c + 3.5} x2={c + 3.5} y2={c - 3.5} />
      </g>
    );
    case ACTIVITY.COMPROMISE: return (
      <g fill={color}>
        {/* Cisco-style "!?" — bang on left, query on right */}
        <text x={c} y={c + 3.5} textAnchor="middle"
              fontSize="9" fontWeight="900"
              fontFamily="'IBM Plex Sans', sans-serif">!?</text>
      </g>
    );
    case ACTIVITY.SCAN: return (
      <g fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round">
        <circle cx={c - 1} cy={c - 1} r="2.8" />
        <line x1={c + 1.2} y1={c + 1.2} x2={c + 4} y2={c + 4} />
      </g>
    );
    case ACTIVITY.REBOOT: return (
      <line x1={c} y1={c - 4} x2={c} y2={c + 4}
            stroke={color} strokeWidth="1.9" strokeLinecap="round" />
    );
    default: return null;
  }
}

// ═══════════════════════════════════════════════════════════════════
// Event glyph — Cisco Secure Endpoint symbol vocabulary applied.
//   Base disc + activity mark + disposition ring
//   Malicious → red hexagon shield replaces the disc (Cisco disposition)
//   Hover → rule-provenance tooltip (R1.1)
// ═══════════════════════════════════════════════════════════════════
function EventGlyph({ frame, x, y, selected, onSelect }) {
  const v = verdictFor(frame);
  const meta = LANE_META[frame.lane] || LANE_META.process;
  const kind = activityOf(frame);
  const isMalicious = v === "malicious";
  const isSuspicious = v === "suspicious";
  const conf = confidenceTierOf(frame);
  const [hovered, setHovered] = useState(false);

  const size = 22;
  const half = size / 2;
  const mitre0 = (frame.mitre || [])[0];

  // Disposition ring color
  const ringColor = isMalicious ? VERDICT.malicious.color
                  : isSuspicious ? "#F59E0B"
                  : "#71717A";

  // Activity-mark color
  const markColor = (kind === ACTIVITY.COMPROMISE || kind === ACTIVITY.DETECT)
    ? "#FCA5A5"
    : (isSuspicious ? "#FCD34D" : meta.accent);

  return (
    <>
      <button
        data-testid={`event-glyph-${frame.frame_iid}`}
        onClick={() => onSelect(frame)}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        onFocus={() => setHovered(true)}
        onBlur={() => setHovered(false)}
        className="absolute z-10 outline-none focus-visible:ring-2 focus-visible:ring-amber-500
                   transition-transform duration-150 hover:scale-125"
        style={{
          left: x - half, top: y - half,
          width: size, height: size,
          filter: selected
            ? "drop-shadow(0 0 8px rgba(245,158,11,0.7))"
            : (isMalicious ? "drop-shadow(0 0 4px rgba(225,29,72,0.5))" : "none"),
        }}
      >
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
          {isMalicious ? (
            <g>
              <polygon
                points={`${half},1 ${size - 1},${half - 4} ${size - 1},${half + 4} ${half},${size - 1} 1,${half + 4} 1,${half - 4}`}
                fill="#450A0A"
                stroke={VERDICT.malicious.color}
                strokeWidth="1.6"
              />
              <ActivityMark kind={kind} color="#FCA5A5" />
            </g>
          ) : (
            <g>
              <circle cx={half} cy={half} r={half - 2}
                      fill="#0B0B0E"
                      stroke={selected ? "#F59E0B" : ringColor}
                      strokeWidth={selected ? 1.8 : 1.5} />
              <ActivityMark kind={kind} color={markColor} />
            </g>
          )}
        </svg>

        {mitre0 && (
          <span
            className="absolute -top-3 -right-1 text-[8px] leading-none px-1 py-[1px] rounded-sm
                       bg-zinc-800 text-zinc-300 border border-zinc-700 pointer-events-none z-20"
            style={{ fontFamily: "'IBM Plex Mono', monospace" }}
          >
            {mitre0}
          </span>
        )}
      </button>

      {hovered && !selected && (
        <ProvenanceCard frame={frame} x={x} y={y} verdict={v}
                        conf={conf} activity={kind} meta={meta} />
      )}
    </>
  );
}

// ─── Rule-provenance hover card (R1.1) ───────────────────────────────
function ProvenanceCard({ frame, x, y, verdict, conf, activity, meta }) {
  const vMeta = VERDICT[verdict];
  const rule = frame.rule_id || frame.provenance?.rule_id;
  const source = frame.provenance?.source;
  const adapter = frame.provenance?.adapter;
  return (
    <div
      data-testid={`provenance-card-${frame.frame_iid}`}
      className="absolute z-30 pointer-events-none w-[320px] bg-zinc-950/98 border border-zinc-800
                 rounded-sm shadow-2xl p-3"
      style={{
        left: x + 16,
        top: Math.max(y - 40, 4),
        fontFamily: "'IBM Plex Sans', sans-serif",
        boxShadow: "0 12px 32px -8px rgba(0,0,0,0.85), 0 0 0 1px rgba(245,158,11,0.15)",
      }}
    >
      {/* Header: verdict + confidence + activity + lane */}
      <div className="flex items-center gap-1.5 mb-2 flex-wrap">
        <span className="inline-flex items-center gap-1 text-[8px] font-bold tracking-[0.2em] px-1 py-0.5 rounded-sm border"
              style={{ color: vMeta.color, borderColor: vMeta.color + "66", background: vMeta.color + "14" }}>
          <vMeta.Icon size={9} /> {vMeta.label}
        </span>
        <span className="inline-flex items-center gap-1 text-[8px] font-bold tracking-[0.2em] px-1 py-0.5 rounded-sm border"
              style={{ color: conf.color, borderColor: conf.color + "66", background: conf.color + "14" }}>
          {conf.label}
        </span>
        <span className="inline-flex items-center gap-1 text-[8px] font-bold tracking-[0.2em] px-1 py-0.5 rounded-sm border border-zinc-800 text-zinc-400 uppercase">
          <meta.Icon size={9} style={{ color: meta.accent }} /> {meta.label}
        </span>
      </div>

      {/* Command / label */}
      <div className="text-[10px] text-zinc-100 leading-relaxed break-words mb-2"
           style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
        {frame.label || frame.action}
      </div>

      {/* Provenance grid */}
      <div className="text-[9px] space-y-0.5"
           style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
        <ProvRow label="action"   value={frame.action}                       muted />
        <ProvRow label="ts"       value={new Date(frame.ts).toISOString()}   muted />
        <ProvRow label="rule_id"  value={rule || "— (no rule fired)"}
                                  emphasize={!!rule} />
        <ProvRow label="source"   value={source || "shadow_adapter"}         muted />
        {adapter && <ProvRow label="adapter" value={adapter} muted />}
        {frame.provenance?.confidence != null && (
          <ProvRow label="conf" value={String(frame.provenance.confidence)} muted />
        )}
      </div>

      {(frame.mitre || []).length > 0 && (
        <div className="mt-2 pt-2 border-t border-zinc-900 flex flex-wrap gap-1">
          {frame.mitre.map(t => (
            <span key={t}
                  className="text-[9px] px-1 py-[1px] border border-rose-500/30 rounded-sm
                             text-rose-400 bg-rose-500/5"
                  style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
              {t}
            </span>
          ))}
        </div>
      )}

      <div className="mt-2 pt-2 border-t border-zinc-900 text-[9px] text-zinc-600">
        Click to open Evidence Panel · Activity: {activity}
      </div>
    </div>
  );
}
function ProvRow({ label, value, muted, emphasize }) {
  return (
    <div className="flex items-baseline gap-2">
      <span className="w-14 shrink-0 text-zinc-500">{label}</span>
      <span className={"flex-1 break-all " +
                      (emphasize ? "text-amber-400" : (muted ? "text-zinc-400" : "text-zinc-200"))}>
        {value}
      </span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Bottom ruler
// ═══════════════════════════════════════════════════════════════════
function TimeRuler({ ticks, zoom, minTs, maxTs, total, rows }) {
  const fmt = (ts) => new Date(ts).toISOString().replace("T", " ").slice(0, 19) + "Z";
  return (
    <div className="h-10 shrink-0 border-t border-zinc-800 bg-zinc-950 flex items-center relative"
         style={{ fontFamily: "'IBM Plex Mono', monospace" }} data-testid="time-ruler">
      <div style={{ width: LEFT_RAIL_W }}
           className="shrink-0 h-full border-r border-zinc-800 flex items-center px-3">
        <Clock size={11} className="text-zinc-600 mr-1.5" />
        <span className="text-[9px] tracking-[0.18em] text-zinc-500 font-semibold">
          WINDOW · {zoom.toUpperCase()}
        </span>
      </div>
      <div className="flex-1 h-full relative flex items-center">
        {ticks.map((t, i) => (
          <span key={i} className="absolute top-0 bottom-0 w-px bg-zinc-800"
                style={{ left: `${(i / (ticks.length - 1 || 1)) * 100}%` }} />
        ))}
        {ticks.length > 0 && (
          <>
            <span className="absolute left-3 text-[9px] text-zinc-500 tabular-nums">{fmt(minTs)}</span>
            <span className="absolute left-1/2 -translate-x-1/2 text-[9px] text-zinc-600 tabular-nums">
              {fmt((minTs + maxTs) / 2)}
            </span>
            <span className="absolute right-3 text-[9px] text-zinc-500 tabular-nums">{fmt(maxTs)}</span>
          </>
        )}
      </div>
      <div className="w-56 shrink-0 h-full border-l border-zinc-800 flex items-center justify-end px-3 gap-2">
        <span className="text-[9px] tracking-[0.18em] text-zinc-500 font-semibold">EVENTS</span>
        <span className="text-[11px] text-zinc-200 tabular-nums">{total}</span>
        <span className="text-zinc-700 mx-1">·</span>
        <span className="text-[9px] tracking-[0.18em] text-zinc-500 font-semibold">ROWS</span>
        <span className="text-[11px] text-zinc-200 tabular-nums">{rows}</span>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Right drawer (Case Overview / Activity feed / Evidence Panel)
// ═══════════════════════════════════════════════════════════════════
function Drawer({ selected, onClose, overview, totalEvents, caseId, frames, onPickEvent }) {
  const [tab, setTab] = useState("overview"); // overview | activity
  return (
    <aside data-testid="v2-trajectory-drawer"
           className="w-[380px] shrink-0 border-l border-zinc-800 bg-zinc-950/95
                      flex flex-col overflow-hidden z-30">
      {selected ? (
        <EvidencePanel frame={selected} onClose={onClose} />
      ) : (
        <>
          {/* Tab strip */}
          <div className="flex items-stretch border-b border-zinc-900 shrink-0">
            <DrawerTab active={tab === "overview"} onClick={() => setTab("overview")}
                       label="Case Overview" tid="tab-overview" />
            <DrawerTab active={tab === "activity"} onClick={() => setTab("activity")}
                       label="Activity" count={frames.length} tid="tab-activity" />
          </div>
          {tab === "overview"
            ? <CaseOverviewPanel overview={overview} totalEvents={totalEvents} caseId={caseId} />
            : <ActivityFeed frames={frames} onPickEvent={onPickEvent} />}
        </>
      )}
    </aside>
  );
}

function DrawerTab({ active, onClick, label, count, tid }) {
  return (
    <button data-testid={tid}
      onClick={onClick}
      className={"flex-1 h-9 flex items-center justify-center gap-2 text-[10px] tracking-[0.2em] " +
                 "font-semibold uppercase transition-colors duration-150 border-b-2 " +
                 (active
                   ? "text-amber-400 border-amber-500 bg-amber-500/5"
                   : "text-zinc-500 border-transparent hover:text-zinc-300")}
    >
      {label}
      {count != null && (
        <span className={"text-[9px] px-1 rounded-sm tabular-nums " +
                        (active ? "bg-amber-500/15 text-amber-400" : "bg-zinc-900 text-zinc-500")}
              style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
          {count}
        </span>
      )}
    </button>
  );
}

// ─── Activity feed (chronological parent → child pairs) ──────────────
function ActivityFeed({ frames, onPickEvent }) {
  // Show most-recent first; each entry: [parent process name] → [event summary]
  const items = useMemo(() => {
    const sorted = [...frames].sort(
      (a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime()
    );
    return sorted.map(f => {
      const parentName = processLabelOf({ label: f.parent?.iid || "", action: "" }) || "—";
      const target = processLabelOf(f);
      return { f, parentName, target };
    });
  }, [frames]);

  if (items.length === 0) {
    return (
      <div className="p-5 text-[11px] text-zinc-600"
           style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
        no activity yet
      </div>
    );
  }
  return (
    <div className="flex-1 overflow-y-auto divide-y divide-zinc-900"
         data-testid="activity-feed">
      {items.map(({ f, parentName, target }, i) => {
        const v = verdictFor(f);
        const vColor = VERDICT[v].color;
        return (
          <button key={f.frame_iid || i}
                  data-testid={`activity-item-${f.frame_iid || i}`}
                  onClick={() => onPickEvent(f)}
                  className="w-full flex items-center gap-2 px-4 py-2 hover:bg-zinc-900/50
                             text-left transition-colors duration-100">
            <span className="w-1.5 h-1.5 rounded-full shrink-0"
                  style={{ background: vColor, boxShadow: `0 0 6px ${vColor}` }} />
            <span className="text-[11px] text-zinc-300 truncate w-24"
                  style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
              {parentName}
            </span>
            <ChevronRight size={11} className="text-zinc-600 shrink-0" />
            <span className="text-[11px] text-zinc-200 truncate flex-1"
                  style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
              {target}
            </span>
            <span className="text-[9px] text-zinc-600 tabular-nums shrink-0"
                  style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
              {new Date(f.ts).toISOString().slice(11, 19)}
            </span>
          </button>
        );
      })}
    </div>
  );
}

function CaseOverviewPanel({ overview, totalEvents, caseId }) {
  return (
    <div className="p-5 flex-1 overflow-y-auto"
         style={{ fontFamily: "'IBM Plex Sans', sans-serif" }}>
      <div className="flex items-center gap-2 mb-1">
        <Shield size={13} className="text-amber-500" />
        <span className="text-[10px] tracking-[0.24em] font-semibold text-zinc-400">
          CASE OVERVIEW
        </span>
      </div>
      <div className="text-[11px] text-zinc-500 mb-5"
           style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
        Select an event on a lifeline, or press{" "}
        <kbd className="border border-zinc-700 rounded px-1 text-[9px]">←</kbd>{" "}
        <kbd className="border border-zinc-700 rounded px-1 text-[9px]">→</kbd> to step through.
      </div>

      {/* Verdict counts */}
      <SectionLabel>Verdict summary</SectionLabel>
      <div className="mb-5 grid grid-cols-3 gap-2">
        <VerdictTile v="malicious"  n={overview.malicious} />
        <VerdictTile v="suspicious" n={overview.suspicious} />
        <VerdictTile v="benign"     n={totalEvents - overview.malicious - overview.suspicious} />
      </div>

      {/* Lane breakdown */}
      <SectionLabel>Event breakdown</SectionLabel>
      <div className="mb-5 space-y-1.5">
        {overview.lanes.map(([lane, n]) => {
          const meta = LANE_META[lane];
          const pct = totalEvents ? Math.round((n / totalEvents) * 100) : 0;
          return (
            <div key={lane} className="flex items-center gap-2" data-testid={`overview-lane-${lane}`}>
              <meta.Icon size={11} style={{ color: meta.accent }} />
              <span className="text-[10px] tracking-widest text-zinc-400 w-20">{meta.label}</span>
              <div className="flex-1 h-1.5 rounded-sm bg-zinc-900 overflow-hidden">
                <div className="h-full" style={{ width: `${pct}%`, background: meta.accent, opacity: 0.7 }} />
              </div>
              <span className="text-[10px] text-zinc-500 tabular-nums w-8 text-right"
                    style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                {n}
              </span>
            </div>
          );
        })}
      </div>

      <SectionLabel>Top MITRE techniques</SectionLabel>
      <div className="mb-5 flex flex-wrap gap-1.5">
        {overview.mitre.length === 0 && (
          <span className="text-[10px] text-zinc-600"
                style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
            no techniques observed
          </span>
        )}
        {overview.mitre.map(([tid, n]) => (
          <span key={tid}
                className="text-[10px] px-1.5 py-0.5 border border-zinc-700 rounded-sm bg-zinc-900 text-zinc-300"
                style={{ fontFamily: "'IBM Plex Mono', monospace" }}
                data-testid={`overview-mitre-${tid}`}>
            {tid}<span className="text-zinc-600 ml-1">×{n}</span>
          </span>
        ))}
      </div>

      <div className="mt-6 pt-4 border-t border-zinc-900">
        <SectionLabel>Case reference</SectionLabel>
        <div className="text-[10px] text-zinc-500 mt-1 break-all"
             style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
          {caseId}
        </div>
        <div className="text-[10px] text-zinc-600 mt-1">
          Processes tracked:{" "}
          <span className="text-zinc-400 tabular-nums"
                style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
            {overview.processes}
          </span>
        </div>
      </div>
    </div>
  );
}

function VerdictTile({ v, n }) {
  const meta = VERDICT[v];
  return (
    <div className="border border-zinc-900 rounded-sm p-2 bg-zinc-950/60"
         data-testid={`verdict-tile-${v}`}>
      <div className="flex items-center gap-1.5">
        <meta.Icon size={11} style={{ color: meta.color }} />
        <span className="text-[9px] tracking-widest font-semibold" style={{ color: meta.color }}>
          {meta.label}
        </span>
      </div>
      <div className="text-lg text-zinc-100 tabular-nums font-semibold mt-1 leading-none"
           style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
        {n}
      </div>
    </div>
  );
}

function EvidencePanel({ frame, onClose }) {
  const meta = LANE_META[frame.lane] || LANE_META.process;
  const v = verdictFor(frame);
  const vMeta = VERDICT[v];
  const conf = confidenceTierOf(frame);
  return (
    <div className="flex-1 flex flex-col overflow-hidden" data-testid="evidence-panel">
      <div className="px-5 pt-5 pb-4 border-b border-zinc-900 relative">
        <div className="absolute top-0 left-0 right-0 h-[3px]" style={{ background: vMeta.color }} />
        <div className="flex items-center gap-2 mb-2">
          <meta.Icon size={13} style={{ color: meta.accent }} />
          <span className="text-[10px] tracking-[0.24em] font-semibold text-zinc-400">
            {meta.label} · {frame.action}
          </span>
          <div className="flex-1" />
          <button
            data-testid="evidence-close"
            onClick={onClose}
            className="text-zinc-600 hover:text-zinc-300 flex items-center gap-1 text-[10px] tracking-wider"
            style={{ fontFamily: "'IBM Plex Mono', monospace" }}
          >
            ESC <X size={11} />
          </button>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1 text-[9px] font-bold tracking-[0.2em] px-1.5 py-0.5 rounded-sm border"
                style={{ color: vMeta.color, borderColor: vMeta.color + "66", background: vMeta.color + "14",
                         fontFamily: "'IBM Plex Sans', sans-serif" }}
                data-testid="verdict-badge">
            <vMeta.Icon size={10} /> {vMeta.label}
          </span>
          <span className="inline-flex items-center gap-1 text-[9px] font-bold tracking-[0.2em] px-1.5 py-0.5 rounded-sm border"
                style={{ color: conf.color, borderColor: conf.color + "66", background: conf.color + "14",
                         fontFamily: "'IBM Plex Sans', sans-serif" }}
                data-testid="confidence-badge">
            {conf.label} CONF
          </span>
        </div>
        <div className="mt-3 text-[12px] text-zinc-200 leading-relaxed break-words"
             style={{ fontFamily: "'IBM Plex Mono', monospace" }}
             data-testid="evidence-label">
          {frame.label}
        </div>
      </div>

      <div className="p-5 space-y-4 overflow-y-auto text-[10px]"
           style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
        <KV k="timestamp" v={frame.ts} />
        <KV k="frame_iid" v={frame.frame_iid} mono />

        <KVGroup title="entity refs">
          {frame.device   && <KV k="device"   v={frame.device.iid}   mono muted />}
          {frame.process  && <KV k="process"  v={frame.process.iid}  mono />}
          {frame.parent   && <KV k="parent"   v={frame.parent.iid}   mono />}
          {frame.file     && <KV k="file"     v={frame.file.iid}     mono />}
          {frame.network  && <KV k="network"  v={frame.network.iid}  mono />}
          {frame.registry && <KV k="registry" v={frame.registry.iid} mono />}
          {frame.user     && <KV k="user"     v={frame.user.iid}     mono />}
        </KVGroup>

        {(frame.mitre || []).length > 0 && (
          <KVGroup title="MITRE ATT&CK">
            <div className="flex flex-wrap gap-1">
              {frame.mitre.map(t => (
                <span key={t}
                      data-testid={`evidence-mitre-${t}`}
                      className="text-[10px] px-1.5 py-0.5 border border-rose-500/30 rounded-sm
                                 text-rose-400 bg-rose-500/5"
                      style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                  {t}
                </span>
              ))}
            </div>
          </KVGroup>
        )}

        {(frame.rule_id || frame.provenance) && (
          <KVGroup title="provenance">
            {frame.rule_id && <KV k="rule_id" v={frame.rule_id} mono />}
            {frame.provenance?.source && <KV k="source" v={frame.provenance.source} />}
            {frame.provenance?.adapter && <KV k="adapter" v={frame.provenance.adapter} />}
            {frame.provenance?.confidence != null &&
              <KV k="confidence" v={String(frame.provenance.confidence)} />}
          </KVGroup>
        )}
      </div>
    </div>
  );
}

// ─── Small helpers ────────────────────────────────────────────────────
function SectionLabel({ children }) {
  return (
    <div className="text-[9px] tracking-[0.24em] font-semibold text-zinc-500 uppercase mb-2">
      {children}
    </div>
  );
}
function KV({ k, v, mono, muted }) {
  return (
    <div className="flex items-baseline gap-2 leading-relaxed">
      <span className="w-20 shrink-0 text-zinc-500">{k}</span>
      <span className={"flex-1 break-all " + (muted ? "text-zinc-500" : "text-zinc-200")}
            style={mono ? { fontFamily: "'IBM Plex Mono', monospace" } : undefined}>
        {v}
      </span>
    </div>
  );
}
function KVGroup({ title, children }) {
  return (
    <div className="border border-zinc-900 rounded-sm p-3 bg-zinc-950/60">
      <div className="text-[9px] tracking-[0.24em] font-semibold text-zinc-500 uppercase mb-2">
        {title}
      </div>
      <div className="space-y-1">{children}</div>
    </div>
  );
}
function formatDuration(ms) {
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  if (ms < 86_400_000) return `${(ms / 3_600_000).toFixed(1)}h`;
  return `${(ms / 86_400_000).toFixed(1)}d`;
}
