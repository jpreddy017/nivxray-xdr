/**
 * Device Trajectory · v2 · "Tactical Surveillance" redesign.
 *
 * Renders GET /api/v2/cases/{caseId}/trajectory/device as five
 * horizontal lanes (SYSTEM · PROCESS · FILES · NETWORK · REGISTRY)
 * with dense pill nodes plotted along a shared time axis.
 *
 * Design tokens: /app/design_guidelines.json (Amber-on-Graphite palette,
 * IBM Plex Sans + Mono, zinc-based surfaces, per-lane accent, MITRE
 * chips, verdict halos, graph-paper track texture, spawn arcs).
 *
 * Feature-flag gated on TRAJECTORY_ENGINE. No RC5 imports.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import {
  Cpu, Activity, FileCode, Globe, Database,
  Search, Shield, ChevronRight, Clock, PenSquare, Radar,
} from "lucide-react";
import { isObservable } from "../flags";
import api from "@/lib/api";

// ─── Lane metadata ────────────────────────────────────────────────────
const LANE_ORDER = ["system", "process", "file", "network", "registry"];
const LANE_META = {
  system:   { label: "SYSTEM",   accent: "#8B5CF6", Icon: Cpu      },
  process:  { label: "PROCESS",  accent: "#E11D48", Icon: Activity },
  file:     { label: "FILES",    accent: "#F59E0B", Icon: FileCode },
  network:  { label: "NETWORK",  accent: "#4F46E5", Icon: Globe    },
  registry: { label: "REGISTRY", accent: "#EA580C", Icon: Database },
};

// ─── Verdict halo ─ deterministic mapping from MITRE presence + rule fire.
function verdictFor(f) {
  const hasMitre = (f.mitre || []).length > 0;
  const rule = (f.rule_id || f.provenance?.rule_id || "").toLowerCase();
  if (hasMitre && rule) return "malicious";
  if (hasMitre) return "suspicious";
  return "benign";
}
const VERDICT_STYLE = {
  benign:      { ring: "rgba(34,197,94,0.28)",  border: "rgba(34,197,94,0.35)"  },
  suspicious:  { ring: "rgba(245,158,11,0.32)", border: "rgba(245,158,11,0.55)" },
  malicious:   { ring: "rgba(225,29,72,0.42)",  border: "rgba(225,29,72,0.85)"  },
};

// Track SVG graph-paper background (kept small to avoid inflating bundle)
const TRACK_GRID_BG =
  "url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='48' height='48'>" +
  "<path d='M48 0H0v48' fill='none' stroke='%2327272A' stroke-opacity='0.35' stroke-width='0.5'/>" +
  "<path d='M12 0v48M24 0v48M36 0v48M0 12h48M0 24h48M0 36h48' fill='none' stroke='%2327272A' stroke-opacity='0.18' stroke-width='0.5'/>" +
  "</svg>\")";

// ─── Component ────────────────────────────────────────────────────────
export default function DeviceTrajectory() {
  const { caseId = "case_dfir_bumblebee_akira_2026" } = useParams() || {};
  const [data, setData] = useState(null);
  const [err, setErr]   = useState(null);
  const [selected, setSelected] = useState(null);
  const [zoom, setZoom] = useState("Fit");
  const [query, setQuery] = useState("");
  const searchRef = useRef(null);
  const trackRef  = useRef(null);
  const enabled = isObservable("TRAJECTORY_ENGINE") || isObservable("CASE_ENGINE");

  // ─── Fetch trajectory ─────────────────────────────────────────────
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

  // ─── Filtered frames ──────────────────────────────────────────────
  const frames = useMemo(() => {
    if (!data?.frames) return [];
    if (!query) return data.frames;
    const q = query.toLowerCase();
    return data.frames.filter(f =>
      (f.label || "").toLowerCase().includes(q) ||
      (f.action || "").toLowerCase().includes(q) ||
      (f.mitre || []).some(t => t.toLowerCase().includes(q)),
    );
  }, [data, query]);

  const { xForFrame, minTs, maxTs, tickTimes } = useMemo(() => {
    if (!frames.length) {
      return { xForFrame: () => 0, minTs: 0, maxTs: 1, tickTimes: [] };
    }
    const times = frames.map(f => new Date(f.ts).getTime());
    let lo = Math.min(...times), hi = Math.max(...times);
    if (hi === lo) hi = lo + 1000;
    const span = hi - lo;
    const ticks = Array.from({ length: 9 }, (_, i) => lo + (span * i) / 8);
    return {
      xForFrame: (f) => (new Date(f.ts).getTime() - lo) / span,
      minTs: lo, maxTs: hi, tickTimes: ticks,
    };
  }, [frames]);

  // Group frames per lane
  const framesByLane = useMemo(() => {
    const out = Object.fromEntries(LANE_ORDER.map(l => [l, []]));
    frames.forEach(f => { (out[f.lane] || out.process).push(f); });
    return out;
  }, [frames]);

  // Aggregate top MITRE tactics + entities for the empty-state overview
  const overview = useMemo(() => {
    const mitreCount = new Map();
    const entityCount = new Map();
    let bLo, bHi;
    frames.forEach(f => {
      (f.mitre || []).forEach(t => mitreCount.set(t, (mitreCount.get(t) || 0) + 1));
      ["process", "file", "network", "registry", "user"].forEach(k => {
        const ent = f[k];
        if (ent?.iid) entityCount.set(ent.iid, (entityCount.get(ent.iid) || 0) + 1);
      });
      const ts = new Date(f.ts).getTime();
      if (!bLo || ts < bLo) bLo = ts;
      if (!bHi || ts > bHi) bHi = ts;
    });
    return {
      mitre: [...mitreCount.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6),
      entities: [...entityCount.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5),
      laneCounts: LANE_ORDER.map(l => [l, framesByLane[l].length]),
      spanMs: bLo && bHi ? bHi - bLo : 0,
    };
  }, [frames, framesByLane]);

  // ─── Keyboard nav (← / → step; `/` focus search; Esc close drawer)
  useEffect(() => {
    if (!enabled) return;
    const handler = (e) => {
      if (e.key === "/" && document.activeElement?.tagName !== "INPUT") {
        e.preventDefault();
        searchRef.current?.focus();
        return;
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

  const onSelect = useCallback((f) => setSelected(f), []);

  // ─── Disabled state ───────────────────────────────────────────────
  if (!enabled) {
    return (
      <div data-testid="v2-trajectory-disabled"
           className="min-h-screen bg-zinc-950 text-zinc-500"
           style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
        <div className="p-6 text-xs">
          Device Trajectory is disabled. Set{" "}
          <code className="text-amber-500">REACT_APP_NIVX_FLAG_TRAJECTORY_ENGINE=shadow</code>{" "}
          or{" "}
          <code className="text-amber-500">REACT_APP_NIVX_FLAG_CASE_ENGINE=shadow</code>{" "}
          to enable.
        </div>
      </div>
    );
  }

  return (
    <div data-testid="v2-device-trajectory"
         className="flex flex-col h-screen overflow-hidden bg-zinc-950 text-zinc-100"
         style={{ fontFamily: "'IBM Plex Sans', sans-serif" }}>
      <Header
        caseId={caseId}
        count={data?.count}
        query={query}
        setQuery={setQuery}
        zoom={zoom}
        setZoom={setZoom}
        searchRef={searchRef}
      />

      {err && (
        <div className="px-4 py-2 border-b border-rose-900/40 bg-rose-950/30 text-rose-400 text-xs"
             style={{ fontFamily: "'IBM Plex Mono', monospace" }}
             data-testid="v2-trajectory-error">
          {String(err)}
        </div>
      )}

      <div className="flex flex-1 min-h-0">
        {/* ═══ Timeline canvas ═══ */}
        <div className="flex-1 flex flex-col min-w-0 relative">
          {/* Lanes */}
          <div ref={trackRef} className="flex-1 flex flex-col overflow-hidden">
            {LANE_ORDER.map((lane, i) => (
              <Swimlane
                key={lane}
                lane={lane}
                events={framesByLane[lane]}
                xForFrame={xForFrame}
                selectedIid={selected?.frame_iid}
                onSelect={onSelect}
                zebra={i % 2 === 1}
              />
            ))}
          </div>

          {/* Bottom time-axis ruler */}
          <TimeRuler ticks={tickTimes} zoom={zoom} minTs={minTs} maxTs={maxTs}
                     total={frames.length} filtered={frames.length !== (data?.frames?.length ?? 0)
                            ? (data?.frames?.length ?? 0) : null} />

          {/* Empty-canvas hint */}
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

        {/* ═══ Right drawer ═══ */}
        <Drawer selected={selected} onClose={() => setSelected(null)}
                overview={overview} totalEvents={data?.count ?? 0} caseId={caseId} />
      </div>

      {/* Floating Training Note CTA */}
      <button
        data-testid="training-note-cta"
        className="fixed bottom-6 right-[404px] bg-amber-500 text-amber-950 px-3 py-1.5 rounded-sm
                   font-semibold text-[11px] tracking-wider shadow-lg hover:bg-amber-400
                   border border-amber-300/60 flex items-center gap-2 z-40
                   transition-colors duration-150"
        style={{ fontFamily: "'IBM Plex Sans', sans-serif" }}
        onClick={() => { /* placeholder — wire to case notes API in R1.1 */ }}
      >
        <PenSquare size={12} /> TRAINING NOTE
      </button>
    </div>
  );
}

// ─── Header bar ───────────────────────────────────────────────────────
function Header({ caseId, count, query, setQuery, zoom, setZoom, searchRef }) {
  return (
    <header className="h-14 shrink-0 flex items-center gap-4 border-b border-zinc-800
                       bg-zinc-950 px-4 z-20">
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

      <div className="hidden md:flex items-center gap-2 pl-4 ml-2 border-l border-zinc-800 h-8">
        <span className="text-[10px] tracking-widest uppercase text-zinc-500 font-semibold">Case</span>
        <code className="text-[11px] text-amber-500"
              style={{ fontFamily: "'IBM Plex Mono', monospace" }}
              data-testid="case-id-label">
          {caseId}
        </code>
        <span className="text-zinc-700 mx-1">·</span>
        <span className="text-[10px] tracking-widest uppercase text-zinc-500 font-semibold">Events</span>
        <span className="text-[11px] text-zinc-200 tabular-nums"
              style={{ fontFamily: "'IBM Plex Mono', monospace" }}
              data-testid="event-count-label">
          {count ?? "—"}
        </span>
      </div>

      <div className="flex-1" />

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-600" size={12} />
        <input
          ref={searchRef}
          data-testid="trajectory-search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="search command / mitre / entity"
          className="pl-8 pr-3 py-1.5 w-72 bg-zinc-900 border border-zinc-700 rounded-sm
                     text-xs text-zinc-200 placeholder-zinc-600 outline-none
                     focus:border-amber-500 focus:ring-1 focus:ring-amber-500
                     transition-colors duration-150"
          style={{ fontFamily: "'IBM Plex Mono', monospace" }}
        />
        <kbd className="absolute right-2 top-1/2 -translate-y-1/2 text-[9px] text-zinc-600
                        border border-zinc-700 rounded px-1 bg-zinc-950 pointer-events-none">/</kbd>
      </div>

      {/* Zoom presets */}
      <div className="flex items-center gap-1 border border-zinc-800 rounded-sm p-0.5" role="tablist">
        {["Fit", "1h", "24h", "7d", "30d"].map(z => (
          <button
            key={z}
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

// ─── Swimlane row ─────────────────────────────────────────────────────
function Swimlane({ lane, events, xForFrame, selectedIid, onSelect, zebra }) {
  const meta = LANE_META[lane];
  const { Icon } = meta;
  return (
    <div
      className="flex flex-1 min-h-[110px] border-b border-zinc-900 last:border-b-0 relative"
      style={{ background: zebra ? "#0B0B0E" : "#0F0F12" }}
      data-testid={`swimlane-${lane}`}
    >
      {/* Left header column */}
      <div className="w-32 shrink-0 border-r border-zinc-800/80 bg-zinc-950/70 relative
                      flex flex-col justify-center px-3 gap-1">
        <div className="flex items-center gap-2">
          <Icon size={13} style={{ color: meta.accent }} />
          <span className="text-[10px] tracking-[0.24em] font-semibold text-zinc-300">
            {meta.label}
          </span>
        </div>
        <div className="text-[10px] text-zinc-600 tabular-nums"
             style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
          {events.length} evt
        </div>
        {/* Left-edge accent stripe */}
        <div className="absolute top-0 right-0 bottom-0 w-[2px]"
             style={{ background: meta.accent, opacity: 0.45 }} />
      </div>

      {/* Track (grid-paper backdrop + nodes) */}
      <div
        className="flex-1 relative overflow-hidden"
        style={{ backgroundImage: TRACK_GRID_BG, backgroundSize: "48px 48px" }}
      >
        {events.map((f, idx) => (
          <EventNode
            key={f.frame_iid || `${lane}-${idx}`}
            frame={f}
            accent={meta.accent}
            xFrac={xForFrame(f)}
            selected={f.frame_iid === selectedIid}
            onSelect={onSelect}
          />
        ))}
      </div>
    </div>
  );
}

// ─── Event pill node ──────────────────────────────────────────────────
function EventNode({ frame, accent, xFrac, selected, onSelect }) {
  const v = verdictFor(frame);
  const vs = VERDICT_STYLE[v];
  const preview = (frame.label || frame.action || "").replace(/\s+/g, " ").trim();
  const mitre0 = (frame.mitre || [])[0];

  // Anchor the node so its left edge lands at the timestamp.
  // Nodes near the right edge of the track are pulled slightly leftwards
  // so their labels stay readable.
  const leftPct = Math.min(Math.max(xFrac * 100, 0.3), 99.4);
  const anchorRight = xFrac > 0.8;

  return (
    <button
      data-testid={`event-node-${frame.frame_iid}`}
      onClick={() => onSelect(frame)}
      className="group absolute top-1/2 -translate-y-1/2 h-7 flex items-center pl-2 pr-2.5
                 rounded-sm bg-zinc-900 hover:bg-zinc-800 cursor-pointer
                 border border-l-[3px] text-left
                 transition-[transform,box-shadow,background-color,border-color] duration-150
                 hover:-translate-y-[3px] hover:z-20 focus:z-20 outline-none focus-visible:ring-1"
      style={{
        left:  anchorRight ? "auto" : `calc(${leftPct}% - 2px)`,
        right: anchorRight ? `calc(${100 - leftPct}% - 2px)` : "auto",
        maxWidth: 260, minWidth: 130,
        borderColor: selected ? "#F59E0B" : vs.border,
        borderLeftColor: accent,
        boxShadow: selected
          ? "0 0 0 1px #F59E0B, 0 6px 24px -8px rgba(245,158,11,0.35)"
          : `0 0 10px -2px ${vs.ring}`,
      }}
    >
      {/* MITRE chip */}
      {mitre0 && (
        <span
          data-testid={`mitre-chip-${frame.frame_iid}`}
          className="absolute -top-2 -right-1 text-[9px] leading-none px-1 py-[2px]
                     bg-zinc-800 text-zinc-300 border border-zinc-700 rounded-sm
                     shadow-sm z-10"
          style={{ fontFamily: "'IBM Plex Mono', monospace" }}
        >
          {mitre0}
        </span>
      )}

      {/* Dot marker */}
      <span className="w-1.5 h-1.5 rounded-full shrink-0 mr-2"
            style={{ background: accent, boxShadow: `0 0 6px ${accent}` }} />

      {/* Command / label */}
      <span className="truncate text-[11px] text-zinc-300 leading-none"
            style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
        {preview || frame.action}
      </span>
    </button>
  );
}

// ─── Time ruler footer ────────────────────────────────────────────────
function TimeRuler({ ticks, zoom, minTs, maxTs, total, filtered }) {
  if (!ticks.length) {
    return (
      <div className="h-10 shrink-0 border-t border-zinc-800 bg-zinc-950 flex items-center
                      px-4 text-[10px] text-zinc-600 tracking-widest"
           style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
        AWAITING OBSERVATIONS
      </div>
    );
  }
  const fmt = (ts) => new Date(ts).toISOString().replace("T", " ").slice(0, 19) + "Z";
  return (
    <div className="h-10 shrink-0 border-t border-zinc-800 bg-zinc-950 flex items-center relative"
         style={{ fontFamily: "'IBM Plex Mono', monospace" }}
         data-testid="time-ruler">
      <div className="w-32 shrink-0 h-full border-r border-zinc-800 flex items-center px-3">
        <Clock size={11} className="text-zinc-600 mr-1.5" />
        <span className="text-[9px] tracking-[0.18em] text-zinc-500 font-semibold">
          WINDOW · {zoom.toUpperCase()}
        </span>
      </div>
      <div className="flex-1 h-full relative flex items-center">
        {/* Tick marks */}
        {ticks.map((t, i) => (
          <span
            key={i}
            className="absolute top-0 bottom-0 w-px bg-zinc-800"
            style={{ left: `${(i / (ticks.length - 1)) * 100}%` }}
          />
        ))}
        <span className="absolute left-3 text-[9px] text-zinc-500 tabular-nums">
          {fmt(minTs)}
        </span>
        <span className="absolute left-1/2 -translate-x-1/2 text-[9px] text-zinc-600 tabular-nums">
          {fmt((minTs + maxTs) / 2)}
        </span>
        <span className="absolute right-3 text-[9px] text-zinc-500 tabular-nums">
          {fmt(maxTs)}
        </span>
      </div>
      <div className="w-52 shrink-0 h-full border-l border-zinc-800 flex items-center justify-end px-3 gap-2">
        <span className="text-[9px] tracking-[0.18em] text-zinc-500 font-semibold">FRAMES</span>
        <span className="text-[11px] text-zinc-200 tabular-nums">{total}</span>
        {filtered !== null && (
          <span className="text-[9px] text-zinc-600 tabular-nums">/ {filtered}</span>
        )}
      </div>
    </div>
  );
}

// ─── Right drawer (empty ⇢ overview · selected ⇢ evidence) ────────────
function Drawer({ selected, onClose, overview, totalEvents, caseId }) {
  return (
    <aside
      data-testid="v2-trajectory-drawer"
      className="w-[380px] shrink-0 border-l border-zinc-800 bg-zinc-950/95
                 flex flex-col overflow-hidden z-30"
    >
      {selected
        ? <EvidencePanel frame={selected} onClose={onClose} />
        : <CaseOverviewPanel overview={overview} totalEvents={totalEvents} caseId={caseId} />}
    </aside>
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
        Select an event on the timeline to inspect its evidence, or press{" "}
        <kbd className="border border-zinc-700 rounded px-1 text-[9px]">←</kbd>{" "}
        <kbd className="border border-zinc-700 rounded px-1 text-[9px]">→</kbd> to step through.
      </div>

      {/* Event breakdown per lane */}
      <SectionLabel>Event breakdown</SectionLabel>
      <div className="mb-5 space-y-1.5">
        {overview.laneCounts.map(([lane, n]) => {
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

      {/* MITRE tactics */}
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
                className="text-[10px] px-1.5 py-0.5 border border-zinc-700 rounded-sm
                           bg-zinc-900 text-zinc-300"
                style={{ fontFamily: "'IBM Plex Mono', monospace" }}
                data-testid={`overview-mitre-${tid}`}>
            {tid}<span className="text-zinc-600 ml-1">×{n}</span>
          </span>
        ))}
      </div>

      {/* Top entities */}
      <SectionLabel>Top entities</SectionLabel>
      <div className="mb-5 space-y-1">
        {overview.entities.length === 0 && (
          <span className="text-[10px] text-zinc-600"
                style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
            no entities extracted
          </span>
        )}
        {overview.entities.map(([iid, n]) => (
          <div key={iid} className="flex items-center gap-2 text-[10px]"
               style={{ fontFamily: "'IBM Plex Mono', monospace" }}
               data-testid={`overview-entity-${iid}`}>
            <ChevronRight size={10} className="text-zinc-600" />
            <span className="text-zinc-400 truncate flex-1" title={iid}>{iid}</span>
            <span className="text-zinc-600 tabular-nums">×{n}</span>
          </div>
        ))}
      </div>

      {/* Case reference footer */}
      <div className="mt-6 pt-4 border-t border-zinc-900">
        <SectionLabel>Case reference</SectionLabel>
        <div className="text-[10px] text-zinc-500 mt-1 break-all"
             style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
          {caseId}
        </div>
        <div className="text-[10px] text-zinc-600 mt-1">
          Timeline span:{" "}
          <span className="text-zinc-400 tabular-nums"
                style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
            {overview.spanMs
              ? formatDuration(overview.spanMs)
              : "—"}
          </span>
        </div>
      </div>
    </div>
  );
}

function EvidencePanel({ frame, onClose }) {
  const meta = LANE_META[frame.lane] || LANE_META.process;
  const v = verdictFor(frame);
  const verdictLabel = v === "malicious" ? "MALICIOUS"
                     : v === "suspicious" ? "SUSPICIOUS"
                     : "OBSERVATION";
  const verdictColor = v === "malicious" ? "#E11D48"
                     : v === "suspicious" ? "#F59E0B"
                     : "#22C55E";
  return (
    <div className="flex-1 flex flex-col overflow-hidden" data-testid="evidence-panel">
      {/* Header with verdict stripe */}
      <div className="px-5 pt-5 pb-4 border-b border-zinc-900 relative">
        <div className="absolute top-0 left-0 right-0 h-[3px]" style={{ background: verdictColor }} />
        <div className="flex items-center gap-2 mb-2">
          <meta.Icon size={13} style={{ color: meta.accent }} />
          <span className="text-[10px] tracking-[0.24em] font-semibold text-zinc-400">
            {meta.label} · {frame.action}
          </span>
          <div className="flex-1" />
          <button
            data-testid="evidence-close"
            onClick={onClose}
            className="text-zinc-600 hover:text-zinc-300 text-[10px] tracking-wider"
            style={{ fontFamily: "'IBM Plex Mono', monospace" }}
          >
            ESC ✕
          </button>
        </div>
        <span
          className="inline-block text-[9px] font-bold tracking-[0.2em] px-1.5 py-0.5 rounded-sm border"
          style={{
            color: verdictColor,
            borderColor: verdictColor + "66",
            background: verdictColor + "14",
            fontFamily: "'IBM Plex Sans', sans-serif",
          }}
          data-testid="verdict-badge"
        >
          {verdictLabel}
        </span>
        <div className="mt-3 text-[12px] text-zinc-200 leading-relaxed break-words"
             style={{ fontFamily: "'IBM Plex Mono', monospace" }}
             data-testid="evidence-label">
          {frame.label}
        </div>
      </div>

      {/* Body */}
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
            {frame.provenance?.confidence != null && (
              <KV k="confidence" v={String(frame.provenance.confidence)} />
            )}
          </KVGroup>
        )}
      </div>
    </div>
  );
}

// ─── Small subcomponents ──────────────────────────────────────────────
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
