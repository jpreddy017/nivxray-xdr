/**
 * DeviceTrajectoryV2 — SOC-analyst investigation workspace.
 *
 * Ground-up rebuild targeting the Cisco Secure Endpoint interaction
 * model (timeline canvas dominant, dense analyst UX, dual-tier scrubber,
 * compact filters, activity-first right panel). Branding and identity
 * remain NivXRay — no Cisco logos, icons, fonts, or proprietary assets.
 *
 * Layout proportions (spec):
 *   Header        · 6%
 *   Filter row    · 6%
 *   Day scrubber  · 8%
 *   Hour scrubber · 8%
 *   Canvas        · ≥55%
 *   Status        · 4%
 *
 * Everything here talks to the SAME backend endpoints as the previous
 * page — no server changes, no RC5 changes.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  Radar, Search, Filter, ChevronDown, ChevronRight, X, HelpCircle,
  Play, Plus, Minus, Network, FileText, KeyRound, Zap,
  ShieldCheck, ShieldAlert, ScanLine, RotateCcw, Skull,
  FolderOpen,
} from "lucide-react";
import { isObservable } from "../flags";
import api from "@/lib/api";

// ═══════════════════════════════════════════════════════════════════
// Design tokens
// ═══════════════════════════════════════════════════════════════════
const NX = {
  bg:          "#1F232A",
  panel:       "#262B33",
  panel2:      "#2D333D",
  canvas:      "#24282F",
  border:      "#3A404A",
  borderStrong:"#4B5563",
  hover:       "#353C46",
  selected:    "#425A7A",
  text:        "#F3F4F6",
  textDim:     "#A8B3C2",
  textMute:    "#646C76",
  link:        "#5FA8FF",
  linkDim:     "#3D6FB0",
  success:     "#55C271",
  warning:     "#F5C542",
  critical:    "#F04B4B",
  density:     "#4A90FF",
  lifeline:    "#4A8B47",
  lifelineDim: "#545C66",
  hatch:       "#3C4048",
};

// Layout constants
const HEADER_H       = 40;
const FILTER_H       = 36;
const DAY_H          = 64;
const HOUR_H         = 44;
const STATUS_H       = 24;
const RAIL_W         = 168;
const RIGHT_W        = 288;
const ROW_H          = 24;    // per-process row
const BAND_H         = 20;    // band header stripe
const GLYPH          = 11;    // px, tiny
const CANVAS_PAD_X   = 12;

// ═══════════════════════════════════════════════════════════════════
// Data helpers
// ═══════════════════════════════════════════════════════════════════
function verdictOf(f) {
  const hasMitre = (f.mitre || []).length > 0;
  const rule = (f.rule_id || f.provenance?.rule_id || "").toLowerCase();
  if (hasMitre && rule) return "malicious";
  if (hasMitre) return "suspicious";
  return "benign";
}
function processLabelOf(f) {
  const raw = f.label || f.action || "";
  const m = raw.match(/([A-Za-z0-9_.-]+\.(?:exe|dll|msi|ps1|bat|cmd|sys|com))/i);
  if (m) return m[1];
  const p = (f.process?.iid || f.parent?.iid || "").split(/[:/\\]/).pop();
  if (p && /^proc_shadow_/i.test(p)) return "Unknown Process";
  return p || (f.action || "event");
}
function processKeyOf(f) {
  const label = processLabelOf(f);
  if (label && /\.(exe|dll|msi|ps1|bat|cmd|sys|com)$/i.test(label)) {
    return `bin:${label.toLowerCase()}`;
  }
  return f.process?.iid || f.parent?.iid || `sys:${f.lane}`;
}
// Lane → analyst band (spec: SYSTEM + PROCESS + REGISTRY = System;
// FILES + NETWORK = Files & Network)
function bandOf(lane, expert) {
  if (expert) {
    const map = { system:"SYSTEM", process:"PROCESS", file:"FILES",
                  network:"NETWORK", registry:"REGISTRY" };
    return map[lane] || "OTHER";
  }
  return (lane === "file" || lane === "network") ? "Files & Network" : "System";
}
// Activity classifier — used to pick the tiny glyph icon.
function activityOf(f) {
  const a = (f.action || "").toLowerCase();
  if (/(ransom|locker|encrypt|removed_volume)/.test(a)) return "compromise";
  if (/(dumped|credential|stolen|ntds)/.test(a))       return "detect";
  if (/(c2|beacon|exfil|connect|tunnel|dns|http|network)/.test(a)) return "network";
  if (/(exploit|prevention|blocked)/.test(a))          return "exploit";
  if (/(restore|rollback|revert)/.test(a))             return "restore";
  if (/(scan|inspect|audit)/.test(a))                  return "scan";
  if (/(delete|remove)/.test(a))                       return "delete";
  if (/(execute|launch|spawn|ran|run|invoke|started)/.test(a)) return "execute";
  if (/(install|drop|create|add|new|write|persist|backup)/.test(a)) return "create";
  if (f.lane === "network")  return "network";
  if (f.lane === "registry") return "registry";
  if (f.lane === "file")     return "file";
  return "execute";
}

// ═══════════════════════════════════════════════════════════════════
// Tiny glyph — colored ring by verdict, white symbol inside
// ═══════════════════════════════════════════════════════════════════
function Glyph({ frame, x, y, selected, onSelect }) {
  const v = verdictOf(frame);
  const kind = activityOf(frame);
  const isMal = v === "malicious";
  const ring = isMal ? NX.critical
             : v === "suspicious" ? NX.warning
             : NX.textDim;
  return (
    <button
      data-testid={`ev-${frame.frame_iid}`}
      onClick={() => onSelect(frame)}
      className="absolute rounded-full outline-none"
      style={{
        left: x - GLYPH / 2, top: y - GLYPH / 2,
        width: GLYPH, height: GLYPH,
        border: `1.2px solid ${selected ? NX.link : ring}`,
        background: isMal ? "#3B0F14" : NX.canvas,
        boxShadow: selected ? `0 0 6px ${NX.link}` : "none",
        transition: "transform 150ms",
      }}
      onMouseEnter={(e) => e.currentTarget.style.transform = "scale(1.35)"}
      onMouseLeave={(e) => e.currentTarget.style.transform = "scale(1)"}
      title={frame.action || frame.label || ""}
    >
      <svg width={GLYPH} height={GLYPH} viewBox="0 0 22 22"
           style={{ display: "block" }}>
        <GlyphIcon kind={kind} color={isMal ? "#FCA5A5" : "#FFFFFF"} />
      </svg>
    </button>
  );
}

function GlyphIcon({ kind, color }) {
  const c = 11;
  const w = 1.6;
  switch (kind) {
    case "execute":
      return <polygon points={`${c-2.5},${c-3} ${c-2.5},${c+3} ${c+3},${c}`} fill={color} />;
    case "create":
      return (
        <g stroke={color} strokeWidth={w} strokeLinecap="round">
          <line x1={c-3} y1={c} x2={c+3} y2={c} />
          <line x1={c} y1={c-3} x2={c} y2={c+3} />
        </g>
      );
    case "delete":
      return (
        <g stroke={color} strokeWidth={w} strokeLinecap="round">
          <line x1={c-3} y1={c-3} x2={c+3} y2={c+3} />
          <line x1={c-3} y1={c+3} x2={c+3} y2={c-3} />
        </g>
      );
    case "network":
      return (
        <g stroke={color} strokeWidth={w} strokeLinecap="round" fill="none">
          <path d={`M ${c-3.5} ${c-1.5} L ${c+3} ${c-1.5}`} />
          <path d={`M ${c+1.5} ${c-3} L ${c+3.5} ${c-1.5} L ${c+1.5} ${c}`} />
          <path d={`M ${c+3.5} ${c+1.5} L ${c-3} ${c+1.5}`} />
          <path d={`M ${c-1.5} ${c+3} L ${c-3.5} ${c+1.5} L ${c-1.5} ${c}`} />
        </g>
      );
    case "registry":
      return <rect x={c-3} y={c-3} width="6" height="6" fill="none" stroke={color} strokeWidth={w} />;
    case "file":
      return (
        <path d={`M ${c-2.5} ${c-3.5} L ${c+1.5} ${c-3.5} L ${c+2.5} ${c-2.5} L ${c+2.5} ${c+3.5} L ${c-2.5} ${c+3.5} Z`}
              fill="none" stroke={color} strokeWidth={w} strokeLinejoin="round" />
      );
    case "detect":
      return (
        <g fill={color}>
          <circle cx={c} cy={c} r="2.5" />
        </g>
      );
    case "compromise":
      return (
        <text x={c} y={c+3} textAnchor="middle" fontSize="8" fontWeight="900"
              fill={color} fontFamily="Inter, sans-serif">!</text>
      );
    case "exploit":
      return (
        <path d={`M ${c+1} ${c-4} L ${c-3} ${c+1} L ${c} ${c+1} L ${c-1} ${c+4} L ${c+3} ${c-1} L ${c} ${c-1} Z`}
              fill={color} />
      );
    case "scan":
      return (
        <g stroke={color} strokeWidth={w} fill="none">
          <circle cx={c-1} cy={c-1} r="2.2" />
          <line x1={c+0.8} y1={c+0.8} x2={c+3} y2={c+3} strokeLinecap="round" />
        </g>
      );
    case "restore":
      return (
        <path d={`M ${c+3.5} ${c-1} A 3.5 3.5 0 1 0 ${c-3} ${c+2} M ${c+3.5} ${c-3} L ${c+3.5} ${c-1} L ${c+1.5} ${c-1}`}
              fill="none" stroke={color} strokeWidth={w} strokeLinecap="round" strokeLinejoin="round" />
      );
    default:
      return <circle cx={c} cy={c} r="2" fill={color} />;
  }
}

// ═══════════════════════════════════════════════════════════════════
// Root
// ═══════════════════════════════════════════════════════════════════
export default function DeviceTrajectoryV2() {
  const navigate = useNavigate();
  const { caseId = "case_dfir_bumblebee_akira_2026" } = useParams() || {};
  const [data, setData]         = useState(null);
  const [err, setErr]           = useState(null);
  const [selected, setSelected] = useState(null);
  const [expert, setExpert]     = useState(false);
  const [rightTab, setRightTab] = useState("activity"); // activity | overview | mitre | reference
  const [query, setQuery]       = useState("");
  const [filters, setFilters]   = useState({ verdict: "all", lane: "all", mitre: null });
  const [filterOpen, setFilterOpen] = useState(false);
  const [zoom, setZoom]         = useState("Fit");
  const [cases, setCases]       = useState(null);
  const [caseMenu, setCaseMenu] = useState(false);
  const canvasRef  = useRef(null);
  const searchRef  = useRef(null);
  const [canvasW, setCanvasW] = useState(1200);

  const enabled = isObservable("TRAJECTORY_ENGINE") || isObservable("CASE_ENGINE");

  // Fetch trajectory
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    (async () => {
      try {
        const r = await api.get(`/v2/cases/${encodeURIComponent(caseId)}/trajectory/device?limit=1000`);
        if (!cancelled) setData(r.data);
      } catch (e) {
        if (!cancelled) setErr(e?.response?.data?.detail || e.message);
      }
    })();
    return () => { cancelled = true; };
  }, [caseId, enabled]);

  // Fetch case list for selector
  useEffect(() => {
    if (!enabled) return;
    (async () => {
      try {
        const r = await api.get(`/v2/cases`);
        setCases(r.data?.cases || r.data || []);
      } catch { /* ignore */ }
    })();
  }, [enabled]);

  // Resize
  useEffect(() => {
    if (!canvasRef.current) return;
    const ro = new ResizeObserver(() => {
      setCanvasW(canvasRef.current?.clientWidth || 1200);
    });
    ro.observe(canvasRef.current);
    return () => ro.disconnect();
  }, [data]);

  // Auto-open evidence on selection
  useEffect(() => { if (selected) setRightTab("evidence"); }, [selected]);

  // Keyboard shortcuts
  useEffect(() => {
    if (!enabled) return;
    const h = (e) => {
      if (e.key === "/" && document.activeElement?.tagName !== "INPUT") {
        e.preventDefault(); searchRef.current?.focus();
      }
      if (e.key === "Escape") setSelected(null);
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [enabled]);

  // Filter + search
  const allFrames = data?.frames || [];
  const frames = useMemo(() => {
    const q = query.trim().toLowerCase();
    return allFrames.filter(f => {
      const v = verdictOf(f);
      if (filters.verdict !== "all" && v !== filters.verdict) return false;
      if (filters.lane !== "all" && f.lane !== filters.lane)  return false;
      if (filters.mitre && !(f.mitre || []).includes(filters.mitre)) return false;
      if (!q) return true;
      return processLabelOf(f).toLowerCase().includes(q) ||
             (f.label || "").toLowerCase().includes(q) ||
             (f.action || "").toLowerCase().includes(q) ||
             (f.mitre || []).some(t => t.toLowerCase().includes(q));
    });
  }, [allFrames, filters, query]);

  // Bounds + xForTs
  const { minTs, maxTs, xForTs } = useMemo(() => {
    if (!frames.length) return { minTs: 0, maxTs: 0, xForTs: () => 0 };
    const ts = frames.map(f => new Date(f.ts).getTime());
    let lo = Math.min(...ts), hi = Math.max(...ts);
    if (hi === lo) hi = lo + 1000;
    const span = hi - lo;
    const usable = Math.max(canvasW - CANVAS_PAD_X * 2, 200);
    return {
      minTs: lo, maxTs: hi,
      xForTs: (t) => CANVAS_PAD_X + ((new Date(t).getTime() - lo) / span) * usable,
    };
  }, [frames, canvasW]);

  // Rows
  const rows = useMemo(() => {
    const byKey = new Map();
    frames.forEach(f => {
      const k = processKeyOf(f);
      if (!byKey.has(k)) {
        byKey.set(k, {
          key: k, label: processLabelOf(f),
          events: [], firstTs: new Date(f.ts).getTime(),
          lastTs: new Date(f.ts).getTime(),
          parentKey: f.parent?.iid || null,
          worstVerdict: "benign",
          lane: f.lane || "process",
        });
      }
      const r = byKey.get(k);
      r.events.push(f);
      const t = new Date(f.ts).getTime();
      if (t < r.firstTs) r.firstTs = t;
      if (t > r.lastTs)  r.lastTs  = t;
      const v = verdictOf(f);
      if (v === "malicious" || (v === "suspicious" && r.worstVerdict !== "malicious"))
        r.worstVerdict = v;
    });
    // Sort: analyst band first (System block, then Files & Network)
    const bandRank = (r) => (r.lane === "file" || r.lane === "network") ? 1 : 0;
    const arr = [...byKey.values()].sort((a, b) => {
      const A = expert ? ["system","process","file","network","registry"].indexOf(a.lane)
                       : bandRank(a);
      const B = expert ? ["system","process","file","network","registry"].indexOf(b.lane)
                       : bandRank(b);
      if (A !== B) return A - B;
      return a.firstTs !== b.firstTs ? a.firstTs - b.firstTs : a.label.localeCompare(b.label);
    });
    return arr;
  }, [frames, expert]);

  const rowIndex = useMemo(() => {
    const m = new Map();
    rows.forEach((r, i) => m.set(r.key, i));
    return m;
  }, [rows]);

  // Band groups + row Y positions
  const { groups, rowY, canvasH } = useMemo(() => {
    let y = 0;
    const rY = [];
    const gs = [];
    let curBand = null, curGroup = null;
    rows.forEach((r) => {
      const b = bandOf(r.lane, expert);
      if (b !== curBand) {
        y += BAND_H;
        curBand = b;
        curGroup = { label: b, rows: [], top: y };
        gs.push(curGroup);
      }
      rY.push(y);
      curGroup.rows.push(r);
      y += ROW_H;
    });
    return { groups: gs, rowY: rY, canvasH: y + 8 };
  }, [rows, expert]);

  const yOf = (i) => (rowY[i] ?? 0) + ROW_H / 2;

  // Overview / counts
  const counts = useMemo(() => {
    const c = { malicious: 0, suspicious: 0, benign: 0 };
    allFrames.forEach(f => c[verdictOf(f)] += 1);
    const laneC = { system:0, process:0, file:0, network:0, registry:0 };
    allFrames.forEach(f => { if (laneC[f.lane] != null) laneC[f.lane] += 1; });
    const mitreC = new Map();
    allFrames.forEach(f => (f.mitre || []).forEach(t =>
      mitreC.set(t, (mitreC.get(t) || 0) + 1)));
    return {
      verdict: c, lane: laneC,
      topMitre: [...mitreC.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8),
    };
  }, [allFrames]);

  if (!enabled) {
    return (
      <div className="min-h-screen p-6 text-xs"
           style={{ background: NX.bg, color: NX.textMute,
                    fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>
        Device Trajectory is disabled. Set{" "}
        <code style={{ color: NX.link }}>NIVX_FLAG_TRAJECTORY_ENGINE=shadow</code>{" "}or{" "}
        <code style={{ color: NX.link }}>NIVX_FLAG_CASE_ENGINE=shadow</code>.
      </div>
    );
  }

  return (
    <div data-testid="v2-device-trajectory"
         className="flex flex-col h-screen overflow-hidden"
         style={{
           background: NX.bg, color: NX.text,
           fontFamily: "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif",
         }}>

      {/* ─── Header ─── */}
      <TrajectoryHeader
        caseId={caseId} caseCount={data?.count} procCount={rows.length}
        cases={cases} caseMenu={caseMenu} setCaseMenu={setCaseMenu}
        onPickCase={(id) => navigate(`/v2/trajectory/${encodeURIComponent(id)}`)}
        query={query} setQuery={setQuery} searchRef={searchRef}
        zoom={zoom} setZoom={setZoom}
      />

      {/* ─── Filter row ─── */}
      <FilterRow
        filters={filters} setFilters={setFilters}
        open={filterOpen} setOpen={setFilterOpen}
        counts={counts} totalShown={frames.length} totalAll={allFrames.length}
      />

      {/* ─── Day scrubber ─── */}
      <DayScrubber frames={allFrames} minTs={minTs} maxTs={maxTs} />

      {/* ─── Hour scrubber ─── */}
      <HourScrubber frames={allFrames} minTs={minTs} />

      {err && (
        <div className="px-3 py-1.5 text-[11px]"
             style={{ background: `${NX.critical}22`, color: NX.critical,
                      borderBottom: `1px solid ${NX.critical}` }}>
          {String(err)}
        </div>
      )}

      {/* ─── Main workspace ─── */}
      <div className="flex flex-1 min-h-0">
        <LeftRail
          groups={groups} selectedKey={selected ? processKeyOf(selected) : null}
          onPickRow={(r) => setSelected(r.events[0])}
          onOpenAncestry={(key) => {
            const iid = key.startsWith("bin:") ? key.slice(4) : key;
            navigate(`/v2/ancestry/${encodeURIComponent(caseId)}/${encodeURIComponent(iid)}`);
          }}
          expert={expert} onToggleExpert={() => setExpert(v => !v)}
        />

        {/* Canvas */}
        <div ref={canvasRef} className="flex-1 relative overflow-auto"
             style={{ background: NX.canvas }}
             data-testid="trajectory-canvas">
          <div className="relative" style={{ height: canvasH, minWidth: canvasW }}>
            {/* Faint vertical hour columns */}
            <div className="absolute inset-0 pointer-events-none"
                 style={{
                   backgroundImage:
                     `repeating-linear-gradient(90deg, transparent 0 47px, ${NX.border}88 47px 48px)`,
                 }} />

            {/* Band header stripes */}
            {groups.map((g, i) => (
              <div key={g.label + i} className="absolute inset-x-0 flex items-center px-3"
                   style={{
                     top: g.top - BAND_H, height: BAND_H,
                     background: NX.panel,
                     borderBottom: `1px solid ${NX.border}`,
                   }}>
                <span className="text-[9px] tracking-[0.22em] uppercase font-semibold"
                      style={{ color: NX.textDim }}>{g.label}</span>
                <span className="ml-auto text-[9px] tabular-nums"
                      style={{ color: NX.textMute }}>{g.rows.length}</span>
              </div>
            ))}

            {/* Selected row highlight */}
            {selected && (() => {
              const i = rowIndex.get(processKeyOf(selected));
              if (i == null) return null;
              return (
                <div className="absolute inset-x-0 pointer-events-none"
                     style={{ top: rowY[i] ?? 0, height: ROW_H,
                              background: `${NX.selected}22` }} />
              );
            })()}

            {/* Lifelines */}
            <svg width={canvasW} height={canvasH}
                 className="absolute top-0 left-0 pointer-events-none">
              {rows.map((r, i) => {
                const y = yOf(i);
                const x1 = xForTs(r.firstTs);
                const x2 = xForTs(r.lastTs);
                const sel = selected && processKeyOf(selected) === r.key;
                const stroke = r.worstVerdict === "malicious" ? NX.critical
                             : r.worstVerdict === "suspicious" ? NX.warning
                             : sel ? NX.lifeline : NX.lifelineDim;
                return (
                  <line key={r.key} x1={x1 - 3} y1={y} x2={x2 + 3} y2={y}
                        stroke={stroke} strokeWidth={sel ? 1.2 : 0.9}
                        strokeDasharray="2 3"
                        opacity={sel ? 0.9 : 0.4} />
                );
              })}
            </svg>

            {/* Event glyphs */}
            {frames.map(f => {
              const i = rowIndex.get(processKeyOf(f));
              if (i == null) return null;
              const x = xForTs(f.ts);
              const y = yOf(i);
              return (
                <Glyph key={f.frame_iid || `${x}-${y}`}
                       frame={f} x={x} y={y}
                       selected={selected?.frame_iid === f.frame_iid}
                       onSelect={setSelected} />
              );
            })}
          </div>
        </div>

        {/* Right panel */}
        <RightPanel
          tab={rightTab} setTab={setRightTab}
          selected={selected} onClose={() => setSelected(null)}
          frames={frames} onPickEvent={setSelected}
          counts={counts} caseId={caseId}
        />
      </div>

      {/* ─── Status footer ─── */}
      <Footer minTs={minTs} maxTs={maxTs}
              shown={frames.length} total={allFrames.length}
              procs={rows.length} zoom={zoom} />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Header — logo | case | search | zoom · compact single row
// ═══════════════════════════════════════════════════════════════════
function TrajectoryHeader({
  caseId, caseCount, procCount,
  cases, caseMenu, setCaseMenu, onPickCase,
  query, setQuery, searchRef, zoom, setZoom,
}) {
  return (
    <header className="shrink-0 flex items-center gap-3 px-3 relative"
            style={{ height: HEADER_H, background: NX.panel,
                     borderBottom: `1px solid ${NX.border}` }}>
      <div className="flex items-center gap-2">
        <div className="w-5 h-5 rounded-sm flex items-center justify-center"
             style={{ background: `${NX.link}22`, border: `1px solid ${NX.link}55` }}>
          <Radar size={11} style={{ color: NX.link }} />
        </div>
        <div style={{ lineHeight: 1 }}>
          <div className="text-[8px] tracking-[0.24em] uppercase font-semibold"
               style={{ color: NX.textMute }}>NivXRay</div>
          <div className="text-[12px] font-semibold leading-none mt-0.5"
               style={{ color: NX.text }}>Device Trajectory</div>
        </div>
      </div>

      <span style={{ width: 1, height: 22, background: NX.border }} />

      {/* Case selector */}
      <div className="relative">
        <button
          data-testid="case-selector"
          onClick={() => setCaseMenu(!caseMenu)}
          className="flex items-center gap-1.5 px-2 py-1 rounded-sm text-[11px]"
          style={{
            background: NX.panel2, border: `1px solid ${NX.border}`,
            color: NX.text, fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
          }}
        >
          <FolderOpen size={11} style={{ color: NX.textDim }} />
          <span className="truncate max-w-[220px]">{caseId}</span>
          <ChevronDown size={10} style={{ color: NX.textDim,
            transform: caseMenu ? "rotate(180deg)" : "none", transition: "transform 150ms" }} />
        </button>
        {caseMenu && cases && (
          <div className="absolute top-full mt-1 left-0 w-80 max-h-72 overflow-y-auto z-40 rounded-sm"
               style={{ background: NX.panel2, border: `1px solid ${NX.border}`,
                        boxShadow: "0 12px 28px -8px rgba(0,0,0,0.7)" }}
               data-testid="case-menu">
            {cases.length === 0 && (
              <div className="p-3 text-[11px]" style={{ color: NX.textMute }}>
                no cases indexed
              </div>
            )}
            {cases.map(c => {
              const id = c.case_id || c._id || c.id;
              const active = id === caseId;
              return (
                <button key={id}
                        data-testid={`case-option-${id}`}
                        onClick={() => { onPickCase(id); setCaseMenu(false); }}
                        className="w-full text-left px-3 py-1.5 text-[11px]"
                        style={{
                          background: active ? `${NX.link}22` : "transparent",
                          color: active ? NX.text : NX.textDim,
                          borderBottom: `1px solid ${NX.border}44`,
                          fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
                        }}
                        onMouseEnter={(e) => !active && (e.currentTarget.style.background = NX.hover)}
                        onMouseLeave={(e) => !active && (e.currentTarget.style.background = "transparent")}>
                  {id}
                </button>
              );
            })}
          </div>
        )}
      </div>

      <span className="text-[10px] tracking-wider uppercase font-semibold"
            style={{ color: NX.textMute }}>Events</span>
      <span className="text-[11px] tabular-nums"
            style={{ color: NX.text, fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>
        {caseCount ?? "—"}
      </span>
      <span className="text-[10px] tracking-wider uppercase font-semibold"
            style={{ color: NX.textMute }}>Procs</span>
      <span className="text-[11px] tabular-nums"
            style={{ color: NX.text, fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>
        {procCount}
      </span>

      <div className="flex-1" />

      {/* Search */}
      <div className="relative">
        <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2"
                style={{ color: NX.textMute }} />
        <input
          ref={searchRef}
          data-testid="trajectory-search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search Device Trajectory"
          className="pl-8 pr-8 py-1.5 w-72 rounded-md outline-none text-[12px]"
          style={{
            background: NX.panel2, border: `1px solid ${NX.textMute}`,
            color: NX.text,
          }}
          onFocus={(e) => e.currentTarget.style.borderColor = NX.link}
          onBlur={(e)  => e.currentTarget.style.borderColor = NX.textMute}
        />
        <kbd className="absolute right-2 top-1/2 -translate-y-1/2 text-[9px] rounded px-1 pointer-events-none"
             style={{ color: NX.textMute, border: `1px solid ${NX.border}`, background: NX.panel }}>/</kbd>
      </div>

      {/* Zoom presets */}
      <div className="flex items-center rounded-sm p-0.5"
           style={{ border: `1px solid ${NX.border}` }}>
        {["Fit", "1h", "24h", "7d", "30d"].map(z => (
          <button key={z}
            data-testid={`zoom-${z}`}
            onClick={() => setZoom(z)}
            className="px-2 py-1 text-[10px] font-semibold tracking-wider rounded-sm"
            style={{
              background: zoom === z ? `${NX.link}22` : "transparent",
              color:      zoom === z ? NX.link       : NX.textDim,
              fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
              transition: "background 150ms",
            }}>
            {z.toUpperCase()}
          </button>
        ))}
      </div>
    </header>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Compact filter row · single line with Filters ▼ dropdown
// ═══════════════════════════════════════════════════════════════════
function FilterRow({ filters, setFilters, open, setOpen, counts, totalShown, totalAll }) {
  const active = (filters.verdict !== "all" ? 1 : 0)
               + (filters.lane !== "all" ? 1 : 0)
               + (filters.mitre ? 1 : 0);
  return (
    <div className="shrink-0 flex items-center gap-3 px-3"
         style={{ height: FILTER_H, background: NX.panel,
                  borderBottom: `1px solid ${NX.border}` }}
         data-testid="filter-row">
      <div className="relative">
        <button
          data-testid="filters-btn"
          onClick={() => setOpen(!open)}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded-sm text-[11px]"
          style={{
            background: NX.panel2, border: `1px solid ${NX.border}`,
            color: NX.text,
          }}>
          <Filter size={11} style={{ color: NX.textDim }} />
          <span>Filters</span>
          {active > 0 && (
            <span className="text-[9px] px-1 rounded-sm tabular-nums"
                  style={{ background: `${NX.link}33`, color: NX.link }}>
              {active}
            </span>
          )}
          <ChevronDown size={10} style={{ color: NX.textDim,
            transform: open ? "rotate(180deg)" : "none", transition: "transform 150ms" }} />
        </button>
        {open && (
          <div className="absolute top-full mt-1 left-0 w-72 z-40 rounded-sm py-1.5"
               style={{ background: NX.panel2, border: `1px solid ${NX.border}`,
                        boxShadow: "0 12px 28px -8px rgba(0,0,0,0.7)" }}
               data-testid="filters-menu">
            <FilterSection label="Verdict">
              {[
                ["all",        "All",         null],
                ["malicious",  "Malicious",   counts.verdict.malicious],
                ["suspicious", "Suspicious",  counts.verdict.suspicious],
                ["benign",     "Observation", counts.verdict.benign],
              ].map(([k, lbl, n]) => (
                <FilterItem key={k} active={filters.verdict === k} label={lbl} count={n}
                            onClick={() => setFilters({ ...filters, verdict: k })}
                            testId={`f-verdict-${k}`} />
              ))}
            </FilterSection>
            <FilterSection label="Lane">
              <FilterItem active={filters.lane === "all"} label="All lanes"
                          onClick={() => setFilters({ ...filters, lane: "all" })}
                          testId="f-lane-all" />
              {["system","process","file","network","registry"].map(l => (
                <FilterItem key={l} active={filters.lane === l}
                            label={l.charAt(0).toUpperCase() + l.slice(1)}
                            count={counts.lane[l] || 0}
                            onClick={() => setFilters({ ...filters, lane: l })}
                            testId={`f-lane-${l}`} />
              ))}
            </FilterSection>
            {counts.topMitre.length > 0 && (
              <FilterSection label="MITRE Techniques">
                {counts.topMitre.slice(0, 6).map(([t, n]) => (
                  <FilterItem key={t} active={filters.mitre === t}
                              label={t} count={n}
                              onClick={() => setFilters({ ...filters, mitre: filters.mitre === t ? null : t })}
                              testId={`f-mitre-${t}`} />
                ))}
              </FilterSection>
            )}
            {active > 0 && (
              <button data-testid="filter-clear"
                onClick={() => setFilters({ verdict: "all", lane: "all", mitre: null })}
                className="w-full text-left px-3 py-1.5 text-[11px]"
                style={{ color: NX.link, borderTop: `1px solid ${NX.border}` }}>
                Clear filters
              </button>
            )}
          </div>
        )}
      </div>

      {/* Active filter chips (small text pills) */}
      {[
        filters.verdict !== "all" && { k: "verdict", v: filters.verdict },
        filters.lane !== "all" && { k: "lane", v: filters.lane },
        filters.mitre && { k: "mitre", v: filters.mitre },
      ].filter(Boolean).map(({ k, v }) => (
        <span key={k+v} className="text-[10px] px-1.5 py-0.5 rounded-sm"
              style={{
                background: `${NX.link}22`, color: NX.link,
                fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
              }}>
          {v}
          <button
            onClick={() =>
              setFilters({ ...filters, [k]: k === "mitre" ? null : "all" })}
            className="ml-1" style={{ color: NX.link }}>
            <X size={9} />
          </button>
        </span>
      ))}

      <div className="flex-1" />

      <div className="flex items-center gap-1.5 text-[11px] tabular-nums"
           style={{ color: NX.textDim, fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>
        <span style={{ color: NX.text }}>{totalShown}</span>
        <span style={{ color: NX.textMute }}>/</span>
        <span>{totalAll}</span>
        <span style={{ color: NX.textMute }}>events</span>
      </div>
    </div>
  );
}
function FilterSection({ label, children }) {
  return (
    <div className="pb-1">
      <div className="px-3 py-1 text-[9px] tracking-[0.22em] uppercase font-semibold"
           style={{ color: NX.textMute }}>{label}</div>
      {children}
    </div>
  );
}
function FilterItem({ active, label, count, onClick, testId }) {
  return (
    <button data-testid={testId} onClick={onClick}
      className="w-full flex items-center gap-2 px-3 py-1 text-[12px] text-left"
      style={{
        color: active ? NX.text : NX.textDim,
        background: active ? `${NX.link}22` : "transparent",
      }}
      onMouseEnter={(e) => !active && (e.currentTarget.style.background = NX.hover)}
      onMouseLeave={(e) => !active && (e.currentTarget.style.background = "transparent")}>
      <span className="flex-1">{label}</span>
      {count != null && (
        <span className="text-[10px] tabular-nums"
              style={{ color: active ? NX.link : NX.textMute,
                       fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>{count}</span>
      )}
    </button>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Day scrubber (spec §3) — blue density curve + red critical dots
// ═══════════════════════════════════════════════════════════════════
function DayScrubber({ frames, minTs, maxTs }) {
  const hasData = frames.length > 0 && maxTs > minTs;
  const days = useMemo(() => {
    const anchor = hasData ? maxTs : Date.now();
    const end = new Date(anchor); end.setUTCHours(0, 0, 0, 0);
    const out = [];
    for (let i = 30; i >= 0; i--) {
      const d = new Date(end); d.setUTCDate(end.getUTCDate() - i);
      out.push(d);
    }
    return out;
  }, [hasData, maxTs]);
  const { dayCount, crit } = useMemo(() => {
    const c = new Map(), cr = new Set();
    frames.forEach(f => {
      const iso = new Date(f.ts).toISOString().slice(0, 10);
      c.set(iso, (c.get(iso) || 0) + 1);
      if (verdictOf(f) === "malicious") cr.add(iso);
    });
    return { dayCount: c, crit: cr };
  }, [frames]);
  const activeKey = hasData ? new Date(minTs).toISOString().slice(0, 10) : null;
  const maxN = Math.max(1, ...days.map(d => dayCount.get(d.toISOString().slice(0, 10)) || 0));

  return (
    <div className="shrink-0 relative"
         style={{ height: DAY_H, background: NX.panel,
                  borderBottom: `1px solid ${NX.border}` }}
         data-testid="day-scrubber">
      {/* density curve */}
      <svg className="absolute inset-0 w-full h-full pointer-events-none"
           viewBox="0 0 100 100" preserveAspectRatio="none">
        <polyline
          points={days.map((d, i) => {
            const n = dayCount.get(d.toISOString().slice(0, 10)) || 0;
            const y = 78 - (n / maxN) * 60;
            const x = (i / Math.max(1, days.length - 1)) * 100;
            return `${x.toFixed(2)},${y.toFixed(2)}`;
          }).join(" ")}
          fill="none"
          stroke={NX.density}
          strokeWidth="0.7"
          strokeLinejoin="round"
          strokeLinecap="round"
        />
      </svg>
      {/* day cells */}
      <div className="absolute inset-0 flex items-end px-3 pb-1">
        {days.map((d, i) => {
          const iso = d.toISOString().slice(0, 10);
          const isCrit = crit.has(iso);
          const isActive = iso === activeKey;
          const firstOfMonth = d.getUTCDate() === 1 || i === 0;
          return (
            <div key={iso}
                 className="flex-1 relative h-full flex flex-col justify-end items-center"
                 title={iso}>
              {isCrit && (
                <span className="absolute top-2 w-1.5 h-1.5 rounded-full"
                      style={{ background: NX.critical }} />
              )}
              {isActive && (
                <span className="absolute inset-x-0 bottom-4 mx-auto w-4 h-4 rounded-full"
                      style={{ border: `1.5px solid ${NX.text}`,
                               background: `${NX.density}33` }} />
              )}
              <span className="text-[9px] tabular-nums leading-none pb-0.5"
                    style={{
                      color: isActive ? NX.text : NX.textDim,
                      fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
                    }}>
                {d.getUTCDate()}
              </span>
              {firstOfMonth && (
                <span className="absolute top-1 left-0 text-[9px] uppercase tracking-widest font-semibold"
                      style={{ color: NX.textMute }}>
                  {d.toLocaleString("en-US", { month: "short", timeZone: "UTC" })}
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
// Hour scrubber (spec §3) — 24-hour + hatched future
// ═══════════════════════════════════════════════════════════════════
function HourScrubber({ frames, minTs }) {
  const activeKey = frames.length ? new Date(minTs).toISOString().slice(0, 10) : null;
  const activeHrs = useMemo(() => {
    const s = new Set();
    if (!activeKey) return s;
    frames.forEach(f => {
      const d = new Date(f.ts);
      if (d.toISOString().slice(0, 10) === activeKey) s.add(d.getUTCHours());
    });
    return s;
  }, [frames, activeKey]);
  const firstActive = activeHrs.size ? Math.min(...activeHrs) : -1;
  return (
    <div className="shrink-0 flex items-stretch relative"
         style={{ height: HOUR_H, background: NX.hatch,
                  borderBottom: `1px solid ${NX.border}` }}
         data-testid="hour-scrubber">
      {Array.from({ length: 24 }, (_, h) => {
        const has = activeHrs.has(h);
        return (
          <div key={h} className="flex-1 relative flex items-end justify-center pb-1"
               style={!has ? {
                 backgroundImage:
                   `repeating-linear-gradient(135deg, transparent 0 3px, ${NX.border}55 3px 4px)`,
               } : { background: `${NX.density}0F` }}
               title={`${h.toString().padStart(2,"0")}:00`}>
            {h === firstActive && (
              <div className="absolute inset-y-1 w-px left-1/2"
                   style={{ background: NX.text, opacity: 0.85 }} />
            )}
            <span className="text-[9px] tabular-nums leading-none"
                  style={{
                    color: has ? NX.text : NX.textMute,
                    fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
                  }}>
              {(h % 2 === 0) ? h.toString().padStart(2,"0") : ""}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Left rail · compact process list
// ═══════════════════════════════════════════════════════════════════
function LeftRail({ groups, selectedKey, onPickRow, onOpenAncestry, expert, onToggleExpert }) {
  return (
    <div className="shrink-0"
         style={{ width: RAIL_W, background: NX.panel2,
                  borderRight: `1px solid ${NX.border}` }}
         data-testid="left-rail">
      <div className="flex items-center justify-between px-3"
           style={{ height: 24, borderBottom: `1px solid ${NX.border}` }}>
        <span className="text-[9px] tracking-[0.22em] uppercase font-semibold"
              style={{ color: NX.textDim }}>Processes</span>
        <button
          data-testid="expert-toggle"
          onClick={onToggleExpert}
          className="text-[9px] tracking-widest font-semibold px-1.5 py-[1px] rounded-sm"
          style={{
            background: expert ? `${NX.link}22` : NX.panel,
            color: expert ? NX.link : NX.textMute,
            border: `1px solid ${expert ? `${NX.link}66` : NX.border}`,
          }}>
          {expert ? "EXPERT" : "ANALYST"}
        </button>
      </div>
      <div className="overflow-y-auto" style={{ maxHeight: "calc(100vh - 240px)" }}>
        {groups.map((g) => (
          <div key={g.label}>
            <div className="flex items-center px-3"
                 style={{ height: BAND_H, background: NX.panel,
                          borderBottom: `1px solid ${NX.border}` }}>
              <span className="text-[9px] tracking-[0.22em] uppercase font-semibold"
                    style={{ color: NX.textDim }}>{g.label}</span>
              <span className="ml-auto text-[9px] tabular-nums"
                    style={{ color: NX.textMute }}>{g.rows.length}</span>
            </div>
            {g.rows.map((r) => {
              const sel = selectedKey === r.key;
              const vc = r.worstVerdict === "malicious" ? NX.critical
                       : r.worstVerdict === "suspicious" ? NX.warning
                       : NX.border;
              const isUnknown = r.label === "Unknown Process";
              return (
                <div key={r.key} className="group w-full flex items-center gap-1 pl-2 pr-1"
                     style={{
                       height: ROW_H,
                       background: sel ? `${NX.selected}33` : "transparent",
                       borderBottom: `1px solid ${NX.border}22`,
                       borderLeft:   `2px solid ${vc}88`,
                     }}
                     onMouseEnter={(e) => !sel && (e.currentTarget.style.background = NX.hover)}
                     onMouseLeave={(e) => !sel && (e.currentTarget.style.background = "transparent")}>
                  <button
                    data-testid={`row-${r.key}`}
                    onClick={() => onPickRow(r)}
                    className="flex-1 flex items-center gap-1.5 text-left outline-none">
                    <span className="flex-1 truncate text-[11px]"
                          style={{
                            color: isUnknown ? NX.textMute : NX.link,
                            fontStyle: isUnknown ? "italic" : "normal",
                            textDecoration: sel ? "underline" : "none",
                            textUnderlineOffset: "2px",
                          }}>
                      {r.label}
                    </span>
                    <span className="text-[9px] tabular-nums"
                          style={{ color: NX.textMute,
                                   fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>
                      {r.events.length}
                    </span>
                  </button>
                  <button
                    data-testid={`ancestry-${r.key}`}
                    title="Open ancestry"
                    onClick={(e) => { e.stopPropagation(); onOpenAncestry(r.key); }}
                    className="opacity-0 group-hover:opacity-100 w-4 h-4 flex items-center justify-center rounded-sm"
                    style={{ color: NX.textMute, border: `1px solid ${NX.border}` }}>
                    <ChevronRight size={10} />
                  </button>
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Right panel — Activity default; auto-switches to Evidence on select
// ═══════════════════════════════════════════════════════════════════
function RightPanel({ tab, setTab, selected, onClose, frames, onPickEvent, counts, caseId }) {
  const tabs = [
    { k: "activity",  label: "Activity",  count: frames.length },
    { k: "evidence",  label: "Evidence",  count: null },
    { k: "overview",  label: "Overview",  count: null },
    { k: "mitre",     label: "MITRE",     count: counts.topMitre.length },
    { k: "reference", label: "Reference", count: null },
  ];
  return (
    <aside className="shrink-0 flex flex-col overflow-hidden"
           style={{ width: RIGHT_W, background: NX.panel,
                    borderLeft: `1px solid ${NX.border}` }}
           data-testid="right-panel">
      <div className="flex items-stretch" style={{ borderBottom: `1px solid ${NX.border}` }}>
        {tabs.map(t => (
          <button key={t.k}
                  data-testid={`tab-${t.k}`}
                  onClick={() => setTab(t.k)}
                  className="flex-1 flex items-center justify-center gap-1 py-2 text-[10px] tracking-wider uppercase font-semibold"
                  style={{
                    color: tab === t.k ? NX.text : NX.textMute,
                    background: tab === t.k ? NX.panel2 : "transparent",
                    borderBottom: tab === t.k ? `2px solid ${NX.link}` : `2px solid transparent`,
                  }}>
            {t.label}
            {t.count != null && (
              <span className="text-[9px] tabular-nums"
                    style={{ color: NX.textMute,
                             fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>
                {t.count}
              </span>
            )}
          </button>
        ))}
      </div>
      <div className="flex-1 overflow-y-auto">
        {tab === "activity"  && <ActivityFeed frames={frames} onPick={onPickEvent} selected={selected} />}
        {tab === "evidence"  && <EvidencePanel selected={selected} onClose={onClose} />}
        {tab === "overview"  && <OverviewPanel counts={counts} caseId={caseId} />}
        {tab === "mitre"     && <MitrePanel counts={counts} />}
        {tab === "reference" && <ReferencePanel caseId={caseId} />}
      </div>
    </aside>
  );
}

function ActivityFeed({ frames, onPick, selected }) {
  const rows = useMemo(() => {
    return [...frames].sort((a, b) => new Date(a.ts) - new Date(b.ts));
  }, [frames]);
  if (!rows.length) {
    return <div className="p-3 text-[11px]" style={{ color: NX.textMute }}>No events.</div>;
  }
  return (
    <div>
      {rows.map(f => {
        const sel = selected?.frame_iid === f.frame_iid;
        const parent = f.parent?.iid ? f.parent.iid.split(/[:/\\]/).pop() : null;
        const child = processLabelOf(f);
        const v = verdictOf(f);
        const dot = v === "malicious" ? NX.critical
                  : v === "suspicious" ? NX.warning
                  : NX.textDim;
        return (
          <button key={f.frame_iid}
                  data-testid={`act-${f.frame_iid}`}
                  onClick={() => onPick(f)}
                  className="w-full text-left px-3 py-1.5 flex items-center gap-2"
                  style={{
                    background: sel ? `${NX.selected}33` : "transparent",
                    borderBottom: `1px solid ${NX.border}33`,
                  }}
                  onMouseEnter={(e) => !sel && (e.currentTarget.style.background = NX.hover)}
                  onMouseLeave={(e) => !sel && (e.currentTarget.style.background = "transparent")}>
            <span className="w-1.5 h-1.5 rounded-full shrink-0"
                  style={{ background: dot }} />
            <div className="flex-1 min-w-0">
              {parent && (
                <div className="text-[10px] truncate"
                     style={{ color: NX.textMute,
                              fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>
                  {parent}
                </div>
              )}
              <div className="text-[11px] flex items-center gap-1">
                {parent && <span style={{ color: NX.textMute }}>↳</span>}
                <span className="truncate" style={{ color: NX.link }}>{child}</span>
              </div>
              <div className="text-[9px] truncate"
                   style={{ color: NX.textMute,
                            fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>
                {f.action || f.lane || ""}
              </div>
            </div>
            <div className="text-[9px] tabular-nums shrink-0"
                 style={{ color: NX.textMute,
                          fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>
              {new Date(f.ts).toISOString().slice(11, 19)}
            </div>
          </button>
        );
      })}
    </div>
  );
}

function EvidencePanel({ selected, onClose }) {
  if (!selected) {
    return (
      <div className="p-3 text-[11px]" style={{ color: NX.textMute }}>
        Select an event on the timeline to view its evidence.
      </div>
    );
  }
  const parent = selected.parent?.iid ? selected.parent.iid.split(/[:/\\]/).pop() : null;
  const child = processLabelOf(selected);
  const v = verdictOf(selected);
  const rule = selected.rule_id || selected.provenance?.rule_id;
  const conf = selected.provenance?.confidence;
  const artifactIid = selected.provenance?.artifact_iid;

  // Ordered list per spec §12
  const items = [
    ["Timestamp",   new Date(selected.ts).toISOString()],
    ["Severity",    v],
    ["Description", selected.label || selected.action || "—"],
    ["Source",      selected.provenance?.adapter || selected.provenance?.source || "shadow"],
    ["Parent",      parent || "—"],
    ["Child",       child],
    ["Lane",        selected.lane || "—"],
    ["Action",      selected.action || "—"],
    ["Command",     selected.raw?.command || selected.raw?.text || "—"],
    ["MITRE",       (selected.mitre || []).join(", ") || "—"],
    ["Rule",        rule || "—"],
    ["Confidence",  conf != null ? conf.toFixed(2) : "—"],
    ["Artifact",    artifactIid || "—"],
    ["Frame IID",   selected.frame_iid || "—"],
  ];
  return (
    <div className="p-3 text-[11px]">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-[10px] tracking-wider uppercase font-semibold"
              style={{ color: NX.textDim }}>Evidence</span>
        <button data-testid="evidence-close" onClick={onClose}
                className="ml-auto opacity-60 hover:opacity-100"
                style={{ color: NX.textMute }}>
          <X size={12} />
        </button>
      </div>
      <div className="space-y-1">
        {items.map(([k, val]) => (
          <div key={k} className="flex items-baseline gap-2">
            <span className="text-[10px] tracking-widest uppercase font-semibold shrink-0 w-20"
                  style={{ color: NX.textMute }}>{k}</span>
            <span className="flex-1 break-all"
                  style={{ color: NX.text,
                           fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>
              {String(val)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function OverviewPanel({ counts, caseId }) {
  return (
    <div className="p-3 space-y-3 text-[11px]">
      <Section title="Verdict Summary">
        <Kv label="Malicious"    val={counts.verdict.malicious}    color={NX.critical} />
        <Kv label="Suspicious"   val={counts.verdict.suspicious}   color={NX.warning} />
        <Kv label="Observation"  val={counts.verdict.benign}       color={NX.success} />
      </Section>
      <Section title="Event Breakdown">
        {Object.entries(counts.lane).map(([l, n]) => (
          <Kv key={l} label={l.charAt(0).toUpperCase() + l.slice(1)} val={n} color={NX.textDim} />
        ))}
      </Section>
      <Section title="Case Reference">
        <div style={{ color: NX.text,
                      fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>{caseId}</div>
      </Section>
    </div>
  );
}

function MitrePanel({ counts }) {
  if (!counts.topMitre.length)
    return <div className="p-3 text-[11px]" style={{ color: NX.textMute }}>No MITRE techniques.</div>;
  return (
    <div className="p-3 text-[11px] space-y-1">
      {counts.topMitre.map(([t, n]) => (
        <div key={t} className="flex items-center gap-2 px-2 py-1 rounded-sm"
             style={{ background: NX.panel2, border: `1px solid ${NX.border}` }}>
          <span style={{ color: NX.link,
                         fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>{t}</span>
          <span className="ml-auto text-[10px] tabular-nums"
                style={{ color: NX.textMute,
                         fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>{n}</span>
        </div>
      ))}
    </div>
  );
}

function ReferencePanel({ caseId }) {
  return (
    <div className="p-3 text-[11px] space-y-2">
      <div style={{ color: NX.textDim }}>
        Deterministic evidence chain for case
      </div>
      <div style={{ color: NX.link,
                    fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>{caseId}</div>
      <div style={{ color: NX.textMute }}>
        See <span style={{ color: NX.link }}>Investigation Report</span> and
        {" "}<span style={{ color: NX.link }}>Process Ancestry</span> for full context.
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div>
      <div className="text-[9px] tracking-[0.22em] uppercase font-semibold mb-1"
           style={{ color: NX.textMute }}>{title}</div>
      <div className="space-y-0.5">{children}</div>
    </div>
  );
}
function Kv({ label, val, color }) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
      <span className="flex-1" style={{ color: NX.textDim }}>{label}</span>
      <span className="text-[11px] tabular-nums"
            style={{ color: NX.text,
                     fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>{val}</span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Status footer (spec ~4% height)
// ═══════════════════════════════════════════════════════════════════
function Footer({ minTs, maxTs, shown, total, procs, zoom }) {
  const fmt = (t) => t ? new Date(t).toISOString().replace("T"," ").slice(0, 19) + "Z" : "—";
  return (
    <div className="shrink-0 flex items-center gap-4 px-3 text-[10px]"
         style={{
           height: STATUS_H, background: NX.panel,
           borderTop: `1px solid ${NX.border}`,
           color: NX.textDim, fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
         }}
         data-testid="footer">
      <span>WINDOW · {zoom.toUpperCase()}</span>
      <span>{fmt(minTs)}</span>
      <span style={{ color: NX.textMute }}>→</span>
      <span>{fmt(maxTs)}</span>
      <div className="flex-1" />
      <span>EVENTS <span style={{ color: NX.text }}>{shown}</span> / {total}</span>
      <span>ROWS <span style={{ color: NX.text }}>{procs}</span></span>
    </div>
  );
}
