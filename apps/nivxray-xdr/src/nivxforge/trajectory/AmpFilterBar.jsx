/**
 * Filters + scoped search — Cisco's Navigator header:
 *
 *   ▼  [ Filters ⌄ ]  [ Search Device Trajectory            ] [🔍]
 *
 * The dropdown carries the filter matrix: activity type (with observed
 * counts), disposition, and the timeframe presets over the 30-day
 * retained period. Counts are counts of persisted observations, so an
 * analyst can see what exists before filtering it away.
 */
import React, { useState } from "react";
import { ChevronDown, ChevronLeft, ChevronRight, Crosshair, Search,
         ZoomIn, ZoomOut } from "lucide-react";

import { C, typeLabel } from "./ampModel";
import EventGlyph, { LEGEND_TYPES } from "./AmpIcons";

const PRESETS = [
  { key: "1d", label: "Last 24 hours", days: 1 },
  { key: "7d", label: "Last 7 days", days: 7 },
  { key: "14d", label: "Last 14 days", days: 14 },
  { key: "30d", label: "Last 30 days", days: 30 },
  { key: "all", label: "All observed", days: null },
];

const DISPOSITIONS = [
  ["MALICIOUS", "Malicious", C.malicious],
  ["SUSPICIOUS", "Suspicious", C.suspicious],
  ["UNKNOWN_NOT_ASSESSED", "Unknown · not assessed", C.inkFaint],
];

const WinBtn = ({ onClick, title, testid, children }) => (
  <button onClick={onClick} title={title} data-testid={testid}
          style={{ padding: "3px 5px", lineHeight: 1, cursor: "pointer",
                   background: C.paper, color: C.inkDim, borderRadius: 2,
                   border: `1px solid ${C.gridStrong}`, display: "flex" }}>
    {children}
  </button>
);

export default function AmpFilterBar({
  typeCounts = [], kinds, onKinds, dispositions, onDispositions,
  query, onQuery, preset, onPreset, matched, total, collapsed,
  onCollapsed, onZoom, onPan, onFitDay,
}) {
  const [open, setOpen] = useState(false);
  const count = kinds.length + dispositions.length
    + (preset !== "all" ? 1 : 0);

  const toggle = (list, setter) => (v) => setter(
    list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  return (
    <div style={{ display: "flex", gap: 7, alignItems: "center",
                  padding: "7px 9px", borderBottom: `1px solid ${C.grid}` }}
         data-testid="amp-filter-bar">
      <button onClick={() => onCollapsed(!collapsed)}
              data-testid="amp-navigator-collapse"
              style={{ background: "none", border: "none", cursor: "pointer",
                       color: C.inkDim, padding: 0 }}>
        {collapsed ? <ChevronRight size={13} /> : <ChevronDown size={13} />}
      </button>

      <div style={{ position: "relative" }}>
        <button onClick={() => setOpen((v) => !v)}
                data-testid="amp-filters-button"
                style={{ fontSize: 11, padding: "4px 10px", borderRadius: 3,
                         cursor: "pointer", background: C.paper,
                         color: count ? C.link : C.inkDim,
                         border: `1px solid ${count ? C.link
                           : C.gridStrong}`, display: "flex", gap: 5,
                         alignItems: "center" }}>
          Filters{count ? ` (${count})` : ""} <ChevronDown size={10} />
        </button>
        {open && (
          <div data-testid="amp-filters-menu"
               style={{ position: "absolute", top: 27, left: 0, zIndex: 60,
                        background: C.paper, width: 296, maxHeight: 460,
                        overflowY: "auto", padding: 9, borderRadius: 3,
                        border: `1px solid ${C.gridStrong}`,
                        boxShadow: "0 10px 26px rgba(20,32,44,.18)" }}>
            <Section title="Activity type" />
            {typeCounts.length === 0 && (
              <div style={{ fontSize: 10.4, color: C.inkFaint }}>
                No activity types observed
              </div>
            )}
            {typeCounts.map((t) => (
              <label key={t.event_type}
                     data-testid={`amp-filter-type-${t.event_type}`}
                     style={{ display: "flex", alignItems: "center", gap: 7,
                              fontSize: 10.6, color: C.ink, padding: "3px 2px",
                              cursor: "pointer" }}>
                <input type="checkbox" checked={kinds.includes(t.event_type)}
                       onChange={() => toggle(kinds, onKinds)(t.event_type)} />
                <svg width={15} height={15} viewBox="-7.5 -7.5 15 15">
                  <EventGlyph event={{ event_type: t.event_type }}
                              color={C.glyph} />
                </svg>
                <span style={{ flex: 1 }}>{typeLabel(t.event_type)}</span>
                <span className="mono" style={{ color: C.inkFaint,
                                                fontSize: 9.6 }}>
                  {t.count}
                </span>
              </label>
            ))}

            <Section title="Disposition" />
            {DISPOSITIONS.map(([key, label, color]) => (
              <label key={key} data-testid={`amp-filter-disp-${key}`}
                     style={{ display: "flex", alignItems: "center", gap: 7,
                              fontSize: 10.6, color: C.ink, padding: "3px 2px",
                              cursor: "pointer" }}>
                <input type="checkbox" checked={dispositions.includes(key)}
                       onChange={() => toggle(dispositions,
                                              onDispositions)(key)} />
                <span style={{ width: 8, height: 8, borderRadius: "50%",
                               background: color }} />
                {label}
              </label>
            ))}

            <Section title="Timeframe · 30-day retained period" />
            <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
              {PRESETS.map((p) => (
                <button key={p.key} data-testid={`amp-preset-${p.key}`}
                        onClick={() => onPreset(p.key, p.days)}
                        style={{ fontSize: 10.2, padding: "3px 8px",
                                 cursor: "pointer", borderRadius: 2,
                                 color: preset === p.key ? "#FFFFFF" : C.inkDim,
                                 background: preset === p.key ? C.link
                                   : C.paper,
                                 border: `1px solid ${preset === p.key
                                   ? C.link : C.gridStrong}` }}>
                  {p.label}
                </button>
              ))}
            </div>

            <Section title="Legend" />
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}
                 data-testid="amp-legend">
              {LEGEND_TYPES.map((t) => (
                <span key={t} style={{ display: "flex", alignItems: "center",
                                       gap: 4, fontSize: 9.6,
                                       color: C.inkDim }}>
                  <svg width={15} height={15} viewBox="-7.5 -7.5 15 15">
                    <EventGlyph event={{ event_type: t }} color={C.glyph} />
                  </svg>
                  {typeLabel(t)}
                </span>
              ))}
            </div>
            <div style={{ fontSize: 9.6, color: C.inkFaint, marginTop: 6,
                          lineHeight: 1.5 }}>
              A red ringed mark is malicious or a detection · a numbered mark
              aggregates that many observations · a dotted connector means the
              parent process was never observed.
            </div>

            <button onClick={() => { onKinds([]); onDispositions([]);
                                     onQuery(""); setOpen(false); }}
                    data-testid="amp-filters-clear"
                    style={{ marginTop: 9, width: "100%", fontSize: 10.2,
                             padding: "4px 0", cursor: "pointer",
                             background: C.paperAlt, color: C.inkDim,
                             border: `1px solid ${C.grid}` }}>
              Clear all filters
            </button>
          </div>
        )}
      </div>

      <div style={{ position: "relative", flex: 1, display: "flex" }}>
        <input value={query} onChange={(e) => onQuery(e.target.value)}
               data-testid="amp-filter-search"
               placeholder="Search Device Trajectory — IP, filename, SHA-256, process, command line, MITRE technique"
               style={{ flex: 1, fontSize: 11, color: C.ink,
                        padding: "5px 9px", background: C.paper,
                        border: `1px solid ${C.gridStrong}`,
                        borderRight: "none",
                        borderRadius: "3px 0 0 3px" }} />
        <span style={{ display: "flex", alignItems: "center",
                       padding: "0 9px", background: C.paperAlt,
                       border: `1px solid ${C.gridStrong}`,
                       borderRadius: "0 3px 3px 0" }}>
          <Search size={12} color={C.inkDim} />
        </span>
      </div>

      {/* Window controls — the same navigation the 24-hour band
          performs by dragging, kept reachable as buttons. */}
      <WinBtn onClick={() => onZoom(0.5)} title="Zoom in"
              testid="amp-nav-zoom-in"><ZoomIn size={11} /></WinBtn>
      <WinBtn onClick={() => onZoom(2)} title="Zoom out"
              testid="amp-nav-zoom-out"><ZoomOut size={11} /></WinBtn>
      <WinBtn onClick={() => onPan(-0.5)} title="Earlier"
              testid="amp-nav-step-back"><ChevronLeft size={11} /></WinBtn>
      <WinBtn onClick={() => onPan(0.5)} title="Later"
              testid="amp-nav-step-fwd"><ChevronRight size={11} /></WinBtn>
      <WinBtn onClick={onFitDay} title="Fit the selected day"
              testid="amp-nav-fit-day"><Crosshair size={11} /></WinBtn>

      <span className="mono" data-testid="amp-filter-count"
            style={{ fontSize: 9.6, color: C.inkDim, whiteSpace: "nowrap" }}>
        {matched} / {total} observations
      </span>
    </div>
  );
}

const Section = ({ title }) => (
  <div style={{ fontSize: 9, fontWeight: 800, letterSpacing: ".5px",
                textTransform: "uppercase", color: C.inkFaint,
                margin: "9px 0 4px", borderBottom: `1px solid ${C.grid}`,
                paddingBottom: 3 }}>
    {title}
  </div>
);

export { PRESETS };
