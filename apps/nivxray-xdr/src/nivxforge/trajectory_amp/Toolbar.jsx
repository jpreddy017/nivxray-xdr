import React from "react";
import { KINDS, PAL } from "./model";
import { GlyphIcon } from "./Glyphs";
import { ui } from "./ui";

export default function Toolbar({ present, kinds, setKinds, summary, query, setQuery, onSearch, isolation, onClearIsolation,
                                  hideOthers, setHideOthers, tzMode, setTzMode, legendOpen, setLegendOpen, onZoom }) {
  const toggle = (k) => setKinds((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; });
  return (
    <section data-testid="trajectory-toolbar" style={{ ...ui.panel, padding: "8px 12px", display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
      <span style={{ fontSize: 11, color: PAL.muted, letterSpacing: 1 }}>EVENT TYPES</span>
      {Object.keys(KINDS).filter((k) => present.has(k)).map((k) => (
        <button key={k} data-testid={`filter-kind-${k}`} aria-pressed={kinds.has(k)} onClick={() => toggle(k)}
          style={{ ...ui.btn, ...(kinds.has(k) ? ui.btnOn : {}), display: "inline-flex", gap: 6, alignItems: "center", padding: "3px 8px" }}>
          <GlyphIcon kind={k} size={13} />{KINDS[k].label}<span style={{ color: PAL.muted }}>{present.get(k)}</span>
        </button>
      ))}
      <span data-testid="filter-indicator" data-active={String(summary.active)}
        style={{ ...ui.chip, background: summary.active ? "#3A2C10" : "transparent", border: `1px solid ${summary.active ? PAL.amber : PAL.grid}`, color: summary.active ? "#F3D18C" : PAL.muted }}>
        {summary.active ? "Filtered · " : ""}{summary.text}
        {summary.active && <button data-testid="filter-reset" onClick={() => setKinds(new Set())} style={{ ...ui.btn, padding: "1px 8px" }}>Reset</button>}
      </span>
      <span style={{ flex: 1 }} />
      <form onSubmit={(e) => { e.preventDefault(); onSearch(query); }} style={{ display: "flex", gap: 6 }}>
        <input data-testid="trajectory-search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="SHA-256 or file name → isolate lineage"
          style={{ ...ui.btn, width: 290, cursor: "text", background: PAL.bg }} />
        <button data-testid="trajectory-search-submit" type="submit" style={ui.btn}>Isolate</button>
      </form>
      {isolation && (
        <span data-testid="isolation-chip" style={{ ...ui.chip, background: "#0F3440", border: `1px solid ${PAL.accent}`, color: "#BFF1FA" }}>
          Isolation active · {isolation.label} · {isolation.count} rows
          <label style={{ display: "inline-flex", gap: 4, fontSize: 11 }}><input data-testid="isolation-hide-toggle" type="checkbox" checked={hideOthers} onChange={(e) => setHideOthers(e.target.checked)} />hide others</label>
          <button data-testid="isolation-clear" onClick={onClearIsolation} style={{ ...ui.btn, padding: "1px 8px" }}>Clear</button>
        </span>
      )}
      <button data-testid="zoom-out" style={ui.btn} onClick={() => onZoom(2)}>−</button>
      <button data-testid="zoom-in" style={ui.btn} onClick={() => onZoom(0.5)}>+</button>
      <button data-testid="tz-toggle" style={ui.btn} onClick={() => setTzMode(tzMode === "UTC" ? "LOCAL" : "UTC")}>{tzMode === "UTC" ? "UTC" : "Local"} time</button>
      <button data-testid="legend-toggle" style={{ ...ui.btn, ...(legendOpen ? ui.btnOn : {}) }} onClick={() => setLegendOpen(!legendOpen)}>Legend</button>
    </section>
  );
}
