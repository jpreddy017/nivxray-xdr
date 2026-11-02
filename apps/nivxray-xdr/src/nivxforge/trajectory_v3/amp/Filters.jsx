import "./filters.css";
import { FilterIcon } from "./Glyphs";
import React, { useMemo, useRef, useState } from "react";
import { DEFAULT_ON, FILTER_GROUPS } from "./model";
import { C } from "./theme";

const LIVE = FILTER_GROUPS.flatMap(([, its]) => its.filter((x) => !x[2]).map((x) => x[0]));

// "All ATT&CK tactics" -> "ATTCK". Kept byte-identical to the shipped ids so
// existing automation and the filters contract keep addressing the same nodes.
const groupId = (g) => g.split(" ")[1].replace(/[^A-Za-z]/g, "");

/** A checkbox that can say "some", not just yes/no. */
function Tri({ on, off, testid, onChange }) {
  const ref = useRef(null);
  React.useEffect(() => {
    if (ref.current) ref.current.indeterminate = !on && !off;
  }, [on, off]);
  return <input ref={ref} type="checkbox" data-testid={testid} checked={on}
    onChange={onChange} />;
}

export function FiltersPanel({ applied, onApply, onCancel, present = new Set() }) {
  const [on, setOn] = useState(new Set(applied));
  const [shut, setShut] = useState(() => new Set());
  const set = (keys, v) => setOn((s) => { const n = new Set(s); keys.forEach((k) => (v ? n.add(k) : n.delete(k))); return n; });

  // A type is selectable when it is always collected, or when THIS device
  // actually produced it. Everything else stays visible but inert, so an
  // absent type reads as "not collected" rather than as "no activity".
  const live = useMemo(() => FILTER_GROUPS.map(([g, its]) => [g, its,
    its.filter(([k, , nc]) => !nc || present.has(k)).map(([k]) => k)]), [present]);
  const available = live.flatMap(([, , ks]) => ks);
  const allOn = available.every((k) => on.has(k));
  const allOff = !available.some((k) => on.has(k));
  const dirty = available.some((k) => on.has(k) !== applied.has(k))
    || [...applied].some((k) => !on.has(k));

  return (
    <div data-testid="v3-filters-panel" style={{ position: "absolute", right: 0, top: 46, zIndex: 40, width: "min(960px, calc(100vw - 40px))", background: C.tip, border: `1px solid ${C.line}`,
      borderRadius: 8, boxShadow: "0 14px 40px rgba(0,0,0,.55)", fontSize: 13.5, color: C.text, animation: "v3in .12s ease-out" }}>
      <div className="v3-scroll" style={{ maxHeight: "min(620px, 65vh)", overflowY: "auto", padding: "12px 16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <label style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: 700, flex: 1 }}>
            <Tri on={allOn} off={allOff} testid="v3-filter-all-types" onChange={() => set(available, !allOn)} /> All types</label>
          <button className="v3-link" data-testid="v3-filters-reset" style={{ fontSize: 12 }}
            disabled={DEFAULT_ON.every((k) => on.has(k)) && on.size === DEFAULT_ON.length}
            onClick={() => setOn(new Set(DEFAULT_ON))}>Reset</button>
        </div>
        <div className="v3-filter-groups">{live.map(([g, its, ks], groupIndex) => {
          const id = groupId(g);
          const all = ks.length > 0 && ks.every((k) => on.has(k));
          const none = !ks.some((k) => on.has(k));
          const sel = ks.filter((k) => on.has(k)).length;
          const open = !shut.has(g);
          return (<div key={g} className={groupIndex < 2 ? "v3-filter-section v3-filter-section-wide" : "v3-filter-section"} data-testid={`v3-filter-section-${id}`} style={{ marginBottom: 10, paddingLeft: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <label style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: 600, flex: 1 }}>
                <Tri on={all} off={none} testid={`v3-filter-group-${id}`} onChange={() => set(ks, !all)} /> {g}</label>
              <span data-testid={`v3-filter-count-${id}`} style={{ fontSize: 11, color: C.muted, fontVariantNumeric: "tabular-nums" }}>
                {sel}/{ks.length}</span>
              <button className="v3-link" data-testid={`v3-filter-toggle-${id}`} aria-expanded={open}
                title={open ? "Collapse" : "Expand"} style={{ fontSize: 11, width: 14 }}
                onClick={() => setShut((s) => { const n = new Set(s); open ? n.add(g) : n.delete(g); return n; })}>
                {open ? "\u2212" : "+"}</button>
            </div>
            {/* Rendered even when collapsed: hiding must not change what is selected. */}
            <div className="v3-filter-options" style={{ display: open ? "grid" : "none" }}>
              {its.map(([k, l, nc0]) => { const nc = nc0 && !present.has(k); return <label key={k} data-testid={`v3-filter-${k}`} style={{ display: "flex", gap: 8, alignItems: "center", paddingLeft: 22, color: nc ? C.muted : C.label, opacity: nc ? 0.55 : 1 }}>
                <FilterIcon filterKey={k} />
                <input type="checkbox" disabled={!!nc} checked={!nc && on.has(k)} onChange={() => set([k], !on.has(k))} /> {l}{nc ? <i style={{ fontSize: 11 }}> · not collected</i> : ""}</label>; })}
            </div>
          </div>);
        })}</div>
      </div>
      <div style={{ display: "flex", gap: 16, justifyContent: "flex-end", alignItems: "center", padding: "10px 16px", borderTop: `1px solid ${C.line}` }}>
        {allOff && <span data-testid="v3-filters-none-warning" style={{ marginRight: "auto", fontSize: 11.5, color: C.amber }}>
          No types selected — the grid will be empty</span>}
        <button className="v3-link" data-testid="v3-filters-cancel" onClick={onCancel}>Cancel</button>
        <button className="v3-btn v3-btn-blue" data-testid="v3-filters-apply" onClick={() => onApply(on)}>
          Apply filters{dirty ? " \u2022" : ""}</button>
      </div>
    </div>
  );
}

export const LIVE_FILTERS = LIVE;
