import React, { useState } from "react";
import { FILTER_GROUPS } from "./model";
import { C } from "./theme";

const LIVE = FILTER_GROUPS.flatMap(([, its]) => its.filter((x) => !x[2]).map((x) => x[0]));

export function FiltersPanel({ applied, onApply, onCancel, present = new Set() }) {
  const [on, setOn] = useState(new Set(applied));
  const set = (keys, v) => setOn((s) => { const n = new Set(s); keys.forEach((k) => (v ? n.add(k) : n.delete(k))); return n; });
  const allOn = LIVE.every((k) => on.has(k));
  return (
    <div data-testid="v3-filters-panel" style={{ position: "absolute", right: 0, top: 46, zIndex: 40, width: 330, background: C.tip, border: `1px solid ${C.line}`,
      borderRadius: 8, boxShadow: "0 14px 40px rgba(0,0,0,.55)", fontSize: 13.5, color: C.text, animation: "v3in .12s ease-out" }}>
      <div className="v3-scroll" style={{ maxHeight: 520, overflowY: "auto", padding: "12px 16px" }}>
        <label style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: 700, marginBottom: 8 }}>
          <input data-testid="v3-filter-all-types" type="checkbox" checked={allOn} onChange={() => set(LIVE, !allOn)} /> All types</label>
        {FILTER_GROUPS.map(([g, its]) => {
          const live = its.filter((x) => !x[2]).map((x) => x[0]), all = live.every((k) => on.has(k));
          return (<div key={g} style={{ marginBottom: 10, paddingLeft: 10 }}>
            <label style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: 600 }}>
              <input type="checkbox" data-testid={`v3-filter-group-${g.split(" ")[1].replace(/[^A-Za-z]/g, "")}`} checked={all} onChange={() => set(live, !all)} /> {g}</label>
            {its.map(([k, l, nc0]) => { const nc = nc0 && !present.has(k); return <label key={k} data-testid={`v3-filter-${k}`} style={{ display: "flex", gap: 8, alignItems: "center", paddingLeft: 22, color: nc ? C.muted : C.label, opacity: nc ? 0.55 : 1 }}>
              <span style={{ color: C.muted }}>•</span>
              <input type="checkbox" disabled={!!nc} checked={!nc && on.has(k)} onChange={() => set([k], !on.has(k))} /> {l}{nc ? <i style={{ fontSize: 11 }}> · not collected</i> : ""}</label>; })}
          </div>);
        })}
      </div>
      <div style={{ display: "flex", gap: 16, justifyContent: "flex-end", alignItems: "center", padding: "10px 16px", borderTop: `1px solid ${C.line}` }}>
        <button className="v3-link" data-testid="v3-filters-cancel" onClick={onCancel}>Cancel</button>
        <button className="v3-btn v3-btn-blue" data-testid="v3-filters-apply" onClick={() => onApply(on)}>Apply filters</button>
      </div>
    </div>
  );
}

export const LIVE_FILTERS = LIVE;
