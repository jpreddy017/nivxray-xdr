import React, { useEffect, useRef, useState } from "react";
import { C, Mark } from "./Grid3";
import { FILTER_GROUPS, fmt, narrative, short } from "./model";

const Tok = ({ t, onCtx }) => {
  if (typeof t === "string") return t;
  if (t.unk) return <span style={{ color: "#C9A2FF" }}>{t.unk}</span>;
  if (t.det) return <b data-testid="v3-detection-name" style={{ color: t.sev === "HIGH" || t.sev === "CRITICAL" ? C.red : C.amber }}>{t.det}</b>;
  return <span title={t.full} onContextMenu={(e) => { e.preventDefault(); onCtx(e, t.full); }}
    style={{ borderBottom: `1px dotted ${C.muted}`, cursor: "help" }}>{t.tok}</span>;
};

export function ActivityList({ items, sel, onSelect }) {
  const ref = useRef(null);
  useEffect(() => { ref.current?.querySelector('[data-selected="1"]')?.scrollIntoView({ block: "nearest" }); }, [sel]);
  return (
    <div data-testid="v3-activity" ref={ref} style={{ overflowY: "auto", height: 560 }}>
      {items.map((it) => (
        <div key={it.col} data-testid={`v3-activity-row-${it.col}`} data-selected={sel?.col === it.col ? "1" : "0"} onClick={() => onSelect(it)}
          style={{ display: "grid", gridTemplateColumns: "58px 14px minmax(0,1fr) 22px minmax(0,1fr)", gap: 6, alignItems: "center", padding: "9px 10px", fontSize: 13,
            cursor: "pointer", background: sel?.col === it.col ? C.sel : "transparent", borderBottom: `1px solid ${C.band}`,
            boxShadow: sel?.col === it.col ? `inset 3px 0 0 ${C.accent}` : "none" }}>
          <span style={{ color: C.muted, fontSize: 11.5, fontVariantNumeric: "tabular-nums" }}>{new Date(it.ev.timestamp_instant_ms).toISOString().slice(11, 19)}</span>
          <span style={{ color: C.red }}>{it.ev.e3_detection ? "▲" : ""}</span>
          <b style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{it.actor?.label || "Unknown"}</b>
          <svg width={20} height={18} viewBox="-10 -9 20 18"><Mark it={it} /></svg>
          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{it.target?.label}</span>
        </div>))}
    </div>
  );
}

export function ActivityDetails({ it, onBack, onCtx }) {
  const e = it.ev, d = e.e3_detection;
  return (
    <div data-testid="v3-activity-details" style={{ padding: 12, height: 536, overflowY: "auto", fontSize: 13, lineHeight: 1.55 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <button data-testid="v3-details-back" onClick={onBack} style={{ background: "none", border: 0, color: C.accent, fontSize: 18, cursor: "pointer" }}>‹</button>
        <span data-testid="v3-details-time" title={`Local: ${fmt(e.timestamp_instant_ms, true)}`} style={{ borderBottom: `1px dotted ${C.muted}` }}>{fmt(e.timestamp_instant_ms)}</span>
        <span style={{ flex: 1 }} />
        {d && <span data-testid="v3-severity" style={{ border: `1px solid ${C.amber}`, color: C.amber, borderRadius: 3, padding: "0 6px", fontSize: 11 }}>{d.severity}</span>}
      </div>
      <div data-testid="v3-narrative">{narrative(it).map((ln, i) => <p key={i} style={{ margin: "0 0 6px" }}>{ln.map((t, j) => <Tok key={j} t={t} onCtx={onCtx} />)}</p>)}</div>
      <details data-testid="v3-evidence" style={{ marginTop: 10, color: C.muted, fontSize: 12 }}>
        <summary style={{ cursor: "pointer", color: C.text }}>Evidence &amp; provenance</summary>
        {[["Observation", e.observation_id], ["Event", e.event_iid], ["Process instance", e.process_iid], ["PID", e.pid],
          ["Causal state", it.causal === "PROVEN" ? "PROVEN (creation record names the parent instance)" : it.causal === "CORRELATED" ? "CORRELATED (parent image only, no instance id)" : "PARENT NOT OBSERVED"],
          ["Observed (UTC)", fmt(e.timestamp_instant_ms)], ["Observed (local)", fmt(e.timestamp_instant_ms, true)], ["Timestamp basis", e.timestamp_basis],
          ["Hash", e.event_content_digest ? `content digest ${short(e.event_content_digest)} (not a file SHA-256)` : "not collected"],
          ["Detection", d ? `${d.name} · ${d.engine} · ${d.at} · is_verdict=${d.is_verdict}` : "none recorded"],
          ["What we cannot tell you", "File SHA-256 on file events (S-3); true creator for spoofing (S-1); process end (S-7)."]]
          .map(([k, v]) => <div key={k} style={{ display: "grid", gridTemplateColumns: "120px 1fr", gap: 6 }}><span>{k}</span><span style={{ color: C.text, wordBreak: "break-all" }}>{v ?? "not collected"}</span></div>)}
      </details>
    </div>
  );
}

export function FiltersPanel({ applied, onApply, onCancel }) {
  const [on, setOn] = useState(new Set(applied));
  const flip = (k) => setOn((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; });
  return (
    <div data-testid="v3-filters-panel" style={{ position: "absolute", right: 0, top: 36, zIndex: 20, width: 300, maxHeight: 460, overflowY: "auto",
      background: C.panel, border: `1px solid ${C.line}`, borderRadius: 6, padding: 10, fontSize: 12, boxShadow: "0 12px 30px rgba(0,0,0,.5)" }}>
      {FILTER_GROUPS.map(([g, its]) => {
        const live = its.filter((x) => !x[2]).map((x) => x[0]);
        const all = live.every((k) => on.has(k));
        return (<div key={g} style={{ marginBottom: 8 }}>
          <label style={{ fontWeight: 700, display: "block" }}><input type="checkbox" checked={all} onChange={() => setOn((s) => { const n = new Set(s); live.forEach((k) => (all ? n.delete(k) : n.add(k))); return n; })} /> {g}</label>
          {its.map(([k, l, nc]) => <label key={k} data-testid={`v3-filter-${k}`} style={{ display: "block", paddingLeft: 18, color: nc ? "#5A6878" : C.text }}>
            <input type="checkbox" disabled={!!nc} checked={!nc && on.has(k)} onChange={() => flip(k)} /> {l}{nc ? " · not collected" : ""}</label>)}
        </div>);
      })}
      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", position: "sticky", bottom: -10, background: C.panel, padding: "6px 0" }}>
        <button data-testid="v3-filters-cancel" onClick={onCancel}>Cancel</button>
        <button data-testid="v3-filters-apply" onClick={() => onApply(on)}>Apply filters</button>
      </div>
    </div>
  );
}
