import React, { useEffect, useRef, useState } from "react";
import { GlyphIcon } from "./Glyphs";
import { cap, fmt, narrative, short } from "./model";
import { ACT_H, C } from "./theme";

const SEV = { HIGH: C.red, CRITICAL: C.red, MEDIUM: C.amber, LOW: C.accent };

export function ActivityList({ items, sel, onSelect, hidden, height }) {
  const ref = useRef(null);
  const [st, setSt] = useState(0);
  const idx = sel ? items.findIndex((it) => it.col === sel.col) : -1;
  useEffect(() => {
    const b = ref.current;
    if (!b || idx < 0 || hidden) return;
    const y = idx * ACT_H;
    if (y < b.scrollTop || y > b.scrollTop + b.clientHeight - ACT_H) b.scrollTop = Math.max(0, y - b.clientHeight / 2);
  }, [idx, hidden]);
  const r0 = Math.max(0, Math.floor(st / ACT_H) - 5), r1 = r0 + Math.ceil(height / ACT_H) + 10;
  return (
    <div data-testid="v3-activity" ref={ref} className="v3-scroll" onScroll={(e) => setSt(e.currentTarget.scrollTop)}
      style={{ overflowY: "auto", height, display: hidden ? "none" : "block", position: "relative" }}>
      <div style={{ height: items.length * ACT_H, position: "relative" }}>
        {items.slice(r0, r1).map((it, i) => {
          const on = sel?.col === it.col, d = it.ev.e3_detection;
          return (
            <div key={it.col} data-testid={`v3-activity-row-${it.col}`} data-selected={on ? "1" : "0"} onClick={() => onSelect(it)}
              title={fmt(it.ev.timestamp_instant_ms)}
              style={{ position: "absolute", top: (r0 + i) * ACT_H, left: 0, right: 0, height: ACT_H, boxSizing: "border-box", display: "grid",
                gridTemplateColumns: "16px minmax(0,1fr) 24px minmax(0,1fr)", gap: 8, alignItems: "center", padding: "0 14px", fontSize: 15, cursor: "pointer",
                background: on ? C.sel : "transparent", borderBottom: `1px solid ${C.line}`, boxShadow: on ? `inset 3px 0 0 ${C.accent}` : "none", transition: "background-color .12s" }}>
              <span>{d && <svg width={13} height={12} viewBox="0 0 13 12"><path d="M6.5,0.5 L12.5,11.5 L0.5,11.5 Z" fill={SEV[d.severity] || C.amber} /></svg>}</span>
              <b style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: C.text }}>{it.actor?.label || "Unknown"}</b>
              <GlyphIcon it={it} />
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: C.label }}>{it.target?.label}</span>
            </div>);
        })}
      </div>
    </div>
  );
}

const BRK = /([\\/=,;&?:|. -])/;
export const wrapText = (s) => String(s ?? "").split(BRK).map((p, i) => (i % 2 ? <React.Fragment key={i}>{p}<wbr /></React.Fragment> : p));

function Tok({ t, onCtx, onCopy }) {
  if (typeof t === "string") return t;
  if (t.unk) return <span data-testid="v3-unknown-token" style={{ color: C.accent }}>{t.unk}</span>;
  if (t.det) return <b data-testid="v3-detection-name" style={{ color: SEV[t.sev] || C.amber }}>{t.det}</b>;
  if (t.hash) return <span data-testid="v3-hash-chip" title={t.hash} onClick={() => onCopy(t.hash)} style={{ fontFamily: "ui-monospace, Menlo, monospace", fontSize: 12,
    background: "rgba(255,255,255,.07)", border: `1px solid ${C.line}`, borderRadius: 3, padding: "0 5px", cursor: "copy" }}>{short(t.hash)} ⧉</span>;
  return <span data-testid="v3-token" title={t.full} onClick={(e) => onCtx(e)} onContextMenu={(e) => { e.preventDefault(); onCtx(e); }}
    style={{ borderBottom: `1px dotted ${C.muted}`, cursor: "pointer", overflowWrap: "anywhere" }}>{wrapText(t.tok)}</span>;
}

const ago = (a, b) => (a && b ? `${Math.round((Date.parse(b) - a) / 1000)} s` : "not collected");

export function ActivityDetails({ it, onBack, onCtx, onCopy, height }) {
  const e = it.ev, d = e.e3_detection;
  const ev = [["Observation", e.observation_id], ["Event", e.event_iid], ["Process instance", e.process_iid], ["Parent instance", e.parent_process_iid], ["PID", e.pid],
    ["Causal state", it.causal === "PROVEN" ? "PROVEN — creation record names the parent instance" : it.causal === "CORRELATED" ? "CORRELATED — parent image only" : "UNRESOLVED — actor not observed"],
    ["Observed", fmt(e.timestamp_instant_ms)], ["Ingested", e.e3_ingested_at || "not collected"], ["Lateness", ago(e.timestamp_instant_ms, e.e3_ingested_at)],
    ["Timestamp basis", e.timestamp_basis], ["Provenance", e.provenance ? `${e.provenance.source || ""} ${e.provenance.origin || ""} ${e.provenance.canonical_event_id || ""}` : "not collected"],
    ["Detection", d ? `${d.name} · ${d.engine} · ${d.at} · is_verdict=${String(d.is_verdict)}` : "none recorded"],
    ["What we cannot tell you", "File SHA-256 where the sensor did not hash; the true creator under PPID spoofing; process end time; any verdict without an evidence-backed assessment."]];
  return (
    <div data-testid="v3-activity-details" className="v3-scroll" style={{ padding: "12px 16px", height, boxSizing: "border-box", overflowY: "auto", overflowX: "hidden", fontSize: 14, lineHeight: 1.6, animation: "v3in .15s ease-out" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
        <button data-testid="v3-details-back" onClick={onBack} style={{ background: "none", border: 0, color: C.accent, fontSize: 22, cursor: "pointer", lineHeight: 1 }}>‹</button>
        <span data-testid="v3-details-time" title={`Local: ${fmt(e.timestamp_instant_ms, true)}`} style={{ color: C.muted, borderBottom: `1px dashed ${C.muted}` }}>{fmt(e.timestamp_instant_ms)}</span>
        <span style={{ flex: 1 }} />
        {d && <span data-testid="v3-severity" style={{ border: `1px solid ${SEV[d.severity] || C.amber}`, color: SEV[d.severity] || C.amber, borderRadius: 3, padding: "0 8px", fontSize: 12 }}>{cap(d.severity)}</span>}
      </div>
      <div data-testid="v3-narrative">{narrative(it).map((ln, i) => <p key={i} style={{ margin: "0 0 8px" }}>{ln.map((t, j) => <Tok key={j} t={t} onCtx={onCtx} onCopy={onCopy} />)}</p>)}</div>
      <details data-testid="v3-evidence" style={{ marginTop: 12, color: C.muted, fontSize: 12.5 }}>
        <summary style={{ cursor: "pointer", color: C.text }}>Evidence &amp; provenance</summary>
        {ev.map(([k, v]) => <div key={k} style={{ display: "grid", gridTemplateColumns: "112px minmax(0,1fr)", gap: 8, padding: "2px 0" }}><span>{k}</span>
          <span style={{ color: C.text, overflowWrap: "anywhere" }}>{wrapText(v ?? "not collected")}</span></div>)}
      </details>
    </div>
  );
}
