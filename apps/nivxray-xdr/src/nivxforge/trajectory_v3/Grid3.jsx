import React, { useEffect, useMemo, useRef, useState } from "react";
import { COL_W } from "./model";

const ROW_H = 24, HDR_H = 54, LABEL_W = 260;
export const C = { bg: "#1a1c20", panel: "#24272c", nav: "#2e3a4c", band: "#0f1012", line: "#3a3d42", text: "#e3e6ea", muted: "#9aa1ab",
  accent: "#6ea0ff", amber: "#e3a33a", red: "#e5534b", green: "#3DBA7A", sel: "rgba(110,160,255,.16)" };

export function Mark({ it, selected }) {
  const k = it.kind.glyph, s = 12;
  const shape = it.shape === "hexagon" ? <path d="M-6,0 L-3,-6 L3,-6 L6,0 L3,6 L-3,6 Z" fill={C.panel} stroke={C.red} strokeWidth={1.6} />
    : it.shape === "circle" ? <circle r={6} fill={C.panel} stroke={C.green} strokeWidth={1.6} />
      : <rect x={-s / 2} y={-s / 2} width={s} height={s} rx={1.5} fill={C.panel} stroke="#9AA8B8" strokeWidth={1.3} />;
  const inner = { create: <path d="M-3,0 H3 M0,-3 V3" stroke={C.text} strokeWidth={1.5} />,
    exec: <path d="M-2.5,-3.2 L3,0 L-2.5,3.2 Z" fill={C.text} />,
    net: <path d="M-3.5,-1.5 H3 M1.5,-3 L3,-1.5 L1.5,0 M3.5,1.5 H-3 M-1.5,0 L-3,1.5 L-1.5,3" stroke={C.text} strokeWidth={1} fill="none" />,
    dns: <circle r={2.4} fill="none" stroke={C.text} strokeWidth={1.2} />,
    reg: <path d="M-3,-3 h6 v6 h-6 z M-3,0 h6" stroke={C.text} strokeWidth={1} fill="none" /> }[k] || <circle r={1.8} fill={C.text} />;
  return (
    <g>
      {selected && <circle r={11} fill="rgba(63,169,245,.25)" stroke={C.accent} strokeWidth={1.5} />}
      {shape}{inner}
      {it.ev.e3_detection && <path d="M4,-11 L9,-3 L-1,-3 Z" fill={C.amber} stroke={C.bg} strokeWidth={0.6} />}
      {it.ev.e3_status_history && <circle cx={-7} cy={-7} r={2.6} fill={C.accent} />}
    </g>
  );
}

const ROW = { height: ROW_H, boxSizing: "border-box", padding: "0 10px", fontSize: 13, display: "flex", alignItems: "center",
  justifyContent: "flex-end", whiteSpace: "nowrap", overflow: "hidden" };
const ICON = { PE: "M2,1 h6 l3,3 v9 h-9 z M8,1 v3 h3", Network: "M6.5,1 a5.5,5.5 0 1,0 0.01,0 M1,6.5 h11 M6.5,1 c-3,3 -3,8 0,11 c3,-3 3,-8 0,-11",
  DNS: "M1,3 h11 v7 h-11 z M3,6.5 h7", Registry: "M1,1 h5 v5 h-5 z M7,1 h5 v5 h-5 z M1,7 h5 v5 h-5 z M7,7 h5 v5 h-5 z" };
function TypeIcon({ type }) {
  return (<svg width={13} height={13} viewBox="0 0 13 13" style={{ marginLeft: 8, flex: "none" }}>
    <path d={ICON[type] || ICON.PE} fill="none" stroke={C.muted} strokeWidth={1} /></svg>);
}

function lines(rows) {
  const out = [];
  for (const s of ["System", "Files & Network"]) {
    const rs = rows.filter((r) => r.section === s);
    if (rs.length) out.push({ hdr: s }, ...rs);
  }
  return out;
}

export default function Grid3({ model, items, sel, onSelect, onContext, hover, setHover, returnTo }) {
  const box = useRef(null);
  const [sl, setSl] = useState(0);
  const [vw, setVw] = useState(1000);
  const ls = useMemo(() => lines(model.rows), [model.rows]);
  const yOf = useMemo(() => new Map(ls.map((l, i) => [l.key || `h${i}`, i * ROW_H + ROW_H / 2])), [ls]);
  const ncol = model.items.length + 6;
  const W = ncol * COL_W, H = ls.length * ROW_H;
  useEffect(() => { if (box.current) setVw(box.current.clientWidth - LABEL_W); }, []);
  useEffect(() => {
    if (sel == null || !box.current || !returnTo.current) return;
    returnTo.current = false;
    box.current.scrollLeft = Math.max(0, sel.col * COL_W - (box.current.clientWidth - LABEL_W) / 2);
  });
  const c0 = Math.max(0, Math.floor(sl / COL_W) - 30), c1 = c0 + Math.ceil(vw / COL_W) + 60;
  const vis = items.filter((it) => it.col >= c0 && it.col <= c1);
  const selOff = sel && (sel.col * COL_W < sl || sel.col * COL_W > sl + vw);
  const lead = [];
  const last = new Map();
  for (const it of vis) {
    const k = `${it.target?.key}|${it.kind.glyph}`;
    const p = last.get(k);
    if (p != null && it.col - p <= 6) lead.push([p, it.col, it.target?.key]);
    last.set(k, it.col);
  }
  const x = (col) => col * COL_W + COL_W / 2;
  const hl = (key) => hover && (hover.a === key || hover.t === key);
  return (
    <div data-testid="v3-grid" ref={box} onScroll={(e) => setSl(e.currentTarget.scrollLeft)}
      style={{ overflow: "auto", height: 560, position: "relative", background: C.bg, borderTop: `1px solid ${C.line}` }}>
      <div style={{ display: "grid", gridTemplateColumns: `${LABEL_W}px ${W}px`, width: LABEL_W + W }}>
        <div style={{ position: "sticky", left: 0, top: 0, zIndex: 4, height: HDR_H, background: C.panel, color: C.muted, fontSize: 12,
          display: "flex", alignItems: "flex-end", justifyContent: "flex-end", padding: "0 10px 6px", borderRight: `1px solid ${C.line}` }}>
          <b style={{ color: C.text, fontSize: 17 }}>Timeline</b>
        </div>
        <svg data-testid="v3-time-header" width={W} height={HDR_H} style={{ position: "sticky", top: 0, zIndex: 3, background: C.panel }}>
          {vis.map((it, i) => {
            const prev = model.items[it.col - 1];
            const d = new Date(it.ev.timestamp_instant_ms), pd = prev && new Date(prev.ev.timestamp_instant_ms);
            const day = !pd || d.toISOString().slice(0, 10) !== pd.toISOString().slice(0, 10);
            const min = !pd || d.toISOString().slice(11, 16) !== pd.toISOString().slice(11, 16);
            return (<g key={i}>
              {day && <><line x1={it.col * COL_W} x2={it.col * COL_W} y1={0} y2={HDR_H} stroke={C.muted} />
                <text data-testid={`v3-day-${d.toISOString().slice(0, 10)}`} x={it.col * COL_W + 4} y={13} fill={C.text} fontSize={11} fontWeight={600}>
                  {d.toLocaleString("en-US", { month: "short", day: "numeric", timeZone: "UTC" })}</text></>}
              {min && <text x={x(it.col) + 3} y={HDR_H - 4} fill={C.muted} fontSize={9.5} transform={`rotate(-90 ${x(it.col) + 3} ${HDR_H - 4})`}>{d.toISOString().slice(11, 16)}</text>}
            </g>);
          })}
          {selOff && <text data-testid="v3-return-to-activity" x={sl + vw - 150} y={13} fill={C.accent} fontSize={11.5} style={{ cursor: "pointer" }}
            onClick={() => { returnTo.current = true; setSl((v) => v + 0.01); }}>↩ Return to activity</text>}
        </svg>
        <div style={{ position: "sticky", left: 0, zIndex: 2, background: C.panel, borderRight: `1px solid ${C.line}` }}>
          {ls.map((l, i) => l.hdr
            ? <div key={i} data-testid={`v3-section-${l.hdr.split(" ")[0].toLowerCase()}`} style={{ ...ROW, position: "sticky", top: HDR_H, zIndex: 3, background: C.band,
              color: C.text, fontSize: 12, fontWeight: 700, letterSpacing: ".06em", textTransform: "uppercase", justifyContent: "flex-start" }}>{l.hdr}</div>
            : <div key={l.key} data-testid={`v3-row-${i}`} data-row-type={l.type} title={l.path || l.label}
              style={{ ...ROW, color: l.detection ? "#FF8A84" : C.text, fontWeight: sel && (sel.target?.key === l.key || sel.actor?.key === l.key) ? 700 : 400,
                background: sel?.target?.key === l.key ? C.sel : sel?.actor?.key === l.key ? "rgba(110,160,255,.08)" : hl(l.key) ? "rgba(110,160,255,.12)" : "transparent" }}>
              <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{l.label}</span>
              <span style={{ color: C.muted, fontSize: 11, marginLeft: 6, flex: "none" }}>[{l.type}]</span>
              <TypeIcon type={l.type} /></div>)}
        </div>
        <svg data-testid="v3-grid-body" width={W} height={H} style={{ display: "block" }}>
          <defs><pattern id="v3h" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="1.4" height="6" fill="rgba(132,148,166,.25)" /></pattern></defs>
          {ls.map((l, i) => l.hdr && <rect key={i} y={i * ROW_H} width={W} height={ROW_H} fill={C.band} />)}
          {sel?.actor && sel.actor !== sel.target && yOf.has(sel.actor.key) && <rect y={yOf.get(sel.actor.key) - ROW_H / 2} width={W} height={ROW_H} fill="rgba(110,160,255,.07)" />}
          {sel?.target && yOf.has(sel.target.key) && <rect y={yOf.get(sel.target.key) - ROW_H / 2} width={W} height={ROW_H} fill={C.sel} />}
          {hover && hover.col !== sel?.col && <rect x={hover.col * COL_W} width={COL_W} height={H} fill="rgba(110,160,255,.06)" />}
          {sel && <rect data-testid="v3-selected-column" x={sel.col * COL_W} width={COL_W} height={H} fill="rgba(110,160,255,.12)" />}
          <rect x={model.items.length * COL_W} width={6 * COL_W} height={H} fill="url(#v3h)"><title>After the last loaded evidence / now</title></rect>
          {model.rows.flatMap((r) => [...r.instances.values()].filter((n) => n.to >= c0 && n.from <= c1).map((n) => (
            <line key={`${r.key}${n.iid}`} data-testid="v3-lifeline" x1={x(n.from)} x2={x(n.to) + COL_W / 2} y1={yOf.get(r.key)} y2={yOf.get(r.key)}
              stroke={sel?.target?.key === r.key ? C.accent : "#3A4B5E"} strokeWidth={2} />)))}
          {lead.map(([a, b, key], i) => <line key={`l${i}`} x1={x(a)} x2={x(b)} y1={yOf.get(key)} y2={yOf.get(key)} stroke={C.muted} strokeDasharray="1.5 3" />)}
          {vis.map((it) => it.actor && it.target && it.actor !== it.target && (
            <g key={`c${it.col}`} data-testid={`v3-connector-${it.col}`} data-causal={it.causal}>
              <line x1={x(it.col)} x2={x(it.col)} y1={yOf.get(it.actor.key)} y2={yOf.get(it.target.key)}
                stroke={sel?.col === it.col || (hover?.col === it.col) ? C.accent : "#5C7189"} strokeWidth={sel?.col === it.col ? 2 : 1.2}
                strokeDasharray={it.causal === "CORRELATED" ? "4 3" : it.causal === "UNRESOLVED" ? "1.5 3" : undefined} />
              <circle cx={x(it.col)} cy={yOf.get(it.actor.key)} r={2} fill="#5C7189" />
            </g>))}
          {vis.map((it) => it.target && (
            <g key={`m${it.col}`} data-testid={`v3-marker-${it.col}`} data-shape={it.shape} data-detection={it.ev.e3_detection ? "1" : "0"}
              transform={`translate(${x(it.col)},${yOf.get(it.target.key)})`} style={{ cursor: "pointer" }}
              onClick={() => onSelect(it)} onContextMenu={(e) => { e.preventDefault(); onContext(e, it); }}
              onMouseEnter={() => setHover({ a: it.actor?.key, t: it.target?.key, col: it.col })} onMouseLeave={() => setHover(null)}>
              <Mark it={it} selected={sel?.col === it.col} />
              <title>{`${it.kind.label} · ${it.target.label} · ${new Date(it.ev.timestamp_instant_ms).toISOString().slice(0, 19)}Z${it.ev.e3_detection ? ` · ${it.ev.e3_detection.name}` : ""}`}</title>
            </g>))}
        </svg>
      </div>
    </div>
  );
}
