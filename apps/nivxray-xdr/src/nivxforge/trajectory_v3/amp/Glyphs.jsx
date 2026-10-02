import React from "react";
import { LEGEND } from "./labels";
import { C } from "./theme";

const INNER = {
  create: <path d="M-3.2,0 H3.2 M0,-3.2 V3.2" stroke={C.text} strokeWidth={1.6} />,
  copy: <path d="M-3,2 L0,-2.5 L3,2" stroke={C.text} strokeWidth={1.5} fill="none" />,
  move: <path d="M-3.5,0 H3 M1,-2.2 L3.2,0 L1,2.2" stroke={C.text} strokeWidth={1.4} fill="none" />,
  exec: <path d="M-2.3,-3.2 L3.2,0 L-2.3,3.2 Z" fill="none" stroke={C.text} strokeWidth={1.3} />,
  exec_blocked: <g><path d="M-2.3,-3.2 L3.2,0 L-2.3,3.2 Z" fill="none" stroke={C.text} strokeWidth={1.3} />
    <path data-testid="v3-glyph-exec-blocked" d="M4,4.5 L6,1.1 L10,1.1 L12,4.5 L10,7.9 L6,7.9 Z" fill={C.red} stroke={C.page} strokeWidth={0.6} /></g>,
  open: <circle r={2.6} fill="none" stroke={C.text} strokeWidth={1.3} />,
  net: <path d="M-3.5,-1.4 H3 M1.4,-3 L3,-1.4 L1.4,0.2 M3.5,1.6 H-3 M-1.4,0 L-3,1.6 L-1.4,3.2" stroke={C.text} strokeWidth={1.1} fill="none" />,
  exploit: <path d="M0.8,-3.8 L-2.2,0.4 H0.2 L-0.8,3.8 L2.4,-0.6 H0 Z" fill={C.text} />,
  restore: <path d="M2.8,-1 A3,3 0 1,0 2,2.4 M2.8,-3 V-1 H0.8" stroke={C.text} strokeWidth={1.2} fill="none" />,
  scan: <path d="M-2.6,-2.6 L2.6,2.6 M2.6,-2.6 L-2.6,2.6" stroke={C.text} strokeWidth={1.5} />,
  usb: <path d="M0,3.5 V-3 M-2,-1.5 L0,-3.5 L2,-1.5 M-2.5,0 V1.2 H0 M2.5,-0.5 V1.8 H0" stroke={C.text} strokeWidth={1} fill="none" />,
  dns: <path d="M-3.2,-2 h6.4 v4 h-6.4 z M-1.6,0 h3.2" stroke={C.text} strokeWidth={1} fill="none" />,
  reg: <path d="M-3,-3 h2.6 v2.6 h-2.6 z M0.4,-3 h2.6 v2.6 h-2.6 z M-3,0.4 h2.6 v2.6 h-2.6 z M0.4,0.4 h2.6 v2.6 h-2.6 z" stroke={C.text} strokeWidth={0.9} fill="none" />,
  modify: <path d="M-3,3 L-2.4,0.8 L1.8,-3.4 L3.4,-1.8 L-0.8,2.4 Z" stroke={C.text} strokeWidth={1} fill="none" />,
  delete: <path d="M-3.2,0 H3.2" stroke={C.text} strokeWidth={1.8} />,
  other: <circle r={1.8} fill={C.text} />,
};

export function Shape({ shape, r = 7 }) {
  if (shape === "hexagon") return <path d={`M${-r},0 L${-r / 2},${-r} L${r / 2},${-r} L${r},0 L${r / 2},${r} L${-r / 2},${r} Z`} fill={C.panel} stroke={C.red} strokeWidth={1.7} />;
  if (shape === "circle") return <circle r={r} fill={C.panel} stroke={C.green} strokeWidth={1.7} />;
  return <rect x={-r} y={-r} width={2 * r} height={2 * r} rx={1.5} fill={C.panel} stroke={C.label} strokeWidth={1.3} />;
}

export function Mark({ it, selected, small }) {
  if (small) return <g>{selected && <circle r={7} fill="none" stroke={C.accent} strokeWidth={2} filter="url(#v3glow)" />}<Shape shape={it.shape} r={3.4} /></g>;
  return (
    <g>
      {selected && <circle r={12.5} fill="rgba(110,160,255,.18)" stroke={C.accent} strokeWidth={2} filter="url(#v3glow)" />}
      <Shape shape={it.shape} />
      {INNER[it.kind.glyph] || INNER.other}
      {it.flags?.warn && <path data-testid="v3-flag-warning" d="M5,-13 L10.5,-4 L-0.5,-4 Z" fill={C.amber} stroke={C.page} strokeWidth={0.8} />}
      {it.flags?.audit && <g data-testid="v3-flag-audit" transform="translate(8,-9)"><path d="M-4.5,0 Q0,-3.6 4.5,0 Q0,3.6 -4.5,0 Z" fill={C.panel} stroke={C.muted} strokeWidth={0.9} />
        <circle r={1.4} fill={C.muted} /></g>}
      {it.flags?.cmd && !it.flags?.warn && <path d="M-11,-11 h5 v4 h-5 z M-10,-9.5 l1,0.8 l-1,0.8" stroke={C.muted} strokeWidth={0.8} fill={C.panel} />}
      {it.ev?.e3_status_history && <circle cx={-8} cy={8} r={2.6} fill={C.accent} />}
      {["Rule-mapped", "Intel-derived"].includes(it.ev?.e3_attack?.type) && <g data-testid="dt-attack-badge" transform="translate(8.5,8.5)"><title>ATT&amp;CK mapped (rule metadata, not a verdict)</title>
        <path d="M0,-4 L4,0 L0,4 L-4,0 Z" fill={C.panel} stroke={C.accent} strokeWidth={1.1} /><circle r={1.2} fill={C.accent} /></g>}
    </g>
  );
}

export function GlyphIcon({ it, size = 20 }) {
  return <svg width={size} height={size} viewBox="-10 -10 20 20" style={{ flex: "none" }}><Mark it={it} /></svg>;
}

const LEG_GLYPHS = LEGEND;
const fake = (shape, glyph, flags = {}) => ({ shape, kind: { glyph }, flags });

export function Legend() {
  const cell = (it, label, k) => (
    <div key={k} style={{ display: "flex", alignItems: "center", gap: 8, padding: "2px 0" }}>
      <svg width={30} height={26} viewBox="-15 -13 30 26"><Mark it={it} /></svg><span>{label}</span></div>);
  return (
    <div data-testid="v3-legend" style={{ position: "absolute", right: 0, top: 30, zIndex: 45, width: 520, background: C.tip, border: `1px solid ${C.line}`, borderRadius: 8,
      padding: "12px 16px", fontSize: 12.5, color: C.text, boxShadow: "0 14px 40px rgba(0,0,0,.55)", display: "grid", gridTemplateColumns: "1fr 1fr", columnGap: 16 }}>
      <b style={{ gridColumn: "1 / -1", marginBottom: 4 }}>Disposition (outer shape)</b>
      {cell(fake("circle", "other"), "Benign (known-good evidence only)", "c")}{cell(fake("hexagon", "other"), "Malicious (evidence-backed only)", "h")}
      {cell(fake("square", "other"), "Unknown / no hit / no detection", "s")}
      <b style={{ gridColumn: "1 / -1", margin: "8px 0 4px" }}>Activity (inner symbol)</b>
      {LEG_GLYPHS.map(([g, l]) => cell(fake("square", g), l, g))}
      <b style={{ gridColumn: "1 / -1", margin: "8px 0 4px" }}>Flags</b>
      {cell(fake("square", "exec", { warn: true }), "Warning (detection)", "fw")}{cell(fake("square", "exec", { audit: true }), "Audit only (not collected)", "fa")}
      {cell(fake("square", "exec", { cmd: true }), "Command line", "fc")}
    </div>
  );
}
