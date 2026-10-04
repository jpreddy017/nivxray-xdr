import React, { useMemo, useRef, useState } from "react";
import { PAL, fmtInstant, fmtShort, xOf } from "./model";
import { useWidth } from "./hooks";
import { ui } from "./ui";

const DAY = 86_400_000;
const H30 = 58, H24 = 40;

function useSelect(svgRef, toTime, onRange, onClick) {
  const [sel, setSel] = useState(null);
  const pos = (e) => e.clientX - svgRef.current.getBoundingClientRect().left;
  const down = (e) => {
    if (e.button !== 0) return;
    const x0 = pos(e);
    const move = (ev) => setSel([x0, pos(ev)]);
    const up = (ev) => {
      window.removeEventListener("mousemove", move); window.removeEventListener("mouseup", up);
      const x1 = pos(ev); setSel(null);
      if (Math.abs(x1 - x0) > 4) onRange(toTime(Math.min(x0, x1)), toTime(Math.max(x0, x1)));
      else onClick(toTime(x1));
    };
    window.addEventListener("mousemove", move); window.addEventListener("mouseup", up);
  };
  return [sel, down];
}

function Gaps({ intervals, a, b, w, h, prefix }) {
  return (intervals || []).map((g, k) => {
    const x1 = xOf(Math.max(g.from_ms, a), a, b, w), x2 = xOf(Math.min(g.to_ms, b), a, b, w);
    if (x2 - x1 < 1) return null;
    return (
      <rect key={k} data-testid={`${prefix}-gap-${k}`} data-state={g.state} x={x1} y={0} width={x2 - x1} height={h} fill="url(#nav-hatch)">
        <title>{g.state === "NO_TELEMETRY_RECEIVED" ? "No telemetry received (not 'no activity')" : g.state.replace(/_/g, " ").toLowerCase()}</title>
      </rect>
    );
  });
}

export default function Navigator({ density, cov30, hourly, view, refMs, tzMode, onView }) {
  const [wrap, W] = useWidth(1100);
  const s30 = useRef(null), s24 = useRef(null);
  const days = density?.days || [];
  const a = days.length ? Date.parse(`${days[0].day}T00:00:00Z`) : refMs - 29 * DAY;
  const b = a + Math.max(1, days.length) * DAY;
  const day0 = Math.floor((view.t1 - 1) / DAY) * DAY;
  const max = Math.max(1, ...days.map((d) => d.count));
  const eoi = useMemo(() => {
    const m = new Map();
    for (const e of density?.events_of_interest || []) {
      const k = Math.floor((e.t_ms - a) / DAY);
      const c = m.get(k) || { n: 0, det: false };
      c.n += 1; c.det = c.det || e.detection; m.set(k, c);
    }
    return m;
  }, [density, a]);
  const span = view.t1 - view.t0;
  const set = (t0, t1) => onView({ t0, t1: Math.max(t1, t0 + 5000) });
  const [sel30, down30] = useSelect(s30, (x) => a + (x / W) * (b - a), set, (t) => { const d = Math.floor(t / DAY) * DAY; set(d, d + DAY); });
  const [sel24, down24] = useSelect(s24, (x) => day0 + (x / W) * DAY, set, () => {});
  const hmax = Math.max(1, ...(hourly || []));
  const dw = W / Math.max(1, days.length);

  return (
    <section data-testid="trajectory-navigator" style={{ ...ui.panel, padding: "10px 14px 8px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, fontSize: 12 }}>
        <strong style={{ letterSpacing: 1, fontSize: 11, color: PAL.muted }}>30-DAY ACTIVITY</strong>
        <span data-testid="nav-window-label" style={{ color: PAL.text, marginLeft: 8 }}>{fmtInstant(view.t0, tzMode)} → {fmtInstant(view.t1, tzMode)}</span>
        <span style={{ flex: 1 }} />
        <button data-testid="nav-prev" style={ui.btn} onClick={() => set(view.t0 - span, view.t1 - span)}>‹ Prev</button>
        <button data-testid="nav-now" style={ui.btn} onClick={() => set(refMs - span, refMs)}>Now</button>
        <button data-testid="nav-next" style={ui.btn} onClick={() => set(Math.min(view.t0 + span, refMs - span), Math.min(view.t1 + span, refMs))}>Next ›</button>
        <button data-testid="nav-24h" style={ui.btn} onClick={() => set(refMs - DAY, refMs)}>Last 24h</button>
        <button data-testid="nav-30d" style={ui.btn} onClick={() => set(a, Math.min(b, refMs))}>30 days</button>
      </div>
      <div ref={wrap}>
        <svg ref={s30} width={W} height={H30} onMouseDown={down30} style={{ display: "block", cursor: "crosshair" }}>
          <defs><pattern id="nav-hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <rect width="6" height="6" fill="rgba(58,46,26,.18)" /><rect width="1.5" height="6" fill="rgba(183,138,58,.22)" /></pattern></defs>
          <Gaps intervals={cov30?.intervals} a={a} b={b} w={W} h={H30} prefix="nav30" />
          {days.map((d, i) => {
            const h = d.count ? 4 + (Math.log1p(d.count) / Math.log1p(max)) * (H30 - 22) : 0;
            return (
              <g key={d.day} data-testid={`nav-day-${d.day}`} data-count={d.count}>
                <rect x={i * dw} y={0} width={dw} height={H30} fill="transparent" stroke={PAL.grid} strokeWidth={0.5}><title>{d.day} · {d.count} events (UTC day)</title></rect>
                {h > 0 && <rect x={i * dw + 2} y={H30 - 12 - h} width={Math.max(1, dw - 4)} height={h} fill="#2C5E6B" />}
                {i % 5 === 0 && <text x={i * dw + 3} y={H30 - 2} fontSize={9} fill={PAL.faint}>{d.day.slice(5)}</text>}
              </g>
            );
          })}
          {[...eoi.entries()].map(([k, c]) => (
            <circle key={k} data-testid={`nav-eoi-${k}`} data-count={c.n} cx={k * dw + dw / 2} cy={9} r={2.5 + 1.6 * Math.sqrt(c.n)}
              fill={c.det ? PAL.amber : "none"} stroke={c.det ? PAL.bg : PAL.neutral} strokeWidth={1}>
              <title>{c.n} event(s) of interest{c.det ? " incl. detections" : " (sensor severity HIGH, no detection)"}</title></circle>
          ))}
          <rect data-testid="nav-view-bracket" x={xOf(view.t0, a, b, W)} y={1} height={H30 - 2}
            width={Math.max(2, xOf(view.t1, a, b, W) - xOf(view.t0, a, b, W))} fill="rgba(76,195,217,.12)" stroke={PAL.accent} />
          {sel30 && <rect x={Math.min(...sel30)} width={Math.abs(sel30[1] - sel30[0])} y={0} height={H30} fill="rgba(76,195,217,.25)" />}
        </svg>
        <div style={{ fontSize: 11, color: PAL.muted, margin: "6px 0 3px" }}>24 HOURS · {new Date(day0).toISOString().slice(0, 10)} (UTC day) · drag to select a range</div>
        <svg ref={s24} data-testid="nav-24h-strip" width={W} height={H24} onMouseDown={down24} style={{ display: "block", cursor: "crosshair" }}>
          <Gaps intervals={cov30?.intervals} a={day0} b={day0 + DAY} w={W} h={H24} prefix="nav24" />
          {(hourly || []).map((n, h) => (
            <g key={h} data-testid={`nav-hour-${h}`} data-count={n}>
              <rect x={(h * W) / 24} y={0} width={W / 24} height={H24} fill="transparent" stroke={PAL.grid} strokeWidth={0.5} />
              {n > 0 && <rect x={(h * W) / 24 + 2} y={H24 - 12 - (n / hmax) * (H24 - 16)} width={W / 24 - 4} height={(n / hmax) * (H24 - 16)} fill="#2C5E6B" />}
              {h % 3 === 0 && <text x={(h * W) / 24 + 3} y={H24 - 2} fontSize={9} fill={PAL.faint}>{fmtShort(day0 + h * 3_600_000, tzMode)}</text>}
            </g>
          ))}
          <rect x={xOf(Math.max(view.t0, day0), day0, day0 + DAY, W)} y={1} height={H24 - 2}
            width={Math.max(2, xOf(Math.min(view.t1, day0 + DAY), day0, day0 + DAY, W) - xOf(Math.max(view.t0, day0), day0, day0 + DAY, W))}
            fill="rgba(76,195,217,.12)" stroke={PAL.accent} />
          {sel24 && <rect x={Math.min(...sel24)} width={Math.abs(sel24[1] - sel24[0])} y={0} height={H24} fill="rgba(76,195,217,.25)" />}
        </svg>
      </div>
    </section>
  );
}
