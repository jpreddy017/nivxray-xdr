import React, { useEffect, useRef, useState } from "react";
import { C, DAY } from "./theme";

const MON = (t) => new Date(t).toLocaleString("en-US", { month: "short", timeZone: "UTC" });
const hhmm = (ms) => new Date(ms).toISOString().slice(11, 16);

function DayTip({ t, dets, onJump, edge }) {
  return (
    <div data-testid="v3-day-tooltip" style={{ position: "absolute", top: 64, ...(edge ? { right: 0 } : { left: "50%", transform: "translateX(-50%)" }), zIndex: 30, background: C.tip,
      border: `1px solid ${C.line}`, borderRadius: 8, padding: "10px 14px", minWidth: 170, boxShadow: "0 10px 30px rgba(0,0,0,.45)", textAlign: "left",
      fontSize: 13, color: C.text, animation: "v3in .12s ease-out", whiteSpace: "nowrap" }}>
      <div style={{ fontWeight: 600, marginBottom: 6 }}>{new Date(t).toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" })}</div>
      {dets.length ? <>
        <div style={{ color: C.muted, marginBottom: 4 }}><span style={{ color: C.red }}>●</span> Compromise events</div>
        {dets.map((d, i) => <div key={i} style={{ display: "flex", gap: 14 }}><span>{i + 1}</span>
          <button className="v3-link" data-testid={`v3-tip-jump-${i}`} onClick={(e) => { e.stopPropagation(); onJump(d); }}>{hhmm(d.ms)}</button>
          <span style={{ color: C.muted, fontSize: 11.5 }}>{d.name}</span></div>)}
      </> : <div style={{ color: C.muted }}>No compromise events</div>}
    </div>
  );
}

function HourStrip({ day0, view, now, dets, onView, hours }) {
  const ref = useRef(null);
  const [tmp, setTmp] = useState(null);
  const frac = (x) => Math.min(1, Math.max(0, (x - ref.current.getBoundingClientRect().left) / ref.current.clientWidth));
  const down = (e) => {
    const f0 = frac(e.clientX), ms0 = day0 + f0 * DAY, inside = ms0 >= view.t0 && ms0 <= view.t1;
    let last = null;
    const mv = (ev) => {
      const ms = day0 + frac(ev.clientX) * DAY;
      last = inside ? { t0: view.t0 + (ms - ms0), t1: view.t1 + (ms - ms0) } : { t0: Math.min(ms0, ms), t1: Math.max(ms0, ms) };
      setTmp(last);
    };
    const up = () => {
      window.removeEventListener("mousemove", mv); window.removeEventListener("mouseup", up); setTmp(null);
      const h = Math.floor(f0 * 24) * 3_600_000 + day0;
      const r = last && last.t1 - last.t0 > 60_000 ? last : inside ? null : { t0: h, t1: h + 3_600_000 };
      if (r) onView({ t0: Math.round(r.t0), t1: Math.round(Math.min(r.t1, now)) });
    };
    window.addEventListener("mousemove", mv); window.addEventListener("mouseup", up);
  };
  const v = tmp || view, pct = (ms) => `${Math.min(100, Math.max(0, ((ms - day0) / DAY) * 100))}%`;
  return (
    <div style={{ position: "relative", height: 44, marginTop: 6 }}>
      <div ref={ref} data-testid="v3-hour-strip" onMouseDown={down} style={{ position: "relative", height: 24, background: C.inset, borderRadius: 4, cursor: "crosshair", userSelect: "none" }}>
        {Array.from({ length: 25 }, (_, h) => <span key={h} style={{ position: "absolute", left: `${(h / 24) * 100}%`, top: 0, bottom: 0, borderLeft: h % 24 ? `1px solid rgba(255,255,255,.06)` : "none" }}>
          <span style={{ position: "absolute", left: 3, top: 5, fontSize: 10.5, color: C.muted }}>{h === 0 ? "0:00" : h === 24 ? "" : h}</span></span>)}
        {(hours || []).map((n, h) => (n === 0 && day0 + (h + 1) * 3_600_000 <= now ? <div key={`nd${h}`} data-testid="v3-nodata-hour"
          title="No observation retained for this hour (not proof the sensor was offline)" style={{ position: "absolute", left: `${(h / 24) * 100}%`, width: `${100 / 24}%`,
          top: 0, bottom: 0, background: `repeating-linear-gradient(135deg, ${C.hatch} 0 2px, transparent 2px 7px)` }} /> : null))}
        {now < day0 + DAY && <div title="Not yet occurred" style={{ position: "absolute", left: pct(now), right: 0, top: 0, bottom: 0, borderRadius: "0 4px 4px 0",
          background: `repeating-linear-gradient(135deg, ${C.hatch} 0 2px, transparent 2px 7px)` }} />}
        {dets.filter((d) => d.ms >= day0 && d.ms < day0 + DAY).map((d, i) => <span key={i} data-testid="v3-hour-det" title={`${d.name} ${hhmm(d.ms)}`}
          style={{ position: "absolute", left: pct(d.ms), top: -3, width: 3, height: 30, background: C.red, borderRadius: 2 }} />)}
        <div data-testid="v3-hour-bracket" style={{ position: "absolute", left: pct(Math.max(v.t0, day0)), width: `calc(${pct(Math.min(v.t1, day0 + DAY))} - ${pct(Math.max(v.t0, day0))})`,
          minWidth: 4, top: -2, bottom: -2, border: `2px solid ${C.accent}`, borderRadius: 4, background: "rgba(110,160,255,.12)", cursor: "grab" }} />
      </div>
      <div style={{ fontSize: 10.5, color: C.muted, marginTop: 3 }}>{new Date(day0).toLocaleString("en-US", { month: "short", day: "numeric", timeZone: "UTC" })}</div>
    </div>
  );
}

export default function Navigator({ days, dets, view, now, onView, onJump, fetchHours }) {
  const [open, setOpen] = useState(true);
  const [hours, setHours] = useState(null);
  const [tip, setTip] = useState(null);
  const today = Math.floor(now / DAY) * DAY;
  const cells = Array.from({ length: 30 }, (_, i) => today - (29 - i) * DAY);
  const tot = new Map((days || []).map((d) => [Date.parse(`${d.day}T00:00:00Z`), d.total]));
  const max = Math.max(1, ...cells.map((t) => tot.get(t) || 0));
  const day0 = Math.floor(Math.min(view.t1 - 1, now) / DAY) * DAY;
  useEffect(() => {
    let live = true;
    setHours(null);
    fetchHours?.(new Date(day0).toISOString().slice(0, 10)).then((h) => { if (live) setHours(h); }).catch(() => {});
    return () => { live = false; };
  }, [day0, fetchHours]);
  const pts = cells.map((t, i) => `${i * 48 + 24},${30 - ((tot.get(t) || 0) / max) * 26}`).join(" ");
  return (
    <div data-testid="v3-navigator" style={{ background: C.nav, padding: "10px 16px 6px 8px", display: "flex", gap: 8, borderRadius: "10px 10px 0 0" }}>
      <button data-testid="v3-nav-collapse" onClick={() => setOpen(!open)} style={{ background: "none", border: 0, color: C.text, cursor: "pointer", alignSelf: "flex-start",
        fontSize: 15, width: 22, transform: open ? "none" : "rotate(-90deg)", transition: "transform .15s" }}>∨</button>
      {open ? <div style={{ flex: 1, minWidth: 0 }}>
        <svg data-testid="v3-sparkline" viewBox={`0 0 ${30 * 48} 32`} preserveAspectRatio="none" style={{ width: "100%", height: 22, display: "block" }}>
          <polyline points={pts} fill="none" stroke={C.accent} strokeWidth={1.4} vectorEffect="non-scaling-stroke" /></svg>
        <div style={{ display: "flex" }}>
          {cells.map((t) => {
            const dd = dets.filter((d) => d.ms >= t && d.ms < t + DAY), n = tot.get(t) || 0, cur = t === day0, d = new Date(t);
            return (
              <div key={t} data-testid={`v3-day-cell-${d.toISOString().slice(0, 10)}`} onMouseEnter={() => setTip(t)} onMouseLeave={() => setTip(null)}
                onClick={() => onView({ t0: t, t1: Math.min(t + DAY, now) })}
                style={{ flex: "1 1 48px", minWidth: 30, position: "relative", cursor: "pointer", textAlign: "center", borderRadius: 4, padding: "3px 0 2px",
                  background: cur ? "rgba(110,160,255,.22)" : tip === t ? "rgba(255,255,255,.06)" : "transparent", transition: "background-color .12s" }}>
                <div style={{ height: 14, display: "flex", alignItems: "center", justifyContent: "center", gap: 3 }}>
                  {dd.length > 0 && <span style={{ width: 10, height: 10, borderRadius: 10, background: C.red }} />}
                  {n > 0 && <span style={{ width: 5, height: 5, borderRadius: 5, background: C.accent }} />}</div>
                <div style={{ fontSize: 12, color: cur ? C.text : C.label, fontWeight: cur ? 700 : 400 }}>{d.getUTCDate()}</div>
                <div style={{ fontSize: 10, color: C.muted, height: 12 }}>{d.getUTCDate() === 1 || t === cells[0] ? MON(t) : ""}</div>
                {tip === t && <DayTip t={t} dets={dd} onJump={onJump} edge={t > cells[24]} />}
              </div>);
          })}
        </div>
        <HourStrip day0={day0} view={view} now={now} dets={dets} onView={onView} hours={hours} />
      </div> : <div style={{ color: C.muted, fontSize: 12, paddingTop: 2 }}>Navigator</div>}
    </div>
  );
}
