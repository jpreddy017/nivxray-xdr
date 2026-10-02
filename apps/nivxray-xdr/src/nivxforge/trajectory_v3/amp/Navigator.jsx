import React, { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { C, DAY } from "./theme";

const H = 3_600_000;
const MON = (t) => new Date(t).toLocaleString("en-US", { month: "short", timeZone: "UTC" });
const hhmm = (ms) => new Date(ms).toISOString().slice(11, 16);
const dateL = (t) => new Date(t).toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" });
const SEVR = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
export const topDetection = (dd) => [...dd].sort((a, b) => (SEVR[b.severity] || 0) - (SEVR[a.severity] || 0) || a.ms - b.ms)[0];
const Dot = ({ n, testid, onEnter, onLeave, onClick, style, on, at }) => (
  <span data-testid={testid} data-selected={on ? "1" : "0"} data-at={at} className="v3-nav-cell" onMouseEnter={onEnter} onMouseLeave={onLeave} onMouseDown={(e) => e.stopPropagation()} onClick={onClick}
    style={{ width: 10, height: 10, borderRadius: 10, background: C.red, display: "inline-flex", alignItems: "center", justifyContent: "center",
      boxShadow: on ? `0 0 0 2px ${C.page}, 0 0 0 4px ${C.text}, 0 0 10px 3px ${C.red}` : "none", zIndex: on ? 2 : 1, ...style }}>
    {n > 1 && <span style={{ position: "absolute", top: -9, left: 7, fontSize: 9.5, color: C.text, background: C.tip, borderRadius: 6, padding: "0 3px" }}>{n}</span>}</span>);

// One tooltip/popover for BOTH bars: hover = preview (250ms bridge), click = pinned (outside/Esc/link/another day closes), portal + edge flip.
function Tip({ tip, onJump, onMore, onClose, keep, leave }) {
  const ref = useRef(null);
  useEffect(() => {
    if (!tip?.pinned) return undefined;
    const key = (e) => {
      if (e.key === "Escape") onClose();
      if (e.key === "Tab" && ref.current) {
        const f = [...ref.current.querySelectorAll("button")]; if (!f.length) return;
        const i = f.indexOf(document.activeElement);
        if (e.shiftKey && i <= 0) { e.preventDefault(); f[f.length - 1].focus(); } else if (!e.shiftKey && i === f.length - 1) { e.preventDefault(); f[0].focus(); }
      }
    };
    const out = (e) => { if (ref.current && !ref.current.contains(e.target) && !e.target.closest?.("[data-nav-anchor]")) onClose(); };
    window.addEventListener("keydown", key); document.addEventListener("mousedown", out);
    setTimeout(() => ref.current?.querySelector("button")?.focus(), 0);
    return () => { window.removeEventListener("keydown", key); document.removeEventListener("mousedown", out); };
  }, [tip, onClose]);
  if (!tip) return null;
  const W = 300, x = Math.max(8, Math.min(tip.x - W / 2, window.innerWidth - W - 8)), below = tip.y + 220 < window.innerHeight;
  const vis = tip.dets.slice(0, 5);
  return createPortal(
    <div ref={ref} data-testid="v3-day-tooltip" data-pinned={tip.pinned ? "1" : "0"} role={tip.pinned ? "dialog" : "tooltip"} onMouseEnter={keep} onMouseLeave={leave}
      className="v3amp" style={{ position: "fixed", left: x, ...(below ? { top: tip.y + 8 } : { bottom: window.innerHeight - tip.top + 8 }), width: W, zIndex: 1000, background: C.tip,
        border: `1px solid ${tip.pinned ? C.accent : C.line}`, borderRadius: 8, padding: "10px 14px", boxShadow: "0 10px 30px rgba(0,0,0,.45)", fontSize: 13, color: C.text, animation: "v3in .12s ease-out" }}>
      <div style={{ fontWeight: 600, marginBottom: 6 }}>{tip.title}{tip.count != null && <span style={{ color: C.muted, fontWeight: 400 }}> · {tip.count} activity</span>}</div>
      {tip.dets.length ? <>
        <div style={{ color: C.muted, marginBottom: 4 }}><span style={{ color: C.red }}>●</span> Compromise events · {tip.dets.length}</div>
        {vis.map((d, i) => <div key={i} style={{ display: "flex", gap: 12 }}><span>{i + 1}</span>
          <button className="v3-link" data-testid={`v3-tip-jump-${i}`} onClick={(e) => { e.stopPropagation(); onClose(); onJump(d); }}>{hhmm(d.ms)}</button>
          <span style={{ color: C.muted, fontSize: 11.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{d.name}</span></div>)}
        {tip.dets.length > 5 && <button className="v3-link" data-testid="v3-tip-more" style={{ fontSize: 12, marginTop: 4 }} onClick={() => { onClose(); onMore(tip.t0, tip.t1); }}>+{tip.dets.length - 5} more</button>}
      </> : <div style={{ color: C.muted }}>No compromise events</div>}
    </div>, document.body);
}

function useTip() {
  const [tip, setTip] = useState(null), timer = useRef(null);
  const keep = () => clearTimeout(timer.current);
  const leave = () => { clearTimeout(timer.current); timer.current = setTimeout(() => setTip((t) => (t?.pinned ? t : null)), 250); };
  const show = (el, data, pinned = false) => {
    keep();
    const r = el.getBoundingClientRect();
    setTip((t) => (t?.pinned && !pinned ? t : { ...data, x: r.left + r.width / 2, y: r.bottom, top: r.top, pinned }));
  };
  return { tip, keep, leave, show, close: () => setTip(null) };
}

function HourStrip({ day0, view, now, dets, onView, onJump, hours, T, selMs }) {
  const ref = useRef(null);
  const [tmp, setTmp] = useState(null);
  const frac = (x) => Math.min(1, Math.max(0, (x - ref.current.getBoundingClientRect().left) / ref.current.clientWidth));
  const drag = (mode) => (e) => {
    e.stopPropagation();
    const ms0 = day0 + frac(e.clientX) * DAY, v0 = view;
    let last = null;
    document.body.classList.add("v3-grabbing");
    const mv = (ev) => {
      const ms = day0 + frac(ev.clientX) * DAY, d = ms - ms0;
      last = mode === "pan" ? { t0: v0.t0 + d, t1: v0.t1 + d } : mode === "l" ? { t0: Math.min(v0.t1 - 60_000, v0.t0 + d), t1: v0.t1 }
        : mode === "r" ? { t0: v0.t0, t1: Math.max(v0.t0 + 60_000, v0.t1 + d) } : { t0: Math.min(ms0, ms), t1: Math.max(ms0, ms) };
      setTmp(last);
    };
    const up = () => {
      window.removeEventListener("mousemove", mv); window.removeEventListener("mouseup", up); setTmp(null); document.body.classList.remove("v3-grabbing");
      if (last && last.t1 - last.t0 > 60_000 && Math.abs(last.t0 - v0.t0) + Math.abs(last.t1 - v0.t1) > 60_000) onView({ t0: Math.round(last.t0), t1: Math.round(Math.min(last.t1, now)) });
    };
    window.addEventListener("mousemove", mv); window.addEventListener("mouseup", up);
  };
  const v = tmp || view, pct = (ms) => `${Math.min(100, Math.max(0, ((ms - day0) / DAY) * 100))}%`;
  const inDay = dets.filter((d) => d.ms >= day0 && d.ms < day0 + DAY).sort((a, b) => a.ms - b.ms);
  const clusters = [];
  inDay.forEach((d) => { const c = clusters[clusters.length - 1]; if (c && d.ms - c.at < DAY * 0.015) c.items.push(d); else clusters.push({ at: d.ms, items: [d] }); });
  const hourTip = (h) => ({ title: `${dateL(day0)} · ${String(h).padStart(2, "0")}:00–${String(h + 1).padStart(2, "0")}:00`, count: hours?.[h] ?? null,
    dets: inDay.filter((d) => d.ms >= day0 + h * H && d.ms < day0 + (h + 1) * H), t0: day0 + h * H, t1: day0 + (h + 1) * H });
  const pick = (h, e) => {
    const t0 = day0 + h * H;
    if (e.shiftKey) onView({ t0: Math.min(view.t0, t0), t1: Math.min(Math.max(view.t1, t0 + H), now) });
    else onView({ t0, t1: Math.min(t0 + H, now) });
  };
  const isToday = now >= day0 && now < day0 + DAY;
  return (
    <div style={{ position: "relative", height: 44, marginTop: 6 }}>
      <div ref={ref} data-testid="v3-hour-strip" onMouseDown={drag("range")} style={{ position: "relative", height: 24, background: C.inset, borderRadius: 4, userSelect: "none", display: "flex" }}>
        {Array.from({ length: 24 }, (_, h) => {
          const sel = view.t0 <= day0 + h * H && view.t1 >= day0 + (h + 1) * H && !(view.t0 <= day0 && view.t1 >= day0 + DAY);
          return <div key={h} data-testid={`v3-hour-cell-${h}`} data-nav-anchor="1" className="v3-nav-cell" data-selected={sel ? "1" : "0"}
            onMouseEnter={(e) => T.show(e.currentTarget, hourTip(h))} onMouseLeave={T.leave}
            onClick={(e) => { pick(h, e); T.show(e.currentTarget, hourTip(h), true); }}
            style={{ flex: 1, position: "relative", borderLeft: h ? "1px solid rgba(255,255,255,.06)" : "none", borderRadius: 3 }}>
            <span style={{ position: "absolute", left: 3, top: 5, fontSize: 10.5, color: C.muted, pointerEvents: "none" }}>{h === 0 ? "0:00" : h}</span>
            {hours?.[h] > 0 && <span data-testid={`v3-hour-activity-${h}`} style={{ position: "absolute", right: 3, top: 9, width: 5, height: 5, borderRadius: 5, background: C.accent, pointerEvents: "none" }} />}
            {hours && hours[h] === 0 && day0 + (h + 1) * H <= now && <div data-testid="v3-nodata-hour" title="No observation retained for this hour (not proof the sensor was offline)"
              style={{ position: "absolute", inset: 0, pointerEvents: "none", background: `repeating-linear-gradient(135deg, ${C.hatch} 0 2px, transparent 2px 7px)` }} />}
          </div>;
        })}
        {now < day0 + DAY && <div title="Not yet occurred" style={{ position: "absolute", left: pct(now), right: 0, top: 0, bottom: 0, borderRadius: "0 4px 4px 0", pointerEvents: "none",
          background: `repeating-linear-gradient(135deg, ${C.hatch} 0 2px, transparent 2px 7px)` }} />}
        {isToday && <div data-testid="v3-now-line" title={`Now ${hhmm(now)} UTC`} style={{ position: "absolute", left: pct(now), top: -2, bottom: -2, width: 1, background: "#cfe3ff", pointerEvents: "none" }} />}
        <div data-testid="v3-hour-bracket" onMouseDown={drag("pan")} style={{ position: "absolute", left: pct(Math.max(v.t0, day0)), width: `calc(${pct(Math.min(v.t1, day0 + DAY))} - ${pct(Math.max(v.t0, day0))})`,
          minWidth: 4, top: -2, bottom: -2, border: `2px solid ${C.accent}`, borderRadius: 4, background: "rgba(110,160,255,.12)", cursor: "grab", pointerEvents: "auto" }}>
          <span data-testid="v3-bracket-l" onMouseDown={drag("l")} style={{ position: "absolute", left: -5, top: 0, bottom: 0, width: 8, cursor: "ew-resize" }} />
          <span data-testid="v3-bracket-r" onMouseDown={drag("r")} style={{ position: "absolute", right: -5, top: 0, bottom: 0, width: 8, cursor: "ew-resize" }} />
        </div>
        {clusters.map((c, i) => { const hit = selMs != null && c.items.find((d) => Math.abs(d.ms - selMs) < 60_000);
          return <Dot key={i} n={c.items.length} testid="v3-hour-det" on={!!hit} at={new Date(hit ? hit.ms : c.at).toISOString()} style={{ position: "absolute", left: `calc(${pct(c.at)} - 5px)`, top: 7 }}
          onEnter={(e) => T.show(e.currentTarget, { title: `${dateL(day0)} · ${hhmm(c.at)}`, dets: c.items, t0: c.at, t1: c.at + 1 })} onLeave={T.leave}
          onClick={(e) => { e.stopPropagation(); T.show(e.currentTarget, { title: `${dateL(day0)} · ${hhmm(c.at)}`, dets: c.items, t0: c.at, t1: c.at + 1 }, true); onJump(topDetection(c.items)); }} />; })}
      </div>
      <div style={{ fontSize: 10.5, color: C.muted, marginTop: 3 }}>{dateL(day0)}</div>
    </div>
  );
}

export default function Navigator({ days, dets, view, now, onView, onJump, fetchHours, onMore, selMs }) {
  const [open, setOpen] = useState(true);
  const [hours, setHours] = useState(null);
  const T = useTip();
  const today = Math.floor(now / DAY) * DAY;
  const cells = Array.from({ length: 30 }, (_, i) => today - (29 - i) * DAY);
  const tot = new Map((days || []).map((d) => [Date.parse(`${d.day}T00:00:00Z`), d.total]));
  const max = Math.max(1, ...cells.map((t) => tot.get(t) || 0));
  const day0 = Math.floor(Math.min(view.t1 - view.t0 <= 2 * H ? (view.t0 + view.t1) / 2 : view.t1 - 1, now) / DAY) * DAY;
  useEffect(() => {
    let live = true;
    setHours(null);
    fetchHours?.(new Date(day0).toISOString().slice(0, 10)).then((h) => { if (live) setHours(h); }).catch(() => {});
    return () => { live = false; };
  }, [day0, fetchHours]);
  const pts = cells.map((t, i) => `${i * 48 + 24},${30 - ((tot.get(t) || 0) / max) * 26}`).join(" ");
  const dayTip = (t, dd) => ({ title: dateL(t), count: tot.get(t) || 0, dets: dd, t0: t, t1: t + DAY });
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
              <div key={t} data-testid={`v3-day-cell-${d.toISOString().slice(0, 10)}`} data-nav-anchor="1" className="v3-nav-cell" data-selected={cur ? "1" : "0"}
                onMouseEnter={(e) => T.show(e.currentTarget, dayTip(t, dd))} onMouseLeave={T.leave}
                onClick={(e) => { onView({ t0: t, t1: Math.min(t + DAY, now) }); T.show(e.currentTarget, dayTip(t, dd), true); }}
                style={{ flex: "1 1 48px", minWidth: 30, position: "relative", textAlign: "center", borderRadius: 4, padding: "3px 0 2px" }}>
                <div style={{ height: 14, display: "flex", alignItems: "center", justifyContent: "center", gap: 3, position: "relative" }}>
                  {dd.length > 0 && <Dot n={1} testid={`v3-day-dot-${d.toISOString().slice(0, 10)}`} onClick={(e) => {
                    e.stopPropagation(); T.show(e.currentTarget.parentNode.parentNode, dayTip(t, dd), true); onJump(topDetection(dd)); }} />}
                  {n > 0 && <span style={{ width: 5, height: 5, borderRadius: 5, background: C.accent }} />}</div>
                <div style={{ fontSize: 12, color: cur ? C.text : C.label, fontWeight: cur ? 700 : 400 }}>{d.getUTCDate()}</div>
                <div style={{ fontSize: 10, color: C.muted, height: 12 }}>{d.getUTCDate() === 1 || t === cells[0] ? MON(t) : ""}</div>
              </div>);
          })}
        </div>
        <HourStrip day0={day0} view={view} now={now} dets={dets} onView={onView} onJump={onJump} hours={hours} T={T} selMs={selMs} />
        <Tip tip={T.tip} onJump={onJump} onMore={onMore || (() => {})} onClose={T.close} keep={T.keep} leave={T.leave} />
      </div> : <div style={{ color: C.muted, fontSize: 12, paddingTop: 2 }}>Navigator</div>}
    </div>
  );
}
