/**
 * Navigator — the Cisco Secure Endpoint trajectory navigator panel:
 *
 *   ▼ [Filters ⌄] [Search Device Trajectory] 🔍
 *   ──────── activity sparkline over the retained period ────────
 *   [ 30-day band · blue dot = activity · red dot = compromise ]
 *     18 19 20 … 16      JUL          AUG
 *   [ 24-hour band · ▲▼ handles on the window edges ]
 *     0:00 1 2 … 23      AUG 16
 *
 * Every bar, cell and dot is a count of persisted observations. A day
 * with nothing observed stays empty — never interpolated. An empty day
 * means "nothing was observed", not "nothing happened".
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { C, DAY_MS, DAY_BINS, MONTHS, fmtHM, fmtSpan, startOfDayUTC,
         dayKeyOf } from "./ampModel";

const DAYS = 30;
const PAD = 9;            // keeps the window handles INSIDE the svg;
                          // at PAD 0 a handle on the last pixel of the
                          // day was clipped away and could not be grabbed
const CELL = 10;          // sparkline user units per day column
const SPARK_H = 38;

/** Density on a log scale — one busy day must not flatten 29 others
 *  into a straight line at zero. */
const dens = (n, max) => (!n ? 0
  : Math.log1p(n) / Math.log1p(Math.max(1, max)));

export default function AmpNavigator({
  days, dayBins, selectedDay, onSelectDay, view, onView, observedEnd,
  cursorTs, onFocusTime, collapsed, header = null,
}) {
  const hourRef = useRef(null);
  const dragRef = useRef(null);
  const [hourW, setHourW] = useState(700);
  const [drag, setDrag] = useState(null);

  useEffect(() => {
    if (!hourRef.current) return;
    const ro = new ResizeObserver((en) => {
      const w = en[0]?.contentRect?.width;
      if (w) setHourW(Math.max(280, Math.floor(w)));
    });
    ro.observe(hourRef.current);
    return () => ro.disconnect();
  }, [collapsed]);

  const byDay = useMemo(() => {
    const m = new Map();
    for (const d of days || []) m.set(d.day, d);
    return m;
  }, [days]);

  /** Anchored on the latest OBSERVED day: Cisco retains 30 days, and
   *  anchoring on "today" would show 30 empty cells for an endpoint
   *  whose last telemetry is older. */
  const cells = useMemo(() => {
    const anchor = observedEnd ? startOfDayUTC(Date.parse(observedEnd))
                               : startOfDayUTC(Date.now());
    const out = [];
    for (let i = DAYS - 1; i >= 0; i -= 1) {
      const ms = anchor - i * DAY_MS;
      const rec = byDay.get(dayKeyOf(ms)) || { total: 0, malicious: 0,
                                               suspicious: 0, detections: 0 };
      out.push({ ms, key: dayKeyOf(ms), ...rec, d: new Date(ms) });
    }
    return out;
  }, [byDay, observedEnd]);

  const maxTotal = Math.max(1, ...cells.map((c) => c.total));
  const maxMal = Math.max(1, ...cells.map((c) => c.malicious + c.detections));
  const dayStart = selectedDay ?? cells[cells.length - 1]?.ms
    ?? startOfDayUTC(Date.now());
  const dayEnd = dayStart + DAY_MS;
  const selIdx = cells.findIndex((c) => c.ms === dayStart);

  const innerW = Math.max(1, hourW - PAD * 2);
  const xOfHour = useCallback((t) => PAD + ((Math.min(Math.max(t, dayStart),
    dayEnd) - dayStart) / DAY_MS) * innerW, [dayStart, dayEnd, innerW]);
  const tOfX = useCallback((x) => dayStart + ((Math.min(Math.max(x, PAD),
    PAD + innerW) - PAD) / innerW) * DAY_MS, [dayStart, innerW]);

  const xs = xOfHour(view.t0);
  const xe = xOfHour(view.t1);

  /** The drag is tracked on the WINDOW, not on the handle. Capturing
   *  the pointer on a 12 px handle made the band emit pointerleave the
   *  moment the drag began, which cancelled it — the control looked
   *  wired and did nothing. */
  const down = (mode) => (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (dragRef.current) return;      // pointerdown + mousedown both fire
    const st = { mode, px: e.clientX, vs: view.t0, ve: view.t1 };
    dragRef.current = st;
    setDrag(st);
    const onMove = (ev) => {
      const rect = hourRef.current?.getBoundingClientRect();
      if (!rect) return;
      if (Math.abs(ev.clientX - st.px) > 3) st.moved = true;
      const lx = ev.clientX - rect.left;
      if (st.mode === "left") {
        onView({ t0: Math.min(tOfX(lx), st.ve - 1000), t1: st.ve });
      } else if (st.mode === "right") {
        onView({ t0: st.vs, t1: Math.max(tOfX(lx), st.vs + 1000) });
      } else {
        const dMs = ((ev.clientX - st.px) / innerW) * DAY_MS;
        const dur = st.ve - st.vs;
        const s = st.vs + dMs;
        onView({ t0: s, t1: s + dur });
        // Dragging past midnight must MOVE THE DAY, not stall at the
        // edge: a control that appears not to work is worse than none.
        const d = startOfDayUTC(s);
        if (d !== dayStart) onSelectDay(d);
      }
    };
    const onUp = (ev) => {
      // A click on the band (no movement) centres the trajectory on the
      // nearest OBSERVED bin — the behaviour the bin hit targets used
      // to own before they were moved behind the band.
      if (st.mode === "band" && !st.moved && (dayBins || []).length) {
        const rect = hourRef.current?.getBoundingClientRect();
        const lx = (ev?.clientX ?? st.px) - (rect?.left ?? 0);
        const t = tOfX(lx);
        let best = null;
        for (const b of dayBins) {
          const d = Math.abs(Date.parse(b.first_timestamp) - t);
          if (!best || d < best.d) best = { d, b };
        }
        if (best) {
          onFocusTime(Date.parse(best.b.first_timestamp),
                      best.b.first_event_iid);
        }
      }
      dragRef.current = null;
      setDrag(null);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  /** A continuous activity-density curve over the retained period,
   *  built from the per-day observation counts the projection reports.
   *  A day with nothing observed sits on the baseline — it is never
   *  interpolated upwards to make the curve look busy. */
  const sparkPath = useMemo(() => {
    const yOf = (n) => SPARK_H - 2 - dens(n, maxTotal) * (SPARK_H - 6);
    const pts = cells.map((c, i) => [i * CELL + CELL / 2, yOf(c.total)]);
    if (!pts.length) return "";
    let d = `M 0 ${pts[0][1]} L ${pts[0][0]} ${pts[0][1]}`;
    for (let i = 1; i < pts.length; i += 1) {
      const [x0, y0] = pts[i - 1];
      const [x1, y1] = pts[i];
      const mx = (x0 + x1) / 2;
      d += ` C ${mx} ${y0} ${mx} ${y1} ${x1} ${y1}`;
    }
    return `${d} L ${DAYS * CELL} ${pts[pts.length - 1][1]}`;
  }, [cells, maxTotal]);

  const maxBin = Math.max(1, ...(dayBins || []).map((b) => b.total));
  const dayTotal = (dayBins || []).reduce((n, b) => n + b.total, 0);

  const onDayClick = (cell) => {
    onSelectDay(cell.ms);
    onView({ t0: cell.ms, t1: cell.ms + DAY_MS });
  };

  return (
    <section data-testid="amp-navigator"
             style={{ background: C.paper,
                      border: `1px solid ${C.gridStrong}`,
                      borderRadius: 6, height: "100%",
                      display: "flex", flexDirection: "column" }}>
      {header || null}
      {!collapsed && (
        <div style={{ padding: "10px 12px 12px", display: "flex",
                      flexDirection: "column", gap: 6 }}>
          {/* activity density over the retained period */}
          <svg width="100%" height={SPARK_H} preserveAspectRatio="none"
               viewBox={`0 0 ${DAYS * CELL} ${SPARK_H}`}
               style={{ display: "block" }}
               data-testid="amp-nav-sparkline">
            <defs>
              <linearGradient id="amp-spark-fill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={C.spark} stopOpacity={0.34} />
                <stop offset="100%" stopColor={C.spark} stopOpacity={0.02} />
              </linearGradient>
            </defs>
            {cells.map((c, i) => (
              <line key={`gl-${c.key}`} x1={i * CELL} y1={0} x2={i * CELL}
                    y2={SPARK_H} stroke={C.grid} strokeWidth={0.5}
                    vectorEffect="non-scaling-stroke" />
            ))}
            {selIdx >= 0 && (
              <rect x={selIdx * CELL} y={0} width={CELL} height={SPARK_H}
                    fill={C.selectionRow} data-testid="amp-nav-spark-selected" />
            )}
            <path d={`${sparkPath} L ${DAYS * CELL} ${SPARK_H} L 0 ${SPARK_H} Z`}
                  fill="url(#amp-spark-fill)" />
            <path d={sparkPath} fill="none" stroke={C.spark} strokeWidth={1.4}
                  vectorEffect="non-scaling-stroke" />
            {cells.map((c, i) => (c.total > 0 ? (
              <circle key={`sp-${c.key}`} cx={i * CELL + CELL / 2}
                      cy={SPARK_H - 2 - dens(c.total, maxTotal)
                        * (SPARK_H - 6)}
                      r={1.7} vectorEffect="non-scaling-stroke"
                      fill={(c.malicious + c.detections) > 0 ? C.malicious
                        : C.spark} />
            ) : null))}
          </svg>

          {/* 30-day band */}
          <div style={{ display: "grid",
                        gridTemplateColumns: `repeat(${DAYS}, 1fr)` }}
               data-testid="amp-nav-day-band">
            {cells.map((c) => {
              const active = c.ms === dayStart;
              const has = c.total > 0;
              const red = c.malicious + c.detections;
              const barH = has
                ? Math.max(2, Math.round(dens(c.total, maxTotal) * 26)) : 0;
              return (
                <button key={c.key} onClick={() => onDayClick(c)}
                        data-testid={`amp-nav-day-${c.key}`}
                        data-observations={c.total}
                        data-compromise={red}
                        data-selected={active ? "true" : "false"}
                        title={`${c.key} · ${c.total} observation(s)`
                          + (c.malicious ? ` · ${c.malicious} malicious` : "")
                          + (c.detections ? ` · ${c.detections} detection(s)`
                                          : "")}
                        style={{ height: 34, padding: 0, position: "relative",
                                 cursor: has ? "pointer" : "default",
                                 background: active ? C.selectionRow
                                   : (has ? C.paperAlt : C.paper),
                                 borderStyle: "solid",
                                 borderColor: active ? C.selectionStrong
                                   : C.grid,
                                 borderWidth: active ? 2 : "1px 0.5px",
                                 display: "flex", alignItems: "flex-end",
                                 justifyContent: "center" }}>
                  {red > 0 && (
                    <span data-testid={`amp-nav-day-red-${c.key}`}
                          style={{ position: "absolute", top: 0, left: 0,
                                   right: 0,
                                   height: 2 + Math.round(
                                     dens(red, maxMal) * 2.5),
                                   background: C.malicious }} />
                  )}
                  {has && (
                    <span style={{ width: "62%", height: barH,
                                   background: C.telemetry,
                                   opacity: active ? 1 : 0.72 }} />
                  )}
                </button>
              );
            })}
          </div>
          <div style={{ display: "grid",
                        gridTemplateColumns: `repeat(${DAYS}, 1fr)`,
                        marginTop: 2 }}>
            {cells.map((c) => (
              <div key={c.key}
                   style={{ fontSize: 9, textAlign: "center",
                            color: c.ms === dayStart ? C.ink : C.inkFaint,
                            fontWeight: c.ms === dayStart ? 700 : 400 }}>
                {c.d.getUTCDate()}
              </div>
            ))}
          </div>
          <div style={{ display: "flex", justifyContent: "space-between",
                        fontSize: 9, color: C.inkFaint, marginTop: 1 }}>
            <span>{MONTHS[cells[0].d.getUTCMonth()]}</span>
            {cells[0].d.getUTCMonth() !== cells[DAYS - 1].d.getUTCMonth() && (
              <span>{MONTHS[cells[DAYS - 1].d.getUTCMonth()]}</span>
            )}
          </div>

          {/* the selected day connects down to the 24-hour band */}
          <svg width="100%" height={10} preserveAspectRatio="none"
               viewBox="0 0 100 10" style={{ display: "block" }}>
            {selIdx >= 0 && (
              <polyline
                points={`${((selIdx + 0.5) / DAYS) * 100},0 `
                  + `${((selIdx + 0.5) / DAYS) * 100},5 100,5 100,10 0,10 0,5`}
                fill="none" stroke={C.selectionStrong} strokeWidth={0.6}
                vectorEffect="non-scaling-stroke" opacity={0.65} />
            )}
          </svg>

          {/* 24-hour band */}
          <div ref={hourRef} style={{ width: "100%" }}>
            <svg width={hourW} height={44}
                 style={{ display: "block", touchAction: "none" }}
                 data-dragging={drag ? drag.mode : "none"}
                 data-testid="amp-nav-hour-band">
              <defs>
                <pattern id="amp-nav-hatch" width={6} height={6}
                         patternUnits="userSpaceOnUse"
                         patternTransform="rotate(45)">
                  <rect width={6} height={6} fill={C.paperAlt} />
                  <line x1={0} y1={0} x2={0} y2={6} stroke={C.hatch}
                        strokeWidth={2.6} />
                </pattern>
              </defs>
              {Array.from({ length: 24 }, (_, h) => (
                <rect key={h} x={PAD + (h / 24) * innerW} y={8}
                      width={innerW / 24} height={30}
                      fill={C.paper} stroke={C.grid} strokeWidth={0.8} />
              ))}

              {(dayBins || []).map((b) => {
                const x = PAD + ((b.bin + 0.5) / DAY_BINS) * innerW;
                const red = b.malicious + b.detections > 0;
                const r = 2 + Math.round(dens(b.total, maxBin) * 2.4);
                return (
                  <circle key={b.bin} cx={x} cy={red ? 17 : 28} r={r}
                          fill={red ? C.malicious : C.telemetry}
                          data-testid={`amp-nav-bin-${b.bin}`} />
                );
              })}

              {/* bin hit targets sit BEHIND the window band and its
                  handles, so a drag is never stolen by a 7 px click
                  target — the band's own click still centres the
                  trajectory on the nearest observed bin. */}
              {(dayBins || []).map((b) => (
                <rect key={`hit-${b.bin}`}
                      x={PAD + (b.bin / DAY_BINS) * innerW - 3} y={8}
                      width={7} height={30} fill="transparent"
                      style={{ cursor: "pointer" }}
                      onClick={() => onFocusTime(
                        Date.parse(b.first_timestamp), b.first_event_iid)}
                      data-testid={`amp-nav-bin-hit-${b.bin}`}>
                  <title>{`${b.total} observation(s) · ${b.first_timestamp}`
                    + " · click to centre the trajectory here"}</title>
                </rect>
              ))}

              {/* time outside the window is hatched: it is not empty,
                  it is OUT OF VIEW */}
              <rect x={PAD} y={8} width={Math.max(0, xs - PAD)} height={30}
                    fill="url(#amp-nav-hatch)" pointerEvents="none"
                    data-testid="amp-nav-hatch-before" />
              <rect x={xe} y={8} width={Math.max(0, PAD + innerW - xe)}
                    height={30} fill="url(#amp-nav-hatch)"
                    pointerEvents="none"
                    data-testid="amp-nav-hatch-after" />
              <rect x={xs} y={8} width={Math.max(1, xe - xs)} height={30}
                    fill={C.navWindow} pointerEvents="none" />

              <rect x={xs} y={8} width={Math.max(1, xe - xs)} height={30}
                    fill="transparent" style={{ cursor: "grab" }}
                    onPointerDown={down("band")} onMouseDown={down("band")}
                    data-testid="amp-nav-band" />

              {/* triangle handles, as in the Cisco band */}
              {[["left", xs], ["right", xe]].map(([side, x]) => (
                <g key={side} style={{ cursor: "ew-resize" }}
                   onPointerDown={down(side)} onMouseDown={down(side)}
                   data-testid={`amp-nav-handle-${side}`}>
                  <rect x={x - 8} y={0} width={16} height={44}
                        fill="transparent" />
                  <path d={`M ${x - 5} 1 L ${x + 5} 1 L ${x} 8 Z`}
                        fill={C.handle} />
                  <path d={`M ${x - 5} 43 L ${x + 5} 43 L ${x} 36 Z`}
                        fill={C.handle} />
                  <line x1={x} y1={8} x2={x} y2={38} stroke={C.handle}
                        strokeWidth={1.2} />
                </g>
              ))}

              {/* precise temporal selection cursor on the window edge */}
              <g pointerEvents="none" data-testid="amp-nav-window-cursor"
                 data-window-start={new Date(view.t0).toISOString()}>
                <line x1={xs} y1={0} x2={xs} y2={44}
                      stroke={C.selectionStrong} strokeWidth={0.8}
                      strokeDasharray="2 2" />
                <text x={Math.min(xs + 3, Math.max(0, innerW - 34))} y={7}
                      fontSize={7.6} fill={C.selectionStrong}>
                  {fmtHM(view.t0)}
                </text>
              </g>

              {cursorTs != null && cursorTs >= dayStart
                && cursorTs < dayEnd && (
                <line x1={xOfHour(cursorTs)} y1={6} x2={xOfHour(cursorTs)}
                      y2={40} stroke={C.ink} strokeWidth={1}
                      pointerEvents="none" data-testid="amp-nav-cursor" />
              )}
            </svg>
            <div style={{ display: "grid",
                          gridTemplateColumns: "repeat(24, 1fr)",
                          margin: `1px ${PAD}px 0` }}>
              {Array.from({ length: 24 }, (_, h) => (
                <div key={h} style={{ fontSize: 9, color: C.inkFaint }}>
                  {h === 0 ? "0:00" : h}
                </div>
              ))}
            </div>
            <div data-testid="amp-nav-day-label"
                 style={{ fontSize: 9, color: C.inkFaint, marginTop: 1 }}>
              {MONTHS[new Date(dayStart).getUTCMonth()]}{" "}
              {new Date(dayStart).getUTCDate()} · {dayTotal} observation(s)
              on this day
            </div>
            <div className="mono" data-testid="amp-nav-window"
                 style={{ fontSize: 9, color: C.inkDim, marginTop: 2 }}>
              window {fmtSpan(Math.max(1, view.t1 - view.t0))} ·{" "}
              {new Date(view.t0).toISOString().slice(0, 19)
                .replace("T", " ")} → {new Date(view.t1).toISOString()
                .slice(0, 19).replace("T", " ")} UTC
            </div>

          </div>
        </div>
      )}
    </section>
  );
}
