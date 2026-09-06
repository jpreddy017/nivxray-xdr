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

import { C, DAY_MS, DAY_BINS, MONTHS, fmtSpan, startOfDayUTC,
         dayKeyOf } from "./ampModel";

const DAYS = 30;
const PAD = 0;

const dotR = (n, max) => (!n ? 0
  : 2 + Math.round((Math.log1p(n) / Math.log1p(Math.max(1, max))) * 2.6));

export default function AmpNavigator({
  days, dayBins, selectedDay, onSelectDay, view, onView, observedEnd,
  cursorTs, onFocusTime, collapsed, header = null,
}) {
  const hourRef = useRef(null);
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

  const down = (mode) => (e) => {
    e.preventDefault();
    e.currentTarget.setPointerCapture?.(e.pointerId);
    setDrag({ mode, px: e.clientX, vs: view.t0, ve: view.t1 });
  };
  const move = (e) => {
    if (!drag) return;
    const rect = hourRef.current.getBoundingClientRect();
    const lx = e.clientX - rect.left;
    if (drag.mode === "left") {
      onView({ t0: Math.min(tOfX(lx), drag.ve - 1000), t1: drag.ve });
    } else if (drag.mode === "right") {
      onView({ t0: drag.vs, t1: Math.max(tOfX(lx), drag.vs + 1000) });
    } else {
      const dMs = ((e.clientX - drag.px) / innerW) * DAY_MS;
      const dur = drag.ve - drag.vs;
      const s = Math.min(Math.max(drag.vs + dMs, dayStart), dayEnd - dur);
      onView({ t0: s, t1: s + dur });
    }
  };
  const up = () => setDrag(null);

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
          {/* activity sparkline */}
          <svg width="100%" height={30} preserveAspectRatio="none"
               viewBox={`0 0 ${DAYS} 30`} style={{ display: "block" }}
               data-testid="amp-nav-sparkline">
            <polygon
              points={`0,30 ${cells.map((c, i) =>
                `${i + 0.5},${29 - (c.total / maxTotal) * 26}`)
                .join(" ")} ${DAYS},30`}
              fill={C.sparkFill} />
            <polyline
              points={cells.map((c, i) =>
                `${i + 0.5},${29 - (c.total / maxTotal) * 26}`).join(" ")}
              fill="none" stroke={C.spark} strokeWidth={1}
              vectorEffect="non-scaling-stroke" />
          </svg>

          {/* 30-day band */}
          <div style={{ display: "grid",
                        gridTemplateColumns: `repeat(${DAYS}, 1fr)` }}
               data-testid="amp-nav-day-band">
            {cells.map((c) => {
              const active = c.ms === dayStart;
              const has = c.total > 0;
              return (
                <button key={c.key} onClick={() => onDayClick(c)}
                        data-testid={`amp-nav-day-${c.key}`}
                        title={`${c.key} · ${c.total} observation(s)`
                          + (c.malicious ? ` · ${c.malicious} malicious` : "")
                          + (c.detections ? ` · ${c.detections} detection(s)`
                                          : "")}
                        style={{ height: 40, padding: 0,
                                 cursor: has ? "pointer" : "default",
                                 background: active ? C.selectionRow
                                   : C.paper,
                                 borderStyle: "solid",
                                 borderColor: active ? C.selectionStrong
                                   : C.grid,
                                 borderWidth: active ? 2 : 1,
                                 display: "flex", flexDirection: "column",
                                 alignItems: "center",
                                 justifyContent: "center", gap: 3 }}>
                  {(c.malicious + c.detections) > 0 && (
                    <span data-testid={`amp-nav-day-red-${c.key}`}
                          style={{ width: dotR(c.malicious + c.detections,
                            maxMal) * 2,
                                   height: dotR(c.malicious + c.detections,
                                     maxMal) * 2,
                                   borderRadius: "50%",
                                   background: C.malicious }} />
                  )}
                  {has && (
                    <span style={{ width: dotR(c.total, maxTotal) * 2,
                                   height: dotR(c.total, maxTotal) * 2,
                                   borderRadius: "50%",
                                   background: C.telemetry }} />
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
                 onPointerMove={move} onPointerUp={up} onPointerLeave={up}
                 data-testid="amp-nav-hour-band">
              {Array.from({ length: 24 }, (_, h) => (
                <rect key={h} x={PAD + (h / 24) * innerW} y={8}
                      width={innerW / 24} height={30}
                      fill={C.paper} stroke={C.grid} strokeWidth={0.8} />
              ))}

              {(dayBins || []).map((b) => {
                const x = PAD + ((b.bin + 0.5) / DAY_BINS) * innerW;
                const red = b.malicious + b.detections > 0;
                const r = 2 + Math.round((b.total / maxBin) * 2.4);
                return (
                  <circle key={b.bin} cx={x} cy={red ? 17 : 28} r={r}
                          fill={red ? C.malicious : C.telemetry}
                          data-testid={`amp-nav-bin-${b.bin}`} />
                );
              })}

              {/* the unselected span is greyed; the window stays clear */}
              <rect x={PAD} y={8} width={Math.max(0, xs - PAD)} height={30}
                    fill="rgba(241,245,249,0.9)" pointerEvents="none" />
              <rect x={xe} y={8} width={Math.max(0, PAD + innerW - xe)}
                    height={30} fill="rgba(241,245,249,0.9)"
                    pointerEvents="none" />
              <rect x={xs} y={8} width={Math.max(1, xe - xs)} height={30}
                    fill={C.navWindow} pointerEvents="none" />

              <rect x={xs} y={8} width={Math.max(1, xe - xs)} height={30}
                    fill="transparent" style={{ cursor: "grab" }}
                    onPointerDown={down("band")}
                    data-testid="amp-nav-band" />

              {/* triangle handles, as in the Cisco band */}
              {[["left", xs], ["right", xe]].map(([side, x]) => (
                <g key={side} style={{ cursor: "ew-resize" }}
                   onPointerDown={down(side)}
                   data-testid={`amp-nav-handle-${side}`}>
                  <rect x={x - 6} y={0} width={12} height={44}
                        fill="transparent" />
                  <path d={`M ${x - 5} 1 L ${x + 5} 1 L ${x} 8 Z`}
                        fill={C.handle} />
                  <path d={`M ${x - 5} 43 L ${x + 5} 43 L ${x} 36 Z`}
                        fill={C.handle} />
                  <line x1={x} y1={8} x2={x} y2={38} stroke={C.handle}
                        strokeWidth={1.2} />
                </g>
              ))}

              {cursorTs != null && cursorTs >= dayStart
                && cursorTs < dayEnd && (
                <line x1={xOfHour(cursorTs)} y1={6} x2={xOfHour(cursorTs)}
                      y2={40} stroke={C.ink} strokeWidth={1}
                      pointerEvents="none" data-testid="amp-nav-cursor" />
              )}

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
            </svg>
            <div style={{ display: "grid",
                          gridTemplateColumns: "repeat(24, 1fr)",
                          marginTop: 1 }}>
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
              on this day · drag the band or its handles to move the
              trajectory window
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
