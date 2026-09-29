/**
 * DT2-3a · AMP parity — the Device Trajectory navigator.
 *
 * Cisco (User Guide p.402 figure; "The Navigator", AMP guide p.171):
 *   ‑ upper ribbon = 30 days of day cells, red dots for compromise
 *     events, dot size relative to the number of events per day
 *   ‑ lower ribbon = the 24 hours of the selected day, a solid band with
 *     circles of varying size; hovering a circle gives the count and the
 *     time, clicking it focuses the trajectory on those events
 *   ‑ the navigator collapses with `-` and expands with `+` or by
 *     clicking the ribbon
 *
 * NOT rendered, deliberately: the line graph above the dates. Cisco's
 * current guide defines it as the endpoint's cloud-query volume per day
 * (p.403), a metric NivXForge does not collect. Substituting our own
 * activity curve under Cisco's meaning would be false parity, so the
 * element is omitted and recorded as a data gap.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { C, DAY_MS, DAY_BINS, MONTHS, startOfDayUTC,
         dayKeyOf } from "./ampModel";
import { moveRange } from "./dt2";

const DAYS = 30;
const PAD = 9;

/** Dot radius relative to the number of events per day, log-damped so one
 *  busy day does not erase 29 others. */
const dens = (n, max) => (!n ? 0
  : Math.log1p(n) / Math.log1p(Math.max(1, max)));

export default function AmpNavigator({
  days, dayBins, selectedDay, onSelectDay, view, onView, observedEnd,
  onFocusTime, collapsed, onCollapsed, bounds = null, header = null,
  searchActive = false,
}) {
  const hourRef = useRef(null);
  const dragRef = useRef(null);
  const [hourW, setHourW] = useState(700);
  const [drag, setDrag] = useState(null);

  useEffect(() => {
    if (!hourRef.current) return undefined;
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
  const dayStart = selectedDay ?? cells[cells.length - 1]?.ms
    ?? startOfDayUTC(Date.now());
  const dayEnd = dayStart + DAY_MS;

  const innerW = Math.max(1, hourW - PAD * 2);
  const xOfHour = useCallback((t) => PAD + ((Math.min(Math.max(t, dayStart),
    dayEnd) - dayStart) / DAY_MS) * innerW, [dayStart, dayEnd, innerW]);
  const tOfX = useCallback((x) => dayStart + ((Math.min(Math.max(x, PAD),
    PAD + innerW) - PAD) / innerW) * DAY_MS, [dayStart, innerW]);

  const xs = view ? xOfHour(view.t0) : PAD;
  const xe = view ? xOfHour(view.t1) : PAD;

  /** The band slides, as Cisco's date and time bars do. The triangle
   *  handles are gone from the presentation; the range engine underneath
   *  is unchanged. */
  const down = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (dragRef.current || !view) return;
    const st = { px: e.clientX, vs: view.t0, ve: view.t1 };
    dragRef.current = st;
    setDrag(st);
    const onMove = (ev) => {
      if (Math.abs(ev.clientX - st.px) > 3) st.moved = true;
      const dMs = ((ev.clientX - st.px) / innerW) * DAY_MS;
      const moved = moveRange({ t0: st.vs, t1: st.ve }, dMs, bounds);
      onView(moved.view);
      const d = startOfDayUTC(moved.view.t0);
      if (d !== dayStart) onSelectDay(d);
    };
    const onUp = (ev) => {
      if (!st.moved && (dayBins || []).length) {
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

  const maxBin = Math.max(1, ...(dayBins || []).map((b) => b.total));

  const onDayClick = (cell) => {
    onSelectDay(cell.ms);
    onView({ t0: cell.ms, t1: cell.ms + DAY_MS });
  };

  const sel = new Date(dayStart);

  if (collapsed) {
    return (
      <section data-testid="amp-navigator" data-collapsed="true"
               style={{ background: C.paper,
                        border: `1px solid ${C.gridStrong}`,
                        borderRadius: 6 }}>
        {header || null}
        {/* Cisco: expand by clicking the ribbon or the + button */}
        <div data-testid="amp-navigator-ribbon"
             onClick={() => onCollapsed(false)}
             style={{ display: "flex", alignItems: "center", gap: 8,
                      padding: "5px 9px", cursor: "pointer",
                      borderTop: `1px solid ${C.grid}` }}>
          <button onClick={(e) => { e.stopPropagation(); onCollapsed(false); }}
                  data-testid="amp-navigator-expand"
                  title="Expand the navigator"
                  style={collapseBtn}>+</button>
          <div style={{ flex: 1, height: 6, background: C.paperAlt,
                        border: `1px solid ${C.grid}`, borderRadius: 2 }} />
        </div>
      </section>
    );
  }

  return (
    <section data-testid="amp-navigator" data-collapsed="false"
             style={{ background: C.paper,
                      border: `1px solid ${C.gridStrong}`,
                      borderRadius: 6, height: "100%",
                      display: "flex", flexDirection: "column" }}>
      {header || null}
      <div style={{ padding: "10px 12px 12px", display: "flex",
                    gap: 8 }}>
        {/* F3 · Cisco places the collapse control at the left of the
            ribbon, vertically centred against it. */}
        <button onClick={() => onCollapsed(true)}
                data-testid="amp-navigator-collapse"
                title="Collapse the navigator"
                style={{ ...collapseBtn, alignSelf: "center" }}>−</button>
        <div style={{ flex: 1, minWidth: 0, display: "flex",
                      flexDirection: "column", gap: 5 }}>

        {/* 30-day ribbon */}
        <div style={{ display: "grid",
                      gridTemplateColumns: `repeat(${DAYS}, 1fr)` }}
             data-testid="amp-nav-day-band">
          {cells.map((c) => {
            const active = c.ms === dayStart;
            const has = c.total > 0;
            const red = c.malicious + c.detections;
            /** Cisco: red dots are compromise events, blue dots are
             *  search results, sized relative to the day's events. The
             *  day aggregate is server-computed over the filtered set,
             *  so with a query active these ARE the search hits. */
            const blue = !red && searchActive && c.total > 0;
            const r = (red || blue) ? 2.5 + dens(c.total, maxTotal) * 4 : 0;
            return (
              <button key={c.key} onClick={() => onDayClick(c)}
                      data-testid={`amp-nav-day-${c.key}`}
                      data-observations={c.total}
                      data-compromise={red}
                      data-selected={active ? "true" : "false"}
                      title={`${c.total} event(s) on ${c.key}`
                        + (red ? ` · ${red} compromise event(s)` : "")}
                      style={{ height: 30, padding: 0, position: "relative",
                               cursor: has ? "pointer" : "default",
                               background: active ? C.selectionRow : C.paper,
                               borderStyle: "solid",
                               borderColor: active ? C.selectionStrong
                                 : C.grid,
                               borderWidth: active ? 1.5 : "1px 0.5px",
                               display: "flex", alignItems: "center",
                               justifyContent: "center" }}>
                {(red > 0 || blue) && (
                  <span data-testid={red > 0
                          ? `amp-nav-day-red-${c.key}`
                          : `amp-nav-day-blue-${c.key}`}
                        style={{ width: r * 2, height: r * 2,
                                 borderRadius: "50%",
                                 background: red > 0 ? C.malicious
                                   : C.telemetry }} />
                )}
              </button>
            );
          })}
        </div>
        <div style={{ display: "grid",
                      gridTemplateColumns: `repeat(${DAYS}, 1fr)` }}>
          {cells.map((c) => (
            <div key={c.key}
                 style={{ fontSize: 9.4, textAlign: "center",
                          color: c.ms === dayStart ? C.selectionStrong
                            : C.inkFaint,
                          fontWeight: c.ms === dayStart ? 700 : 400 }}>
              {c.d.getUTCDate()}
            </div>
          ))}
        </div>
        {/* month name under the day the month begins, as Cisco labels it */}
        <div style={{ display: "grid",
                      gridTemplateColumns: `repeat(${DAYS}, 1fr)` }}>
          {cells.map((c, i) => (
            <div key={`m-${c.key}`}
                 style={{ fontSize: 9.4, color: C.inkFaint,
                          textAlign: "center", whiteSpace: "nowrap" }}>
              {i === 0 || c.d.getUTCDate() === 1
                ? MONTHS[c.d.getUTCMonth()] : ""}
            </div>
          ))}
        </div>

        {/* 24-hour ribbon for the selected day */}
        <div ref={hourRef} style={{ width: "100%", marginTop: 6 }}>
          <svg width={hourW} height={34}
               style={{ display: "block", touchAction: "none" }}
               data-dragging={drag ? "band" : "none"}
               data-testid="amp-nav-hour-band">
            <rect x={PAD} y={4} width={innerW} height={26}
                  fill={C.navWindow} stroke={C.gridStrong}
                  strokeWidth={0.8} />
            {Array.from({ length: 23 }, (_, i) => (
              <line key={i} x1={PAD + ((i + 1) / 24) * innerW} y1={4}
                    x2={PAD + ((i + 1) / 24) * innerW} y2={30}
                    stroke={C.grid} strokeWidth={0.6} />
            ))}

            {view && (
              <rect x={Math.min(xs, xe)} y={4}
                    width={Math.max(2, Math.abs(xe - xs))} height={26}
                    fill={C.paper} stroke={C.selectionStrong}
                    strokeWidth={0.8} pointerEvents="none"
                    data-testid="amp-nav-window-region" />
            )}

            {(dayBins || []).map((b) => {
              const x = PAD + ((b.bin + 0.5) / DAY_BINS) * innerW;
              const red = b.malicious + b.detections > 0;
              const r = 2 + dens(b.total, maxBin) * 3;
              return (
                <circle key={b.bin} cx={x} cy={17} r={r}
                        fill={red ? C.malicious : C.telemetry}
                        data-testid={`amp-nav-bin-${b.bin}`}>
                  <title>{`${b.total} event(s) · `
                    + `${b.first_timestamp}`}</title>
                </circle>
              );
            })}

            {(dayBins || []).map((b) => (
              <rect key={`hit-${b.bin}`}
                    x={PAD + (b.bin / DAY_BINS) * innerW - 3} y={4}
                    width={7} height={26} fill="transparent"
                    onClick={() => onFocusTime(
                      Date.parse(b.first_timestamp), b.first_event_iid)}
                    data-testid={`amp-nav-bin-hit-${b.bin}`}>
                <title>{`${b.total} event(s) · ${b.first_timestamp}`}</title>
              </rect>
            ))}

            <rect x={PAD} y={4} width={innerW} height={26}
                  fill="transparent"
                  onPointerDown={down} onMouseDown={down}
                  data-testid="amp-nav-band" />
          </svg>
          <div style={{ display: "grid",
                        gridTemplateColumns: "repeat(24, 1fr)",
                        margin: `1px ${PAD}px 0` }}>
            {Array.from({ length: 24 }, (_, h) => (
              <div key={h} style={{ fontSize: 9.4, color: C.inkFaint }}>
                {h === 0 ? "0:00" : h}
              </div>
            ))}
          </div>
          <div data-testid="amp-nav-day-label"
               style={{ fontSize: 9.4, color: C.inkFaint, marginTop: 1 }}>
            {MONTHS[sel.getUTCMonth()]} {sel.getUTCDate()}
          </div>
        </div>
        </div>
      </div>
    </section>
  );
}

const collapseBtn = {
  width: 18, height: 18, lineHeight: "16px", textAlign: "center",
  fontSize: 13, cursor: "pointer", background: C.paper, color: C.inkDim,
  border: `1px solid ${C.gridStrong}`, borderRadius: 2, padding: 0,
};
