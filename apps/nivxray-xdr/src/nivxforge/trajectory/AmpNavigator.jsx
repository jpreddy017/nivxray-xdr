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
import { ChevronDown, ChevronRight } from "lucide-react";

import { C, DAY_MS, MONTHS, startOfDayUTC,
         dayKeyOf } from "./ampModel";
import { moveRange } from "./dt2";
import { msUTC } from "./dt2/instant";
import { MODES, calendarDayWindow, domainLabel, hourMarks, utcDayStart } from "./dt2/timeWindow.mjs";

const DAYS = 30;
const PAD = 9;
const HOUR_H = 72;

/** Dot radius relative to the number of events per day, log-damped so one
 *  busy day does not erase 29 others. */
const dens = (n, max) => (!n ? 0
  : Math.log1p(n) / Math.log1p(Math.max(1, max)));

export default function AmpNavigator({
  days, bins = null, selectedDay, onSelectDay, view, onView, observedEnd,
  onFocusTime, collapsed, onCollapsed, bounds = null, header = null,
  searchActive = false, domain = null, refNow = null, status = null,
  unloaded = null,
}) {
  const dayBins = bins || [];
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
    // Day strip ends at the REFERENCE day, never at the newest evidence day (backlog-safe).
    const anchor = utcDayStart(Number.isFinite(refNow) ? refNow : Date.now());
    const out = [];
    for (let i = DAYS - 1; i >= 0; i -= 1) {
      const ms = anchor - i * DAY_MS;
      const rec = byDay.get(dayKeyOf(ms)) || { total: 0, malicious: 0,
                                               suspicious: 0, detections: 0,
                                               compromises: 0 };
      out.push({ ms, key: dayKeyOf(ms), ...rec, d: new Date(ms) });
    }
    return out;
  }, [byDay, refNow]);

  const maxTotal = Math.max(1, ...cells.map((c) => c.total));
  const dayStart = selectedDay ?? cells[cells.length - 1]?.ms
    ?? startOfDayUTC(Date.now());
  // The band domain is the explicit time model (rolling or calendar), never an implied day.
  const band = domain || calendarDayWindow(dayStart);
  const bandStart = band.t0, bandEnd = band.t1, bandSpan = Math.max(1, band.t1 - band.t0);
  const calendar = band.mode === MODES.CALENDAR_DAY;
  const marks = useMemo(() => hourMarks(band), [bandStart, bandEnd]); // eslint-disable-line react-hooks/exhaustive-deps

  const innerW = Math.max(1, hourW - PAD * 2);
  const xOfHour = useCallback((t) => PAD + ((Math.min(Math.max(t, bandStart),
    bandEnd) - bandStart) / bandSpan) * innerW, [bandStart, bandEnd, bandSpan, innerW]);
  const tOfX = useCallback((x) => bandStart + ((Math.min(Math.max(x, PAD),
    PAD + innerW) - PAD) / innerW) * bandSpan, [bandStart, bandSpan, innerW]);

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
      const dMs = ((ev.clientX - st.px) / innerW) * bandSpan;
      const moved = moveRange({ t0: st.vs, t1: st.ve }, dMs, bounds);
      onView({ ...moved.view, mode: MODES.ANALYST });
      const d = startOfDayUTC(moved.view.t0);
      if (calendar && d !== dayStart) onSelectDay(d);
    };
    const onUp = (ev) => {
      if (!st.moved && dayBins.length) {
        const rect = hourRef.current?.getBoundingClientRect();
        const lx = (ev?.clientX ?? st.px) - (rect?.left ?? 0);
        const t = tOfX(lx);
        let best = null;
        for (const b of dayBins) {
          const d = Math.abs(msUTC(b.first_timestamp) - t);
          if (!best || d < best.d) best = { d, b };
        }
        if (best) {
          onFocusTime(msUTC(best.b.first_timestamp),
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

  const maxBin = Math.max(1, ...dayBins.map((b) => b.total));
  const hasRef = Number.isFinite(refNow);
  //: the selected column is the explicit calendar day; otherwise every day the domain overlaps
  const inBand = (ms) => (calendar ? ms === dayStart
    : ms + DAY_MS > bandStart && ms < bandEnd);

  const onDayClick = (cell) => {
    onSelectDay(cell.ms);
    onView(calendarDayWindow(cell.ms));
  };

  const sel = new Date(dayStart);

  if (collapsed) {
    return (
      <section data-testid="amp-navigator" data-collapsed="true"
               style={{ background: "transparent" }}>
        {header || null}
        {/* Cisco: expand by clicking the ribbon or the chevron */}
        <div data-testid="amp-navigator-ribbon"
             onClick={() => onCollapsed(false)}
             style={{ display: "flex", alignItems: "center", gap: 10,
                      padding: "6px 0", cursor: "pointer" }}>
          <button onClick={(e) => { e.stopPropagation(); onCollapsed(false); }}
                  data-testid="amp-navigator-expand"
                  title="Expand the navigator"
                  style={collapseBtn}>
            <ChevronRight size={16} />
          </button>
          <div style={{ flex: 1, height: 3, background: C.link,
                        opacity: 0.55, borderRadius: 2 }} />
        </div>
      </section>
    );
  }

  return (
    <section data-testid="amp-navigator" data-collapsed="false"
             style={{ background: "transparent", height: "100%",
                      display: "flex", flexDirection: "column" }}>
      {header || null}
      <div style={{ padding: "6px 0 2px", display: "flex", gap: 10 }}>
        {/* F3 · Cisco places the collapse chevron at the left of the
            ribbon, vertically centred against it. */}
        <button onClick={() => onCollapsed(true)}
                data-testid="amp-navigator-collapse"
                title="Collapse the navigator"
                style={{ ...collapseBtn, alignSelf: "center" }}>
          <ChevronDown size={16} />
        </button>
        <div style={{ flex: 1, minWidth: 0, display: "flex",
                      flexDirection: "column", gap: 0 }}>

        {/* 30-day ribbon */}
        <div style={{ display: "grid",
                      gridTemplateColumns: `repeat(${DAYS}, 1fr)` }}
             data-testid="amp-nav-day-band">
          {cells.map((c) => {
            const active = inBand(c.ms);
            const has = c.total > 0;
            /** Cisco: red dots are compromise events, blue dots are
             *  search results, sized relative to the day's events. A red
             *  dot requires an AUTHORITATIVE compromise — a malicious
             *  disposition or a server-declared `compromise_authority`.
             *  A telemetry kind named "detection" earns nothing: on
             *  Windows, Sysmon registry events arrive as kind=detection,
             *  and 2431 of them are not 2431 compromises. */
            const red = c.malicious + (c.compromises || 0);
            const blue = !red && searchActive && c.total > 0;
            const r = (red || blue) ? 3 + dens(c.total, maxTotal) * 4 : 0;
            return (
              <button key={c.key} onClick={() => onDayClick(c)}
                      data-testid={`amp-nav-day-${c.key}`}
                      data-observations={c.total}
                      data-compromise={red}
                      data-selected={active ? "true" : "false"}
                      data-reference-day={hasRef && c.ms === startOfDayUTC(refNow)
                        ? "true" : "false"}
                      title={`${c.total} event(s) on ${c.key}`
                        + (red ? ` · ${red} compromise event(s)` : "")}
                      style={{ height: 28, padding: 0, position: "relative",
                               cursor: has ? "pointer" : "default",
                               background: active ? C.paper : C.paper,
                               borderStyle: "solid",
                               borderColor: active ? C.selectionStrong
                                 : C.grid,
                               borderWidth: active ? "1px 1.5px" : "1px 0.5px",
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
        {/* Cisco: the selected day column stays tinted from the day cell
            through its labels and into the 24-hour band. */}
        <div style={{ display: "grid",
                      gridTemplateColumns: `repeat(${DAYS}, 1fr)` }}>
          {cells.map((c) => (
            <div key={c.key}
                 style={{ fontSize: 15, textAlign: "center", paddingTop: 5,
                          background: inBand(c.ms) ? C.selectionRow
                            : "transparent",
                          color: inBand(c.ms) ? C.selectionStrong
                            : C.inkDim,
                          fontWeight: inBand(c.ms) ? 700 : 400 }}>
              {c.d.getUTCDate()}
            </div>
          ))}
        </div>
        {/* month name under the day the month begins, as Cisco labels it */}
        <div style={{ display: "grid",
                      gridTemplateColumns: `repeat(${DAYS}, 1fr)` }}>
          {cells.map((c, i) => (
            <div key={`m-${c.key}`}
                 style={{ fontSize: 13, color: C.inkDim,
                          background: inBand(c.ms) ? C.selectionRow
                            : "transparent",
                          textAlign: "center", whiteSpace: "nowrap",
                          paddingBottom: 4 }}>
              {i === 0 || c.d.getUTCDate() === 1
                ? MONTHS[c.d.getUTCMonth()] : ""}
            </div>
          ))}
        </div>

        {/* 24-hour ribbon for the selected day */}
        <div ref={hourRef} style={{ width: "100%", marginTop: 4 }}>
          <svg width={hourW} height={HOUR_H}
               style={{ display: "block", touchAction: "none" }}
               data-dragging={drag ? "band" : "none"}
               data-testid="amp-nav-hour-band"
               data-domain-mode={band.mode}
               data-domain-from={new Date(bandStart).toISOString()}
               data-domain-to={new Date(bandEnd).toISOString()}>
            <defs>
              <pattern id="amp-nav-future-hatch" width="6" height="6"
                       patternUnits="userSpaceOnUse"
                       patternTransform="rotate(45)">
                <line x1="0" y1="0" x2="0" y2="6" stroke={C.inkDim}
                      strokeWidth="1.2" opacity="0.55" />
              </pattern>
            </defs>
            <rect x={PAD} y={0} width={innerW} height={HOUR_H}
                  fill={C.selectionRow} stroke={C.selection}
                  strokeWidth={0.8} />
            {view && (
              <rect x={Math.min(xs, xe)} y={0}
                    width={Math.max(2, Math.abs(xe - xs))} height={30}
                    fill={C.paper} stroke={C.selectionStrong}
                    strokeWidth={0.8} pointerEvents="none"
                    data-testid="amp-nav-window-region" />
            )}
            {/* after the reference time: not yet occurred — never "no activity" */}
            {unloaded && unloaded.to > bandStart && unloaded.from < bandEnd && (
              <rect x={xOfHour(Math.max(unloaded.from, bandStart))} y={0}
                    width={Math.max(0, xOfHour(Math.min(unloaded.to, bandEnd))
                      - xOfHour(Math.max(unloaded.from, bandStart)))}
                    height={30} fill={C.suspicious} opacity={0.14}
                    pointerEvents="none" data-testid="amp-nav-unloaded">
                <title>Not delivered (per-request cap) — not absent</title>
              </rect>
            )}
            {hasRef && refNow < bandEnd && (
              <rect x={xOfHour(Math.max(refNow, bandStart))} y={0}
                    width={Math.max(0, xOfHour(bandEnd)
                      - xOfHour(Math.max(refNow, bandStart)))}
                    height={30} fill="url(#amp-nav-future-hatch)"
                    pointerEvents="none" data-testid="amp-nav-future">
                <title>After the reference time: not yet occurred</title>
              </rect>
            )}
            {hasRef && refNow >= bandStart && refNow <= bandEnd && (
              <line x1={xOfHour(refNow)} x2={xOfHour(refNow)} y1={0} y2={36}
                    stroke={C.link} strokeWidth={1.6}
                    data-testid="amp-nav-now"
                    data-iso={new Date(refNow).toISOString()} />
            )}

            {marks.filter((m) => m.t > bandStart && m.t < bandEnd).map((m) => (
              <line key={m.t} x1={xOfHour(m.t)} y1={0} x2={xOfHour(m.t)} y2={30}
                    stroke={C.selection} strokeWidth={m.midnight ? 1.4 : 0.5}
                    opacity={m.midnight ? 0.9 : 0.45} />
            ))}

            {dayBins.map((b) => {
              const x = xOfHour(b.mid);
              //: authoritative only — see the day band above
              const red = b.malicious + (b.compromises || 0) > 0;
              const r = 2.4 + dens(b.total, maxBin) * 3;
              return (
                <circle key={b.key} cx={x} cy={15} r={r}
                        fill={red ? C.malicious : C.telemetry}
                        data-compromises={b.compromises || 0}
                        data-bin-start={new Date(b.t).toISOString()}
                        data-testid={`amp-nav-bin-${calendar ? b.bin : b.key}`}>
                  <title>{`${b.total} event(s) · `
                    + `${b.first_timestamp}`
                    + (b.compromises
                      ? ` · ${b.compromises} compromise event(s) · `
                        + `${b.first_compromise_at}` : "")}</title>
                </circle>
              );
            })}

            {dayBins.map((b) => (
              <rect key={`hit-${b.key}`}
                    x={xOfHour(b.mid) - 3} y={0}
                    width={7} height={30} fill="transparent"
                    onClick={() => onFocusTime(
                      msUTC(b.first_timestamp), b.first_event_iid)}
                    data-testid={`amp-nav-bin-hit-${calendar ? b.bin : b.key}`}>
                <title>{`${b.total} event(s) · ${b.first_timestamp}`}</title>
              </rect>
            ))}

            {/* Cisco keeps the hour scale INSIDE the band, 0:00 … 24,
                with the selected date under the first label. */}
            {marks.filter((m, i) => calendar || m.midnight || i % 2 === 0).map((m) => (
              <text key={`h-${m.t}`}
                    x={Math.min(xOfHour(m.t) + 2, PAD + innerW - 2)}
                    y={50} fontSize={m.midnight ? 12 : 13} fill={m.midnight ? C.ink : C.inkDim}
                    fontWeight={m.midnight ? 700 : 400}
                    textAnchor={m.t >= bandEnd ? "end" : "start"}
                    data-testid={`amp-nav-hour-label-${m.hour}`} data-iso={new Date(m.t).toISOString()}>
                {calendar && m.hour === 0 ? (m.t === bandStart ? "0:00" : "24") : m.label}
              </text>
            ))}
            <text x={PAD + 2} y={66} fontSize={13} fill={C.inkDim}
                  data-testid="amp-nav-day-label" data-mode={band.mode}>
              {calendar ? `${MONTHS[sel.getUTCMonth()]} ${sel.getUTCDate()}` : domainLabel(band)}
            </text>

            <rect x={PAD} y={0} width={innerW} height={30}
                  fill="transparent"
                  onPointerDown={down} onMouseDown={down}
                  data-testid="amp-nav-band" />
          </svg>
          {status}
        </div>
        </div>
      </div>
    </section>
  );
}

const collapseBtn = {
  width: 20, height: 20, display: "flex", alignItems: "center",
  justifyContent: "center", cursor: "pointer", background: "transparent",
  color: C.inkDim, border: "none", padding: 0, flexShrink: 0,
};
