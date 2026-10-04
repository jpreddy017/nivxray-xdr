/**
 * The trajectory workspace — the Cisco Secure Endpoint Device
 * Trajectory plot: a vertical axis of processes ("System") then files
 * and network artefacts ("Files & Network"), a horizontal time axis
 * with rotated tick labels, green process lifelines, grey vertical
 * lineage connectors from a parent lifeline down to its child, outline
 * activity icons, and an amber time band with a red marker above the
 * axis at a compromise event.
 *
 * Reproduced behaviours: hover tooltip, click to select, right-click to
 * pivot, drag to move through time and through activity, on-demand
 * loading with no viewport jump, icon aggregation, and dotted
 * treatment where a lifeline or a lineage is truncated.
 *
 * Wheel: the activity axis; shift or horizontal wheel: the time axis;
 * ctrl/cmd + wheel: zoom the window. Dragging, the two scrollbars and
 * the Navigator bands all remain.
 */
import React, { useCallback, useEffect, useMemo, useRef,
                useState } from "react";

import { C, ROW_H, GUTTER, AXIS_H, GROUP_SECTION, eventColor, isRed,
         typeLabel, rowTag, ticksFor } from "./ampModel";
import { INTENT, clampLaneStart, clampToBounds, createGovernor,
         normalizeWheel, panByFraction, timeAtX,
         zoomBySteps } from "./dt2";
import EventGlyph, { CompromiseMarker } from "./AmpIcons";
import { msUTC } from "./dt2/instant";

const AGG_PX = 16;

function aggregate(events, xOf) {
  const buckets = new Map();
  for (const e of events) {
    const x = xOf(e.timestamp);
    const b = Math.round(x / AGG_PX);
    const cur = buckets.get(b);
    if (!cur) {
      buckets.set(b, { x, primary: e, count: 1, members: [e],
                       red: isRed(e) });
    } else {
      cur.count += 1;
      cur.members.push(e);
      if (isRed(e) && !cur.red) { cur.red = true; cur.primary = e; }
    }
  }
  return [...buckets.values()].sort((a, b) => a.x - b.x);
}

export default function AmpCanvas({
  lanes, laneStart, rows, totalLanes, view, plotW, height, byLane,
  selected, onSelect, onView, onLaneStart, onPivot,
  observedStart = null, observedEnd = null,
  compromise = null, onCompromise,
}) {
  const [hover, setHover] = useState(null);
  const [menu, setMenu] = useState(null);
  const pan = useRef(null);
  const boxRef = useRef(null);
  const viewRef = useRef(view);
  const plotWRef = useRef(plotW);
  /** DT2-1 · one governor instance per canvas: the rolling sensitivity
   *  budget must survive across wheel events to bound a burst. */
  const govRef = useRef(null);
  if (!govRef.current) govRef.current = createGovernor();
  const pointerXRef = useRef(null);
  const boundsRef = useRef(null);
  viewRef.current = view;
  plotWRef.current = plotW;
  boundsRef.current = { min: observedStart, max: observedEnd };

  const span = Math.max(1, view.t1 - view.t0);
  const xOf = useCallback((ts) => {
    const t = typeof ts === "number" ? ts : msUTC(ts);
    return ((t - view.t0) / span) * plotW;
  }, [view.t0, span, plotW]);

  const { ticks } = useMemo(
    () => ticksFor(view.t0, view.t1, plotW,
                   Math.max(6, Math.floor(plotW / 68))),
    [view.t0, view.t1, plotW]);

  const rowOf = useMemo(() => {
    const m = new Map();
    lanes.forEach((ln) => m.set(ln.lane_index, ln.lane_index - laneStart));
    return m;
  }, [lanes, laneStart]);

  /** Compromise instants in view — Cisco marks them above the axis and
   *  bands the time column they occupy. */
  /* DT2-3c · AUTHORITATIVE compromises only. This used to band every
     row `isRed()` returned, which on this Windows corpus meant every
     Sysmon registry event that arrived as `kind=detection` — 3,100 false
     compromise bands. A compromise is what an authority concluded, so it
     now comes from the server contract and nothing else. */
  const compromises = useMemo(
    () => (compromise?.events || [])
      .filter((c) => c.observedMs != null)
      .sort((a, b) => a.observedMs - b.observedMs),
    [compromise]);

  const onMouseDown = (ev) => {
    if (ev.button !== 0) return;
    pan.current = { x0: ev.clientX, y0: ev.clientY, t0: view.t0,
                    t1: view.t1, lane0: laneStart, moved: false };
    const onMove = (e2) => {
      const p = pan.current;
      if (!p) return;
      const dx = e2.clientX - p.x0, dy = e2.clientY - p.y0;
      if (!p.moved && Math.abs(dx) < 3 && Math.abs(dy) < 3) return;
      p.moved = true;
      const dt = -(dx / Math.max(1, plotW)) * (p.t1 - p.t0);
      onView(clampToBounds({ t0: p.t0 + dt, t1: p.t1 + dt },
                           boundsRef.current).view);
      const dl = Math.round(-dy / ROW_H);
      onLaneStart(clampLaneStart(p.lane0 + dl, rows, totalLanes));
    };
    const onUp = () => {
      pan.current = null;
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  /** DT2-1 · the normalized pointer pipeline.
   *
   *   RAW WheelEvent
   *     → deltaMode normalization (PIXEL | LINE | PAGE)
   *     → device classification (mouse-like | trackpad-like)
   *     → intent (ZOOM | TIME_PAN | LANE_SCROLL)
   *     → bounded sensitivity (per-event clamp + rolling budget)
   *     → viewport transition (anchored zoom | scale-preserving pan)
   *
   *  Before DT2-1 this handler divided the RAW delta by the plot width
   *  and multiplied by the span, so a single 100 px notch moved a 24-hour
   *  window by more than three hours, and ctrl+wheel applied a 1.25
   *  factor per event — a 50-frame trackpad burst compounded to 1.25^50.
   *  Both are now impossible: pan is clamped per event and per rolling
   *  window, and zoom advances at most ONE ladder level per event with a
   *  minimum interval between commits.
   *
   *  React registers `onWheel` as PASSIVE, so preventDefault there is
   *  rejected by the browser. The listener is attached natively and
   *  non-passively, which is also what keeps the gesture inside this
   *  scroll domain instead of leaking to the page.
   */
  useEffect(() => {
    const el = boxRef.current;
    if (!el) return undefined;
    const onWheel = (e) => {
      e.preventDefault();
      e.stopPropagation();
      const n = normalizeWheel(e);
      const gov = govRef.current;
      const v = viewRef.current;
      const w = Math.max(1, plotWRef.current);
      if (n.intent === INTENT.ZOOM) {
        const steps = gov.governZoom(n.dyPx);
        if (!steps) return;
        /** Anchored on the pointer: the moment under the cursor keeps
         *  its screen position, so the investigation anchor survives. */
        const anchor = timeAtX(v, (pointerXRef.current ?? (GUTTER + w / 2))
          - GUTTER, w);
        onView(zoomBySteps(v, steps, anchor, boundsRef.current).view);
        return;
      }
      if (n.intent === INTENT.TIME_PAN) {
        const f = gov.governPan(n.panPx, w, n.source);
        if (!f) return;
        onView(panByFraction(v, f, boundsRef.current).view);
        return;
      }
      const step = gov.governLane(n.dyPx, ROW_H, n.source);
      if (!step) return;
      onLaneStart(clampLaneStart(laneStart + step, rows, totalLanes));
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [laneStart, rows, totalLanes, onLaneStart, onView]);

  const openMenu = (e, ev) => {
    e.preventDefault();
    e.stopPropagation();
    const box = boxRef.current?.getBoundingClientRect();
    setMenu({ x: e.clientX - (box?.left || 0),
              y: e.clientY - (box?.top || 0), event: ev });
    onSelect(ev);
  };

  let lastSection = null;

  return (
    <div ref={boxRef} data-testid="amp-canvas"
         style={{ position: "relative", background: C.paper,
                  overflow: "hidden", height, cursor: "default", flex: 1,
                  minWidth: 0 }}
         onMouseDown={onMouseDown}
         onMouseMove={(e) => {
           const b = boxRef.current?.getBoundingClientRect();
           pointerXRef.current = e.clientX - (b?.left || 0);
         }}
         data-dt2-scroll-domain="trajectory"
         data-dt2-gesture-map="wheel:lanes|shift-or-dx:time|ctrl-or-meta:zoom"
         data-wheel-navigation="rows|shift-time|ctrl-zoom"
         onMouseLeave={() => { setHover(null); pointerXRef.current = null; }}
         onClick={() => setMenu(null)}>
      <svg width={GUTTER + plotW} height={height} data-testid="amp-svg">
        <defs>
          {/* Time with NO SENSOR COVERAGE is hatched. An empty white
              column would claim "nothing happened here", which is a
              verdict the evidence does not support. */}
          <pattern id="amp-canvas-hatch" width={7} height={7}
                   patternUnits="userSpaceOnUse"
                   patternTransform="rotate(45)">
            <rect width={7} height={7} fill={C.paperAlt} />
            <line x1={0} y1={0} x2={0} y2={7} stroke={C.hatch}
                  strokeWidth={2.8} />
          </pattern>
        </defs>

        {/* ── outside the observed evidence range ────────────────── */}
        {(() => {
          const bands = [];
          if (observedStart != null && observedStart > view.t0) {
            bands.push(["before", GUTTER,
                        Math.min(plotW, xOf(observedStart))]);
          }
          if (observedEnd != null && observedEnd < view.t1) {
            const x = Math.max(0, xOf(observedEnd));
            bands.push(["after", GUTTER + x, plotW - x]);
          }
          return bands.filter(([, , w]) => w > 0.5).map(([k, x, w]) => (
            <g key={`hatch-${k}`}>
              <rect x={x} y={AXIS_H} width={w} height={height - AXIS_H}
                    fill="url(#amp-canvas-hatch)" pointerEvents="none"
                    data-testid={`amp-canvas-hatch-${k}`} />
              <text x={k === "before" ? x + 6 : x + 6} y={AXIS_H + 13}
                    fontSize={8.6} fill={C.inkFaint} pointerEvents="none">
                no sensor coverage
              </text>
            </g>
          ));
        })()}

        {/* ── time axis: rotated tick labels above the plot ─────── */}
        <g data-testid="amp-time-axis">
          <rect x={0} y={0} width={GUTTER + plotW} height={AXIS_H}
                fill={C.paperAlt} />
          <rect x={0} y={0} width={GUTTER} height={AXIS_H}
                fill={C.gutterBg} />
          <text x={GUTTER - 10} y={AXIS_H - 10} textAnchor="end"
                fontSize={10.6} fill={C.inkDim}
                data-testid="amp-gutter-system">
            [ {GROUP_SECTION[lanes[0]?.group] || "System"} ]
          </text>
          <line x1={0} y1={AXIS_H} x2={GUTTER + plotW} y2={AXIS_H}
                stroke={C.gridStrong} />
          {ticks.map((tk) => (
            <g key={tk.t} data-testid={`amp-tick-${tk.t}`}>
              <line x1={GUTTER + tk.x} y1={AXIS_H - 6} x2={GUTTER + tk.x}
                    y2={AXIS_H} stroke={C.gridStrong} />
              <text x={GUTTER + tk.x + 3} y={AXIS_H - 10} fontSize={9.4}
                    fill={tk.major ? C.inkDim : C.inkFaint}>
                {tk.label}
              </text>
            </g>
          ))}
        </g>

        {/* ── vertical gridlines ────────────────────────────────── */}
        {ticks.map((tk) => (
          <line key={`g-${tk.t}`} x1={GUTTER + tk.x} y1={AXIS_H}
                x2={GUTTER + tk.x} y2={height}
                stroke={C.grid} opacity={tk.major ? 1 : 0.42} />
        ))}

        {/* ── amber compromise bands + axis markers ─────────────── */}
        {compromises.map((e) => {
          const x = GUTTER + xOf(e.observedMs);
          return (
            <g key={`k-${e.compromise_event_id}`}
               data-ioc-authority={e.authority}
               data-ioc-contributors={e.contributorIds.length}
               data-testid={`amp-compromise-band-${e.compromise_event_id}`}>
              <rect x={x - 26} y={AXIS_H} width={52} height={height - AXIS_H}
                    fill={C.band} pointerEvents="none" />
              <g transform={`translate(${x},${AXIS_H - 22})`}
                 style={{ cursor: "default" }}
                 onClick={(ev) => {
                   ev.stopPropagation();
                   if (onCompromise) onCompromise(e);
                 }}
                 data-testid={
                   `amp-compromise-marker-${e.compromise_event_id}`}>
                <CompromiseMarker />
              </g>
            </g>
          );
        })}

        {/* ── selected observation · precise temporal guide ─────── */}
        {selected?.timestamp && (() => {
          const t = msUTC(selected.timestamp);
          if (!(t >= view.t0 && t <= view.t1)) return null;
          const x = GUTTER + xOf(t);
          const hhmmss = new Date(t).toISOString().slice(11, 19);
          return (
            <g pointerEvents="none" data-testid="amp-temporal-guide"
               data-at={selected.timestamp}>
              <line x1={x} y1={AXIS_H} x2={x} y2={height}
                    stroke={C.selectionStrong} strokeWidth={0.9}
                    strokeDasharray="3 2" />
              <rect x={x - 26} y={AXIS_H - 13} width={52} height={12}
                    rx={1.5} fill={C.selectionStrong} />
              <text x={x} y={AXIS_H - 4} textAnchor="middle" fontSize={8.4}
                    fill="#FFFFFF" fontWeight={700}>{hhmmss}</text>
            </g>
          );
        })()}

        {/* ── lineage connectors, drawn under the rows ──────────── */}
        <g data-testid="amp-connectors">
          {lanes.map((ln) => {
            const list = byLane.get(ln.lane_index) || [];
            const childRow = rowOf.get(ln.lane_index);
            if (childRow === undefined) return null;
            const cy = AXIS_H + childRow * ROW_H + ROW_H / 2;
            // The connector meets the child at the instant the child
            // STARTED (its first observation), not at whichever of its
            // observations happens to be first inside the window —
            // otherwise the lineage edge would point at the wrong time.
            const startTs = ln.first_seen
              || (list.length ? list[0].timestamp : null);
            if (!startTs) return null;
            const x = GUTTER + xOf(startTs);
            if (x < GUTTER - 4 || x > GUTTER + plotW + 4) return null;
            const pIdx = ln.parent_lane_index;
            if (pIdx === null || pIdx === undefined) return null;
            const inView = rowOf.has(pIdx);
            const py = inView ? AXIS_H + rowOf.get(pIdx) * ROW_H + ROW_H / 2
              : (pIdx < laneStart ? AXIS_H : height);
            // An elbow, not a bare vertical: it leaves the PARENT's
            // lifeline at the instant the child started and turns into
            // the CHILD's lifeline, so the plot reads as a tree.
            const dir = cy >= py ? 1 : -1;
            const elbow = `M ${x} ${py} L ${x} ${cy - 5 * dir} `
              + `Q ${x} ${cy} ${x + 7} ${cy}`;
            return (
              <g key={`c-${ln.lane_id}`}
                 data-testid={`amp-connector-${ln.lane_index}`}
                 data-child-lane-index={ln.lane_index}
                 data-parent-lane-index={pIdx}
                 data-parent-in-view={inView ? "true" : "false"}>
                <path d={elbow} fill="none" stroke={C.connector}
                      strokeWidth={1.1} strokeLinecap="round"
                      strokeDasharray={inView ? undefined : "2 2"} />
                {inView && (
                  <rect x={x - 1.6} y={py - 1.6} width={3.2} height={3.2}
                        fill={C.connector} />
                )}
              </g>
            );
          })}
        </g>

        {/* ── rows ─────────────────────────────────────────────── */}
        {lanes.map((ln) => {
          const r = ln.lane_index - laneStart;
          const y = AXIS_H + r * ROW_H;
          const mid = y + ROW_H / 2;
          const list = byLane.get(ln.lane_index) || [];
          const marks = aggregate(list, xOf);
          const section = GROUP_SECTION[ln.group];
          const newSection = section !== lastSection;
          lastSection = section;
          const isSelRow = selected?.lane_index === ln.lane_index;
          const f = ln.first_seen ? msUTC(ln.first_seen) : null;
          const l = ln.last_seen ? msUTC(ln.last_seen) : null;
          const lx0 = f == null ? null : GUTTER + xOf(f);
          const lx1 = l == null ? null : GUTTER + xOf(l);
          const clip0 = Math.max(GUTTER, Math.min(lx0 ?? GUTTER,
                                                  GUTTER + plotW));
          const clip1 = Math.max(GUTTER, Math.min(lx1 ?? GUTTER,
                                                  GUTTER + plotW));
          const truncL = lx0 != null && lx0 < GUTTER;
          const truncR = lx1 != null && lx1 > GUTTER + plotW;
          const label = `${ln.label || ""}`;
          const shown = label.length > 30 ? `${label.slice(0, 14)}…`
            + label.slice(-14) : label;
          return (
            <g key={ln.lane_id} data-testid={`amp-lane-${ln.lane_index}`}
               data-lane-group={ln.group}
               data-parent-state={ln.parent_state}
               data-parent-lane-index={ln.parent_lane_index}
               data-end-state={ln.end_state}>
              {/* Cisco's gutter is a tinted band; the plot stays white
                  so lifelines and icons read cleanly. */}
              <rect x={0} y={y} width={GUTTER} height={ROW_H}
                    fill={isSelRow ? C.selectionRow : C.gutterBg} />
              {isSelRow && (
                <rect x={GUTTER} y={y} width={plotW} height={ROW_H}
                      fill={C.selectionRow} />
              )}
              <line x1={0} y1={y + ROW_H} x2={GUTTER + plotW} y2={y + ROW_H}
                    stroke={C.grid} strokeWidth={0.6} />

              {/* the vertical axis is sectioned, as in the Cisco gutter:
                  [ System ] first, then [ Files & Network ] */}
              {newSection && r > 0 && (
                <line x1={0} y1={y} x2={GUTTER + plotW} y2={y}
                      stroke={C.gridStrong} strokeWidth={1.6} />
              )}
              {newSection && (
                <text x={6} y={mid + 3.2} fontSize={8.8} fill={C.inkDim}
                      fontWeight={700}
                      data-testid={`amp-section-${section}`}>
                  [ {section} ]
                </text>
              )}

              {/* lineage guides: one vertical tick per ancestor level,
                  so 15 identical process names remain traceable */}
              {ln.group === "PROCESS" && ln.depth > 0
                && Array.from({ length: Math.min(ln.depth, 10) },
                              (_, d) => (
                <line key={d} x1={8 + d * 6} y1={y} x2={8 + d * 6}
                      y2={y + ROW_H} stroke={C.grid} strokeWidth={1} />
              ))}
              {ln.group === "PROCESS" && ln.depth > 0 && (
                <line x1={8 + Math.min(ln.depth, 10) * 6 - 6} y1={mid}
                      x2={8 + Math.min(ln.depth, 10) * 6} y2={mid}
                      stroke={C.connector} strokeWidth={1} />
              )}
              <text x={GUTTER - 10} y={mid + 3.2} textAnchor="end"
                    fontSize={9.4} fill={C.ink}
                    data-testid={`amp-lane-label-${ln.lane_index}`}>
                {shown}
                {ln.pid ? (
                  <tspan fill={C.inkDim}> ({ln.pid})</tspan>
                ) : null}
                <tspan fill={C.inkFaint}> [{rowTag(ln)}]</tspan>
                <title>{`${ln.group} · ${ln.label}\n${ln.image || ""}\n`
                  + `${ln.count} observation(s)\nfirst ${ln.first_seen}`
                  + `\nlast ${ln.last_seen}\npid ${ln.pid ?? "not reported"}`
                  + `\nrow ${ln.lane_index}`
                  + ` · lineage depth ${ln.depth}`}</title>
              </text>
              {ln.malicious_count + ln.detection_count > 0 && (
                <circle cx={GUTTER - 4} cy={mid} r={2.4} fill={C.malicious}
                        data-testid={`amp-lane-red-${ln.lane_index}`} />
              )}
              <line x1={GUTTER} y1={y} x2={GUTTER} y2={y + ROW_H}
                    stroke={C.grid} />

              {/* lifeline */}
              {lx0 != null && clip1 >= GUTTER && clip0 <= GUTTER + plotW && (
                <>
                  {/* Cisco draws a process lifeline as a solid line and
                      a file / network artefact row as a dotted one. */}
                  <line x1={clip0} y1={mid}
                        x2={Math.max(clip0 + 1, clip1)} y2={mid}
                        stroke={ln.group === "PROCESS"
                          ? (list.length ? C.lifeline : C.lifelineDim)
                          : C.connector}
                        strokeWidth={2}
                        strokeDasharray={ln.group === "PROCESS"
                          ? undefined : "2 3"}
                        data-testid={`amp-lifeline-${ln.lane_index}`} />
                  {truncL && (
                    <line x1={GUTTER} y1={mid} x2={GUTTER + 16} y2={mid}
                          stroke={C.lifeline} strokeWidth={2}
                          strokeDasharray="4 3"
                          data-testid={`amp-lifeline-trunc-left-${ln.lane_index}`} />
                  )}
                  {truncR && (
                    <line x1={GUTTER + plotW - 16} y1={mid}
                          x2={GUTTER + plotW} y2={mid} stroke={C.lifeline}
                          strokeWidth={2} strokeDasharray="4 3"
                          data-testid={`amp-lifeline-trunc-right-${ln.lane_index}`} />
                  )}
                  {/* No process_exit was reported, so the lifeline is
                      OPEN: dashed to the right edge rather than closed
                      at the last observation, which would assert a
                      termination nothing observed. */}
                  {!truncR && ln.end_state === "END_NOT_OBSERVED" && (
                    <line x1={clip1} y1={mid} x2={GUTTER + plotW} y2={mid}
                          stroke={ln.group === "PROCESS" ? C.lifeline
                            : C.connector} strokeWidth={1.4}
                          strokeDasharray="3 3" opacity={0.85}
                          data-testid={`amp-lifeline-open-${ln.lane_index}`} />
                  )}
                  {ln.end_state === "EXIT_OBSERVED" && !truncR && (
                    <line x1={clip1} y1={mid - 3.4} x2={clip1} y2={mid + 3.4}
                          stroke={C.lifeline} strokeWidth={1.4}
                          data-testid={`amp-lifeline-end-${ln.lane_index}`} />
                  )}
                </>
              )}

              {/* activity marks */}
              {marks.map((m) => (
                <g key={m.primary.event_iid}
                   transform={`translate(${GUTTER + m.x},${mid})`}
                   style={{ cursor: "default" }}
                   onMouseEnter={() => setHover({ x: GUTTER + m.x, y: mid,
                                                  mark: m })}
                   onClick={(e) => { e.stopPropagation();
                                     onSelect(m.primary); }}
                   onContextMenu={(e) => openMenu(e, m.primary)}
                   data-testid={`amp-event-${m.primary.event_iid}`}>
                  <circle r={7.5} fill="transparent" />
                  <EventGlyph event={m.primary}
                              color={eventColor(m.primary)}
                              count={m.count} red={m.red}
                              selected={selected?.event_iid
                                === m.primary.event_iid} />
                </g>
              ))}
            </g>
          );
        })}

        {lanes.length === 0 && (
          <text x={GUTTER + 16} y={AXIS_H + ROW_H * 3} fontSize={11}
                fill={C.inkFaint} data-testid="amp-canvas-empty">
            No activity rows in this slice of the activity axis.
          </text>
        )}
      </svg>

      {hover && (
        <div data-testid="amp-tooltip"
             style={{ position: "absolute",
                      left: Math.min(hover.x + 12, GUTTER + plotW - 290),
                      top: hover.y + 10, pointerEvents: "none", zIndex: 30,
                      maxWidth: 290, background: "#3A4552", color: "#FFFFFF",
                      borderRadius: 3, padding: "6px 8px", fontSize: 10,
                      lineHeight: 1.45,
                      boxShadow: "0 6px 18px rgba(20,32,44,.28)" }}>
          <div style={{ fontWeight: 700 }}>
            {typeLabel(hover.mark.primary.event_type)}
            {hover.mark.count > 1
              ? ` · ${hover.mark.count} observations aggregated` : ""}
          </div>
          <div className="mono" style={{ opacity: 0.85 }}>
            {hover.mark.primary.timestamp}
          </div>
          {hover.mark.primary.command_line && (
            <div className="mono" style={{ opacity: 0.85,
                                           wordBreak: "break-all" }}>
              {String(hover.mark.primary.command_line).slice(0, 150)}
            </div>
          )}
          <div style={{ marginTop: 3, color: isRed(hover.mark.primary)
            ? "#FFB4B4" : "#BFE0F5" }}>
            {hover.mark.primary.disposition === "UNKNOWN_NOT_ASSESSED"
              ? "Unknown · not assessed by any detection engine"
              : hover.mark.primary.disposition}
          </div>
        </div>
      )}

      {menu && (
        <div data-testid="amp-context-menu"
             style={{ position: "absolute", left: menu.x, top: menu.y,
                      zIndex: 60, background: C.paper, minWidth: 248,
                      maxHeight: 420, overflowY: "auto",
                      border: `1px solid ${C.gridStrong}`, borderRadius: 3,
                      boxShadow: "0 10px 26px rgba(20,32,44,.22)" }}>
          {[["§", "Observe · sightings"],
            ["sightings", "Sightings across NivXRay XDR"],
            ["filter-indicator", "Filter trajectory by this indicator"],
            ["focus", "Focus the window on this observation"],
            ["file-trajectory", "Open fleet File Trajectory"],
            ["§", "Investigate · endpoint"],
            ["process-tree", "Open Process Tree for this process"],
            ["campaign-story", "Open Campaign Story"],
            ["§", "Investigate · NivXRay XDR"],
            ["investigate-xdr", "Investigate in NivXRay XDR"],
            ["§", "Deliberate · reputation"],
            ["⊘reputation",
             "⊘ Reputation lookup — no intelligence enricher configured"],
            ["§", "Respond · enforcement"],
            ["⊘respond", "⊘ Enforcement — no response driver registered"],
            ["§", "Refer · external"],
            ["⊘refer", "⊘ External references — no relay registered"],
            ["§", "Utility"],
            ["copy-digest", "Copy event content digest"]].map(
            ([k, label], i) => (k === "§" ? (
              <div key={`s${i}`} data-testid={`amp-menu-section-${i}`}
                   style={{ padding: "6px 10px 3px", fontSize: 8.4,
                            letterSpacing: .7, color: C.inkFaint,
                            textTransform: "uppercase",
                            borderTop: `1px solid ${C.grid}` }}>
                {label}
              </div>
            ) : k.startsWith("⊘") ? (
              /* Named absence, not a control that goes nowhere. */
              <div key={k} data-testid={`amp-menu-${k.slice(1)}`}
                   title="Capability not available in this build"
                   style={{ fontSize: 10, padding: "5px 10px",
                            color: C.inkFaint, cursor: "not-allowed" }}>
                {label}
              </div>
            ) : (
              <button key={k} data-testid={`amp-menu-${k}`}
                      onClick={() => { onPivot(k, menu.event);
                                       setMenu(null); }}
                      style={{ display: "block", width: "100%",
                               textAlign: "left", fontSize: 10.5,
                               padding: "6px 10px", background: "none",
                               border: "none", cursor: "pointer",
                               color: C.ink }}>
                {label}
              </button>
            )))}
        </div>
      )}
    </div>
  );
}
