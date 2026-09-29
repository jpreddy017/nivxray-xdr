/**
 * DT2-3 · Cisco AMP Device Trajectory — the trajectory graph.
 *
 * Geometry, hierarchy and controls are cloned from the Cisco reference
 * (Demo_Upatre figure; User Guide p.401 text, p.402 figure):
 *   ‑ a gutter on the left carrying `Timeline`, the `System` band, the
 *     `Files & Network` band and then one right-aligned row per file or
 *     process, tagged with its file type
 *   ‑ a date header (`Jul 25` · `Jul 26`) with a rule at each day
 *     boundary, and a rotated time scale beneath it
 *   ‑ a vertical rule separating the gutter from the plot, and a grid
 *     line at every labelled time
 *   ‑ green lifelines with stems to child processes and to the files a
 *     process acted upon, outlined activity glyphs, red compromise
 *     markers and a tinted label for an implicated row
 *   ‑ ▲ ▼ row scrolling, ◀ ▶ time scrolling, and return-to-selection
 *
 * Relationships come only from the server graph. This component computes
 * geometry: it never invents an edge, a lifeline, a file row, a type tag,
 * a verdict or a compromise.
 */
import React, { useEffect, useMemo, useRef, useState } from "react";

import { activityTimeMs, axisRowsOf, edgeFor, graphBoundsOf, isCompromise,
         rowsInWindow, ROW_FILE } from "./dt2/graphModel";
import { MAX_RENDERED_LANES } from "./dt2/bounded";
import { projectX, tickStepFor } from "./dt2/navigation";

/** Absolute metrics read off the Cisco reference figure (1366px wide):
 *  gutter rule at x=238; date header 38px; rotated time scale 48px;
 *  System band 32px; Files & Network band 40px; row pitch 18px. */
const ROW = 18;
const LEFT = 238;
const DATE_H = 38;
const TICK_H = 48;
const AXIS = DATE_H + TICK_H;
const SYS_H = 32;
const FN_H = 40;
const PE = /\.(exe|dll|sys|scr|ocx|com)$/i;

const typeTag = (n) => (PE.test(String(n?.image || n?.label || ""))
  ? "[PE]" : null);
const isMal = (n) => n?.disposition === "MALICIOUS" || n?.malicious === true
  || n?.verdict === "MALICIOUS";

const INTERNAL = /^(proc_[0-9a-f]{6,}|pnode:.*|anode:.*)$/i;
const nameOf = (n) => {
  const s = n?.label || n?.image || "";
  if (!s || INTERNAL.test(String(s))) return "Unknown process";
  return String(s).split(/[\\/]/).pop();
};

/** Text advance for the 10.6px label face, used only to size the tint
 *  behind an implicated row's name as Cisco does. */
const textW = (s) => String(s || "").length * 5.6;

const hm = (t) => new Date(t).toISOString().slice(11, 16);
const hmsms = (t) => new Date(t).toISOString().slice(11, 23);
const hms = (t) => new Date(t).toISOString().slice(11, 19);
const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
             "Oct", "Nov", "Dec"];
const dayName = (t) => {
  const d = new Date(t);
  return `${MON[d.getUTCMonth()]} ${d.getUTCDate()}`;
};

export default function RelationshipCanvas({
  graph, view, plotW = 760, rows = 18, laneOffset = 0, bounds = null,
  selectedNodeId = null, selectedEventMs = null, onSelect, onView,
  onLaneOffset, onReturnToEvent, theme = {},
}) {
  const box = useRef(null);
  const [measured, setMeasured] = useState(0);

  useEffect(() => {
    const el = box.current;
    if (!el) return undefined;
    const ro = new ResizeObserver((en) => {
      const w = en[0]?.contentRect?.width;
      if (w) setMeasured(Math.floor(w));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const C = {
    grid: theme.grid || "#E2E8F0",
    gridStrong: theme.gridStrong || "#CBD5E1",
    paper: theme.paper || "#FFFFFF",
    paperAlt: theme.paperAlt || "#F1F5F9",
    text: theme.ink || "#0F172A",
    faint: theme.inkFaint || "#64748B",
    line: theme.link || "#2563EB",
    malicious: theme.malicious || "#E5484D",
    maliciousRow: "#FBE3E4",
    ioc: theme.suspicious || "#E0A200",
    iocRow: theme.band || "rgba(224,162,0,.18)",
    lifeline: "#9CC97E",
  };

  const every = useMemo(
    () => axisRowsOf(graph, { max: MAX_RENDERED_LANES }), [graph]);
  const gb = useMemo(() => graphBoundsOf(graph), [graph]);

  const axis = useMemo(() => {
    const t0 = view?.t0 ?? gb.min;
    const t1 = view?.t1 ?? gb.max;
    if (t0 == null || t1 == null) return null;
    if (t1 - t0 > 0) return { t0, t1 };
    return { t0: t0 - 30000, t1: t1 + 30000 };
  }, [view, gb]);

  const width = Math.max(320, measured || plotW);
  /** DT2-3a.2 · only rows with evidence in the primary viewport, plus
   *  the evidenced parents needed to explain them. */
  const all = axis ? rowsInWindow(every, axis.t0, axis.t1) : every;
  const start = Math.max(0, Math.min(laneOffset,
                                     Math.max(0, all.length - rows)));
  const visible = all.slice(start, start + rows);
  const height = AXIS + SYS_H + FN_H
    + Math.max(1, rows, visible.length) * ROW + 6;
  /** X IS TIME. This is the only horizontal mapping in the component. */
  const xOf = (t) => (axis == null ? null
    : projectX(t, axis.t0, axis.t1, LEFT, width - LEFT - 20));

  const selIdx = all.findIndex((r) => r.nodeId === selectedNodeId);
  const selOff = selIdx < 0 ? 0
    : (selIdx < start ? -1 : (selIdx >= start + rows ? 1 : 0));

  const pan = (dir) => {
    if (!view || !onView) return;
    const span = view.t1 - view.t0;
    const d = dir * span * 0.25;
    let t0 = view.t0 + d;
    let t1 = view.t1 + d;
    if (bounds?.min != null && t0 < bounds.min) { t0 = bounds.min; t1 = t0 + span; }
    if (bounds?.max != null && t1 > bounds.max) { t1 = bounds.max; t0 = t1 - span; }
    onView({ t0, t1 });
  };

  if (!axis || !all.length) {
    return (
      <div ref={box} data-testid="dt2-relationships-empty"
           style={{ padding: 22, fontSize: 11.6, color: C.faint, flex: 1 }}>
        No activity to display.
      </div>
    );
  }

  // DT2-3a.2 · ticks are generated from the CURRENT PRIMARY VIEWPORT:
  // a 90ms window is labelled in milliseconds, a 13h window in hours.
  // Observed event timestamps are added exactly as recorded.
  const step = tickStepFor(axis.t1 - axis.t0);
  const ticks = (() => {
    const out = [];
    const push = (t, kind) => {
      if (t == null || t < axis.t0 || t > axis.t1) return;
      const x = xOf(t);
      if (out.some((o) => Math.abs(o.x - x) < 24)) return;
      out.push({ t, x, kind });
    };
    const evTimes = [];
    for (const r of visible) {
      if (r.lifeline?.startMs != null) evTimes.push(r.lifeline.startMs);
      for (const a of r.activities) {
        const t = activityTimeMs(a);
        if (t != null) evTimes.push(t);
      }
    }
    evTimes.sort((a, b) => a - b).forEach((t) => push(t, "event"));
    for (let m = Math.ceil(axis.t0 / step) * step; m <= axis.t1; m += step) {
      push(m, "step");
    }
    push(axis.t0, "step");
    return out.sort((a, b) => a.x - b.x);
  })();

  const dayMarks = [];
  const DAY = 86400000;
  for (let d = Math.floor(axis.t0 / DAY) * DAY; d <= axis.t1; d += DAY) {
    if (d >= axis.t0) dayMarks.push(d);
  }
  if (!dayMarks.length || dayMarks[0] > axis.t0) dayMarks.unshift(axis.t0);

  const sysTop = AXIS;
  const fnTop = AXIS + SYS_H;
  const rowTop = AXIS + SYS_H + FN_H;

  /** The bottom thumb's position over the retained period, when the
   *  retention bounds are known; otherwise it sits at the start. */
  const thumbPct = (() => {
    const min = bounds?.min;
    const max = bounds?.max;
    const span = axis.t1 - axis.t0;
    if (min == null || max == null || max - min <= span) return 0;
    return Math.min(96, Math.max(0,
      ((axis.t0 - min) / (max - min - span)) * 96));
  })();

  return (
    <div ref={box} data-testid="dt2-relationship-canvas"
         data-dt2-lane-count={all.length}
         data-dt2-rendered-lanes={visible.length}
         data-dt2-lane-offset={start}
         data-dt2-file-rows={all.filter((r) => r.kind === ROW_FILE).length}
         data-dt2-selected={selectedNodeId || ""}
         data-dt2-view-from={new Date(axis.t0).toISOString()}
         data-dt2-view-to={new Date(axis.t1).toISOString()}
         data-dt2-view-ms={axis.t1 - axis.t0}
         data-dt2-left={LEFT}
         data-dt2-drawable-width={width - LEFT - 20}
         style={{ background: C.paper, flex: 1, minWidth: 0,
                  display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex" }}>
        <svg width={width} height={height} role="img"
             aria-label="device trajectory"
             style={{ display: "block" }}>
          {/* date header · Timeline, then one label per day observed */}
          <text x={LEFT - 14} y={DATE_H - 7} textAnchor="end" fill={C.text}
                fontSize={14} fontWeight={700}>Timeline</text>
          {dayMarks.map((d) => {
            const x = Math.max(LEFT + 2, xOf(d) ?? LEFT + 2);
            if (x > width - 56) return null;
            return (
              <g key={`d-${d}`}>
                <text x={x + 6} y={DATE_H - 7} fill={C.text}
                      fontSize={14} fontWeight={700}>{dayName(d)}</text>
                <line x1={x} x2={x} y1={0} y2={height}
                      stroke={C.gridStrong} strokeWidth={1} />
              </g>
            );
          })}

          {ticks.map((tk) => (
            <g key={`${tk.kind}-${tk.t}`}>
              <line x1={tk.x} x2={tk.x} y1={DATE_H} y2={height}
                    stroke={C.grid} />
              <text x={tk.x} y={AXIS - 6} fill={C.faint} fontSize={9.4}
                    textAnchor="start"
                    data-testid={`dt2-tick-${tk.kind}`}
                    transform={`rotate(-90 ${tk.x} ${AXIS - 6})`}>
                {step < 1000 ? hmsms(tk.t)
                  : step < 60000 ? hms(tk.t) : hm(tk.t)}
              </text>
            </g>
          ))}
          {/* the gutter rule and the axis rule */}
          <line x1={LEFT} x2={LEFT} y1={0} y2={height}
                stroke={C.gridStrong} />
          <line x1={0} x2={width} y1={AXIS} y2={AXIS} stroke={C.gridStrong} />

          {/* F4 · permanent structural sections. An empty System band is
              structure, never a claim that system activity was seen. */}
          <rect x={0} y={sysTop} width={width} height={SYS_H}
                fill={C.paperAlt} />
          <text x={LEFT - 14} y={sysTop + 20} textAnchor="end" fill={C.text}
                fontSize={14} fontWeight={700}
                data-testid="dt2-section-system">System</text>
          <line x1={0} x2={width} y1={fnTop} y2={fnTop}
                stroke={C.gridStrong} />
          <rect x={0} y={fnTop} width={width} height={FN_H}
                fill={C.paper} />
          <text x={LEFT - 14} y={fnTop + 24} textAnchor="end"
                fill={C.text} fontSize={14} fontWeight={700}
                data-testid="dt2-section-files-network">
            Files &amp; Network
          </text>

          {/* stems · process→process and process→file, evidence only */}
          {visible.map((r, row) => {
            if (!r.parentNodeId) return null;
            const pRow = visible.findIndex((x) => x.nodeId === r.parentNodeId);
            if (pRow < 0) return null;
            const edge = r.kind === ROW_FILE ? r.activityEdge
              : edgeFor(graph, r.parentNodeId, r.nodeId);
            if (!edge) return null;
            const y0 = rowTop + pRow * ROW + ROW / 2;
            const y1 = rowTop + row * ROW + ROW / 2;
            const x = Math.max(LEFT + 6, xOf(r.lifeline.startMs) ?? LEFT + 6);
            return (
              <path key={`${r.nodeId}:edge`}
                    data-testid={`dt2-edge-${edge.edge_id}`}
                    data-edge-kind={r.kind === ROW_FILE ? "PROCESS_FILE"
                      : "PROCESS_PROCESS"}
                    data-edge-basis={edge.derivation_basis}
                    d={`M ${x - 9} ${y0} V ${y1} H ${x}`} fill="none"
                    stroke={C.lifeline} strokeWidth={1} />
            );
          })}

          {visible.map((r, row) => {
            const y = rowTop + row * ROW;
            const mid = y + ROW / 2;
            const x0 = xOf(r.lifeline.startMs);
            const x1 = xOf(r.lifeline.endMs);
            const sel = r.nodeId === selectedNodeId;
            const file = r.kind === ROW_FILE;
            const mal = isMal(r.node);
            const ioc = isCompromise(r.node);
            const tag = typeTag(r.node);
            const label = file ? String(r.node.label).split(/[\\/]/).pop()
              : nameOf(r.node);
            const tintW = textW(label) + (tag ? 30 : 0) + 12;
            return (
              <g key={r.nodeId} data-testid={`dt2-lane-${r.nodeId}`}
                 data-row-kind={r.kind}
                 data-lane-depth={r.depth}
                 data-lane-selected={sel ? "true" : "false"}
                 data-lane-malicious={mal ? "true" : "false"}
                 data-lifeline-semantics={r.lifeline.semantics}
                 data-row-start-iso={r.lifeline.startMs != null
                   ? new Date(r.lifeline.startMs).toISOString() : ""}
                 data-row-start-x={x0 != null ? x0.toFixed(2) : ""}
                 data-row-end-iso={r.lifeline.endMs != null
                   ? new Date(r.lifeline.endMs).toISOString() : ""}
                 data-row-end-x={x1 != null ? x1.toFixed(2) : ""}
                 data-row-terminated={r.lifeline.terminated ? "true" : "false"}
                 data-row-y={mid.toFixed(2)}
                 onClick={() => onSelect?.(r)} style={{ cursor: "pointer" }}>
                <rect x={0} y={y} width={width} height={ROW}
                      fill={sel ? C.paperAlt : "transparent"} />
                {sel ? <rect x={0} y={y} width={2.5} height={ROW}
                             fill={C.line} /> : null}
                {mal || ioc ? (
                  <rect x={Math.max(4, LEFT - 8 - tintW)} y={y + 3}
                        width={Math.min(tintW, LEFT - 12)} height={ROW - 6}
                        fill={ioc ? C.iocRow : C.maliciousRow}
                        data-testid={ioc ? `dt2-ioc-row-${r.nodeId}` : undefined} />
                ) : null}
                {/* Cisco writes the row as `name [TYPE]`, right-aligned
                    against the gutter edge, the tag in a lighter face. */}
                <text x={LEFT - 14} y={mid + 3.8} textAnchor="end"
                      fontSize={12}
                      fontWeight={mal || ioc ? 600 : 400}
                      fill={mal ? C.malicious : C.text}>
                  {label}
                  {tag ? (
                    <tspan fill={mal ? C.malicious : C.faint} fontSize={11}>
                      {` ${tag}`}
                    </tspan>
                  ) : null}
                </text>

                {x0 != null ? (
                  <g>
                    <line x1={x0} x2={Math.max(x0 + 2, x1 ?? x0 + 2)} y1={mid}
                          y2={mid} stroke={C.lifeline}
                          strokeWidth={sel ? 2 : 1.3}
                          strokeDasharray={file ? "2 2" : undefined} />
                    {!file && !r.lifeline.terminated ? (
                      <line x1={Math.max(x0 + 2, x1 ?? x0 + 2)} y1={mid}
                            x2={Math.min(width - 20,
                                         Math.max(x0 + 2, x1 ?? x0 + 2) + 13)}
                            y2={mid} stroke={C.lifeline} strokeWidth={1}
                            strokeDasharray="3 3" opacity={0.8} />
                    ) : null}
                    {/* Cisco marks the row's own observed moment with a
                        glyph. Without it a row whose evidence is a single
                        instant draws a 2px line and reads as empty. */}
                    {!file && !r.activities.some((a) => {
                      const at = xOf(activityTimeMs(a));
                      return at != null && Math.abs(at - x0) < 2;
                    }) ? (
                      <rect x={x0 - 5.5} y={mid - 5.5} width={11} height={11}
                            fill={C.paper} stroke={C.faint} strokeWidth={0.9}
                            data-testid={`dt2-row-start-${r.nodeId}`} />
                    ) : null}
                  </g>
                ) : null}

                {r.activities.map((a) => {
                  const ams = activityTimeMs(a);
                  const ax = xOf(ams);
                  if (ax == null) return null;
                  const aIso = new Date(ams).toISOString();
                  const aIoc = isCompromise(a);
                  const aMal = isMal(a);
                  const tid = `dt2-activity-${a.family}-${a.node_id}`;
                  if (aIoc) {
                    return (
                      <g key={a.node_id} data-testid={tid}
                         data-compromise="true">
                        <rect x={ax - 5} y={mid - 5} width={10} height={10}
                              fill={C.iocRow} stroke={C.ioc} strokeWidth={1}
                              data-testid={`dt2-ioc-mark-${a.node_id}`} />
                        <circle cx={ax} cy={mid} r={2.4}
                                fill={C.malicious} />
                      </g>
                    );
                  }
                  return aMal ? (
                    <circle key={a.node_id} cx={ax} cy={mid} r={3.3}
                            fill={C.malicious} data-testid={tid}
                            data-activity-iso={aIso}
                            data-activity-x={ax.toFixed(2)}
                            data-activity-y={mid.toFixed(2)} />
                  ) : (
                    <rect key={a.node_id} x={ax - 5.5} y={mid - 5.5}
                          width={11} height={11} fill={C.paper}
                          stroke={C.faint} strokeWidth={0.9}
                          data-testid={tid}
                          data-activity-iso={aIso}
                          data-activity-x={ax.toFixed(2)}
                          data-activity-y={mid.toFixed(2)} />
                  );
                })}
              </g>
            );
          })}
        </svg>

        {/* F6 · row scrollbar with Cisco's ▲ ▼ buttons */}
        <div style={{ width: 15, display: "flex", flexDirection: "column",
                      borderLeft: `1px solid ${C.grid}`,
                      background: C.paperAlt }}>
          <button onClick={() => onLaneOffset?.(Math.max(0, start - 1))}
                  data-testid="dt2-rows-up" style={arrow(C)}>▲</button>
          <div style={{ flex: 1 }} />
          <button onClick={() => onLaneOffset?.(
                    Math.min(Math.max(0, all.length - rows), start + 1))}
                  data-testid="dt2-rows-down" style={arrow(C)}>▼</button>
        </div>
      </div>

      {/* F6 · time axis scroll with ◀ ▶, and Cisco's return-to-selection */}
      <div style={{ display: "flex", alignItems: "center", gap: 8,
                    marginLeft: LEFT, paddingRight: 6,
                    borderTop: `1px solid ${C.grid}`, height: 22 }}>
        <button onClick={() => pan(-1)} data-testid="dt2-time-earlier"
                style={arrow(C)}>◀</button>
        <div style={{ flex: 1, height: 9, position: "relative" }}>
          <div style={{ position: "absolute", left: `${thumbPct}%`,
                        width: 28, height: 9, borderRadius: 5,
                        background: C.gridStrong }} />
        </div>
        <button onClick={() => pan(1)} data-testid="dt2-time-later"
                style={arrow(C)}>▶</button>
        {selOff !== 0 && (
          <button data-testid="dt2-return-to-row"
                  title="Return to the selected row"
                  onClick={() => onLaneOffset?.(Math.max(
                    0, Math.min(selIdx, Math.max(0, all.length - rows))))}
                  style={{ ...arrow(C), width: "auto", padding: "0 6px" }}>
            {selOff < 0 ? "▲" : "▼"} selected row
          </button>
        )}
        {selectedEventMs != null && axis
          && (selectedEventMs < axis.t0 || selectedEventMs > axis.t1) && (
          <button data-testid="dt2-return-to-event"
                  title="Return to the selected event"
                  onClick={() => onReturnToEvent?.()}
                  style={{ ...arrow(C), width: "auto", padding: "0 6px" }}>
            ◀ selected event
          </button>
        )}
      </div>
    </div>
  );
}

const arrow = (C) => ({
  width: 15, height: 14, lineHeight: "12px", fontSize: 8, padding: 0,
  cursor: "pointer", background: C.paper, color: C.faint,
  border: `1px solid ${C.grid}`, borderRadius: 2, whiteSpace: "nowrap",
});
