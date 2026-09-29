/**
 * DT2-3a/3b/3c · AMP parity — the Device Trajectory graph.
 *
 * Cisco (User Guide p.401 text, p.402 figure):
 *   ‑ the vertical axis lists the FILES AND PROCESSES observed on the
 *     device, right-aligned in the gutter, with a file-type tag
 *   ‑ rows sit under permanent structural sections: `Timeline`,
 *     `System`, `Files & Network`
 *   ‑ the horizontal axis is time, with ticks anchored on the observed
 *     events plus hour reference marks
 *   ‑ a running process is a solid line; child processes and the files
 *     it acted upon stem from that line
 *   ‑ the graph scrolls with ◀ ▶ arrows on the time axis and ▲ ▼ on the
 *     rows, and returns to an off-screen selection (p.402/p.403)
 *
 * Relationships come only from the server graph. This component
 * computes geometry: it never invents an edge, a lifeline, a file row,
 * a type tag, a verdict or a compromise.
 */
import React, { useEffect, useMemo, useRef, useState } from "react";

import { activityTimeMs, axisRowsOf, edgeFor, graphBoundsOf, isCompromise,
         ROW_FILE } from "./dt2/graphModel";
import { MAX_RENDERED_LANES } from "./dt2/bounded";

const ROW = 26;
const LEFT = 232;
const AXIS = 42;
const SECTION = 19;
const PE = /\.(exe|dll|sys|scr|ocx|com)$/i;
const HOUR = 3600000;

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

const hm = (t) => new Date(t).toISOString().slice(11, 16);
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
    maliciousRow: theme.maliciousHalo || "#FDE7E9",
    ioc: theme.suspicious || "#E0A200",
    iocRow: theme.band || "rgba(224,162,0,.18)",
    lifeline: "#2FBF71",
  };

  const all = useMemo(
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
  const start = Math.max(0, Math.min(laneOffset,
                                     Math.max(0, all.length - rows)));
  const visible = all.slice(start, start + rows);
  const height = AXIS + SECTION * 2
    + Math.max(1, visible.length) * ROW + 4;
  const xOf = (t) => (t == null || !axis ? null
    : LEFT + ((t - axis.t0) / (axis.t1 - axis.t0)) * (width - LEFT - 20));

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

  // F5 · ticks anchored on the observed events, plus hour reference
  // marks. Real timestamps are never moved to make the axis look tidy.
  const ticks = (() => {
    const out = [];
    const push = (t, kind) => {
      if (t == null || t < axis.t0 || t > axis.t1) return;
      const x = xOf(t);
      if (out.some((o) => Math.abs(o.x - x) < 27)) return;
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
    for (let h = Math.ceil(axis.t0 / HOUR) * HOUR; h <= axis.t1; h += HOUR) {
      push(h, "hour");
    }
    push(axis.t0, "hour");
    return out.sort((a, b) => a.x - b.x);
  })();

  const dayMarks = [];
  const DAY = 86400000;
  for (let d = Math.floor(axis.t0 / DAY) * DAY; d <= axis.t1; d += DAY) {
    if (d >= axis.t0) dayMarks.push(d);
  }
  if (!dayMarks.length || dayMarks[0] > axis.t0) dayMarks.unshift(axis.t0);

  const sysTop = AXIS;
  const fnTop = AXIS + SECTION;
  const rowTop = AXIS + SECTION * 2;

  return (
    <div ref={box} data-testid="dt2-relationship-canvas"
         data-dt2-lane-count={all.length}
         data-dt2-rendered-lanes={visible.length}
         data-dt2-lane-offset={start}
         data-dt2-file-rows={all.filter((r) => r.kind === ROW_FILE).length}
         data-dt2-selected={selectedNodeId || ""}
         style={{ background: C.paper, flex: 1, minWidth: 0,
                  display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex" }}>
        <svg width={width} height={height} role="img"
             aria-label="device trajectory"
             style={{ display: "block" }}>
          <text x={LEFT - 10} y={AXIS - 10} textAnchor="end" fill={C.text}
                fontSize={10.6} fontWeight={700}>Timeline</text>
          {dayMarks.map((d) => {
            const x = Math.max(LEFT + 2, xOf(d) ?? LEFT + 2);
            if (x > width - 56) return null;
            return (
              <text key={`d-${d}`} x={x + 3} y={14} fill={C.text}
                    fontSize={10} fontWeight={600}>{dayName(d)}</text>
            );
          })}

          {ticks.map((tk) => (
            <g key={`${tk.kind}-${tk.t}`}>
              <line x1={tk.x} x2={tk.x} y1={AXIS} y2={height}
                    stroke={C.grid} />
              <text x={tk.x} y={AXIS - 5} fill={C.faint} fontSize={8.6}
                    textAnchor="start"
                    data-testid={`dt2-tick-${tk.kind}`}
                    transform={`rotate(-90 ${tk.x} ${AXIS - 5})`}>
                {tk.kind === "event" ? hms(tk.t) : hm(tk.t)}
              </text>
            </g>
          ))}
          <line x1={0} x2={width} y1={AXIS} y2={AXIS} stroke={C.gridStrong} />

          {/* F4 · permanent structural sections. An empty System band is
              structure, never a claim that system activity was seen. */}
          <rect x={0} y={sysTop} width={width} height={SECTION}
                fill={C.paperAlt} />
          <text x={LEFT - 10} y={sysTop + 13} textAnchor="end" fill={C.text}
                fontSize={10} fontWeight={700}
                data-testid="dt2-section-system">System</text>
          <rect x={0} y={fnTop} width={width} height={SECTION}
                fill={C.paper} />
          <text x={(LEFT - 10) / 2 + 40} y={fnTop + 13} textAnchor="middle"
                fill={C.text} fontSize={10} fontWeight={700}
                data-testid="dt2-section-files-network">
            Files &amp; Network
          </text>
          <line x1={0} x2={width} y1={rowTop} y2={rowTop} stroke={C.grid} />

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
                    d={`M ${x - 11} ${y0} V ${y1} H ${x}`} fill="none"
                    stroke={C.lifeline} strokeWidth={1} opacity={0.85} />
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
            return (
              <g key={r.nodeId} data-testid={`dt2-lane-${r.nodeId}`}
                 data-row-kind={r.kind}
                 data-lane-depth={r.depth}
                 data-lane-selected={sel ? "true" : "false"}
                 data-lane-malicious={mal ? "true" : "false"}
                 data-lifeline-semantics={r.lifeline.semantics}
                 onClick={() => onSelect?.(r)} style={{ cursor: "pointer" }}>
                <rect x={0} y={y} width={width} height={ROW}
                      fill={sel ? C.paperAlt : "transparent"} />
                {sel ? <rect x={0} y={y} width={2.5} height={ROW}
                             fill={C.line} /> : null}
                {mal || ioc ? (
                  <rect x={6} y={y + 4} width={LEFT - 18} height={ROW - 8}
                        fill={ioc ? C.iocRow : C.maliciousRow}
                        stroke={ioc ? C.ioc : C.malicious} strokeWidth={0.7}
                        data-testid={ioc ? `dt2-ioc-row-${r.nodeId}` : undefined} />
                ) : null}
                {tag ? (
                  <text x={LEFT - 10} y={mid + 3.4} textAnchor="end"
                        fill={C.faint} fontSize={9.2}>{tag}</text>
                ) : null}
                <text x={LEFT - (tag ? 33 : 10)} y={mid + 3.4}
                      textAnchor="end" fontSize={10.4}
                      fontWeight={mal || ioc ? 700 : 400}
                      fill={mal ? C.malicious : C.text}>
                  {file ? String(r.node.label).split(/[\\/]/).pop()
                        : nameOf(r.node)}
                </text>

                {x0 != null ? (
                  <g>
                    <line x1={x0} x2={Math.max(x0 + 2, x1 ?? x0 + 2)} y1={mid}
                          y2={mid} stroke={C.lifeline}
                          strokeWidth={sel ? 2.2 : 1.4}
                          strokeDasharray={file ? "2 2" : undefined} />
                    {!file && !r.lifeline.terminated ? (
                      <line x1={Math.max(x0 + 2, x1 ?? x0 + 2)} y1={mid}
                            x2={Math.min(width - 20,
                                         Math.max(x0 + 2, x1 ?? x0 + 2) + 13)}
                            y2={mid} stroke={C.lifeline} strokeWidth={1.1}
                            strokeDasharray="3 3" opacity={0.8} />
                    ) : null}
                  </g>
                ) : null}

                {r.activities.map((a) => {
                  const ax = xOf(activityTimeMs(a));
                  if (ax == null) return null;
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
                            fill={C.malicious} data-testid={tid} />
                  ) : (
                    <rect key={a.node_id} x={ax - 2.7} y={mid - 2.7}
                          width={5.4} height={5.4} fill={C.paper}
                          stroke={C.text} strokeWidth={0.9}
                          data-testid={tid} />
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
      <div style={{ display: "flex", alignItems: "center", gap: 6,
                    borderTop: `1px solid ${C.grid}`, padding: "2px 4px" }}>
        <button onClick={() => pan(-1)} data-testid="dt2-time-earlier"
                style={arrow(C)}>◀</button>
        <div style={{ flex: 1, height: 6, background: C.paperAlt,
                      border: `1px solid ${C.grid}`, borderRadius: 3 }} />
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
