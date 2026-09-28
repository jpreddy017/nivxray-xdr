/**
 * DT2-3a · AMP parity — the Device Trajectory graph.
 *
 * Cisco (User Guide p.401 text, p.402 figure):
 *   ‑ the vertical axis lists the files and processes observed on the
 *     device, right-aligned in the gutter, with a file-type tag
 *   ‑ the horizontal axis is time, ticks rotated above the plot, with the
 *     date named per column
 *   ‑ a running process is a solid horizontal line; child processes and
 *     the files it acted upon stem from that line
 *   ‑ rows are grouped under section labels (`System`, `Files & Network`)
 *
 * Relationships still come only from `dt2.graph` (DT2-2E). This component
 * computes geometry and never invents an edge, a lifeline, a type tag or a
 * verdict. What cannot be substantiated is simply not drawn.
 *
 * Process/file rows on the vertical axis are DT2-3b; this pass presents
 * the process rows Cisco's way.
 */
import React, { useMemo } from "react";

import { activityTimeMs, edgeFor, graphBoundsOf,
         laneRowsOf } from "./dt2/graphModel";
import { MAX_RENDERED_LANES } from "./dt2/bounded";

const ROW = 30;
const LEFT = 232;
const AXIS = 40;
const SECTION = 20;
const PE = /\.(exe|dll|sys|scr|ocx|com)$/i;

/** Cisco's `[PE]` tag, from the real artefact name only. */
const typeTag = (n) => (PE.test(String(n?.image || n?.label || ""))
  ? "[PE]" : null);

/** A row is styled malicious only where a real verdict says so. */
const isMal = (n) => n?.disposition === "MALICIOUS" || n?.malicious === true
  || n?.verdict === "MALICIOUS";

/** The artefact name. An internal node identifier is never a label: where
 *  the sensor reported no image, the row says so instead of exposing
 *  `proc_…` / `pnode:…` as if it were a process name. */
const INTERNAL = /^(proc_[0-9a-f]{6,}|pnode:.*|anode:.*)$/i;
const nameOf = (n) => {
  const s = n?.label || n?.image || "";
  if (!s || INTERNAL.test(String(s))) return "Unknown process";
  return String(s).split(/[\\/]/).pop();
};

const hm = (t) => new Date(t).toISOString().slice(11, 16);
const dayName = (t) => {
  const d = new Date(t);
  return `${["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
             "Oct", "Nov", "Dec"][d.getUTCMonth()]} ${d.getUTCDate()}`;
};

export default function RelationshipCanvas({
  graph, view, plotW = 760, rows = 18, laneOffset = 0,
  selectedNodeId = null, onSelect, theme = {},
}) {
  const box = React.useRef(null);
  const [measured, setMeasured] = React.useState(0);

  // Cisco's graph fills its pane; measure rather than inherit the legacy
  // canvas's gutter arithmetic.
  React.useEffect(() => {
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
    grid: theme.grid || "#22303c",
    gridStrong: theme.gridStrong || theme.grid || "#2b3b48",
    paper: theme.paper || "#0d1620",
    paperAlt: theme.paperAlt || "#111d28",
    text: theme.ink || theme.text || "#d7e3ec",
    faint: theme.inkFaint || theme.faint || "#6d8291",
    line: theme.link || "#4aa8d8",
    malicious: theme.malicious || "#E5484D",
    maliciousRow: theme.maliciousHalo || "#2A1417",
    lifeline: "#2FBF71",
  };

  const lanes = useMemo(
    () => laneRowsOf(graph, { max: MAX_RENDERED_LANES }), [graph]);
  const gb = useMemo(() => graphBoundsOf(graph), [graph]);

  const axis = useMemo(() => {
    const t0 = view?.t0 ?? gb.min;
    const t1 = view?.t1 ?? gb.max;
    if (t0 == null || t1 == null) return null;
    if (t1 - t0 > 0) return { t0, t1, instant: false };
    return { t0: t0 - 30000, t1: t1 + 30000, instant: true };
  }, [view, gb]);

  const width = Math.max(320, measured || plotW);
  const height = AXIS + SECTION
    + Math.max(3, Math.min(lanes.length, rows)) * ROW;
  const xOf = (t) => (t == null || !axis ? null
    : LEFT + ((t - axis.t0) / (axis.t1 - axis.t0)) * (width - LEFT - 18));

  if (!axis || !lanes.length) {
    return (
      <div data-testid="dt2-relationships-empty"
           style={{ padding: 22, fontSize: 11.6, color: C.faint }}>
        No activity to display.
      </div>
    );
  }

  const ticks = 6;
  const start = Math.max(0, Math.min(laneOffset,
                                     Math.max(0, lanes.length - rows)));
  const visible = lanes.slice(start, start + rows);

  // date columns: the window's own day boundaries, never interpolated
  const dayMarks = [];
  const DAY = 86400000;
  const first = Math.floor(axis.t0 / DAY) * DAY;
  for (let d = first; d <= axis.t1; d += DAY) {
    if (d >= axis.t0) dayMarks.push(d);
  }
  if (!dayMarks.length || dayMarks[0] > axis.t0) dayMarks.unshift(axis.t0);

  return (
    <div ref={box} data-testid="dt2-relationship-canvas"
         data-dt2-lane-count={lanes.length}
         data-dt2-rendered-lanes={visible.length}
         data-dt2-lane-offset={start}
         data-dt2-axis-instant={axis.instant ? "true" : "false"}
         data-dt2-selected={selectedNodeId || ""}
         style={{ background: C.paper, overflow: "hidden", flex: 1,
                  minWidth: 0 }}>
      <svg width={width} height={height} role="img"
           aria-label="device trajectory">
        {/* gutter header + date columns */}
        <text x={8} y={AXIS - 9} fill={C.text} fontSize={10.6}
              fontWeight={600}>Timeline</text>
        {dayMarks.map((d) => {
          const x = Math.max(LEFT + 2, xOf(d) ?? LEFT + 2);
          if (x > width - 54) return null;          // would be clipped
          return (
            <text key={`d-${d}`} x={x + 3} y={13} fill={C.text}
                  fontSize={10}>{dayName(d)}</text>
          );
        })}

        {/* rotated time ticks */}
        {Array.from({ length: ticks + 1 }).map((_, i) => {
          const t = axis.t0 + ((axis.t1 - axis.t0) * i) / ticks;
          const x = xOf(t);
          return (
            <g key={i}>
              <line x1={x} x2={x} y1={AXIS} y2={height} stroke={C.grid} />
              <text x={x} y={AXIS - 5} fill={C.faint} fontSize={8.8}
                    textAnchor="start"
                    transform={`rotate(-90 ${x} ${AXIS - 5})`}>
                {hm(t)}
              </text>
            </g>
          );
        })}
        <line x1={0} x2={width} y1={AXIS} y2={AXIS} stroke={C.gridStrong} />

        {/* Cisco's row section band */}
        <rect x={0} y={AXIS} width={width} height={SECTION}
              fill={C.paperAlt} />
        <text x={8} y={AXIS + 14} fill={C.faint} fontSize={10}
              data-testid="dt2-section-files-network">Files &amp; Network</text>
        <line x1={0} x2={width} y1={AXIS + SECTION} y2={AXIS + SECTION}
              stroke={C.grid} />

        {/* parent → child stems · only where an edge exists in evidence */}
        {visible.map((lane, row) => {
          if (!lane.parentNodeId) return null;
          const parentRow = visible.findIndex(
            (l) => l.nodeId === lane.parentNodeId);
          if (parentRow < 0) return null;
          const edge = edgeFor(graph, lane.parentNodeId, lane.nodeId);
          if (!edge) return null;
          const y0 = AXIS + SECTION + parentRow * ROW + ROW / 2;
          const y1 = AXIS + SECTION + row * ROW + ROW / 2;
          const x = Math.max(LEFT + 6, xOf(lane.lifeline.startMs) ?? LEFT + 6);
          return (
            <path key={lane.nodeId + ":edge"}
                  data-testid={`dt2-edge-${edge.edge_id}`}
                  data-edge-basis={edge.derivation_basis}
                  data-edge-downgraded={String(Boolean(edge.downgraded))}
                  d={`M ${x - 12} ${y0} V ${y1} H ${x}`} fill="none"
                  stroke={C.lifeline} strokeWidth={1} opacity={0.8} />
          );
        })}

        {/* rows */}
        {visible.map((lane, row) => {
          const y = AXIS + SECTION + row * ROW;
          const mid = y + ROW / 2;
          const x0 = xOf(lane.lifeline.startMs);
          const x1 = xOf(lane.lifeline.endMs);
          const sel = lane.nodeId === selectedNodeId;
          const n = lane.node;
          const mal = isMal(n);
          const tag = typeTag(n);
          const label = nameOf(n);
          return (
            <g key={lane.nodeId} data-testid={`dt2-lane-${lane.nodeId}`}
               data-lane-depth={lane.depth}
               data-lane-selected={sel ? "true" : "false"}
               data-lane-malicious={mal ? "true" : "false"}
               data-lifeline-semantics={lane.lifeline.semantics}
               onClick={() => onSelect?.(lane)}
               style={{ cursor: "pointer" }}>
              <rect x={0} y={y} width={width} height={ROW}
                    fill={sel ? C.paperAlt : "transparent"} />
              {sel ? <rect x={0} y={y} width={2.5} height={ROW}
                           fill={C.line} /> : null}
              {/* right-aligned gutter label with the file-type tag */}
              {mal ? (
                <rect x={6} y={y + 5} width={LEFT - 18} height={ROW - 10}
                      fill={C.maliciousRow} stroke={C.malicious}
                      strokeWidth={0.7} />
              ) : null}
              {tag ? (
                <text x={LEFT - 10} y={mid + 3.6} textAnchor="end"
                      fill={C.faint} fontSize={9.4}>{tag}</text>
              ) : null}
              <text x={LEFT - (tag ? 34 : 10)} y={mid + 3.6} textAnchor="end"
                    fill={mal ? C.malicious : C.text} fontSize={10.6}>
                {label}
              </text>

              {/* solid lifeline; a trailing dash only where no exit was
                  observed — never an invented termination */}
              {x0 != null ? (
                <g>
                  <line x1={x0} x2={Math.max(x0 + 2, x1 ?? x0 + 2)} y1={mid}
                        y2={mid} stroke={C.lifeline}
                        strokeWidth={sel ? 2.2 : 1.5} />
                  {!lane.lifeline.terminated ? (
                    <line x1={Math.max(x0 + 2, x1 ?? x0 + 2)} y1={mid}
                          x2={Math.min(width - 18,
                                       Math.max(x0 + 2, x1 ?? x0 + 2) + 14)}
                          y2={mid} stroke={C.lifeline} strokeWidth={1.2}
                          strokeDasharray="3 3" opacity={0.8} />
                  ) : null}
                </g>
              ) : null}

              {/* events on the lifeline: small squares, red for malicious */}
              {lane.activities.map((a) => {
                const ax = xOf(activityTimeMs(a));
                if (ax == null) return null;
                const red = isMal(a);
                return red ? (
                  <circle key={a.node_id} cx={ax} cy={mid} r={3.4}
                          fill={C.malicious}
                          data-testid={`dt2-activity-${a.family}-${a.node_id}`}
                          data-activity-process={a.process_node_id} />
                ) : (
                  <rect key={a.node_id} x={ax - 2.8} y={mid - 2.8} width={5.6}
                        height={5.6} fill={C.paper} stroke={C.text}
                        strokeWidth={0.9}
                        data-testid={`dt2-activity-${a.family}-${a.node_id}`}
                        data-activity-process={a.process_node_id} />
                );
              })}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
