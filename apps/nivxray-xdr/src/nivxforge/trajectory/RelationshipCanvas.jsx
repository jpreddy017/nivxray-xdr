/**
 * DT2-3 · the visible PROCESS / RELATIONSHIP / TIME trajectory.
 *
 * Horizontal time, one lane per process, parent→child connectors drawn only
 * where the server produced an evidence-backed edge, and DNS / NETWORK /
 * FILE / REGISTRY activity plotted against the owning process at its own
 * observed timestamp.
 *
 * Every pixel traces back to `dt2.graph` (DT2-2E). This component computes
 * geometry, never relationships.
 */
import React, { useMemo, useRef } from "react";

import {
  activityTimeMs, childrenOf, edgeFor, graphBoundsOf, laneRowsOf, parentOf,
  whyOf,
} from "./dt2/graphModel";
import { MAX_RENDERED_LANES } from "./dt2/bounded";
import { classifyIntent, INTENT, normalizeWheel } from "./dt2/pointer";
import { panByFraction, zoomBySteps } from "./dt2/viewport";

const ROW = 30;
const LEFT = 232;
const FAM = {
  DNS: { c: "#7fd1ff", g: "▲" },
  NETWORK: { c: "#8ce99a", g: "■" },
  FILE: { c: "#ffd479", g: "◆" },
  REGISTRY: { c: "#d0bfff", g: "●" },
};

export default function RelationshipCanvas({
  graph, view, bounds, plotW = 760, rows = 18, selectedNodeId = null,
  onSelect, onView, theme = {},
}) {
  const wrap = useRef(null);
  const C = {
    grid: theme.grid || "#22303c",
    paper: theme.paper || "#0d1620",
    paperAlt: theme.paperAlt || "#111d28",
    text: theme.text || "#d7e3ec",
    faint: theme.faint || "#6d8291",
    line: theme.link || "#4aa8d8",
  };

  const lanes = useMemo(
    () => laneRowsOf(graph, { max: MAX_RENDERED_LANES }), [graph]);
  const gb = useMemo(() => graphBoundsOf(graph), [graph]);

  // The axis prefers the analyst's viewport; with a single-instant corpus it
  // widens around the evidence rather than dividing by zero.
  const axis = useMemo(() => {
    const t0 = view?.t0 ?? gb.min;
    const t1 = view?.t1 ?? gb.max;
    if (t0 == null || t1 == null) return null;
    if (t1 - t0 > 0) return { t0, t1, instant: false };
    return { t0: t0 - 30000, t1: t1 + 30000, instant: true };
  }, [view, gb]);

  const width = Math.max(320, plotW);
  const height = Math.max(ROW * 3, (Math.min(lanes.length, rows) + 1) * ROW);
  const xOf = (t) => (t == null || !axis ? null
    : LEFT + ((t - axis.t0) / (axis.t1 - axis.t0)) * (width - LEFT - 18));

  React.useEffect(() => {
    const el = wrap.current;
    if (!el || !onView || !view) return undefined;
    const onWheel = (e) => {
      const intent = classifyIntent(e);
      if (intent === INTENT.ROWS) return;              // vertical is scroll
      e.preventDefault();
      const { dx, dy } = normalizeWheel(e);
      if (intent === INTENT.ZOOM) {
        const box = el.getBoundingClientRect();
        const frac = Math.min(1, Math.max(0,
          (e.clientX - box.left - LEFT) / Math.max(1, width - LEFT - 18)));
        onView(zoomBySteps(view, dy > 0 ? -1 : 1,
                           axis.t0 + frac * (axis.t1 - axis.t0), bounds));
      } else {
        onView(panByFraction(view, dx / Math.max(1, width - LEFT), bounds));
      }
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [view, bounds, onView, axis, width]);

  if (!axis || !lanes.length) {
    return (
      <div data-testid="dt2-relationships-empty"
           style={{ padding: 22, fontSize: 11.6, color: C.faint,
                    fontFamily: "var(--mono)" }}>
        NO PROCESS RELATIONSHIP EVIDENCE IN THIS WINDOW — nothing is drawn
        rather than guessed.
      </div>
    );
  }

  const ticks = 6;
  const visible = lanes.slice(0, rows);

  return (
    <div ref={wrap} data-testid="dt2-relationship-canvas"
         data-dt2-lane-count={lanes.length}
         data-dt2-rendered-lanes={visible.length}
         data-dt2-axis-instant={axis.instant ? "true" : "false"}
         data-dt2-selected={selectedNodeId || ""}
         style={{ background: C.paper, overflow: "hidden" }}>
      <svg width={width} height={height} role="img"
           aria-label="device trajectory process relationships">
        {/* time scale */}
        {Array.from({ length: ticks + 1 }).map((_, i) => {
          const t = axis.t0 + ((axis.t1 - axis.t0) * i) / ticks;
          const x = xOf(t);
          return (
            <g key={i}>
              <line x1={x} x2={x} y1={16} y2={height} stroke={C.grid} />
              <text x={x + 3} y={11} fill={C.faint} fontSize={8.6}
                    fontFamily="var(--mono)">
                {new Date(t).toISOString().slice(11, 19)}Z
              </text>
            </g>
          );
        })}
        <line x1={LEFT} x2={width} y1={16} y2={16} stroke={C.grid} />

        {/* parent → child connectors · only where an edge exists */}
        {visible.map((lane, row) => {
          if (!lane.parentNodeId) return null;
          const parentRow = visible.findIndex(
            (l) => l.nodeId === lane.parentNodeId);
          if (parentRow < 0) return null;
          const edge = edgeFor(graph, lane.parentNodeId, lane.nodeId);
          if (!edge) return null;                       // no evidence, no edge
          const y0 = 16 + parentRow * ROW + ROW / 2;
          const y1 = 16 + row * ROW + ROW / 2;
          const x = Math.max(LEFT + 6, xOf(lane.lifeline.startMs) ?? LEFT + 6);
          return (
            <g key={lane.nodeId + ":edge"}
               data-testid={`dt2-edge-${edge.edge_id}`}
               data-edge-basis={edge.derivation_basis}
               data-edge-downgraded={String(Boolean(edge.downgraded))}>
              <path d={`M ${x - 12} ${y0} V ${y1} H ${x - 2}`} fill="none"
                    stroke={C.line} strokeWidth={1} opacity={0.85} />
              <path d={`M ${x - 6} ${y1 - 3} L ${x - 1} ${y1} L ${x - 6} ${y1 + 3}`}
                    fill={C.line} opacity={0.9} />
            </g>
          );
        })}

        {/* lanes: identity, lifeline, attached activity */}
        {visible.map((lane, row) => {
          const y = 16 + row * ROW;
          const mid = y + ROW / 2;
          const x0 = xOf(lane.lifeline.startMs);
          const x1 = xOf(lane.lifeline.endMs);
          const sel = lane.nodeId === selectedNodeId;
          const n = lane.node;
          return (
            <g key={lane.nodeId} data-testid={`dt2-lane-${lane.nodeId}`}
               data-lane-depth={lane.depth}
               data-lane-selected={sel ? "true" : "false"}
               data-lifeline-semantics={lane.lifeline.semantics}
               onClick={() => onSelect?.(lane)}
               style={{ cursor: "pointer" }}>
              <rect x={0} y={y} width={width} height={ROW}
                    fill={sel ? C.paperAlt : "transparent"} />
              {sel ? <rect x={0} y={y} width={2.5} height={ROW}
                           fill={C.line} /> : null}
              <text x={8 + Math.min(lane.depth, 6) * 9} y={mid + 3.4}
                    fill={C.text} fontSize={10.6} fontFamily="var(--mono)">
                {(n.label || n.image || "process").slice(0, 22)}
              </text>
              <text x={LEFT - 74} y={mid + 3.4} fill={C.faint} fontSize={9.2}
                    fontFamily="var(--mono)">
                pid {n.pid ?? "?"}{n.process_guid ? " · GUID" : " · no GUID"}
              </text>
              {/* observed evidence span — never an invented exit */}
              {x0 != null ? (
                <g>
                  <line x1={x0} x2={Math.max(x0 + 2, x1 ?? x0 + 2)} y1={mid}
                        y2={mid} stroke={sel ? C.line : C.text}
                        strokeWidth={sel ? 2.4 : 1.6}
                        strokeDasharray={lane.lifeline.terminated ? "" : "4 3"}
                        opacity={sel ? 1 : 0.75} />
                  <circle cx={x0} cy={mid} r={2.6}
                          fill={sel ? C.line : C.text} />
                  {lane.lifeline.terminated
                    ? <line x1={x1} x2={x1} y1={mid - 4} y2={mid + 4}
                            stroke={C.text} strokeWidth={1.4} />
                    : null}
                </g>
              ) : null}
              {/* attached activity at its OWN timestamp */}
              {lane.activities.map((a) => {
                const ax = xOf(activityTimeMs(a));
                if (ax == null) return null;
                const fam = FAM[a.family] || { c: C.text, g: "•" };
                return (
                  <text key={a.node_id} x={ax} y={mid - 6}
                        data-testid={`dt2-activity-${a.family}-${a.node_id}`}
                        data-activity-process={a.process_node_id}
                        textAnchor="middle" fill={fam.c} fontSize={9.4}
                        fontFamily="var(--mono)">{fam.g}</text>
                );
              })}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/** The compact relationship/navigation rail for the selected process. */
export function RelationshipBasis({ graph, selectedNodeId, onSelect,
                                    onStep, step }) {
  if (!graph || !selectedNodeId) {
    return (
      <div data-testid="dt2-basis-none"
           style={{ padding: "8px 11px", fontSize: 10.6, color: "#6d8291",
                    fontFamily: "var(--mono)" }}>
        SELECT A PROCESS TO SEE ITS RELATIONSHIP BASIS
      </div>
    );
  }
  const parent = parentOf(graph, selectedNodeId);
  const kids = childrenOf(graph, selectedNodeId);
  const why = whyOf(parent ? edgeFor(graph, parent.node_id, selectedNodeId)
                           : null);
  const btn = { fontSize: 10, cursor: "pointer", background: "transparent",
                color: "#4aa8d8", border: "1px solid #22303c",
                borderRadius: 2, padding: "2px 6px", marginRight: 5 };
  return (
    <div data-testid="dt2-basis" style={{ padding: "8px 11px",
                                          fontFamily: "var(--mono)" }}>
      <div style={{ display: "flex", gap: 5, flexWrap: "wrap",
                    marginBottom: 6 }}>
        <button style={btn} disabled={!parent} data-testid="dt2-goto-parent"
                onClick={() => parent && onSelect?.(parent.node_id)}>
          ↑ PARENT{parent ? `: ${parent.label}` : " · none in evidence"}
        </button>
        <button style={btn} disabled={!kids.length}
                data-testid="dt2-goto-child"
                onClick={() => kids[0] && onSelect?.(kids[0].node_id)}>
          ↓ CHILD{kids.length ? ` (${kids.length})` : " · none in evidence"}
        </button>
        <button style={btn} data-testid="dt2-step-before"
                onClick={() => onStep?.(-1)}>← BEFORE</button>
        <button style={btn} data-testid="dt2-step-after"
                onClick={() => onStep?.(1)}>AFTER →</button>
      </div>
      {why ? (
        <div data-testid="dt2-why" data-why-basis={why.basis}
             style={{ fontSize: 10, color: "#8fa6b6", lineHeight: 1.5 }}>
          <b style={{ color: "#d7e3ec" }}>WHY THIS EDGE</b> · {why.basis}
          {why.downgraded ? " · IDENTITY DOWNGRADED" : ""} ·
          {` ${why.evidenceCount} evidence ref(s)`}
          <div style={{ color: "#6d8291" }}>{why.reason}</div>
        </div>
      ) : (
        <div data-testid="dt2-why-none"
             style={{ fontSize: 10, color: "#6d8291" }}>
          NO PARENT EDGE IN EVIDENCE — nothing is inferred from time, image,
          user or PID adjacency.
        </div>
      )}
      {step ? (
        <div data-testid="dt2-step-causality"
             data-causality={step.causality}
             style={{ marginTop: 6, fontSize: 10, color: "#8fa6b6" }}>
          ORDERING STEP · {step.causality}
          <div style={{ color: "#6d8291" }}>{step.causalityReason}</div>
        </div>
      ) : null}
    </div>
  );
}
