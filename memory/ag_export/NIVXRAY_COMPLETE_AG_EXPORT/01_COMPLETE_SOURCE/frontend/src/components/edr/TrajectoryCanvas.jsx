// EDR Device Trajectory · Center Canvas — ENTITY-PER-ROW temporal coordinate system.
// Owner architecture lock (2026-08-26):
//   The center is NOT a graph.  It is a temporal coordinate system
//   for the observed entities.  Connectors are secondary and only
//   represent process ancestry / causality.
//
// Y-axis: one row per entity (grouped by category, deterministic order).
// X-axis: time (span_start → span_end).
// Compromise window: OVERLAY (rule #9), never a filter.
// No text overlap: nodes cluster within same 60s bucket vertically.
import React, { useMemo } from "react";

const KIND_COLOR = {
  process:  "#5a8cdc",
  file:     "#eab040",
  network:  "#40d0c0",
  registry: "#d060d0",
  identity: "#a0d040",
  system:   "#808090",
};

const GROUP_ORDER = ["system", "process", "file", "registry", "network", "identity"];
const ROW_H       = 34;
const HEADER_H    = 48;
const LEFT_GUTTER = 200;
const RIGHT_GUTTER = 24;
const NODE_R      = 6;

const parseTs = (t) => t ? new Date(t).getTime() : null;

export const TrajectoryCanvas = ({ inventory, verdict,
                                     selectedEntityId, selectedEventId,
                                     onEventClick, onEntityClick }) => {
  const events = inventory?.events || [];
  const { span_start, span_end } = inventory || {};

  // Flat entity list in deterministic Y-order (one row each).
  const rows = useMemo(() => {
    const out = [];
    for (const k of GROUP_ORDER) {
      for (const e of (inventory?.entities || {})[k] || []) {
        out.push({ ...e, _kind: k });
      }
    }
    return out;
  }, [inventory]);

  const rowIndexById = useMemo(() => {
    const m = new Map();
    rows.forEach((r, i) => m.set(r.entity_id, i));
    return m;
  }, [rows]);

  const totalHeight = HEADER_H + rows.length * ROW_H + 60;
  const width = Math.max(900, 900);

  const xForTs = useMemo(() => {
    const start = parseTs(span_start);
    const end = parseTs(span_end);
    const range = Math.max(60000, (end || 0) - (start || 0));
    return (ts) => {
      const t = parseTs(ts) || start;
      const usable = width - LEFT_GUTTER - RIGHT_GUTTER;
      return LEFT_GUTTER + ((t - start) / range) * usable;
    };
  }, [span_start, span_end, width]);

  const rowY = (idx) => HEADER_H + idx * ROW_H + ROW_H / 2;

  // Compromise window overlay = min/max of high-weight event ids.
  const compromiseSpan = useMemo(() => {
    if (!verdict?.evidence_rows) return null;
    const badIds = new Set();
    for (const r of verdict.evidence_rows) {
      if (r.weight_contribution > 0) (r.event_ids || []).forEach((id) => badIds.add(id));
    }
    if (!badIds.size) return null;
    let s = null, e = null;
    for (const ev of events) {
      if (!badIds.has(ev.event_id)) continue;
      const t = parseTs(ev.timestamp);
      if (t === null) continue;
      if (s === null || t < s) s = t;
      if (e === null || t > e) e = t;
    }
    return s !== null ? { start: s, end: e } : null;
  }, [verdict, events]);

  // Cluster events per (entity, minute) to avoid text overlap.
  const positioned = useMemo(() => {
    const buckets = new Map();
    for (const ev of events) {
      const t = parseTs(ev.timestamp);
      if (t === null) continue;
      const idx = rowIndexById.get(ev.entity_id);
      if (idx === undefined) continue;
      const key = `${idx}|${Math.floor(t / 60000)}`;
      if (!buckets.has(key)) buckets.set(key, []);
      buckets.get(key).push(ev);
    }
    const out = [];
    for (const [key, group] of buckets.entries()) {
      const [idxStr] = key.split("|");
      const idx = Number(idxStr);
      const cy = rowY(idx);
      const sorted = [...group].sort(
        (a, b) => (a.event_id > b.event_id ? 1 : -1),
      );
      sorted.forEach((ev, i) => {
        const off = i - (sorted.length - 1) / 2;
        out.push({ ev, x: xForTs(ev.timestamp), y: cy + off * 12 });
      });
    }
    return out;
  }, [events, rowIndexById, xForTs]);

  // Ancestry lines (process only) — parent-row → child-row causality.
  const ancestryLines = useMemo(() => {
    const lines = [];
    for (const p of (inventory?.entities?.process || [])) {
      if (!p.parent_entity_id) continue;
      const childIdx = rowIndexById.get(p.entity_id);
      const parentIdx = rowIndexById.get(p.parent_entity_id);
      if (childIdx === undefined || parentIdx === undefined) continue;
      // Anchor: first event of the child on X-axis.
      const childEv = positioned.find((n) => n.ev.entity_id === p.entity_id);
      if (!childEv) continue;
      lines.push({
        from: { x: childEv.x, y: rowY(parentIdx) },
        to:   { x: childEv.x, y: rowY(childIdx) },
      });
    }
    return lines;
  }, [inventory, rowIndexById, positioned]);

  return (
    <div data-testid="trajectory-canvas" style={styles.wrap}>
      <div style={styles.header}>
        <div>Temporal Trajectory</div>
        <div style={styles.spanMeta}>
          {span_start ? new Date(span_start).toLocaleString() : "—"}
          {"  →  "}
          {span_end ? new Date(span_end).toLocaleString() : "—"}
          {"  ·  "}{events.length} events across {rows.length} entities
        </div>
      </div>

      <svg width={width} height={totalHeight}
            style={{ background: "#0a0a0f", display: "block" }}
            data-testid="trajectory-svg">

        {/* Compromise window OVERLAY */}
        {compromiseSpan && (
          <rect
            data-testid="compromise-window"
            x={xForTs(new Date(compromiseSpan.start).toISOString())}
            y={HEADER_H - 6}
            width={Math.max(4,
                xForTs(new Date(compromiseSpan.end).toISOString())
                - xForTs(new Date(compromiseSpan.start).toISOString()))}
            height={totalHeight - HEADER_H - 40}
            fill="rgba(224,76,96,0.10)"
            stroke="rgba(224,76,96,0.35)"
            strokeDasharray="4 4"
          />
        )}

        {/* Entity rows — label + rail */}
        {rows.map((r, i) => {
          const y = rowY(i);
          const isSel = selectedEntityId === r.entity_id;
          return (
            <g key={r.entity_id}>
              <line x1={LEFT_GUTTER} y1={y} x2={width - RIGHT_GUTTER}
                     y2={y} stroke="#181820" strokeWidth={1} />
              <foreignObject x={0} y={y - ROW_H / 2}
                              width={LEFT_GUTTER - 8} height={ROW_H}>
                <div
                  data-testid={`traj-row-${r.entity_id}`}
                  onClick={() => onEntityClick && onEntityClick(r)}
                  style={{
                    ...styles.rowLabel,
                    background: isSel ? "rgba(90,140,220,0.15)" : "transparent",
                    borderLeftColor: isSel ? "#5a8cdc" : "transparent",
                  }}
                >
                  <span style={{ color: KIND_COLOR[r._kind], marginRight: 8 }}>■</span>
                  <span style={styles.rowLabelText}>{r.display_name}</span>
                </div>
              </foreignObject>
            </g>
          );
        })}

        {/* Ancestry connectors (secondary — causality only) */}
        {ancestryLines.map((l, i) => (
          <path key={i}
                 d={`M ${l.from.x},${l.from.y} L ${l.to.x},${l.to.y}`}
                 fill="none" stroke="rgba(90,140,220,0.35)"
                 strokeWidth={1.5} strokeDasharray="2 3" />
        ))}

        {/* Event nodes */}
        {positioned.map(({ ev, x, y }) => {
          const isSelected = ev.event_id === selectedEventId;
          const inSelectedRow = selectedEntityId === ev.entity_id;
          return (
            <g key={ev.event_id}
                data-testid={`traj-node-${ev.event_id}`}
                onClick={() => onEventClick && onEventClick(ev)}
                style={{ cursor: "pointer" }}>
              <circle cx={x} cy={y} r={isSelected ? NODE_R + 2 : NODE_R}
                       fill={KIND_COLOR[ev.kind] || "#666"}
                       fillOpacity={inSelectedRow || isSelected ? 1 : 0.75}
                       stroke={isSelected ? "#ffffff"
                                 : inSelectedRow ? "rgba(255,255,255,0.5)"
                                 : "rgba(255,255,255,0.15)"}
                       strokeWidth={isSelected ? 2 : 1} />
            </g>
          );
        })}
      </svg>

      <div style={styles.footer}>
        {compromiseSpan && (
          <span>
            <span style={{ ...styles.legendDot, background: "#e04c60" }} />
            compromise window (overlay · not a filter)
          </span>
        )}
        <span style={{ opacity: 0.5 }}>·  click a node to inspect  ·  click a row label to pivot</span>
      </div>
    </div>
  );
};

const styles = {
  wrap: {
    background: "#0a0a0f", height: "100%", overflow: "auto",
    fontFamily: "ui-monospace, monospace", color: "#d0d0d5",
  },
  header: {
    padding: "10px 16px 8px",
    display: "flex", justifyContent: "space-between", alignItems: "baseline",
    fontSize: 12, textTransform: "uppercase", letterSpacing: 2,
    borderBottom: "1px solid #23232b",
  },
  spanMeta: {
    fontSize: 10, opacity: 0.6, textTransform: "none", letterSpacing: 0,
  },
  rowLabel: {
    height: "100%", display: "flex", alignItems: "center",
    padding: "0 8px 0 12px",
    fontSize: 11, color: "#e5e5ea",
    borderLeft: "3px solid",
    cursor: "pointer",
    whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
    boxSizing: "border-box",
  },
  rowLabelText: { overflow: "hidden", textOverflow: "ellipsis" },
  legendDot: {
    display: "inline-block", width: 8, height: 8, borderRadius: 2,
    marginRight: 6, verticalAlign: "middle",
  },
  footer: {
    padding: "8px 16px", display: "flex", gap: 16,
    fontSize: 10, borderTop: "1px solid #23232b",
  },
};

export default TrajectoryCanvas;
