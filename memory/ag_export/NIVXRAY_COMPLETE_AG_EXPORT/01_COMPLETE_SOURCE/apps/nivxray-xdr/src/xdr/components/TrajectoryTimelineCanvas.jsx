/**
 * TrajectoryTimelineCanvas · Slice 6 · hybrid Canvas + SVG overlay.
 *
 * Renders horizontal lanes with time-ordered event markers:
 *   • <canvas>   — draws lane rules, hour ticks, and low-cost density
 *                  strokes for every event (scales to thousands).
 *   • <svg>      — overlays interactive markers on top so hover /
 *                  click / keyboard focus / pivots work naturally.
 *
 * Purely presentational.  Consumes normalized events from the parent
 * (already time-filtered + lane-mapped by the backend projection).
 */
import React, { useEffect, useMemo, useRef, useState, useCallback } from "react";

const LANE_HEIGHT = 44;
const LANE_LABEL_W = 132;
const TOP_PAD = 22;
const BOT_PAD = 16;
const MARKER_R = 5;

const SEV_COLOR = {
  critical: "#ff5b5b",
  high:     "#f5a623",
  medium:   "#e8c547",
  low:      "#3ce8b8",
  info:     "#3fc1e8",
};
const KIND_COLOR = {
  detection: "#f5a623",
  activity:  "#3fc1e8",
};

function colorFor(evt) {
  return SEV_COLOR[evt.severity] || KIND_COLOR[evt.kind] || "#78808f";
}

function fmtHour(d) {
  const h = d.getUTCHours().toString().padStart(2, "0");
  const m = d.getUTCMinutes().toString().padStart(2, "0");
  return `${h}:${m}Z`;
}

export default function TrajectoryTimelineCanvas({
  events,
  lanes,
  laneCounts,
  windowStart,
  windowEnd,
  selectedId,
  onSelect,
  activeLanes,
}) {
  const wrapRef = useRef(null);
  const canvasRef = useRef(null);
  const [width, setWidth] = useState(1000);
  const [hoverId, setHoverId] = useState(null);

  // Track container width for responsive drawing.
  useEffect(() => {
    if (!wrapRef.current) return;
    const ro = new ResizeObserver((entries) => {
      const cr = entries[0]?.contentRect;
      if (cr?.width) setWidth(Math.max(560, Math.floor(cr.width)));
    });
    ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, []);

  const tStart = useMemo(() => new Date(windowStart).getTime(), [windowStart]);
  const tEnd   = useMemo(() => new Date(windowEnd).getTime(),   [windowEnd]);
  const span   = Math.max(1, tEnd - tStart);
  const canvasW = width;
  const laneAreaW = canvasW - LANE_LABEL_W - 16;
  const canvasH = TOP_PAD + BOT_PAD + lanes.length * LANE_HEIGHT;

  const laneY = useCallback((laneKey) => {
    const idx = lanes.indexOf(laneKey);
    return TOP_PAD + idx * LANE_HEIGHT + LANE_HEIGHT / 2;
  }, [lanes]);

  const xFor = useCallback((iso) => {
    const t = new Date(iso).getTime();
    const clamped = Math.min(Math.max(t, tStart), tEnd);
    return LANE_LABEL_W + ((clamped - tStart) / span) * laneAreaW;
  }, [tStart, tEnd, span, laneAreaW]);

  // Filter markers to enabled lanes.
  const visible = useMemo(
    () => events.filter((e) => activeLanes.has(e.lane)),
    [events, activeLanes],
  );

  // Draw lanes/ticks/density on the canvas.
  useEffect(() => {
    const c = canvasRef.current;
    if (!c) return;
    const dpr = window.devicePixelRatio || 1;
    c.width  = canvasW * dpr;
    c.height = canvasH * dpr;
    c.style.width  = `${canvasW}px`;
    c.style.height = `${canvasH}px`;
    const ctx = c.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, canvasW, canvasH);

    // Lane backgrounds + labels.
    lanes.forEach((lane, idx) => {
      const y = TOP_PAD + idx * LANE_HEIGHT;
      // Alternating lane background.
      ctx.fillStyle = idx % 2 === 0 ? "#0f131c" : "#0c1017";
      ctx.fillRect(LANE_LABEL_W, y, laneAreaW, LANE_HEIGHT);

      // Label pill.
      ctx.fillStyle = activeLanes.has(lane) ? "#3ce8b8" : "#4a5162";
      ctx.font = "700 10px 'IBM Plex Mono', monospace";
      ctx.textBaseline = "middle";
      ctx.fillText(lane.toUpperCase(), 10, y + LANE_HEIGHT / 2);

      const count = laneCounts?.[lane] ?? 0;
      ctx.fillStyle = "#4a5162";
      ctx.font = "700 9px 'IBM Plex Mono', monospace";
      ctx.fillText(`(${count})`, 84, y + LANE_HEIGHT / 2);

      // Lane baseline.
      ctx.strokeStyle = "#191e2a";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(LANE_LABEL_W, y + LANE_HEIGHT);
      ctx.lineTo(canvasW - 8, y + LANE_HEIGHT);
      ctx.stroke();
    });

    // Hour ticks — up to 12 across the axis, honest & deterministic.
    const targetTicks = Math.min(12, Math.max(4, Math.round(laneAreaW / 90)));
    ctx.strokeStyle = "#212736";
    ctx.fillStyle = "#4a5162";
    ctx.font = "600 9.5px 'IBM Plex Mono', monospace";
    ctx.textAlign = "center";
    for (let i = 0; i <= targetTicks; i++) {
      const frac = i / targetTicks;
      const x = LANE_LABEL_W + frac * laneAreaW;
      ctx.beginPath();
      ctx.moveTo(x, TOP_PAD - 4);
      ctx.lineTo(x, TOP_PAD + lanes.length * LANE_HEIGHT);
      ctx.setLineDash([2, 3]);
      ctx.stroke();
      ctx.setLineDash([]);
      const d = new Date(tStart + frac * span);
      ctx.fillText(fmtHour(d), x, 12);
    }
    ctx.textAlign = "start";

    // Density strokes — every event contributes a subtle vertical line.
    visible.forEach((evt) => {
      const x = xFor(evt.timestamp);
      const y = laneY(evt.lane);
      ctx.strokeStyle = "rgba(155,123,240,0.35)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(x, y - LANE_HEIGHT / 2 + 6);
      ctx.lineTo(x, y + LANE_HEIGHT / 2 - 6);
      ctx.stroke();
    });
  }, [canvasW, canvasH, lanes, laneAreaW, tStart, span, visible, laneY, xFor,
        activeLanes, laneCounts]);

  return (
    <div ref={wrapRef}
          style={{ position: "relative", width: "100%" }}
          data-testid="xdr-trajectory-canvas-wrap">
      <canvas ref={canvasRef} style={{ display: "block" }} />
      <svg
        width={canvasW}
        height={canvasH}
        style={{ position: "absolute", top: 0, left: 0, pointerEvents: "none" }}
        data-testid="xdr-trajectory-svg-overlay"
      >
        {visible.map((evt) => {
          const x = xFor(evt.timestamp);
          const y = laneY(evt.lane);
          const isSel   = selectedId === evt.id;
          const isHover = hoverId === evt.id;
          const stroke  = isSel ? "#3ce8b8" : "#0a0c11";
          const r = isSel ? MARKER_R + 2 : isHover ? MARKER_R + 1 : MARKER_R;
          return (
            <g key={evt.id}
                style={{ cursor: "pointer", pointerEvents: "auto" }}
                onMouseEnter={() => setHoverId(evt.id)}
                onMouseLeave={() => setHoverId((v) => (v === evt.id ? null : v))}
                onClick={() => onSelect?.(evt)}
                data-testid={`xdr-trajectory-marker-${evt.id}`}>
              <circle
                cx={x} cy={y} r={r}
                fill={colorFor(evt)}
                stroke={stroke}
                strokeWidth={isSel ? 2 : 1.5}
                opacity={0.95}
              />
              {isHover && (
                <g pointerEvents="none">
                  <rect
                    x={Math.min(x + 8, canvasW - 260)}
                    y={y - 30}
                    width={250}
                    height={26}
                    rx={4}
                    fill="#11141c"
                    stroke="#212736"
                  />
                  <text
                    x={Math.min(x + 16, canvasW - 252)}
                    y={y - 12}
                    fill="#e7e9ef"
                    fontFamily="'Inter', system-ui, sans-serif"
                    fontSize={11}
                    fontWeight={600}
                  >
                    {(evt.title || evt.rule_id || "event").slice(0, 40)}
                  </text>
                </g>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
