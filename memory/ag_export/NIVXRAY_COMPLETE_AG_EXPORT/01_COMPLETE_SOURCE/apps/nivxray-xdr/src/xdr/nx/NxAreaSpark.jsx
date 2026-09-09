/**
 * NxAreaSpark · §17 · lightweight SVG area/line spark for trends.
 *
 * Consumes only authoritative time-series data (`points` with
 * numeric `y` and optional `label`).  If `points.length < 2`,
 * renders nothing (caller must show an honest empty state).
 *
 * Props:
 *   points: [{ x?: string, y: number }]  (ordered)
 *   width?: px
 *   height?: px
 *   colour?: css colour  (default: --nx-purple)
 *   showAxis?: boolean   (default true)
 *   xTicks?: number      (default 6)
 *   yTicks?: number      (default 5)
 *   testid?: string
 */
import React, { useMemo } from "react";

export default function NxAreaSpark({
  points = [],
  width = 640,
  height = 200,
  colour = "var(--nx-purple, #6D4EE0)",
  fill = "rgba(109, 78, 224, 0.10)",
  showAxis = true,
  xTicks = 6,
  yTicks = 5,
  testid = "nx-area",
}) {
  const layout = useMemo(() => {
    if (points.length < 2) return null;
    const padL = showAxis ? 42 : 6;
    const padR = 12;
    const padT = 12;
    const padB = showAxis ? 24 : 6;
    const innerW = width  - padL - padR;
    const innerH = height - padT - padB;

    const ys = points.map(p => Number(p.y) || 0);
    const yMin = Math.min(0, ...ys);
    const yMaxRaw = Math.max(...ys, 1);
    // Round yMax up to a nice tick so the top gridline hugs the peak.
    const step = niceStep((yMaxRaw - yMin) / yTicks);
    const yMax = Math.ceil(yMaxRaw / step) * step;

    const xAt = (i) => padL + (i / (points.length - 1)) * innerW;
    const yAt = (v) => padT + innerH - ((v - yMin) / (yMax - yMin)) * innerH;

    const line = points.map((p, i) => `${i ? "L" : "M"}${xAt(i)},${yAt(p.y)}`).join(" ");
    const area = `${line} L${xAt(points.length - 1)},${padT + innerH} L${xAt(0)},${padT + innerH} Z`;

    const yTickVals = [];
    for (let v = yMin; v <= yMax + 1e-9; v += step) yTickVals.push(v);
    const xTickIdx = [];
    const step2 = Math.max(1, Math.floor((points.length - 1) / (xTicks - 1)));
    for (let i = 0; i < points.length; i += step2) xTickIdx.push(i);
    if (xTickIdx[xTickIdx.length - 1] !== points.length - 1)
      xTickIdx.push(points.length - 1);

    return { padL, padR, padT, padB, innerW, innerH, xAt, yAt,
              line, area, yTickVals, xTickIdx, yMin, yMax };
  }, [points, width, height, showAxis, xTicks, yTicks]);

  if (!layout) return null;
  const { padL, padT, innerW, innerH, xAt, yAt, line, area,
             yTickVals, xTickIdx } = layout;

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      width="100%" height={height}
      data-testid={testid}
      role="img"
      style={{ display: "block", overflow: "visible" }}
    >
      {/* Y gridlines + labels */}
      {showAxis && yTickVals.map((v, i) => (
        <g key={`y-${i}`}>
          <line
            x1={padL} x2={padL + innerW}
            y1={yAt(v)} y2={yAt(v)}
            stroke="var(--nx-bd-quiet, #E7E5E4)"
            strokeDasharray="2 3"
          />
          <text
            x={padL - 8} y={yAt(v) + 3}
            textAnchor="end"
            fontFamily="var(--mono)"
            fontSize="10"
            fill="var(--nx-faint, #9CA3AF)"
          >{fmtNum(v)}</text>
        </g>
      ))}

      {/* Area + line */}
      <path d={area} fill={fill} />
      <path d={line} stroke={colour} strokeWidth="1.75" fill="none" />

      {/* Data points */}
      {points.map((p, i) => (
        <circle
          key={i}
          cx={xAt(i)} cy={yAt(p.y)}
          r={2}
          fill={colour}
          opacity={0.85}
        />
      ))}

      {/* X labels */}
      {showAxis && xTickIdx.map((i) => (
        <text
          key={`x-${i}`}
          x={xAt(i)}
          y={padT + innerH + 16}
          textAnchor="middle"
          fontFamily="var(--mono)"
          fontSize="10"
          fill="var(--nx-faint, #9CA3AF)"
        >{points[i].label ?? ""}</text>
      ))}
    </svg>
  );
}

function niceStep(raw) {
  if (raw <= 0 || !Number.isFinite(raw)) return 1;
  const pow10 = Math.pow(10, Math.floor(Math.log10(raw)));
  const norm = raw / pow10;
  let step = 1;
  if      (norm > 5) step = 10;
  else if (norm > 2) step = 5;
  else if (norm > 1) step = 2;
  return step * pow10;
}

function fmtNum(v) {
  const n = Number(v) || 0;
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (Math.abs(n) >= 1000)      return `${(n / 1000).toFixed(1)}k`;
  return String(Math.round(n));
}
