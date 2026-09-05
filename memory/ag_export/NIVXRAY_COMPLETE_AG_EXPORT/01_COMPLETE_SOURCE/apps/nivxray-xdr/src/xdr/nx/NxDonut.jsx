/**
 * NxDonut · §17 · lightweight SVG donut for compositional breakdowns.
 *
 * Zero dependencies.  Consumes only authoritative data (`items`
 * with numeric `count`).  Renders NOTHING when total = 0 — caller
 * must handle the honest-empty case at the section level.
 *
 * Props:
 *   items: [{ key, label, count, pct?, tone? }]
 *   total: number
 *   size?: px  (default 180)
 *   thickness?: px  (default 22)
 *   centerLabel?: React node rendered inside the ring
 *   testid?: string
 *
 * Colour policy: colours are drawn from a fixed semantic-neutral
 * palette (§17.4).  Purple is reserved for NivXRay identity; the
 * donut deliberately does not use it for compositional segments
 * unless caller supplies `tone: "purple"`.
 */
import React from "react";

const DEFAULT_PALETTE = [
  "#6D4EE0",  // purple (identity)
  "#2563EB",  // blue
  "#0D9488",  // teal
  "#F59E0B",  // amber
  "#9CA3AF",  // faint
  "#DC2626",  // red (reserved)
];

const TONE_COLOUR = {
  purple: "#6D4EE0",
  blue:   "#2563EB",
  teal:   "#0D9488",
  amber:  "#F59E0B",
  faint:  "#9CA3AF",
  red:    "#DC2626",
  green:  "#059669",
};

export default function NxDonut({
  items = [],
  total,
  size = 180,
  thickness = 22,
  centerLabel,
  testid = "nx-donut",
}) {
  const sum = total ?? items.reduce((a, i) => a + (i.count || 0), 0);
  if (!sum) return null;

  const r      = (size - thickness) / 2;
  const c      = size / 2;
  const circ   = 2 * Math.PI * r;

  let offset = 0;
  const segments = items.map((it, i) => {
    const value  = it.count || 0;
    const frac   = value / sum;
    const length = frac * circ;
    const gap    = Math.max(1, circ * 0.006);  // subtle segment gap
    const stroke = it.tone
      ? (TONE_COLOUR[it.tone] || DEFAULT_PALETTE[i % DEFAULT_PALETTE.length])
      : DEFAULT_PALETTE[i % DEFAULT_PALETTE.length];
    const seg = {
      key:      it.key || i,
      colour:   stroke,
      len:      Math.max(0, length - gap),
      dashRest: circ - Math.max(0, length - gap),
      offset:   offset,
    };
    offset += length;
    return seg;
  });

  return (
    <svg
      width={size} height={size}
      viewBox={`0 0 ${size} ${size}`}
      data-testid={testid}
      role="img"
      style={{ display: "block" }}
    >
      {/* Track */}
      <circle
        cx={c} cy={c} r={r}
        fill="none"
        stroke="var(--nx-surf-inset, #F5F5F4)"
        strokeWidth={thickness}
      />
      {/* Segments */}
      {segments.map(s => (
        <circle
          key={s.key}
          cx={c} cy={c} r={r}
          fill="none"
          stroke={s.colour}
          strokeWidth={thickness}
          strokeDasharray={`${s.len} ${s.dashRest}`}
          strokeDashoffset={-s.offset}
          transform={`rotate(-90 ${c} ${c})`}
          strokeLinecap="butt"
        />
      ))}
      {centerLabel && (
        <foreignObject x={0} y={0} width={size} height={size}>
          <div
            style={{
              width: size, height: size,
              display: "flex", flexDirection: "column",
              alignItems: "center", justifyContent: "center",
              textAlign: "center", pointerEvents: "none",
            }}
          >
            {centerLabel}
          </div>
        </foreignObject>
      )}
    </svg>
  );
}

export { DEFAULT_PALETTE, TONE_COLOUR };
