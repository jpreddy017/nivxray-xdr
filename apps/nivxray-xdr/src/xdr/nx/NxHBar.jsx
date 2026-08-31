/**
 * NxHBar · §17 · horizontal-bar primitive for ranked / categorical
 * counts.  Consumes authoritative values only.  Bar length is
 * proportional to max, not to an assumed total, so partial data
 * still renders correctly.
 *
 * Props:
 *   items: [{ key, label, value, tone? }]
 *   max?: number  (defaults to max(values))
 *   valueFormatter?: (v) => string
 *   testid?: string
 */
import React from "react";
import { TONE_COLOUR } from "./NxDonut";

export default function NxHBar({
  items = [],
  max,
  valueFormatter = (v) => v,
  testid = "nx-hbar",
}) {
  if (!items.length) return null;
  const upper = max ?? Math.max(1, ...items.map(i => Number(i.value) || 0));
  return (
    <ol
      className="nx-hbar"
      data-testid={testid}
      style={{
        listStyle: "none", margin: 0, padding: 0,
        display: "flex", flexDirection: "column", gap: 10,
      }}
    >
      {items.map((it, i) => {
        const pct    = Math.max(0, Math.min(100, ((Number(it.value) || 0) / upper) * 100));
        const colour = TONE_COLOUR[it.tone] || "var(--nx-purple)";
        return (
          <li key={it.key || i} style={{
            display: "grid",
            gridTemplateColumns: "80px 1fr 46px",
            alignItems: "center", gap: 10,
          }}>
            <span style={{
              fontFamily: "var(--sans)", fontSize: 11,
              color: "var(--nx-text-dim)", fontWeight: 600,
            }}>{it.label}</span>
            <span style={{
              position: "relative",
              height: 10,
              background: "var(--nx-surf-inset, #F5F5F4)",
              borderRadius: 3,
            }}>
              <span style={{
                position: "absolute", left: 0, top: 0, bottom: 0,
                width: `${pct}%`,
                background: colour,
                borderRadius: 3,
                transition: "width 200ms ease",
              }} />
            </span>
            <span style={{
              textAlign: "right",
              fontFamily: "var(--mono)", fontSize: 11.5,
              color: "var(--nx-text)", fontWeight: 700,
            }}>{valueFormatter(it.value)}</span>
          </li>
        );
      })}
    </ol>
  );
}
