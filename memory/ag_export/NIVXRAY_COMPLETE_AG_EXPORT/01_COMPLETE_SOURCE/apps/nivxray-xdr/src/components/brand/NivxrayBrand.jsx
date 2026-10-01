/**
 * NivXRay brand mark + wordmark for the standalone XDR tool.
 *
 * The mark now matches the authoritative NivX Machines identity used
 * by the base NivXRay product (see /app/frontend/public/brand/
 * nivxray-mark.svg): asymmetric bracket-N with mint stroke gradient
 * and an orange spark accent — inline SVG, no external asset
 * dependency.  Only the wordmark suffix changes ("XDR").
 */
import React from "react";

/**
 * The mark on its own, sized by `size` (px).
 * Used inside dense chrome (top bars) where space is tight.
 */
export function NivxrayMark({ size = 28, boxed = true, className, ...rest }) {
  const s = size;
  return (
    <svg
      width={s}
      height={s}
      viewBox="0 0 512 512"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      role="img"
      aria-label="NivXRay"
      {...rest}
    >
      <defs>
        {/* Same gradient stops as the base NivX Machines mark. */}
        <linearGradient id="nx-stroke" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%"   stopColor="#5cc0a5" />
          <stop offset="100%" stopColor="#3b8b75" />
        </linearGradient>
        <radialGradient id="nx-glow" cx="50%" cy="50%" r="55%">
          <stop offset="0%"   stopColor="#4aa890" stopOpacity="0.18" />
          <stop offset="70%"  stopColor="#4aa890" stopOpacity="0.02" />
          <stop offset="100%" stopColor="#4aa890" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* Optional frame — matches the base identity. */}
      {boxed && (
        <rect
          x="8" y="8" width="496" height="496" rx="24" ry="24"
          fill="none" stroke="#2d3135" strokeWidth="4"
        />
      )}

      {/* Ambient glow. */}
      <circle cx="256" cy="256" r="200" fill="url(#nx-glow)" />

      {/* Bracket-N geometry — authoritative NivX Machines glyph. */}
      <path
        d="M 96 384 L 96 128 L 176 128 L 320 320 L 320 128 L 416 128"
        fill="none"
        stroke="url(#nx-stroke)"
        strokeWidth="32"
        strokeLinejoin="miter"
        strokeLinecap="square"
      />

      {/* Orange spark accent — identity signature. */}
      <circle cx="416" cy="384" r="32" fill="#e27e5d" />
      <circle cx="416" cy="384" r="46" fill="none"
                stroke="#e27e5d" strokeOpacity="0.35" strokeWidth="4" />
    </svg>
  );
}

/**
 * Full lockup — mark + wordmark ("NIVXRAY" white, "XDR" mint).
 * Suitable for the login page and any large hero.
 */
export function NivxrayLockup({ size = 40 }) {
  return (
    <div
      style={{
        display: "inline-flex", alignItems: "center", gap: 12,
        userSelect: "none",
      }}
      data-testid="xdr-brand-lockup"
    >
      <NivxrayMark size={size} />
      <div style={{ display: "flex", flexDirection: "column", lineHeight: 1 }}>
        <div
          style={{
            fontFamily: "'Inter', 'Segoe UI', system-ui, sans-serif",
            fontWeight: 800, letterSpacing: ".8px",
            fontSize: Math.round(size * 0.5),
            color: "#E7E9EF",
          }}
        >
          NIVXRAY <span style={{ color: "#3CE8B8" }}>XDR</span>
        </div>
        <div
          style={{
            marginTop: 4,
            fontFamily: "'IBM Plex Mono','SFMono-Regular',Consolas,monospace",
            fontSize: Math.round(size * 0.22),
            letterSpacing: "2.5px",
            color: "#78808F",
          }}
        >
          EXTENDED  DETECTION  &nbsp;/&nbsp;  RESPONSE
        </div>
      </div>
    </div>
  );
}

/**
 * Compact wordmark for top bars — no tagline line.
 */
export function NivxrayBrand({ size = 22, "data-testid": testId = "xdr-brand" }) {
  return (
    <span
      style={{
        display: "inline-flex", alignItems: "center", gap: 8,
        fontFamily: "'Inter', 'Segoe UI', system-ui, sans-serif",
        fontWeight: 800, letterSpacing: ".4px",
        fontSize: 13.5, color: "#E7E9EF",
      }}
      data-testid={testId}
    >
      <NivxrayMark size={size} boxed={false} />
      NIVXRAY <span style={{ color: "#3CE8B8" }}>XDR</span>
    </span>
  );
}

export default NivxrayBrand;
