/**
 * NivXRay brand mark + wordmark for the standalone XDR tool.
 *
 * Same visual language as the parent NivXRay identity — angular N
 * glyph with mint gradient and an orange dot accent — but the
 * wordmark suffix is "XDR" (this tool), not "DECODER / THREAT-LAB"
 * (the parent tool).  Pure inline SVG so it renders without any
 * external asset dependency.
 */
import React from "react";

/**
 * The mark on its own, sized by `size` (px).
 * Used inside dense chrome (top bars) where space is tight.
 */
export function NivxrayMark({ size = 28, boxed = true, className, ...rest }) {
  const s = size;
  const stroke = "url(#nx-mint)";
  return (
    <svg
      width={s}
      height={s}
      viewBox="0 0 64 64"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-label="NivXRay"
      {...rest}
    >
      <defs>
        <linearGradient id="nx-mint" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0"   stopColor="#7BE0C1" />
          <stop offset="1"   stopColor="#2FB89A" />
        </linearGradient>
        <radialGradient id="nx-halo" cx="0.5" cy="0.5" r="0.5">
          <stop offset="0"   stopColor="#3CE8B8" stopOpacity="0.14" />
          <stop offset="1"   stopColor="#3CE8B8" stopOpacity="0" />
        </radialGradient>
      </defs>

      {boxed && (
        <rect
          x="1.5" y="1.5" width="61" height="61" rx="10"
          fill="#0A0C11" stroke="#212736" strokeWidth="1"
        />
      )}
      <circle cx="32" cy="32" r="26" fill="url(#nx-halo)" />

      {/* Angular N glyph — one continuous polyline: bottom-left up,
          diagonal down to bottom-right, then straight up.
          Matches the reference identity's blocky N shape and renders
          reliably at any size. */}
      <polyline
        points="18,50 18,14 46,50 46,14"
        fill="none"
        stroke={stroke}
        strokeWidth="7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {/* Orange dot accent — the identity signature. */}
      <circle cx="49" cy="50" r="3.4" fill="#E88B5E" />
      <circle cx="49" cy="50" r="5.8" fill="none" stroke="#E88B5E" strokeOpacity="0.4" strokeWidth="1" />
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
