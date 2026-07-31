/**
 * ADR-0022 §11 · Feature-flag toggle pill.
 *
 * A discreet, page-scoped UI control that flips the `?lab2=1` migration
 * flag without violating the "no permanent nav items" rule (§2).
 *
 * Rules honoured:
 *   - Rendered ONLY inside the Investigate route (not App-wide chrome).
 *   - Does NOT add a route, nav item, or backend surface.
 *   - Deleted at cutover (§12) together with the flag itself.
 *   - Uses tokens only when the flag is ON; falls back to inline neutral
 *     styling when OFF so the legacy renderer stays visually unchanged.
 */
import React, { useCallback } from "react";
import { isLab2Enabled } from "./FeatureFlagResolver";

function setLab2(enabled) {
  if (typeof window === "undefined") return;
  const url = new URL(window.location.href);
  if (enabled) {
    url.searchParams.set("lab2", "1");
  } else {
    url.searchParams.delete("lab2");
  }
  // Full reload — the resolver chooses the renderer at mount time.
  window.location.href = url.toString();
}

const S = {
  wrap: {
    display: "inline-flex",
    alignItems: "center",
    gap: 8,
    padding: "6px 10px",
    borderRadius: 999,
    background: "rgba(125, 211, 252, 0.08)",
    border: "1px solid rgba(125, 211, 252, 0.35)",
    color: "#7dd3fc",
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
    fontSize: 11,
    letterSpacing: "0.14em",
    textTransform: "uppercase",
    cursor: "pointer",
  },
  dot: (on) => ({
    width: 8,
    height: 8,
    borderRadius: 999,
    background: on ? "#34d399" : "#94a3b8",
    boxShadow: on ? "0 0 8px #34d39955" : "none",
  }),
  label: { fontWeight: 600 },
};

export default function Lab2ToggleButton() {
  const enabled = isLab2Enabled();
  const onClick = useCallback(() => setLab2(!enabled), [enabled]);
  return (
    <button
      type="button"
      onClick={onClick}
      style={S.wrap}
      data-testid="lab2-toggle-btn"
      title={
        enabled
          ? "Switch back to the legacy Investigate renderer"
          : "Preview the new Lab 2.0 workspace (feature-flagged, ADR-0022)"
      }
    >
      <span style={S.dot(enabled)} aria-hidden />
      <span style={S.label}>Lab 2.0 · {enabled ? "ON" : "Preview"}</span>
    </button>
  );
}
