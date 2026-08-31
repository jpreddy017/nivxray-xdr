/**
 * NxProvenance · §6 selective provenance sub-line.
 *
 * Renders **only** under authoritative / derived / correlated /
 * decision-critical values.  Do not use it for freeform metadata.
 * If unsure, omit — the grammar prefers no provenance to noise.
 *
 *   <NxProvenance>workspace_cases.live</NxProvenance>
 *   → "Source · workspace_cases.live"
 */
import React from "react";

export default function NxProvenance({ children, inline = false, ...rest }) {
  if (!children) return null;
  return (
    <span
      className={`nx-prov${inline ? " nx-prov--inline" : ""}`}
      {...rest}
    >
      {children}
    </span>
  );
}
