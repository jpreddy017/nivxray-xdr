/**
 * NxExecPulse · §8 execution-state pulse.
 *
 * Renders a pulsing dot + label reserved for four backend-flagged
 * execution states.  Never used for hover, attention, or empty
 * state polish (see amendment A3).
 */
import React from "react";
import NxChip from "./NxChip";

const LABEL = {
  auto_investigation_running: "AUTO-INVESTIGATION RUNNING",
  enrichment_running:         "ENRICHMENT RUNNING",
  response_action_running:    "RESPONSE ACTION RUNNING",
  engine_execution_running:   "ENGINE EXECUTION RUNNING",
};

export default function NxExecPulse({ state, label, ...rest }) {
  if (!state) return null;
  const key = String(state).toLowerCase();
  const text = label || LABEL[key] || String(state).toUpperCase();
  return (
    <NxChip
      tone="running"
      variant="tinted"
      pulse
      dot
      size="md"
      {...rest}
    >
      {text}
    </NxChip>
  );
}
