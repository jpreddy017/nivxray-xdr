/**
 * <EvidenceState> — Round 24.9 primitive.
 *
 * Declares the truth-state of a fact, mapping, edge or capability.
 * The `state` prop is a closed enum — no free strings — so grammar
 * cannot drift into probabilistic language.
 *
 * Two axes:
 *   Truth axis (evidence):
 *     observed | supported | missing | unavailable | suppressed | actioned
 *   Capability axis (adapter):
 *     cap-full | cap-degraded | cap-ingest | cap-unavailable | cap-standby
 *
 *   <EvidenceState state="observed" />
 *   <EvidenceState state="cap-degraded" reason="parse-failures 3" />
 */
import React from "react";

export const EVIDENCE_STATES = [
  "observed", "supported", "missing", "unavailable",
  "suppressed", "actioned",
];
export const CAPABILITY_STATES = [
  "cap-full", "cap-degraded", "cap-ingest",
  "cap-unavailable", "cap-standby",
];
const ALL = [...EVIDENCE_STATES, ...CAPABILITY_STATES];

const DEFAULT_LABELS = {
  observed:        "Observed",
  supported:       "Supported",
  missing:         "Missing",
  unavailable:     "Unavailable",
  suppressed:      "Suppressed",
  actioned:        "Actioned",
  "cap-full":         "Full",
  "cap-degraded":     "Degraded",
  "cap-ingest":       "Ingest only",
  "cap-unavailable":  "Unavailable",
  "cap-standby":      "Standby",
};

export default function EvidenceState({
  state,
  label = null,
  reason = null,
  dot = true,
  testid,
}) {
  const text = label || DEFAULT_LABELS[state] || state;
  return (
    <span
      className="evops-state"
      data-state={state}
      data-testid={testid}
    >
      {dot && <span className="evops-state__dot" aria-hidden />}
      <span>{text}</span>
      {reason && <span className="evops-state__reason">· {reason}</span>}
    </span>
  );
}

