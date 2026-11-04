/**
 * NxStatus / NxMetric · Slice 1 · the platform's status + number grammar.
 *
 * Two product laws live here, so no page can break them by accident:
 *
 *  1. A collector may be online and receiving while its evidence history is
 *     incomplete.  `HEALTHY · EVIDENCE INCOMPLETE` is therefore a real state
 *     and a confirmed collection gap can NEVER render as plain "Healthy".
 *  2. A number renders only when an authoritative backend field produced it.
 *     Absence renders as absence, with the reason — never as a zero.
 */
import React from "react";
import NxChip from "./NxChip";

const STATES = {
  healthy:            { label: "Healthy",            tone: "benign",        variant: "tinted" },
  receiving:          { label: "Receiving",          tone: "benign",        variant: "tinted" },
  degraded:           { label: "Degraded",           tone: "medium",        variant: "tinted" },
  paused:             { label: "Paused",             tone: "medium",        variant: "tinted" },
  backlog:            { label: "Backlog",            tone: "medium",        variant: "tinted" },
  dropping:           { label: "Dropping",           tone: "critical",      variant: "filled" },
  offline:            { label: "Offline",            tone: "critical",      variant: "tinted" },
  not_configured:     { label: "Not configured",     tone: "not_connected", variant: "dashed" },
  never_connected:    { label: "Never connected",    tone: "not_connected", variant: "dashed" },
  not_receiving:      { label: "Not receiving",      tone: "not_connected", variant: "dashed" },
  not_measured:       { label: "Not yet measured",   tone: "not_run",       variant: "dashed" },
  unavailable:        { label: "Verification unavailable", tone: "not_run", variant: "dashed" },
  available:          { label: "Available",          tone: "available",     variant: "dashed" },
  connected:          { label: "Connected",          tone: "benign",        variant: "tinted" },
  refused:            { label: "Refused",            tone: "high",          variant: "tinted" },
  evidence_incomplete:{ label: "Evidence incomplete", tone: "high",         variant: "filled" },
};

/** One authoritative status chip.  `reason` is shown as the title so an
 *  unavailable state always says WHY — never a hidden truth. */
export function NxStatus({ state, label, reason, testid }) {
  const s = STATES[state] || STATES.unavailable;
  return (
    <NxChip tone={s.tone} variant={s.variant} title={reason || undefined}
            data-testid={testid}>
      {label || s.label}
    </NxChip>
  );
}

/** Health + completeness are two different questions.  This renders them as
 *  one honest verdict: HEALTHY · EVIDENCE INCOMPLETE when a gap is confirmed. */
export function NxHealthVerdict({ health, gapConfirmed, gapReason, testid }) {
  return (
    <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}
          data-testid={testid}>
      <NxStatus state={health} />
      {gapConfirmed && (
        <NxStatus state="evidence_incomplete" reason={gapReason}
                  testid={`${testid || "verdict"}-gap`} />
      )}
    </span>
  );
}

/** A number that cannot lie.  `value == null` renders the honest absence
 *  state and its reason instead of a zero. */
export function NxMetric({
  label, value, unit, reason = "No authoritative source for this metric yet",
  state = "not_measured", testid,
}) {
  const missing = value == null || value === "";
  return (
    <div className="nx-kpi nx-kpi--noicon" data-testid={testid}>
      <div className="nx-kpi-body">
        {missing ? (
          <div style={{ marginBottom: 4 }}>
            <NxStatus state={state} reason={reason} />
          </div>
        ) : (
          <div className="nx-kpi-value">
            {typeof value === "number" ? value.toLocaleString() : value}
            {unit && <span className="nx-t-meta" style={{ marginLeft: 4 }}>{unit}</span>}
          </div>
        )}
        <div className="nx-kpi-label">{label}</div>
        {missing && <div className="nx-kpi-sub">{reason}</div>}
      </div>
    </div>
  );
}

export default NxStatus;
