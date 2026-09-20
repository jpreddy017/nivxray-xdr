/**
 * NxOpsState · ONE presentation mapping for the platform's operational
 * state vocabulary.
 *
 * The backend legitimately answers with machine tokens
 * (`NOT_CONFIGURED`, `NOT_OBSERVED`, `NOT_PROVEN`, `PARTIAL`, …). Those
 * tokens are the AUTHORITY and are never renamed, reinterpreted or
 * merged. This module only decides how a token is SHOWN to an analyst or
 * administrator, and it keeps the raw token attached to the element
 * (`data-nx-state`) and in the tooltip so the technical fact is one hover
 * — or one Technical details disclosure — away.
 *
 * An unmapped token is rendered as an unmapped token (`data-nx-unmapped`),
 * never silently prettified: a missing mapping is a product gap we want to
 * see, not hide.
 */
import React from "react";
import NxChip from "./NxChip";

const S = (label, tone, variant = "tinted") => ({ label, tone, variant });

//: token → presentation.  Grouped by the question the state answers.
export const OPS_STATES = {
  // ── collection / delivery ──────────────────────────────────────
  RECEIVING:            S("Receiving", "benign"),
  CONFIGURED:           S("Configured", "low"),
  NOT_CONFIGURED:       S("Not configured", "not_connected", "dashed"),
  NOT_OBSERVED:         S("Not observed", "not_connected", "dashed"),
  NEVER_OBSERVED:       S("Never observed", "not_connected", "dashed"),
  GAP_DETECTED:         S("Collection gap", "medium"),
  DEGRADED:             S("Degraded", "medium"),
  BACKLOG:              S("Backlog", "medium"),
  DROPPING:             S("Dropping", "critical", "filled"),
  OFFLINE:              S("Offline", "critical"),
  STALE:                S("Stale", "medium"),

  // ── understanding · parsing / normalization ────────────────────
  SUPPORTED:            S("Supported", "benign"),
  PARTIAL:              S("Partial", "medium"),
  UNSUPPORTED:          S("Not supported", "not_run", "dashed"),
  NOT_YET_SUPPORTED:    S("Not yet supported", "not_run", "dashed"),
  MATERIALISED:         S("Materialised", "benign"),
  MATERIALIZED:         S("Materialised", "benign"),
  OBSERVED:             S("Observed", "benign"),
  MATCHED:              S("Matched", "low"),

  // ── detection capability / coverage ───────────────────────────
  AVAILABLE_NOW:        S("Available now", "benign"),
  AVAILABLE:            S("Available", "available"),
  POTENTIAL:            S("Potential", "medium", "dashed"),
  BLOCKED:              S("Blocked", "critical"),
  NOT_PROVEN:           S("Not verified", "not_run", "dashed"),
  NOT_ESTABLISHED:      S("Not established", "not_run", "dashed"),
  NOT_EVALUATED:        S("Not evaluated", "not_run", "dashed"),
  NOT_MEASURED:         S("Not measured", "not_run", "dashed"),
  UNMEASURED:           S("Not measured", "not_run", "dashed"),
  NOT_AVAILABLE:        S("Not available", "not_run", "dashed"),
  NOT_APPLICABLE:       S("Not applicable", "not_run", "dashed"),
  NOT_REPORTED:         S("Not reported", "not_run", "dashed"),
  NOT_RECORDED:         S("Not recorded", "not_run", "dashed"),

  // ── pivot / provider availability (Task 3A) ───────────────────
  NOT_AUTHORIZED:       S("Not authorized", "high", "dashed"),
  REQUIRED_IDENTIFIER_MISSING: S("Identifier missing", "medium", "dashed"),
  TEMPORARILY_UNAVAILABLE: S("Temporarily unavailable", "medium"),
  NOT_IMPLEMENTED:      S("Not implemented", "not_run", "dashed"),

  // ── verdicts an operator acts on ──────────────────────────────
  PASS:                 S("Pass", "benign"),
  FAIL:                 S("Fail", "critical", "filled"),
  ERROR:                S("Error", "critical", "filled"),
  REFUSED:              S("Refused", "high"),
  MISSING:              S("Missing", "high"),
  CAPABILITY_UNAVAILABLE: S("Capability unavailable", "not_run", "dashed"),
  EVIDENCE_INCOMPLETE:  S("Evidence incomplete", "high", "filled"),
  INTEGRITY_ALARM:      S("Integrity alarm", "critical", "filled"),

  // ── platform/engine condition (Control Center, Admin) ─────────
  REAL_RUNTIME_VERIFIED: S("Verified at runtime", "benign"),
  REACHABLE:            S("Reachable", "benign"),
  UNREACHABLE:          S("Unreachable", "critical"),
  UNASSIGNED:           S("Unassigned", "medium", "dashed"),
  NOT_SET:              S("Not set", "not_run", "dashed"),
  NOT_ATTRIBUTED:       S("Not attributed", "not_run", "dashed"),
  UNNAMED:              S("Unnamed", "not_run", "dashed"),
  IN_PROGRESS:          S("In progress", "running"),
  OPERATOR_CONFIGURED:  S("Operator configured", "low"),
  PLATFORM_DEFAULT:     S("Platform default", "not_run", "dashed"),

  // ── response lifecycle ────────────────────────────────────────
  REQUESTED:            S("Requested", "not_run", "dashed"),
  PENDING_APPROVAL:     S("Pending approval", "medium"),
  AUTHORIZED:           S("Approved · not dispatched", "low"),
  DISPATCHED:           S("Dispatched", "low"),
  EXECUTING:            S("Executing", "running"),
  EXECUTED:             S("Executed · unproven", "medium"),
  RESULT_REPORTED:      S("Result reported · unverified", "medium"),
  VERIFIED:             S("Verified", "benign"),
  VERIFICATION_FAILED:  S("Verification failed", "critical"),
  FAILED:               S("Failed", "critical"),
  TIMED_OUT:            S("Timed out", "high"),
  SIMULATED:            S("Simulated", "not_run", "dashed"),
  REJECTED:             S("Rejected", "high"),
  CANCELLED:            S("Cancelled", "not_run", "dashed"),
};

/** Normalise `NOT OBSERVED`, `not-observed`, `Not Observed` → one key. */
export const opsKey = (raw) =>
  String(raw ?? "").trim().toUpperCase().replace(/[\s-]+/g, "_");

/**
 * Resolve a backend token to its presentation.
 * `known: false` means the platform took no measurement at all.
 */
export function opsState(raw) {
  const token = opsKey(raw);
  if (!token) {
    return { token: null, label: "Not available", tone: "not_run",
             variant: "dashed", mapped: true, known: false };
  }
  const hit = OPS_STATES[token];
  if (hit) return { token, ...hit, mapped: true, known: true };
  // Unmapped: readable, but visibly unmapped.
  const label = token.toLowerCase().replace(/_/g, " ")
    .replace(/^./, (c) => c.toUpperCase());
  return { token, label, tone: "neutral", variant: "dashed",
           mapped: false, known: true };
}

/** The analyst-facing label only — for table cells that are not chips. */
export const opsLabel = (raw) => opsState(raw).label;

/**
 * One status chip for the whole product.
 *
 * `reason` is the backend's own sentence and is surfaced verbatim in the
 * tooltip — a state that cannot be established always says why.
 */
export default function NxState({ value, reason, size = "sm",
                                  showToken = false, testid }) {
  const s = opsState(value);
  const title = [s.token, reason].filter(Boolean).join(" · ") || undefined;
  return (
    <NxChip tone={s.tone} variant={s.variant} size={size} title={title}
            data-nx-state={s.token || "NOT_AVAILABLE"}
            data-nx-unmapped={s.mapped ? undefined : "true"}
            data-testid={testid
              || `nx-state-${(s.token || "not-available").toLowerCase()}`}>
      {s.label}
      {showToken && s.token && (
        <span className="nx-state-token">{s.token}</span>
      )}
    </NxChip>
  );
}

export { NxState };
