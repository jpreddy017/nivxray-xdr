/**
 * NivXRay chip primitives — grammar-locked (§5 truth-state).
 *
 * These are thin wrappers around NxChip that keep the existing
 * chip API (`<PriorityChip code="P1" />`, `<VerdictChip value="…" />`)
 * so the queue, record, drawers and dashboards need no callsite
 * changes.  Every callsite now inherits grammar §5:
 *   - filled  →  known / observed state
 *   - dashed  →  unknown / not-run / no-evidence / not-connected
 *
 * The grammar is enforced in *one* place.  No page may bring its
 * own tone table.
 */
import React from "react";
import { NxChip, NxHonestyChip } from "@/xdr/nx";

/* Priority — filled semantic chip.  P?/absent → dashed unknown. */
const PRIORITY_TONE = {
  P1: "critical", P2: "high", P3: "medium", P4: "benign", P5: "on_hold",
};
export function PriorityChip({ code, onClick }) {
  const tone = code && PRIORITY_TONE[code];
  if (!tone) return <NxHonestyChip state="unknown" data-testid="chip-priority-unknown" />;
  return (
    <NxChip
      tone={tone}
      variant="filled"
      size="sm"
      onClick={onClick}
      data-testid={`chip-priority-${code}`}
    >
      {code}
    </NxChip>
  );
}

/* Severity — filled tinted chip.  unknown → dashed. */
const SEVERITY_TONE = {
  critical: "critical", high: "high", medium: "medium",
  low: "benign", info: "low",
};
export function SeverityChip({ value, onClick }) {
  const k = String(value || "unknown").toLowerCase();
  if (!SEVERITY_TONE[k])
    return <NxHonestyChip state="unknown" data-testid="chip-severity-unknown" />;
  return (
    <NxChip
      tone={SEVERITY_TONE[k]}
      variant="tinted"
      size="sm"
      onClick={onClick}
      data-testid={`chip-severity-${k}`}
    >
      {k.toUpperCase()}
    </NxChip>
  );
}

/* Verdict — filled semantic chip.  unknown → dashed. */
const VERDICT_TONE = {
  malicious: "malicious", suspicious: "suspicious", benign: "benign",
};
export function VerdictChip({ value, onClick }) {
  const k = String(value || "unknown").toLowerCase();
  if (!VERDICT_TONE[k])
    return <NxHonestyChip state="unknown" data-testid="chip-verdict-unknown" />;
  return (
    <NxChip
      tone={VERDICT_TONE[k]}
      variant="filled"
      size="sm"
      onClick={onClick}
      data-testid={`chip-verdict-${k}`}
    >
      {k.toUpperCase()}
    </NxChip>
  );
}

/* State — tinted lifecycle chip. */
const STATE_TONE = {
  new: "new", triaged: "in_progress",
  in_progress: "in_progress", investigating: "in_progress",
  on_hold: "on_hold", waiting_customer: "on_hold",
  containment: "high", eradication: "critical", recovery: "benign",
  resolved: "resolved", closed: "closed",
};
export function StateChip({ value, onClick }) {
  const k = String(value || "new").toLowerCase();
  const tone = STATE_TONE[k] || "on_hold";
  return (
    <NxChip
      tone={tone}
      variant="tinted"
      size="sm"
      onClick={onClick}
      data-testid={`chip-state-${k}`}
    >
      {k.replace(/_/g, " ").toUpperCase()}
    </NxChip>
  );
}

/* Side-state — grammar §5: always dashed (represents "waiting"). */
export function SideStateChip({ value }) {
  if (!value) return null;
  const k = String(value).toLowerCase();
  return (
    <NxChip
      tone="purple"
      variant="dashed"
      size="sm"
      data-testid={`chip-side-state-${k}`}
    >
      {k.replace(/_/g, " ").toUpperCase()}
    </NxChip>
  );
}

/* Domain tag — tinted, purple identity. */
export function DomainTag({ value, onClick }) {
  if (!value) return null;
  const k = String(value).toUpperCase();
  return (
    <NxChip
      tone="purple"
      variant="tinted"
      size="sm"
      onClick={onClick}
      data-testid={`chip-domain-${k}`}
    >
      {k}
    </NxChip>
  );
}
