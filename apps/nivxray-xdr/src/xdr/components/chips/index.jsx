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
// Owner-locked priority ladder (2026-09-05):
//   P1 = CRITICAL · P2 = HIGH · P3 = MEDIUM · P4 = LOW · P5 = INFORMATIONAL
// Four visually distinct steps, each with its own hue AND its own
// severity glyph, so rank survives greyscale and colour-blindness.
const PRIORITY_TONE = {
  P1: "pri-1", P2: "pri-2", P3: "pri-3", P4: "pri-4", P5: "pri-5",
};
const PRIORITY_LABEL = {
  P1: "P1 · CRITICAL", P2: "P2 · HIGH", P3: "P3 · MEDIUM",
  P4: "P4 · LOW", P5: "P5 · INFORMATIONAL",
};
// Rank glyph — filled blocks descending.  Colour is never the only
// carrier of priority.
const PRIORITY_GLYPH = {
  P1: "\u25B0\u25B0\u25B0\u25B0", P2: "\u25B0\u25B0\u25B0\u25B1",
  P3: "\u25B0\u25B0\u25B1\u25B1", P4: "\u25B0\u25B1\u25B1\u25B1",
  P5: "\u25B1\u25B1\u25B1\u25B1",
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
      data-priority-rank={code}
      title={PRIORITY_LABEL[code]}
    >
      <span aria-hidden="true"
             style={{ fontFamily: "var(--nx-font-mono)", fontSize: "0.82em",
                         letterSpacing: "-0.06em", marginRight: 4,
                         opacity: 0.9 }}>
        {PRIORITY_GLYPH[code]}
      </span>
      {code}
    </NxChip>
  );
}

/* Severity — filled tinted chip.  unknown → dashed. */
// Severity uses the SAME four-step ladder as priority so the two
// columns can never contradict each other visually.
const SEVERITY_TONE = {
  critical: "critical", high: "high", medium: "medium",
  low: "low", informational: "neutral", info: "neutral",
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
