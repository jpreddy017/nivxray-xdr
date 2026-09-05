/**
 * NxChip · §5 truth-state chip grammar.
 *
 *   variant: "filled" | "tinted" | "dashed"
 *     - filled  → known/observed, high visibility
 *     - tinted  → known/observed, softer surface
 *     - dashed  → absent/uncertain/not-run (locked grammar)
 *
 *   tone: semantic key (critical · high · medium · low · malicious
 *         · suspicious · benign · new · in_progress · on_hold ·
 *         resolved · closed · sla-ok · sla-risk · sla-breached ·
 *         available · searched · no_evidence · not_connected ·
 *         not_run · running · complete · partial · failed · purple)
 *
 *   pulse: when true, adds §8 execution-state pulse to the dot.
 */
import React from "react";

const TONE = {
  critical:   { c: "var(--nx-critical)",  bg: "var(--nx-critical-bg)",   bd: "var(--nx-critical-bd)"  },
  high:       { c: "var(--nx-high)",      bg: "var(--nx-high-bg)",       bd: "var(--nx-high-bd)"      },
  medium:     { c: "var(--nx-medium)",    bg: "var(--nx-medium-bg)",     bd: "var(--nx-medium-bd)"    },
  low:        { c: "var(--nx-low)",       bg: "var(--nx-low-bg)",        bd: "var(--nx-low-bd)"       },

  malicious:  { c: "var(--nx-malicious)", bg: "var(--nx-malicious-bg)",  bd: "var(--nx-malicious-bd)" },
  suspicious: { c: "var(--nx-suspicious)",bg: "var(--nx-suspicious-bg)", bd: "var(--nx-suspicious-bd)"},
  benign:     { c: "var(--nx-benign)",    bg: "var(--nx-benign-bg)",     bd: "var(--nx-benign-bd)"    },

  new:         { c: "var(--nx-lc-new)",         bg: "var(--nx-low-bg)",     bd: "var(--nx-low-bd)"     },
  in_progress: { c: "var(--nx-lc-in_progress)", bg: "var(--nx-purple-dim)", bd: "#C7B7FF"              },
  on_hold:     { c: "var(--nx-lc-on_hold)",     bg: "var(--nx-workspace-alt)", bd: "var(--nx-divider-strong)" },
  resolved:    { c: "var(--nx-lc-resolved)",    bg: "var(--nx-benign-bg)",  bd: "var(--nx-benign-bd)"  },
  closed:      { c: "var(--nx-lc-closed)",      bg: "var(--nx-workspace-alt)", bd: "var(--nx-divider-strong)" },

  "sla-ok":       { c: "var(--nx-sla-ok)",       bg: "var(--nx-benign-bg)",   bd: "var(--nx-benign-bd)"   },
  "sla-risk":     { c: "var(--nx-sla-risk)",     bg: "var(--nx-high-bg)",     bd: "var(--nx-high-bd)"     },
  "sla-breached": { c: "var(--nx-sla-breached)", bg: "var(--nx-critical-bg)", bd: "var(--nx-critical-bd)" },

  available:     { c: "var(--nx-ev-available)",     bg: "var(--nx-teal-dim)",       bd: "#5EEAD4" },
  searched:      { c: "var(--nx-ev-searched)",      bg: "var(--nx-low-bg)",         bd: "var(--nx-low-bd)" },
  no_evidence:   { c: "var(--nx-ev-no_evidence)",   bg: "var(--nx-medium-bg)",      bd: "var(--nx-medium-bd)" },
  not_connected: { c: "var(--nx-ev-not_connected)", bg: "var(--nx-workspace-alt)",  bd: "var(--nx-divider-strong)" },

  not_run:  { c: "var(--nx-exec-not_run)",  bg: "var(--nx-workspace-alt)", bd: "var(--nx-divider-strong)" },
  running:  { c: "var(--nx-exec-running)",  bg: "var(--nx-purple-dim)",    bd: "#C7B7FF" },
  complete: { c: "var(--nx-exec-complete)", bg: "var(--nx-benign-bg)",     bd: "var(--nx-benign-bd)" },
  partial:  { c: "var(--nx-exec-partial)",  bg: "var(--nx-medium-bg)",     bd: "var(--nx-medium-bd)" },
  failed:   { c: "var(--nx-exec-failed)",   bg: "var(--nx-critical-bg)",   bd: "var(--nx-critical-bd)" },

  purple:    { c: "var(--nx-purple)", bg: "var(--nx-purple-dim)", bd: "#C7B7FF" },
  neutral:   { c: "var(--nx-muted)",  bg: "var(--nx-workspace-alt)", bd: "var(--nx-divider-strong)" },
};

const NxChip = React.forwardRef(function NxChip({
  tone = "neutral",
  variant = "tinted",
  size = "md",
  pulse = false,
  dot = false,
  children,
  onClick,
  as: Tag = onClick ? "button" : "span",
  style,
  className = "",
  ...rest
}, ref) {
  const t = TONE[tone] || TONE.neutral;
  const chipStyle = {
    "--nx-tone":    t.c,
    "--nx-tone-bg": t.bg,
    "--nx-tone-bd": t.bd,
    ...style,
  };
  const cls = [
    "nx-chip",
    `nx-chip--${variant}`,
    `nx-chip--${size}`,
    pulse && "nx-chip--pulse",
    onClick && "nx-chip--interactive",
    className,
  ].filter(Boolean).join(" ");
  return (
    <Tag
      ref={ref}
      type={Tag === "button" ? "button" : undefined}
      role={onClick ? "button" : undefined}
      className={cls}
      style={chipStyle}
      onClick={onClick}
      {...rest}
    >
      {dot && <span className="nx-chip-dot" aria-hidden />}
      {children}
    </Tag>
  );
});

export default NxChip;

/** Convenience wrapper for the honesty grammar — always dashed. */
export const NxHonestyChip = ({ state = "unknown", ...rest }) => {
  // Phase 1-a · epistemic-state grammar.  The glyph carries the meaning so
  // it never depends on colour alone; the border grammar is locked:
  //   solid border  = we KNOW      dashed border = we do NOT (yet) know.
  const key = String(state || "unknown").toLowerCase();
  const SPEC = {
    evidence_present:       { glyph: "\u25C6", label: "EVIDENCE PRESENT",       known: true  },
    no_evidence:            { glyph: "\u25C7", label: "NO EVIDENCE",            known: true  },
    unknown:                { glyph: "?",      label: "UNKNOWN",                known: false },
    not_run:                { glyph: "\u25CB", label: "NOT_RUN",                known: false },
    capability_unavailable: { glyph: "\u2298", label: "CAPABILITY UNAVAILABLE", known: false },
    not_connected:          { glyph: "\u2298", label: "NOT CONNECTED",          known: false },
    not_available:          { glyph: "\u2298", label: "NOT AVAILABLE",          known: false },
  };
  const spec = SPEC[key] || {
    glyph: "?", label: String(state).toUpperCase(), known: false,
  };
  const TITLE = {
    // NO EVIDENCE is an honest NEGATIVE RESULT, not missing data.
    no_evidence: "The query ran and returned zero matches — an honest negative result, not missing data.",
    evidence_present: "Confirmed, citable telemetry backs this value.",
    unknown: "Evaluable, but no verdict has been asserted yet.",
    not_run: "The engine exists and has not executed for this record.",
    capability_unavailable: "Registered capability with no configured integration.",
    not_connected: "Transport was never established for this source.",
  };
  return (
    <span
      className="nx-ep"
      data-ep={key}
      data-known={spec.known ? "true" : "false"}
      data-testid={`nx-epistemic-${key}`}
      title={TITLE[key] || spec.label}
      {...rest}
    >
      <span className="nx-ep__glyph" aria-hidden="true">{spec.glyph}</span>
      {spec.label}
    </span>
  );
};
