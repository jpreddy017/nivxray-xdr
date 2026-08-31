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
  const toneByState = {
    unknown:       "neutral",
    not_run:       "not_run",
    no_evidence:   "no_evidence",
    not_connected: "not_connected",
    not_available: "neutral",
  };
  const labelByState = {
    unknown:       "UNKNOWN",
    not_run:       "NOT_RUN",
    no_evidence:   "NO EVIDENCE",
    not_connected: "NOT CONNECTED",
    not_available: "NOT AVAILABLE",
  };
  const key = String(state || "unknown").toLowerCase();
  return (
    <NxChip
      variant="dashed"
      tone={toneByState[key] || "neutral"}
      size="sm"
      {...rest}
    >
      {labelByState[key] || String(state).toUpperCase()}
    </NxChip>
  );
};
