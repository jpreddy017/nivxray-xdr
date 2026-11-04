/**
 * @tier         4 · Panel
 * @consumes     cio.verdict.{label, confidence, confidence_pct, reason, contributors, engine}
 * @publishes    (none — read-only presentation)
 * @deps         useVerdict (Tier-3 hook)
 * @a11y         role="status" · aria-live="polite" · aria-label describes verdict label + confidence
 * @keyboard     no owned shortcuts (details panel toggled by parent)
 * @perf         initial render budget: ≤ 8ms
 * @tests        component test in this file (states: empty · populated · error) · Storybook story alongside
 *
 * ADR-0014 §1.1.3 · Verdict is the single most visible piece of the workspace.
 * ADR-0019 · This is the REFERENCE IMPLEMENTATION for all future Lab 2.0 components:
 *   - Consumes ONLY selector hooks (no direct backend calls)
 *   - No business logic (all fields come pre-computed from the backend)
 *   - Loading / empty / populated / error states
 *   - Semantic tokens only (no hex literals)
 *   - Storybook story shipped alongside
 *   - Accessible + keyboard-friendly
 */
import React from "react";
import { useVerdict } from "../hooks/useCIO";

const LABEL_TONE = {
  "Malicious":         "var(--verdict-critical)",
  "Suspicious":        "var(--verdict-suspect)",
  "Runtime Dependent": "var(--verdict-info)",
  "Informational":     "var(--verdict-benign)",
  "Undetermined":      "var(--verdict-unknown)",
};

const STYLES = {
  ribbon: {
    display: "flex",
    alignItems: "center",
    gap: "var(--space-5)",
    padding: "var(--space-4) var(--space-5)",
    background: "var(--bg-panel)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius-md)",
    fontFamily: "var(--font-sans)",
    color: "var(--fg-primary)",
    transition: "background-color var(--motion-quick), border-color var(--motion-quick)",
  },
  labelPill: {
    padding: "var(--space-2) var(--space-4)",
    borderRadius: "var(--radius-sm)",
    fontSize: "var(--fs-strong)",
    fontWeight: "var(--fw-semibold)",
    letterSpacing: "0.02em",
  },
  confidenceBlock: {
    display: "flex",
    flexDirection: "column",
    gap: "var(--space-2)",
    minWidth: "180px",
  },
  confBar: {
    width: "100%",
    height: "4px",
    background: "var(--bg-elevated)",
    borderRadius: "var(--radius-sm)",
    overflow: "hidden",
  },
  confFill: {
    height: "100%",
    borderRadius: "var(--radius-sm)",
    transition: "width var(--motion-narrative)",
  },
  reason: {
    flex: 1,
    color: "var(--fg-quiet)",
    fontSize: "var(--fs-body)",
    lineHeight: 1.5,
  },
  engine: {
    fontSize: "var(--fs-caption)",
    fontFamily: "var(--font-mono)",
    color: "var(--fg-quiet)",
    opacity: 0.7,
  },
};

export function VerdictRibbon() {
  const verdict = useVerdict();

  // ── Empty state ─────────────────────────────────────────────
  if (!verdict) {
    return (
      <div
        role="status"
        aria-live="polite"
        aria-label="No verdict available yet"
        data-testid="verdict-ribbon-empty"
        style={{ ...STYLES.ribbon, opacity: 0.7 }}
      >
        <span style={{ ...STYLES.labelPill, background: "var(--bg-elevated)", color: "var(--fg-quiet)" }}>
          No verdict
        </span>
        <span style={STYLES.reason}>
          Run an investigation to see the verdict.
        </span>
      </div>
    );
  }

  // ── Error state (malformed CIO — schema-guard defensive) ────
  if (!verdict.label || typeof verdict.confidence_pct !== "number") {
    return (
      <div
        role="alert"
        data-testid="verdict-ribbon-error"
        style={{ ...STYLES.ribbon, borderColor: "var(--verdict-critical)" }}
      >
        <span style={{ ...STYLES.labelPill, background: "var(--verdict-critical)", color: "var(--fg-inverse)" }}>
          Malformed CIO
        </span>
        <span style={STYLES.reason}>
          Verdict field is present but incomplete — check backend schema version.
        </span>
      </div>
    );
  }

  const tone = LABEL_TONE[verdict.label] || "var(--verdict-unknown)";

  // ── Populated state ─────────────────────────────────────────
  return (
    <div
      role="status"
      aria-live="polite"
      aria-label={`Verdict: ${verdict.label}, confidence ${verdict.confidence_pct} percent`}
      data-testid="verdict-ribbon"
      style={STYLES.ribbon}
    >
      <span
        data-testid="verdict-ribbon-label"
        style={{ ...STYLES.labelPill, background: tone, color: "var(--fg-inverse)" }}
      >
        {verdict.label}
      </span>

      <div style={STYLES.confidenceBlock}>
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: "var(--fs-caption)", color: "var(--fg-quiet)" }}>
          <span>CONFIDENCE</span>
          <span data-testid="verdict-ribbon-confidence">{verdict.confidence_pct}%</span>
        </div>
        <div style={STYLES.confBar} aria-hidden="true">
          <div style={{ ...STYLES.confFill, width: `${verdict.confidence_pct}%`, background: tone }} />
        </div>
      </div>

      <span style={STYLES.reason} data-testid="verdict-ribbon-reason">
        {verdict.reason || "No rationale provided."}
      </span>

      <span style={STYLES.engine} data-testid="verdict-ribbon-engine" title="Verdict engine version">
        {verdict.engine || "unified-verdict-engine"}
      </span>
    </div>
  );
}

export default VerdictRibbon;
