/**
 * NxSeverity · the platform's ONE severity / verdict / lifecycle grammar.
 *
 * Before this file, incident severity was rendered by `sev-critical` CSS in
 * the queue, by `status_chips[].tone` on the record, and by `SEV_CLASS` in the
 * endpoint inventory — three vocabularies for one fact. Every surface now maps
 * through here, so a verdict can never look different on two pages.
 *
 * Honesty rules baked in:
 *   · an absent verdict renders "UNKNOWN", never "benign";
 *   · a confidence renders only when the backend supplied one;
 *   · risk renders as `n/100` only when `risk_score` is a number.
 */
import React from "react";
import NxChip from "./NxChip";

const VERDICT_TONE = {
  malicious: "malicious", suspicious: "suspicious", benign: "benign",
  clean: "benign", unknown: "neutral", common: "neutral",
};
const VERDICT_LABEL = {
  malicious: "MALICIOUS", suspicious: "SUSPICIOUS", benign: "BENIGN",
  clean: "CLEAN", unknown: "UNKNOWN", common: "COMMON",
};

/** Disposition / verdict. `value` is the raw backend token. */
export function NxVerdict({ value, title, testid }) {
  const k = String(value || "unknown").toLowerCase();
  return (
    <NxChip tone={VERDICT_TONE[k] || "neutral"} variant="filled"
            title={title || undefined} data-testid={testid}>
      {VERDICT_LABEL[k] || k.toUpperCase()}
    </NxChip>
  );
}

const LC_LABEL = {
  new: "New", in_progress: "In progress", on_hold: "On hold",
  resolved: "Resolved", closed: "Closed",
};

/** Incident lifecycle state. */
export function NxLifecycle({ value, testid }) {
  const k = String(value || "").toLowerCase();
  if (!k) {
    return <NxChip tone="neutral" variant="dashed" data-testid={testid}>
      Not recorded</NxChip>;
  }
  return (
    <NxChip tone={LC_LABEL[k] ? k : "neutral"} variant="tinted"
            data-testid={testid}>
      {LC_LABEL[k] || k}
    </NxChip>
  );
}

/** Priority band. `priority` is the backend `{code,label}` object. */
export function NxPriority({ priority, testid }) {
  const code = priority?.code || null;
  if (!code) {
    return <NxChip tone="neutral" variant="dashed" data-testid={testid}>
      No priority</NxChip>;
  }
  const n = Number(String(code).replace(/\D/g, "")) || 5;
  return (
    <NxChip tone={`pri-${Math.min(5, Math.max(1, n))}`} variant="filled"
            title={priority?.label || undefined} data-testid={testid}>
      {code}{priority?.label ? ` · ${priority.label}` : ""}
    </NxChip>
  );
}

/** Confidence — rendered only when the backend supplied one. */
export function NxConfidence({ value, testid }) {
  if (value == null || value === "") {
    return <NxChip tone="neutral" variant="dashed"
                   title="No confidence value on this record"
                   data-testid={testid}>Confidence not recorded</NxChip>;
  }
  const num = typeof value === "number";
  return (
    <NxChip tone="low" variant="tinted" data-testid={testid}>
      {num ? `${value}% confidence` : String(value).toUpperCase()}
    </NxChip>
  );
}

/** Risk 0-100. Never invented. */
export function NxRisk({ score, testid }) {
  if (typeof score !== "number") {
    return <NxChip tone="neutral" variant="dashed"
                   title="No risk score on this record"
                   data-testid={testid}>Risk not scored</NxChip>;
  }
  const tone = score >= 80 ? "critical" : score >= 60 ? "high"
             : score >= 40 ? "medium" : "low";
  return (
    <NxChip tone={tone} variant="tinted" data-testid={testid}>
      {score}/100 risk
    </NxChip>
  );
}

/** Provenance — NivXRay's differentiator. Never softened. */
export function NxProvenanceChip({ provenance, basis, isReal, testid }) {
  const real = !!isReal;
  return (
    <NxChip tone={real ? "available" : "no_evidence"}
            variant={real ? "tinted" : "dashed"}
            title={basis || undefined} data-testid={testid}>
      {provenance || (real ? "REAL_SENSOR_DERIVED" : "PROVENANCE_UNKNOWN")}
    </NxChip>
  );
}

export default NxVerdict;
