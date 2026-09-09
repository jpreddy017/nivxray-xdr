/**
 * Recovery Status Ribbon
 * ────────────────────────────────────────────────────────────
 * Priority 3 · owner-approved 2026-02
 *
 * Split "Confidence" into TWO clearly-named signals plus a Terminal
 * State pill. Additive UI — does NOT replace any existing panel.
 *
 *   • Threat Confidence   — verdict-card score (existing signal).
 *   • Canonical Confidence — completeness of the deterministic
 *                            recovery, derived by IEDDE (Rule 23).
 *   • Terminal State      — Canonical · Binary Artifact Recovered ·
 *                            Stability Gate · Partial Recovery.
 *   • Reason              — human-readable IEDDE stop reason.
 */
import { Shield, GaugeCircle, Flag } from "lucide-react";

const _pillColor = (state) => {
  switch (state) {
    case "canonical":
      return "bg-emerald-500/15 text-emerald-300 border-emerald-500/40";
    case "binary_artifact_recovered":
      return "bg-cyan-500/15 text-cyan-300 border-cyan-500/40";
    case "stability_gate":
      return "bg-amber-500/15 text-amber-300 border-amber-500/40";
    case "partial_recovery":
      return "bg-orange-500/15 text-orange-300 border-orange-500/40";
    case "decode_error":
      return "bg-rose-500/15 text-rose-300 border-rose-500/40";
    default:
      return "bg-neutral-500/15 text-neutral-300 border-neutral-500/40";
  }
};

const _pillLabel = (state) => {
  switch (state) {
    case "canonical":
      return "Canonical";
    case "binary_artifact_recovered":
      return "Binary Artifact Recovered";
    case "stability_gate":
      return "Stability Gate";
    case "partial_recovery":
      return "Partial Recovery";
    case "decode_error":
      return "Decode Error";
    default:
      return state || "Unknown";
  }
};

const _confidenceColor = (n) => {
  if (n == null) return "text-neutral-400";
  if (n >= 90) return "text-emerald-300";
  if (n >= 70) return "text-lime-300";
  if (n >= 50) return "text-amber-300";
  return "text-orange-300";
};

export default function RecoveryStatusRibbon({
  threatConfidence,
  canonicalConfidence,
  canonicalConfidenceReason,
  terminalState,
  binaryArtifact,
}) {
  if (
    threatConfidence == null &&
    canonicalConfidence == null &&
    !terminalState
  ) {
    return null;
  }

  return (
    <div
      className="flex flex-wrap items-center gap-3 px-4 py-2 rounded-lg bg-neutral-900/70 border border-neutral-800 mb-3"
      data-testid="recovery-status-ribbon"
    >
      {/* Threat Confidence ---------------------------------------- */}
      {typeof threatConfidence === "number" && (
        <div
          className="flex items-center gap-2"
          data-testid="ribbon-threat-confidence"
        >
          <Shield className="w-4 h-4 text-rose-400" />
          <span className="text-[11px] uppercase tracking-wider text-neutral-500">
            Threat Confidence
          </span>
          <span
            className={`font-mono text-sm font-semibold ${_confidenceColor(
              threatConfidence
            )}`}
          >
            {threatConfidence}%
          </span>
        </div>
      )}

      {/* Canonical Confidence ------------------------------------ */}
      {typeof canonicalConfidence === "number" && (
        <div
          className="flex items-center gap-2"
          data-testid="ribbon-canonical-confidence"
          title={canonicalConfidenceReason || ""}
        >
          <GaugeCircle className="w-4 h-4 text-sky-400" />
          <span className="text-[11px] uppercase tracking-wider text-neutral-500">
            Canonical Confidence
          </span>
          <span
            className={`font-mono text-sm font-semibold ${_confidenceColor(
              canonicalConfidence
            )}`}
          >
            {canonicalConfidence}%
          </span>
        </div>
      )}

      {/* Terminal State ------------------------------------------ */}
      {terminalState && (
        <div
          className="flex items-center gap-2"
          data-testid="ribbon-terminal-state"
        >
          <Flag className="w-4 h-4 text-amber-400" />
          <span className="text-[11px] uppercase tracking-wider text-neutral-500">
            Terminal State
          </span>
          <span
            className={`px-2 py-0.5 rounded text-xs font-mono border ${_pillColor(
              terminalState
            )}`}
            data-testid="ribbon-terminal-state-badge"
          >
            {_pillLabel(terminalState)}
          </span>
          {binaryArtifact && terminalState === "binary_artifact_recovered" && (
            <span className="text-xs font-mono text-cyan-300">
              {binaryArtifact.kind} · {binaryArtifact.subtype}
            </span>
          )}
        </div>
      )}

      {/* Reason (compact) ---------------------------------------- */}
      {canonicalConfidenceReason && (
        <div
          className="text-[11px] font-mono text-neutral-500 truncate max-w-[400px]"
          title={canonicalConfidenceReason}
          data-testid="ribbon-canonical-reason"
        >
          {canonicalConfidenceReason}
        </div>
      )}
    </div>
  );
}
