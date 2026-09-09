/**
 * <Action> — Round 24.9 primitive.
 *
 * An operator command bound to an EvidenceState capability.  When
 * the capability is anything other than `cap-full` or `cap-ingest`,
 * the action MUST expose an honest disabled state with a
 * machine-readable reason — never silently greyed.
 *
 *   <Action
 *     label="Test connection"
 *     capability="cap-full"
 *     onRun={handleTest}
 *   />
 *
 *   <Action
 *     label="Isolate host"
 *     capability="cap-unavailable"
 *     reason="NOT_SUPPORTED by adapter"
 *   />
 *
 * Grammar guarantees:
 *   · `label` is always visible — no icon-only buttons.
 *   · If disabled, the reason is rendered inline.
 *   · No colour beyond token-driven tones.
 */
import React from "react";

const CAPABILITY_ENABLED = new Set(["cap-full", "cap-ingest", "cap-degraded"]);

export default function Action({
  label,
  icon: Icon = null,
  capability = "cap-full",
  tone = "default",
  onRun = null,
  reason = null,
  forceDisabled = false,
  testid,
}) {
  const capabilityAllows = CAPABILITY_ENABLED.has(capability);
  const disabled = forceDisabled || !capabilityAllows || !onRun;
  return (
    <button
      type="button"
      className="evops-action"
      data-tone={tone}
      data-capability={capability}
      disabled={disabled}
      onClick={disabled ? undefined : onRun}
      data-testid={testid}
      title={disabled && reason ? String(reason) : undefined}
    >
      {Icon && <Icon size={12} aria-hidden />}
      <span>{label}</span>
      {disabled && reason && (
        <span className="evops-action__reason">· {reason}</span>
      )}
    </button>
  );
}

export function ActionGroup({ children, testid }) {
  return (
    <div className="evops-action-group" data-testid={testid}>
      {children}
    </div>
  );
}
