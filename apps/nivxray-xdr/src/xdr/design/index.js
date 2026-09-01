/**
 * NivXRay Evidence Operations Design System — Round 24.9.
 *
 * Import site:  `@/xdr/design`
 *
 * Every consumer imports through this barrel; never reach into an
 * individual primitive file, so future grammar rewrites happen in
 * one place.
 *
 * Feature flag:
 *   `VITE_XDR_DESIGN_V2` env → truthy string enables the v2 UI.
 *   `?design=v2` URL query   → forces v2 for a single browser
 *                              session (dev/preview override).
 *   `?design=v1` URL query   → forces the legacy UI.
 */
export { default as Entity }         from "./Entity";
export { default as EvidenceState,
         EVIDENCE_STATES,
         CAPABILITY_STATES }         from "./EvidenceState";
export { default as Provenance }     from "./Provenance";
export { default as Relationship }   from "./Relationship";
export { default as Action,
         ActionGroup }               from "./Action";

export { default as IntegrationControlCenter } from "./IntegrationControlCenter";
export { default as CortexOnboardingWizard } from "./CortexOnboardingWizard";

/** Runtime feature-flag lookup — safe to call from any React tree. */
export function isDesignV2Enabled() {
  if (typeof window !== "undefined") {
    try {
      const q = new URLSearchParams(window.location.search);
      const forced = q.get("design");
      if (forced === "v2") return true;
      if (forced === "v1") return false;
    } catch {
      /* URL parse failure → fall through to env flag */
    }
  }
  const env = import.meta?.env?.VITE_XDR_DESIGN_V2;
  return env === "1" || env === "true";
}
