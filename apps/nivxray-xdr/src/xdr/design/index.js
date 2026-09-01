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
export { default as RecommendationsTabV2 } from "./RecommendationsTabV2";

/** Runtime feature-flag lookup — safe to call from any React tree.
 *
 * Behaviour (Round 27 refinement):
 *   1. Env `VITE_XDR_DESIGN_V2` truthy → always v2 for this build.
 *   2. `?design=v2` on the current URL → v2, and cached in
 *      sessionStorage so subsequent client-side navigations retain
 *      the opt-in (the owner-locked "coexist behind flag, migrate
 *      progressively" contract).
 *   3. `?design=v1` on the current URL → force legacy for this
 *      session; also clears any prior sessionStorage v2 opt-in.
 *   4. Otherwise → whatever sessionStorage remembers, else legacy.
 */
export function isDesignV2Enabled() {
  const env = import.meta?.env?.VITE_XDR_DESIGN_V2;
  if (env === "1" || env === "true") return true;
  if (typeof window === "undefined") return false;
  try {
    const q = new URLSearchParams(window.location.search);
    const forced = q.get("design");
    if (forced === "v2") {
      try { window.sessionStorage.setItem("xdr-design", "v2"); } catch { /* ignore */ }
      return true;
    }
    if (forced === "v1") {
      try { window.sessionStorage.setItem("xdr-design", "v1"); } catch { /* ignore */ }
      return false;
    }
    const remembered = window.sessionStorage.getItem("xdr-design");
    return remembered === "v2";
  } catch {
    return false;
  }
}
