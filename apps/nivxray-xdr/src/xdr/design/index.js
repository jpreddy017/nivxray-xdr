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
export { default as MitreTabV2 }            from "./MitreTabV2";
export { default as RecordHeaderV2 }        from "./RecordHeaderV2";
export { default as Glyph }                 from "./glyphs";
export * from "./glyphs";

/** Surfaces that have been fully migrated onto the Round 24.9
 * grammar.  Adding a surface to this set makes v2 its DEFAULT for
 * every analyst.  Surfaces that are absent stay on their existing
 * implementation — the `?design=v2` query has no effect on them
 * because there is no v2 module wired.
 *
 * Owner-locked semantics (2026-02-14):
 *   migrated surface  → v2 default
 *   unmigrated surface→ existing implementation (unaffected)
 *   ?design=v1        → escape hatch on migrated surfaces only
 *
 * Round 27 adds `integrations` + `recommendations`.  Future
 * migrations extend this set only after the surface actually ships.
 */
export const MIGRATED_SURFACES = new Set([
  "integrations",
  "recommendations",
  "mitre",
  "incident-header",
]);

/** Per-surface flag lookup.  Prefer this over `isDesignV2Enabled()`
 * — it prevents an env-forced v2 from accidentally lighting up
 * surfaces that were never migrated. */
export function isDesignV2EnabledFor(surface) {
  if (!MIGRATED_SURFACES.has(surface)) return false;
  // Hard env override — a deployment can pin v1 (e.g. rollback).
  const env = import.meta?.env?.VITE_XDR_DESIGN_V2;
  if (env === "0" || env === "false") return false;
  if (env === "1" || env === "true")  return true;
  if (typeof window === "undefined")  return true;
  try {
    const q = new URLSearchParams(window.location.search);
    const forced = q.get("design");
    if (forced === "v1") {
      try { window.sessionStorage.setItem("xdr-design", "v1"); } catch { /* ignore */ }
      return false;
    }
    if (forced === "v2") {
      try { window.sessionStorage.setItem("xdr-design", "v2"); } catch { /* ignore */ }
      return true;
    }
    const remembered = window.sessionStorage.getItem("xdr-design");
    if (remembered === "v1") return false;
    return true;         // owner-locked default for migrated surfaces
  } catch {
    return true;
  }
}

/** Legacy call-site helper retained for callers that predate the
 * surface-aware split.  Returns true only when we can safely assume
 * every migrated surface is on v2 (i.e. env-forced or explicit
 * `?design=v2`).  New code should use `isDesignV2EnabledFor`. */
export function isDesignV2Enabled() {
  const env = import.meta?.env?.VITE_XDR_DESIGN_V2;
  if (env === "1" || env === "true") return true;
  if (typeof window === "undefined") return false;
  try {
    const q = new URLSearchParams(window.location.search);
    const forced = q.get("design");
    if (forced === "v2") return true;
    if (forced === "v1") return false;
    return window.sessionStorage.getItem("xdr-design") === "v2";
  } catch {
    return false;
  }
}
