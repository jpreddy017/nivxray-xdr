/**
 * ADR-0022 §4 · FeatureFlagResolver.
 *
 * The route owns the experience. This resolver reads the `?lab2=1`
 * migration flag (or `REACT_APP_LAB2_ENABLED` env for CI harnesses)
 * and chooses which renderer to mount. Renderers do NOT know about
 * each other and NEVER coexist in the same DOM tree.
 *
 * When cutover happens, delete this file and replace every callsite
 * with the Lab2Renderer directly (ADR-0022 §12 · Final Cutover).
 */
export function isLab2Enabled() {
  if (typeof window === "undefined") return false;
  const url = new URLSearchParams(window.location.search);
  if (url.get("lab2") === "1") return true;
  if (url.get("lab2") === "0") return false;
  // Env fallback for CI / storybook harnesses
  return process.env.REACT_APP_LAB2_ENABLED === "1";
}
