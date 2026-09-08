/**
 * Product scope · the client-side half of the XDR/EDR product boundary.
 *
 * XDR and EDR currently ship in ONE bundle. The host-conditional
 * redirects in `vercel.json` keep each production hostname to its own
 * product, but they are SERVER rules: they fire on every real navigation
 * and cannot fire on a client-side `navigate()` that happens after the
 * page is already loaded. Without this module the EDR hostname could
 * still end up rendering XDR — the "silently falls back into the wrong
 * product" failure the owner prohibited.
 *
 * `REACT_APP_PRODUCT_SCOPE` is a PRODUCT-SCOPE variable, deliberately
 * NOT a cross-product origin variable: it says "this deployment IS the
 * XDR product" and lights up no launcher, so it does not conflict with
 * the decision to leave REACT_APP_XDR_URL / _EDR_URL / _WORKSPACE_URL
 * unset until each product is runtime-verified.
 *
 * UNSET is a first-class, meaningful state. Preview and any combined
 * deployment genuinely serve both products at one origin, so nothing is
 * foreign there and behaviour is byte-for-byte what it was before. Only
 * a deployment that declares a scope enforces a boundary.
 */

const raw = (process.env.REACT_APP_PRODUCT_SCOPE || "").trim().toLowerCase();

/** "xdr" | "edr" | "" — "" means a combined deployment (preview). */
export const PRODUCT_SCOPE = raw === "xdr" || raw === "edr" ? raw : "";

export const IS_SCOPED = PRODUCT_SCOPE !== "";

/** Where `/` and the catch-all should land for this deployment. */
export const HOME_PATH = `/${PRODUCT_SCOPE || "xdr"}`;

/**
 * Which product owns a path.
 *   "xdr" | "edr" | null (null = neutral: shared by both products)
 *
 * `/login` is neutral — both hostnames need it. `/kb` and `/docs` are
 * XDR-owned because they redirect into `/xdr/*`.
 */
export function productOfPath(pathname) {
  const p = (pathname || "/").toLowerCase();
  if (p === "/login") return null;
  if (p === "/" ) return null;
  if (p === "/edr" || p.startsWith("/edr/")) return "edr";
  if (p === "/xdr" || p.startsWith("/xdr/")) return "xdr";
  if (p === "/kb" || p.startsWith("/kb/")) return "xdr";
  if (p === "/docs" || p.startsWith("/docs/")) return "xdr";
  return null;
}

/** True only when this deployment declares a scope and the path is the
 *  OTHER product's. Always false on an unscoped/combined deployment. */
export function isForeignPath(pathname) {
  if (!IS_SCOPED) return false;
  const owner = productOfPath(pathname);
  return owner !== null && owner !== PRODUCT_SCOPE;
}
