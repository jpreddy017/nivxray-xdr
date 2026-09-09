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


/** Product-scope-aware branding · the single source of truth for the
 *  wordmark, product name, tagline and document title.
 *
 *  The login page is shared by both products, so it must never hard-code a
 *  product identity: `/login` is the generic entry point that BOTH hostnames
 *  land on, and a hard-coded default is exactly why edr.nivxforge.com
 *  rendered "NIVXRAY XDR". Anything showing a product name reads from here.
 *
 *  An unscoped (combined/preview) build keeps the XDR identity, so preview
 *  behaviour is unchanged.
 */
const BRANDS = {
  xdr: {
    scope: "xdr",
    suffix: "XDR",
    // Rendered verbatim inside the lockup, so the XDR wordmark and tagline
    // stay byte-for-byte identical to the shipped production build.
    taglineLead: "EXTENDED",
    name: "NivXRay",
    nameSuffix: "XDR",
    label: "NivXRay XDR",
    wordmark: "NIVXRAY XDR",
    subtitle: "Extended detection & response",
    documentTitle: "NivXRay XDR",
  },
  edr: {
    scope: "edr",
    suffix: "EDR",
    taglineLead: "ENDPOINT",
    name: "NivXRay",
    nameSuffix: "EDR",
    label: "NivXRay EDR",
    wordmark: "NIVXRAY EDR",
    subtitle: "Endpoint detection & response",
    documentTitle: "NivXRay EDR",
  },
};

/** Branding for an explicit scope; falls back to the XDR identity. */
export const brandFor = (scope) => BRANDS[scope] || BRANDS.xdr;

/** Branding for THIS deployment. */
export const BRAND = brandFor(PRODUCT_SCOPE);
