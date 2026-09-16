/**
 * Product origins · pre-production preparation for the domain split.
 *
 * Locked target topology:
 *   xdr.nivxforge.com        → NivXRay XDR
 *   edr.nivxforge.com        → NivXForge EDR
 *   workspace.nivxmachines.com → NivXMachines Workspace
 *
 * Today XDR and EDR ship in ONE bundle, so every cross-product pivot is
 * an in-app `navigate()`. Once they live on separate origins that is no
 * longer a pivot — it keeps the analyst on the wrong product host. So
 * every pivot must resolve its target through here.
 *
 * Two modes, and the distinction matters for honesty:
 *
 *   CONFIGURED    an origin is set → absolute cross-origin URL.
 *   SAME_ORIGIN   nothing set → the two products genuinely ARE one
 *                 deployment at one origin (preview, and any combined
 *                 deployment), so in-app navigation is correct. This is
 *                 NOT the "silently navigating inside the wrong product"
 *                 failure the owner prohibited — that failure is
 *                 pretending to leave for a product that lives
 *                 elsewhere. Callers still disclose the mode.
 *
 * Workspace is different: it is ALWAYS a separate deployment, never in
 * this bundle, so with no URL there is nothing to open and the control
 * must read NOT CONFIGURED rather than navigate anywhere.
 *
 * Env names: `REACT_APP_*` and `VITE_*` are both accepted (see
 * `vite.config.js`) so the deployment can use either convention. These
 * are PUBLIC configuration only — never put a credential in a build
 * variable, it ends up readable in the browser bundle.
 */

const clean = (v) => (v || "").trim().replace(/\/+$/, "");

export const XDR_URL = clean(process.env.REACT_APP_XDR_URL);
export const EDR_URL = clean(process.env.REACT_APP_EDR_URL);
export const WORKSPACE_URL = clean(process.env.REACT_APP_WORKSPACE_URL);

const ORIGINS = { xdr: XDR_URL, edr: EDR_URL, workspace: WORKSPACE_URL };

/** `CONFIGURED` when the product has its own origin, else `SAME_ORIGIN`. */
export const productMode = (product) =>
  (ORIGINS[product] ? "CONFIGURED" : "SAME_ORIGIN");

/**
 * Where a pivot to `product` should send the analyst.
 * Returns an absolute URL when that product has its own origin, and the
 * in-app path when it does not (one bundle, one origin). `path` must
 * already carry the context contract — tenant / customer / endpoint /
 * incident / detection / evidence / time range stay in the query string,
 * which is exactly why it survives becoming cross-origin.
 */
export const productHref = (product, path) => {
  const p = path.startsWith("/") ? path : `/${path}`;
  const origin = ORIGINS[product];
  return origin ? `${origin}${p}` : p;
};

/** True when the pivot leaves this origin and so needs a real navigation. */
export const isCrossOrigin = (product) => Boolean(ORIGINS[product]);
