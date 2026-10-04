/**
 * P0-FIX-4A · WHO may choose a customer, decided by the SERVER.
 *
 * The console used to render "SELECT CUSTOMER" unconditionally, so a user
 * authorized for exactly one customer was asked to pick the only thing it
 * could ever be — and, for a principal without `tenants.read`, the menu
 * could not even be populated. The browser was also the place the choice
 * was stored, which is the wrong place for anything that resembles
 * authority.
 *
 * The decision is now read from ONE authoritative field:
 * `active_customer.basis` out of `/api/xdr/rbac/session-context`. Those
 * bases are the server's own six (`services.session_context.SCOPE_BASES`);
 * nothing here infers authority from a role name, and nothing here grants
 * anything — the backend re-authorises every single request.
 */
export const CONTROL_CONTEXT_ONLY = "CONTEXT_ONLY";
export const CONTROL_SWITCHABLE = "SWITCHABLE";
export const CONTROL_UNRESOLVED = "UNRESOLVED";

/** Server bases under which a principal legitimately has a choice. */
export const SWITCHABLE_BASES = Object.freeze([
  "MULTIPLE_AUTHORIZED_TENANTS",
  "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER",
]);

/** Server bases that resolve to exactly one customer, server-side. */
export const BOUND_BASES = Object.freeze([
  "SINGLE_AUTHORIZED_TENANT",
  "INHERITED_FROM_INCIDENT",
  "EXPLICIT_REQUEST_TENANT",
]);

/**
 * Which customer control the EDR console may render.
 *
 * `UNRESOLVED` is returned while the session context has not arrived, so
 * the console shows neutral context instead of flashing a selector the
 * user may not be entitled to.
 */
export function customerControlFor(sess) {
  const basis = sess?.active_customer?.basis;
  if (!basis) return CONTROL_UNRESOLVED;
  if (SWITCHABLE_BASES.includes(basis)) return CONTROL_SWITCHABLE;
  if (BOUND_BASES.includes(basis)) return CONTROL_CONTEXT_ONLY;
  return CONTROL_UNRESOLVED;                       // NOT_AUTHORIZED, unknown
}

/** The customer the SERVER resolved for this principal, or null. */
export function serverCustomer(sess) {
  const value = sess?.active_customer?.value;
  return value && String(value).trim() ? String(value).trim() : null;
}

/** The customer's human name, from the server's own customer list. */
export function customerLabel(sess) {
  const id = serverCustomer(sess);
  if (!id) return null;
  const row = (sess?.customers || []).find((c) => c.customer === id)
    || (sess?.authorized_customers || []).find((c) => c.customer === id);
  return row?.display_name || row?.name || id;
}

/**
 * P0-FIX-6B-2 · the principal's AUTHORITY CLASS, as the server states it.
 *
 * `PLATFORM` is only ever the explicit server-side designation. A role name
 * (`admin`, `soc_manager`, …) means nothing here, and neither does the size
 * of the authorized list.
 */
export function authorityScope(sess) {
  return sess?.tenant_scope?.authority_scope === "PLATFORM"
    ? "PLATFORM" : "CUSTOMER";
}

export function isPlatformPrincipal(sess) {
  return authorityScope(sess) === "PLATFORM";
}

/**
 * The customers the picker may OFFER — the server-authorized set.
 *
 * Grant-derived for a CUSTOMER principal, the authoritative ACTIVE tenants
 * for a PLATFORM principal. Never the tenant registry read directly, never
 * `localStorage`, never `?tenant=`, never inferred from a role.
 */
export function authorizedCustomers(sess) {
  const rows = sess?.authorized_customers;
  return Array.isArray(rows)
    ? rows.filter((r) => r && String(r.customer || "").trim()) : [];
}

/**
 * P0-FIX-4B · whether tenant-bound page content may render at all.
 *
 * `loading` and `error` are both non-rendering states, but they are NOT
 * the same state: loading is neutral and transient, error is fail-closed
 * and must say so. Rendering EDR content while the authoritative customer
 * context is unknown would mean rendering it under whatever the browser
 * last claimed — the exact thing Fix 4A removed.
 */
export const GATE_RESOLVING = "RESOLVING";
export const GATE_FAILED = "AUTHORITY_UNAVAILABLE";
export const GATE_RENDER = "RENDER";

export function contentGateFor(sessState, control) {
  if (sessState === "error") return GATE_FAILED;
  if (sessState !== "ready") return GATE_RESOLVING;
  if (control === CONTROL_UNRESOLVED) return GATE_FAILED;
  return GATE_RENDER;
}
