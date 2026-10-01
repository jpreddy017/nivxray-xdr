/**
 * The ACTIVE AUTHORITATIVE TENANT for this browser session.
 *
 * B7 Option A · the backend has no default tenant. Every tenant-scoped
 * control-plane call must name a registered, ACTIVE tenant explicitly, so the
 * client needs exactly one place that answers "which tenant is selected?".
 *
 * Deliberately NOT here:
 *   - no `"default"` fallback. A missing selection returns `null` and the API
 *     fails closed with `TENANT_REQUIRED`, which is the honest outcome. An
 *     invented tenant is how the old console silently read another tenancy.
 *   - no hardcoded tenant id of any kind. The value comes from the operator's
 *     selection, never from source.
 *   - no registry lookup. Whether the named tenant exists and is ACTIVE is the
 *     server's decision (`services.tenant_registry`), never the browser's.
 *
 * P0-FIX-4A · a SERVER BINDING outranks both browser inputs.
 *
 * When the server's session context resolved exactly one customer for this
 * principal (`active_customer.basis = SINGLE_AUTHORIZED_TENANT` and the
 * other bound bases), `bindServerTenant()` records it as NOT switchable.
 * From that moment `?tenant=` and a stale or hand-edited `nvx_tenant` are
 * IGNORED, and a foreign persisted value is overwritten with the server's
 * answer. The browser can no longer name a different customer at all.
 *
 * This is presentation hygiene, not security: the backend re-authorises
 * every request (`routers.edr_tenancy.edr_tenant`), so a hostile value was
 * already refused. What this removes is the browser's role in DECIDING.
 *
 * Resolution order (first hit wins):
 *   0. the SERVER binding, when the principal may not switch.
 *   1. `nvx_tenant` in localStorage — the persisted operator selection.
 *
 * `?tenant=` is NO LONGER an input here. A URL parameter is the easiest
 * thing in the world to edit, so it may no longer reach the
 * `X-Tenant-Id` interceptor. A deep link is now ADOPTED as an explicit
 * selection by the console, and only for a principal the SERVER says may
 * switch (`NivXForgeConsole.jsx`).
 */
const STORAGE_KEY = "nvx_tenant";

export const TENANT_HEADER = "X-Tenant-Id";

let serverTenant = null;
let serverSwitchable = true;
let sealed = false;

/**
 * Record the customer the SERVER resolved for this principal.
 *
 * @param tenantId the server's `active_customer.value`
 * @param switchable whether the server says this principal may choose
 */
export const TENANT_BOUND_EVENT = "nvx-tenant-bound";

export function bindServerTenant(tenantId, { switchable = false } = {}) {
  const id = tenantId && String(tenantId).trim()
    ? String(tenantId).trim() : null;
  const changed = id !== serverTenant
    || Boolean(switchable) !== serverSwitchable;
  serverTenant = id;
  serverSwitchable = Boolean(switchable);
  sealed = false;
  if (id && !serverSwitchable) {
    try {
      if (window.localStorage.getItem(STORAGE_KEY) !== id) {
        window.localStorage.setItem(STORAGE_KEY, id);   // drop stale/foreign
      }
    } catch {
      /* ignore */
    }
  }
  // Surfaces that read the acting customer before the console resolved it
  // (a page is the PARENT of the console, so it renders first) are told
  // once, instead of displaying the stale browser value for ever.
  if (changed) {
    try {
      window.dispatchEvent(new CustomEvent(TENANT_BOUND_EVENT, { detail: id }));
    } catch {
      /* no window (SSR, tests) */
    }
  }
  return id;
}

/**
 * P0-FIX-4B · SEAL the acting tenant: the authoritative customer context
 * could NOT be established, so nothing may act as any customer.
 *
 * This is the fail-closed state. It is deliberately different from "no
 * selection yet": a sealed authority refuses to fall back to `?tenant=`,
 * `nvx_tenant`, `"default"`, the first tenant, or the customer the browser
 * was acting as a moment ago.
 */
export function sealTenantAuthority() {
  serverTenant = null;
  serverSwitchable = false;
  sealed = true;
  try {
    window.dispatchEvent(new CustomEvent(TENANT_BOUND_EVENT, { detail: null }));
  } catch {
    /* no window (SSR, tests) */
  }
  return null;
}

export function tenantAuthoritySealed() {
  return sealed;
}

/** Test/diagnostic helper: forget the binding. */
export function resetServerTenant() {
  serverTenant = null;
  serverSwitchable = true;
  sealed = false;
}

export function serverBoundTenant() {
  return serverTenant;
}

/** False once the server bound this principal to exactly one customer. */
export function tenantIsSwitchable() {
  return serverSwitchable;
}

export function activeTenant() {
  if (sealed) return null;                     // fail closed, never fall back
  if (serverTenant && !serverSwitchable) return serverTenant;
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored && stored.trim()) return stored.trim();
  } catch {
    /* no window/localStorage (SSR, tests) — treat as no selection */
  }
  return null;
}

export function setActiveTenant(tenantId) {
  // A principal the server bound to one customer cannot re-point itself,
  // and a sealed authority cannot be talked into a customer at all.
  if (sealed || (serverTenant && !serverSwitchable)) return;
  try {
    if (tenantId && String(tenantId).trim()) {
      window.localStorage.setItem(STORAGE_KEY, String(tenantId).trim());
    } else {
      window.localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    /* ignore */
  }
}
