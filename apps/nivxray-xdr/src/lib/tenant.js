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
 * Resolution order (first hit wins):
 *   1. `?tenant=` on the URL — deep links and the XDR context bar already
 *      carry it (`NivXForgeConsole.jsx` reads the same parameter).
 *   2. `nvx_tenant` in localStorage — the persisted operator selection.
 */
const STORAGE_KEY = "nvx_tenant";

export const TENANT_HEADER = "X-Tenant-Id";

export function activeTenant() {
  try {
    const fromUrl = new URLSearchParams(window.location.search).get("tenant");
    if (fromUrl && fromUrl.trim()) return fromUrl.trim();
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored && stored.trim()) return stored.trim();
  } catch {
    /* no window/localStorage (SSR, tests) — treat as no selection */
  }
  return null;
}

export function setActiveTenant(tenantId) {
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
