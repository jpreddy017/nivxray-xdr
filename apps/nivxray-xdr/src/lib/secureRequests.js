import axios from "axios";
import { invalidateSecurity, securitySnapshot, trackRequest } from "./securityState";
import { sealTenantAuthority } from "./tenant";

/**
 * Server refusal codes that mean "this request named no customer, or named
 * one that cannot be established" — a SELECTION condition, not a verdict on
 * what this principal may do.
 *
 * `services/session_context.authorize_requested_tenant()` is explicit about
 * the difference: with several authorised customers and none named it raises
 * TENANT_REQUIRED ("there is no default tenant"), and with no tenant scope at
 * all it raises TENANT_NOT_RESOLVED. Neither says the page is forbidden.
 *
 * Treating them as a page denial is what produced the `/edr` loop: the
 * dashboard mounted, its first tenant-scoped read came back 403
 * TENANT_REQUIRED because no customer was selected, the whole route was
 * latched "denied" — which also hides the customer picker, so the one action
 * that would resolve it was unreachable — and "Recheck access" merely
 * restarted the cycle.
 *
 * Authorisation is untouched: the server refused the data and still does.
 * The console simply stops reinterpreting "pick a customer" as "forbidden",
 * and the caller renders the server's own code and reason in place.
 */
const TENANT_SELECTION_CODES = new Set([
  "TENANT_REQUIRED",
  "TENANT_NOT_RESOLVED",
]);

/** The server's machine-readable refusal code, when it sent one. */
export function refusalCode(detail) {
  if (detail && typeof detail === "object" && !Array.isArray(detail)) {
    const code = detail.code || detail.error;
    return code ? String(code) : null;
  }
  return null;
}

/** Is this 403 a missing/unresolvable customer selection rather than a denial? */
export function isTenantSelectionRefusal(detail) {
  return TENANT_SELECTION_CODES.has(refusalCode(detail));
}

/** Abort reads on scope/session change and fence late responses from old contexts. */
export function secureRequests(client) {
  client.interceptors.request.use((config) => {
    const controller = new AbortController();
    const original = config.signal;
    const abort = () => controller.abort();
    if (original?.aborted) abort();
    original?.addEventListener("abort", abort, { once: true });
    const release = trackRequest(abort);
    config.signal = controller.signal;
    config.__security = { epoch: securitySnapshot().epoch,
      path: globalThis.window?.location?.pathname || "",
      release: () => { release(); original?.removeEventListener("abort", abort); } };
    return config;
  });
  const finish = (config) => {
    const context = config?.__security;
    context?.release();
    return context;
  };
  client.interceptors.response.use((response) => {
    const context = finish(response.config);
    if (context && context.epoch !== securitySnapshot().epoch) {
      throw new axios.CanceledError("Security context changed");
    }
    return response;
  }, (error) => {
    const context = finish(error.config);
    if (context && context.epoch !== securitySnapshot().epoch) {
      return Promise.reject(new axios.CanceledError("Security context changed"));
    }
    const status = error.response?.status;
    if (status === 401) {
      localStorage.removeItem("nvx_token");
      localStorage.removeItem("nvx_email");
      sealTenantAuthority();
      invalidateSecurity("expired");
    } else if (status === 403
               && !isTenantSelectionRefusal(error.response?.data?.detail)) {
      invalidateSecurity("denied", context?.path || globalThis.window?.location?.pathname || "");
    }
    // A tenant-selection refusal deliberately invalidates NOTHING: it is not a
    // denial, and bumping the epoch here would also abort every in-flight read
    // on the page — including the customer-independent ones — leaving the
    // console stuck mid-load with no way to recover.
    return Promise.reject(error);
  });
}

/** Same fencing for the retained E3 preview's fetch transport; no auth/header contract changes. */
export async function secureFetchJson(url, options = {}) {
  const context = { epoch: securitySnapshot().epoch,
    path: globalThis.window?.location?.pathname || "" };
  const controller = new AbortController();
  const abort = () => controller.abort();
  if (options.signal?.aborted) abort();
  options.signal?.addEventListener("abort", abort, { once: true });
  const release = trackRequest(abort);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    const data = await response.json().catch(() => ({}));
    if (context.epoch !== securitySnapshot().epoch) throw new axios.CanceledError("Security context changed");
    release();
    if (!response.ok) {
      if (response.status === 401) {
        localStorage.removeItem("nvx_token"); localStorage.removeItem("nvx_email");
        sealTenantAuthority(); invalidateSecurity("expired");
      } else if (response.status === 403 && !isTenantSelectionRefusal(data.detail)) {
        invalidateSecurity("denied", context.path);
      }
      throw Object.assign(new Error(data.detail || `HTTP ${response.status}`), { status: response.status });
    }
    return data;
  } finally {
    release(); options.signal?.removeEventListener("abort", abort);
  }
}
