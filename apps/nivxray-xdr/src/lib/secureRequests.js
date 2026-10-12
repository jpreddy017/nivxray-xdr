import axios from "axios";
import { invalidateSecurity, securitySnapshot, trackRequest } from "./securityState";
import { sealTenantAuthority } from "./tenant";

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
    } else if (status === 403) {
      invalidateSecurity("denied", context?.path || globalThis.window?.location?.pathname || "");
    }
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
      } else if (response.status === 403) invalidateSecurity("denied", context.path);
      throw Object.assign(new Error(data.detail || `HTTP ${response.status}`), { status: response.status });
    }
    return data;
  } finally {
    release(); options.signal?.removeEventListener("abort", abort);
  }
}
