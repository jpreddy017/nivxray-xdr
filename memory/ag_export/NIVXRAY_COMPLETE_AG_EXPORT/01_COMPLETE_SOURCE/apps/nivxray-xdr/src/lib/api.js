/**
 * NivXRay XDR standalone axios client.
 *
 * Talks to the same NivXRay backend as `/app/frontend` but is a
 * completely separate instance living inside this bundle.  Reads the
 * base URL from `REACT_APP_NIVXRAY_API_URL` (defined via Vite
 * `define`), which falls back to `REACT_APP_BACKEND_URL` for parity
 * with the original app during development.
 */
import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || "";
export const API_BASE = `${BACKEND_URL}/api`;

const TIMEOUT_DEFAULT = 30_000;
const TIMEOUT_LONG    = 60_000;

const pickTimeout = (url = "") => {
  if (/\/incidents\/.+\/summary/i.test(url)) return TIMEOUT_LONG;
  if (/\/activity\/inventory/i.test(url))     return TIMEOUT_LONG;
  if (/\/edr\/(detections|process-tree)/i.test(url)) return TIMEOUT_LONG;
  return TIMEOUT_DEFAULT;
};

const api = axios.create({ baseURL: API_BASE, timeout: TIMEOUT_DEFAULT });

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("nvx_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  if (config.timeout == null || config.timeout === TIMEOUT_DEFAULT) {
    config.timeout = pickTimeout(config.url || "");
  }
  return config;
});

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err?.response?.status === 401) {
      // 401 = session expired.  Clear token and bounce to login.
      localStorage.removeItem("nvx_token");
      localStorage.removeItem("nvx_email");
      if (!window.location.pathname.endsWith("/login")) {
        window.location.href = "/login";
      }
    }
    return Promise.reject(err);
  },
);

export default api;
