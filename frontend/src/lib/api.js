import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
export const API_BASE = `${BACKEND_URL}/api`;

const api = axios.create({ baseURL: API_BASE, timeout: 180000 });

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("nvx_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err?.response?.status === 401) {
      // Session expired — surface a clear message BEFORE redirecting so the user
      // doesn't experience a silent "black screen" flash to /login.
      localStorage.removeItem("nvx_token");
      localStorage.removeItem("nvx_email");
      if (window.location.pathname !== "/login") {
        try {
          // Try sonner first (already installed via shadcn) — quiet if missing
          // eslint-disable-next-line no-new-func
          const evt = new CustomEvent("nvx:session-expired");
          window.dispatchEvent(evt);
        } catch (_) {}
        // Fallback native alert so the user always sees something
        try {
          window.alert(
            "Your NivXRay session has expired.\n\nYou'll be redirected to the login page — sign back in and re-run the decode. Your input is preserved in your browser."
          );
        } catch (_) {}
        // Preserve the last input in localStorage so it survives the redirect
        try {
          const ta = document.querySelector('[data-testid="input-textarea"]');
          if (ta && ta.value) localStorage.setItem("nvx_last_input", ta.value);
        } catch (_) {}
        window.location.href = "/login";
      }
    }
    return Promise.reject(err);
  },
);

export default api;
