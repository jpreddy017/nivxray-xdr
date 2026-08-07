import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
export const API_BASE = `${BACKEND_URL}/api`;

// ─── Per-path timeout policy ────────────────────────────────────────────
// Cloudflare Free/Pro tier's origin timeout is 100s. We fail at 90s locally
// so the user gets an actionable NivXRay error instead of a Cloudflare 524
// page. Deep decoders (magic on huge inputs) get a middle-ground 60s.
const TIMEOUT_LLM     = 90_000;   // /ai/*, /decode/chain/narrative
// RC3.0 · Feb-2026 — decode endpoints get 90s of grace time. The
// backend's hard-abort is 12s (`_HARD_ABORT_MS` in orchestrator.py),
// but the intelligence/enrichment pass (MITRE, LOLBAS, IOC, verdict-card
// rebuild) adds up to ~20-40s on very large samples. 90s comfortably
// covers the tail without letting the analyst wait forever on runaways.
const TIMEOUT_DECODE  = 90_000;   // /decode/smart, /decode/magic, /decode/chain, /analyze
const TIMEOUT_DEFAULT = 30_000;   // everything else (auth, history, admin, etc.)

const pickTimeout = (url = "") => {
  if (/\/ai\/|\/decode\/chain\/narrative|\/troubleshoot\/auto\?use_ai=true/i.test(url)) return TIMEOUT_LLM;
  if (/\/decode\/|\/analyze/i.test(url)) return TIMEOUT_DECODE;
  // Corpus confusion matrix — cold compute walks all 245 samples through
  // the deterministic decoder. ~11s local, may be slower behind Cloudflare
  // on prod. Give it the same headroom as decode ops so first-time visitors
  // don't hit the 30s default and see a spurious timeout.
  if (/\/training\/confusion/i.test(url)) return TIMEOUT_DECODE;
  // Feb-2026 · Save Case can be slow on Prod (CPU-throttled containers
  // finalising verdict-card + IOC serialization on heavy payloads).
  // 60s gives the backend comfortable headroom vs the previous 30s
  // that was tripping on shellcode / large-output cases.
  if (/\/cases\/save/i.test(url)) return 60_000;
  // P0.1 · AUTO INVESTIGATE — the sync endpoint holds the request until
  // decoding finishes; the async /jobs endpoint accepts up to 50 MB of
  // incident text so the upload alone can take a while on slow links.
  // 90 s on both paths keeps very large incidents from tripping a client
  // timeout before the server has even started work.
  if (/\/v2\/auto-investigate/i.test(url)) return TIMEOUT_LLM;
  if (/\/v2\/report-writer/i.test(url)) return TIMEOUT_LLM;
  return TIMEOUT_DEFAULT;
};

// ─── Retry policy ──────────────────────────────────────────────────────
// Retry on: network errors, 502/503/504/524. Never on 4xx (client error).
// Exponential backoff: 500ms → 1500ms → 4500ms. Max 2 retries.
const RETRY_STATUSES = new Set([502, 503, 504, 524]);
const RETRY_BACKOFF_MS = [500, 1500, 4500];
const MAX_RETRIES = 2;

const shouldRetry = (err) => {
  if (err?.code === "ECONNABORTED") return false;      // caller-triggered abort — never retry
  if (!err.response) return true;                       // network / DNS / connection refused
  return RETRY_STATUSES.has(err.response.status);
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const api = axios.create({ baseURL: API_BASE, timeout: TIMEOUT_DEFAULT });

// ═══════════════════════════════════════════════════════════════════════
// R28 · Restore is Rendering
// ═══════════════════════════════════════════════════════════════════════
// During a case/history restore, the frontend MUST NOT invoke any
// business-logic endpoint (/die/understand, /die/analyze, /die/narrate,
// /decode/*, /analyze/*, /ai/*).  Restore = deserialize + validate +
// render — nothing else.  Any violation logs a red console warning
// AND fires a telemetry ping so the regression is caught in CI + prod.
let _restoreModeActive = false;
let _restoreLabel      = "";

/** Enter restore mode.  Call BEFORE hydrating panels from an SSOT. */
export function beginRestoreMode(label = "unknown") {
  _restoreModeActive = true;
  _restoreLabel = label;
}

/** Exit restore mode.  Call in ``finally`` after hydration. */
export function endRestoreMode() {
  _restoreModeActive = false;
  _restoreLabel = "";
}

const _R28_FORBIDDEN_PATTERNS = [
  /\/die\/(understand|analyze|narrate)/i,
  /\/decode\//i,
  /\/analyze\//i,
  /\/ai\//i,
  /\/troubleshoot\//i,
];

function _r28_check(url = "") {
  if (!_restoreModeActive) return;
  if (!_R28_FORBIDDEN_PATTERNS.some((re) => re.test(url))) return;
  // Red console banner — analysts + reviewers see it immediately.
  // eslint-disable-next-line no-console
  console.error(
    `%c[R28 VIOLATION] Restore is rendering — business-logic endpoint called during restore: ${url} (label=${_restoreLabel})`,
    "color:#fff;background:#c0392b;padding:2px 6px;border-radius:2px;font-weight:700",
  );
  // Non-blocking telemetry ping — never delays the caller.
  try {
    const token = localStorage.getItem("nvx_token");
    fetch(`${API_BASE}/telemetry/frontend`, {
      method: "POST",
      keepalive: true,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({
        kind: "r28_violation",
        url,
        label: _restoreLabel,
        ts:  Date.now(),
        page: window.location.pathname,
      }),
    }).catch(() => {});
  } catch (_) { /* never block */ }
}

// ─── Request: per-URL timeout + AbortController ────────────────────────
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("nvx_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  // R28 · Restore is Rendering — surface violations immediately.
  _r28_check(config.url || "");
  // Only override if caller didn't pass an explicit timeout
  if (config.timeout == null || config.timeout === TIMEOUT_DEFAULT) {
    config.timeout = pickTimeout(config.url || "");
  }
  // AbortController wiring — allows external cancel() and reliable timeout error surface
  if (!config.signal) {
    const controller = new AbortController();
    config.signal = controller.signal;
    config.__abortController = controller;
    // Fallback abort after timeout (guarantees we return a clean error even if
    // axios's own timeout doesn't fire — e.g. long TLS handshake).
    const to = setTimeout(() => controller.abort(new Error("client-timeout")), config.timeout + 500);
    config.__timerId = to;
  }
  return config;
});

// ─── Response: retry with exp backoff + surface X-Request-ID + 401 handling ──
api.interceptors.response.use(
  (response) => {
    // Clean up timeout timer
    const cfg = response.config || {};
    if (cfg.__timerId) clearTimeout(cfg.__timerId);
    // Expose request-id for the SocVerdictPanel / toast to display in errors
    response.__requestId = response.headers?.["x-request-id"];
    return response;
  },
  async (err) => {
    const cfg = err?.config || {};
    if (cfg.__timerId) clearTimeout(cfg.__timerId);

    // ── Retry logic ────────────────────────────────────────────────────
    cfg.__retryCount = cfg.__retryCount || 0;
    if (shouldRetry(err) && cfg.__retryCount < MAX_RETRIES && !cfg.__noRetry) {
      const delay = RETRY_BACKOFF_MS[cfg.__retryCount] || 5000;
      cfg.__retryCount += 1;
      await sleep(delay);
      // Drop old AbortController — request interceptor will create a fresh one
      delete cfg.signal;
      delete cfg.__abortController;
      delete cfg.__timerId;
      return api.request(cfg);
    }

    // ── Attach a friendly, actionable message + request-id ────────────
    const rid = err?.response?.headers?.["x-request-id"];
    if (rid) err.requestId = rid;
    if (err.code === "ECONNABORTED" || (err.message || "").includes("timeout") || err.name === "CanceledError") {
      err.friendlyMessage =
        "Request timed out. If this was an AI narrative on a large chain, try fewer stages " +
        "or use TROUBLESHOOT (offline, no LLM). For huge payloads, split into smaller inputs.";
    } else if (err.response?.status === 413) {
      err.friendlyMessage = "Payload too large — max 500 KB per request. Split into stages via CHAIN MODE.";
    } else if (err.response?.status === 504 || err.response?.status === 524) {
      err.friendlyMessage =
        "Server timeout. The AI narrative on very large chains can exceed the limit — try fewer stages, " +
        "or click TROUBLESHOOT (offline) which never times out.";
    }

    // ── 401 session-expired flow (preserved from original) ────────────
    if (err?.response?.status === 401) {
      localStorage.removeItem("nvx_token");
      localStorage.removeItem("nvx_email");
      if (window.location.pathname !== "/login") {
        try { window.dispatchEvent(new CustomEvent("nvx:session-expired")); } catch (_) {}
        try {
          window.alert(
            "Your NivXRay session has expired.\n\nYou'll be redirected to the login page — " +
              "sign back in and re-run the decode. Your input is preserved in your browser."
          );
        } catch (_) {}
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

// ─── Server-Sent Events helper (for /decode/chain/narrative/stream) ────
// Usage:
//   const abort = new AbortController();
//   await apiStream("/decode/chain/narrative/stream", body, {
//     onProgress: ({stage, elapsed_ms}) => setLabel(`${stage} · ${elapsed_ms}ms`),
//     onDone:     (data) => setNarrative(data),
//     onError:    (msg) => setStatus(`ERROR ${msg}`),
//     signal:     abort.signal,
//   });
export async function apiStream(path, body, { onProgress, onDone, onError, signal } = {}) {
  const token = localStorage.getItem("nvx_token");
  const resp = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      Accept: "text/event-stream",
    },
    body: JSON.stringify(body),
    signal,
  });
  if (!resp.ok) {
    onError?.(`HTTP ${resp.status}`);
    return;
  }
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    // Split SSE frames on double-newline
    const parts = buffer.split(/\n\n/);
    buffer = parts.pop();
    for (const frame of parts) {
      const evt = /event:\s*(\w+)/.exec(frame)?.[1];
      const dat = /data:\s*(.+)/.exec(frame)?.[1];
      if (!evt || !dat) continue;
      let payload;
      try { payload = JSON.parse(dat); } catch { payload = { raw: dat }; }
      if (evt === "progress") onProgress?.(payload);
      else if (evt === "done") onDone?.(payload);
      else if (evt === "error") onError?.(payload?.detail || "unknown");
    }
  }
}

export default api;
