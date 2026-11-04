/**
 * v2 feature-flag reader.
 *
 * Mirrors the backend 3-state contract (`disabled | shadow | enabled`)
 * but keeps its own client-side registry — no attempt to authoritatively
 * sync from the backend. That comes in a later phase when a
 * `/api/v2/flags` endpoint lands.
 *
 * Default: every flag DISABLED. Any deviation must be opt-in per
 * build (via Vite env vars) or per session (via localStorage under
 * key `nvx-v2-flags`).
 */

export const V2_FLAG_STATES = /** @type {const} */ (["disabled", "shadow", "enabled"]);

const KNOWN_FLAGS = [
  "CASE_ENGINE",
  "GRAPH_ENGINE",
  "TIMELINE_V2",
  "TRAJECTORY_ENGINE",
  "ADAPTERS",
  "REPLAY",
  "NOTEBOOK",
  "ARTIFACT_STORE",
  "KNOWLEDGE_LAYER",
  "NEGATIVE_EVIDENCE",
  "COPILOT",
  "VERDICT_ENGINE_V3",
  "SECURITY_STATE",
];

function readOverride(name) {
  try {
    const raw = localStorage.getItem("nvx-v2-flags");
    if (!raw) return null;
    const map = JSON.parse(raw);
    const v = map?.[name];
    return typeof v === "string" ? v.toLowerCase() : null;
  } catch {
    return null;
  }
}

export function getFlag(name) {
  if (!KNOWN_FLAGS.includes(name)) return "disabled";
  const override = readOverride(name);
  if (override && V2_FLAG_STATES.includes(override)) return override;
  const envKey = `REACT_APP_NIVX_FLAG_${name}`;
  const envVal = (process.env[envKey] || "").toLowerCase();
  if (V2_FLAG_STATES.includes(envVal)) return envVal;
  return "disabled";
}

export function isEnabled(name)    { return getFlag(name) === "enabled"; }
export function isObservable(name) { const s = getFlag(name); return s === "shadow" || s === "enabled"; }
export function isDisabled(name)   { return getFlag(name) === "disabled"; }
