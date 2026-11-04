/**
 * DT2-1 · investigation state in the URL, and history semantics.
 *
 * PUSH   — the analyst navigated somewhere materially different.
 * REPLACE— transient viewport movement (a wheel tick, a drag frame).
 *
 * Cisco publishes nothing about browser Back/Forward in Device
 * Trajectory, so all of this is a NIVXFORGE DESIGN DECISION.
 */

export const URL_KEYS = [
  "device", "from", "to", "zoom", "day",
  "event", "process_iid", "detection",
  "q", "kinds", "dispositions", "focus_state",
];

/** Materially different investigation → a history entry. */
export const PUSH_KEYS = ["device", "event", "detection", "process_iid",
                          "q", "kinds", "dispositions"];
/** Viewport geometry → replace, so the wheel cannot flood history. */
export const REPLACE_KEYS = ["from", "to", "zoom", "day", "focus_state"];

export const SENSITIVE_PATTERN =
  /(token|secret|password|passwd|bearer|authorization|jwt|api[-_]?key|cookie|session|raw_payload|payload|credential)/i;

const str = (v) => (v == null || v === "" ? null : String(v));

export function serialize(state) {
  const out = {};
  for (const k of URL_KEYS) {
    const v = str(state?.[k]);
    if (v != null) out[k] = v;
  }
  return out;
}

export function deserialize(params) {
  const get = typeof params?.get === "function"
    ? (k) => params.get(k)
    : (k) => params?.[k];
  const out = {};
  for (const k of URL_KEYS) {
    const v = str(get(k));
    if (v != null) out[k] = v;
  }
  return out;
}

/** Guard: no credential, no raw evidence payload, ever, in a URL. */
export function assertNoSensitive(state) {
  for (const [k, v] of Object.entries(state || {})) {
    if (SENSITIVE_PATTERN.test(String(k))) {
      throw new Error(`DT2_URL_SENSITIVE_KEY:${k}`);
    }
    if (!URL_KEYS.includes(k)) {
      throw new Error(`DT2_URL_UNDECLARED_KEY:${k}`);
    }
    if (typeof v === "string" && v.length > 512) {
      throw new Error(`DT2_URL_OVERSIZED_VALUE:${k}`);
    }
  }
  return true;
}

export const HISTORY = { PUSH: "PUSH", REPLACE: "REPLACE", NONE: "NONE" };

/** `transient` covers wheel ticks, drag frames and inertia: those are
 *  ALWAYS replace, whatever changed. */
export function historyMode(prev, next, { transient = false } = {}) {
  const a = serialize(prev || {});
  const b = serialize(next || {});
  const differs = (keys) => keys.some((k) => (a[k] ?? null) !== (b[k] ?? null));
  if (!differs(URL_KEYS)) return HISTORY.NONE;
  if (transient) return HISTORY.REPLACE;
  if (differs(PUSH_KEYS)) return HISTORY.PUSH;
  if (differs(REPLACE_KEYS)) return HISTORY.REPLACE;
  return HISTORY.NONE;
}

/** Restore an investigation from a history entry. Missing keys mean
 *  "unspecified", never "reset the investigation". */
export function restore(params, fallback = {}) {
  const s = deserialize(params);
  const fromMs = Date.parse(s.from);
  const toMs = Date.parse(s.to);
  const view = (Number.isFinite(fromMs) && Number.isFinite(toMs)
                && toMs > fromMs) ? { t0: fromMs, t1: toMs } : fallback.view;
  return {
    device: s.device ?? fallback.device ?? null,
    view: view ?? null,
    zoom: s.zoom != null ? Number(s.zoom) : (fallback.zoom ?? null),
    day: s.day != null ? Number(s.day) : (fallback.day ?? null),
    event: s.event ?? null,
    detection: s.detection ?? null,
    process_iid: s.process_iid ?? null,
    q: s.q ?? "",
    kinds: s.kinds ? s.kinds.split(",").filter(Boolean) : [],
    dispositions: s.dispositions
      ? s.dispositions.split(",").filter(Boolean) : [],
    focus_state: s.focus_state ?? null,
  };
}
