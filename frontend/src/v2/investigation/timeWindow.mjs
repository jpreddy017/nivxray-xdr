// DT time model (dt.time.v1). UTC instants internally; a browser timezone is presentation only.
// Modes are never silently converted: every view carries its mode and the label says which one it is.
// VENDORED COPY at frontend/src/v2/investigation/timeWindow.mjs — a parity test keeps both byte-identical.
export const DAY = 86_400_000;
export const HOUR = 3_600_000;
export const SKEW_TOLERANCE_MS = 120_000;
export const BIN_COUNT = 240;
export const MODES = Object.freeze({
  ROLLING: "ROLLING", CALENDAR_DAY: "CALENDAR_DAY", EVIDENCE_BOUNDED: "EVIDENCE_BOUNDED",
  LINKED: "LINKED", ANALYST: "ANALYST",
});
const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const fin = Number.isFinite;

export const utcDayStart = (ms) => Math.floor(ms / DAY) * DAY;
export const isoZ = (ms) => new Date(ms).toISOString().slice(0, 19) + "Z";
export const dayKey = (ms) => new Date(ms).toISOString().slice(0, 10);

// A zone-less source string ("2026-09-22 15:43:31.770") is UTC, never the analyst's local time.
export function parseUtc(v) {
  if (fin(v)) return v;
  if (typeof v !== "string" || !v) return null;
  let s = v.trim().replace(" ", "T");
  if (!/(Z|[+-]\d\d:?\d\d)$/i.test(s)) s += "Z";
  const t = Date.parse(s);
  return fin(t) ? t : null;
}

// Placement instant: OBSERVED time only. ingested_at / received_at are never a substitute.
export function observedAt(e) {
  if (!e) return null;
  if (fin(e.timestamp_instant_ms)) return e.timestamp_instant_ms;
  return parseUtc(e.observed_at) ?? parseUtc(e.timestamp);
}

export function rollingWindow(refNow, spanMs = DAY) {
  if (!fin(refNow) || !(spanMs > 0)) return null;
  return { t0: refNow - spanMs, t1: refNow, mode: MODES.ROLLING, ref: refNow };
}

export function calendarDayWindow(dayStartMs) {
  if (!fin(dayStartMs)) return null;
  const d = utcDayStart(dayStartMs);
  return { t0: d, t1: d + DAY, mode: MODES.CALENDAR_DAY, ref: null };
}

export function evidenceBoundedWindow(obsMin, obsMax) {
  if (!fin(obsMin) || !fin(obsMax)) return null;
  const lo = Math.min(obsMin, obsMax), hi = Math.max(obsMin, obsMax);
  return { t0: lo, t1: hi > lo ? hi : lo + 1, mode: MODES.EVIDENCE_BOUNDED, ref: null };
}

export const withMode = (view, mode, ref = null) => (view ? { t0: view.t0, t1: view.t1, mode, ref } : null);
export const modeOf = (view) => (view && view.mode) || MODES.ANALYST;

// First view: an explicit link wins; a detection instant opens its UTC day; otherwise rolling 24 h to the
// reference time. Never anchored to the newest delivered observation.
export function initialWindow({ refNow, linked = null, at = null } = {}) {
  if (linked && fin(linked.t0) && fin(linked.t1) && linked.t1 > linked.t0) return withMode(linked, MODES.LINKED);
  if (fin(at)) return withMode(calendarDayWindow(at), MODES.LINKED);
  return rollingWindow(refNow);
}

// A rolling view follows the reference time; every other mode stays exactly where it was put.
export function advanceRolling(view, refNow) {
  if (!view || modeOf(view) !== MODES.ROLLING || !fin(refNow)) return view;
  return rollingWindow(refNow, view.t1 - view.t0);
}

function spanText(ms) {
  const h = ms / HOUR;
  return h >= 48 ? `${(h / 24).toFixed(1)} d` : `${h.toFixed(1)} h`;
}

export function windowLabel(view) {
  if (!view || !fin(view.t0) || !fin(view.t1)) return "Window UNKNOWN";
  const range = `${isoZ(view.t0)} → ${isoZ(view.t1)}`;
  switch (modeOf(view)) {
    case MODES.ROLLING: return `Rolling ${spanText(view.t1 - view.t0)} to reference time · ${range}`;
    case MODES.CALENDAR_DAY: return `Calendar day ${dayKey(view.t0)} (UTC) · ${range}`;
    case MODES.EVIDENCE_BOUNDED: return `Evidence-bounded ${spanText(view.t1 - view.t0)} (not "last 24 h") · ${range}`;
    case MODES.LINKED: return `Linked window · ${range}`;
    default: return `Analyst window ${spanText(view.t1 - view.t0)} · ${range}`;
  }
}

// Placement is by OBSERVED time only. Future (beyond reference + skew tolerance) never stretches a window.
export function classifyObservations(times, view, refNow) {
  const out = { inWindow: 0, before: 0, after: 0, future: 0, invalid: 0, skewed: 0 };
  for (const t of times || []) {
    if (!fin(t)) { out.invalid += 1; continue; }
    if (fin(refNow) && t > refNow && t <= refNow + SKEW_TOLERANCE_MS) out.skewed += 1;
    if (fin(refNow) && t > refNow + SKEW_TOLERANCE_MS) out.future += 1;
    else if (!view) continue;
    else if (t < view.t0) out.before += 1;
    else if (t > view.t1) out.after += 1;
    else out.inWindow += 1;
  }
  return out;
}

// Evidence extent within the window. This is NOT sensor coverage: it is where observations exist.
// The trailing gap is measured to min(window end, reference time); gaps under `quietMs` are normal delivery cadence.
export const QUIET_MS = 15 * 60_000;
export function evidenceExtent(view, obsMin, obsMax, refNow = null, quietMs = QUIET_MS) {
  if (!view) return { state: "UNKNOWN", statement: "Window unknown." };
  if (!fin(obsMin) || !fin(obsMax)) {
    return { state: "UNKNOWN", statement: "No observations: activity is UNKNOWN, not absent." };
  }
  if (obsMax < view.t0 || obsMin > view.t1) {
    return { state: "NONE_IN_WINDOW", statement: "No observations in this window. Absence is not inactivity." };
  }
  const end = fin(refNow) ? Math.min(view.t1, refNow) : view.t1;
  const from = Math.max(view.t0, obsMin), to = Math.min(view.t1, obsMax);
  const trailing = end - to > quietMs ? { from: to, to: end } : null;
  return { state: trailing ? "ENDS_BEFORE_WINDOW_END" : "REACHES_WINDOW_END", from, to, trailing,
           statement: trailing ? `Observations end at ${isoZ(to)}; none delivered after it in this window. `
             + "No observation ≠ nothing happened; delivery may be pending upstream." : "" };
}

// The part of a window that lies after the reference time: it has not happened yet.
export function futurePart(view, refNow) {
  if (!view || !fin(refNow) || view.t1 <= refNow) return null;
  return { from: Math.max(view.t0, refNow), to: view.t1 };
}

// Pan/zoom bounds: retained evidence start .. reference time (+ skew tolerance). Never the newest observation.
export function navBounds(evidence, refNow) {
  const min = evidence && fin(evidence.min) ? evidence.min : null;
  if (fin(refNow)) return { min, max: refNow + SKEW_TOLERANCE_MS };
  return { min, max: evidence && fin(evidence.max) ? evidence.max : null };
}

// The interval requested from the API: the view plus prefetch, trimmed to bounds, ALWAYS covering the view.
export function queryInterval(view, prefetch = 0, bounds = null) {
  if (!view || !(view.t1 > view.t0)) return null;
  const pad = (view.t1 - view.t0) * Math.max(0, prefetch);
  let t0 = view.t0 - pad, t1 = view.t1 + pad;
  if (bounds && fin(bounds.min)) t0 = Math.min(view.t0, Math.max(t0, bounds.min));
  if (bounds && fin(bounds.max)) t1 = Math.max(view.t1, Math.min(t1, bounds.max));
  return { t0, t1 };
}

export const covers = (outer, inner) => !!outer && !!inner && outer.t0 <= inner.t0 && outer.t1 >= inner.t1;

// Server pages are OLDEST-FIRST (`in_lane[:limit]`), and dt2.graph is built from that page only.
// has_more therefore means the NEWEST part of the queried interval was not delivered.
export function capOf(resp) {
  const evs = (resp && resp.events) || [];
  let last = null;
  for (const e of evs) { const t = observedAt(e); if (fin(t) && (last == null || t > last)) last = t; }
  return { hasMore: !!(resp && resp.has_more), returned: evs.length,
           matched: fin(resp && resp.matched_in_window) ? resp.matched_in_window : null, loadedTo: last };
}

export function truncationOf(cap, view) {
  if (!cap || !cap.hasMore) return { state: "COMPLETE", hidden: null, statement: "" };
  const hidden = view && fin(cap.loadedTo) && cap.loadedTo < view.t1
    ? { from: Math.max(view.t0, cap.loadedTo), to: view.t1 } : null;
  const of = fin(cap.matched) ? ` of ${cap.matched}` : "";
  const after = fin(cap.loadedTo) ? ` after ${isoZ(cap.loadedTo)}` : "";
  return { state: "TRUNCATED_OLDEST_FIRST", hidden,
           statement: `Per-request cap: only the oldest ${cap.returned}${of} observations in the requested interval `
             + `were delivered; observations${after} are NOT drawn (not absent).` };
}

// Request budget so that a view plus its prefetch fits one oldest-first page.
export const pageBudget = (limit, prefetch = 0) => Math.max(1, Math.floor(limit / (1 + 2 * Math.max(0, prefetch))));

// The newest part of `view` whose binned observation count fits `budget`, still ending at view.t1.
export function tailWindow(bins, view, budget) {
  if (!view || !(view.t1 > view.t0) || !(budget > 0)) return null;
  const w = DAY / BIN_COUNT;
  const inView = (bins || []).filter((b) => b.t < view.t1 && b.t + w > view.t0).sort((a, b) => b.t - a.t);
  let sum = 0, t0 = view.t1;
  if (!inView.length) t0 = view.t1 - (view.t1 - view.t0) / 2;
  for (const b of inView) {
    if (sum + b.total > budget) break;
    sum += b.total;
    t0 = Math.max(view.t0, b.t);
  }
  if (t0 >= view.t1) t0 = Math.max(view.t0, view.t1 - w);
  const rolling = modeOf(view) === MODES.ROLLING;
  return { t0, t1: view.t1, mode: rolling ? MODES.ROLLING : MODES.ANALYST, ref: rolling ? view.ref : null,
           estimated: sum };
}

// The navigator band domain that contains the view. One model for the band, the canvas and the query.
export function navDomain(view, refNow) {
  if (!view || !(view.t1 > view.t0)) return null;
  const mode = modeOf(view);
  if (mode === MODES.CALENDAR_DAY) return calendarDayWindow(view.t0);
  if (view.t1 - view.t0 >= DAY) return { t0: view.t0, t1: view.t1, mode, ref: view.ref ?? null };
  const r = rollingWindow(refNow);
  if (r && view.t0 >= r.t0 && view.t1 <= r.t1 + SKEW_TOLERANCE_MS) return r;
  const d = utcDayStart(view.t0);
  if (view.t1 <= d + DAY) return calendarDayWindow(d);
  return { t0: view.t1 - DAY, t1: view.t1, mode: MODES.ANALYST, ref: null };
}

// Every UTC day an interval touches: bins are fetched per day and joined on absolute time.
export function daysTouched(domain, max = 400) {
  if (!domain || !(domain.t1 > domain.t0)) return [];
  const out = [];
  for (let d = utcDayStart(domain.t0); d < domain.t1 && out.length < max; d += DAY) out.push(dayKey(d));
  return out;
}

// Per-day bins (bin index on that UTC day) → absolute-time bins inside the domain.
export function binsInDomain(binsByDay, domain, binCount = BIN_COUNT) {
  if (!domain) return [];
  const w = DAY / binCount, out = [];
  for (const [key, bins] of binsByDay || []) {
    const d = Date.parse(`${key}T00:00:00Z`);
    if (!fin(d)) continue;
    for (const b of bins || []) {
      const t = d + b.bin * w;
      if (t + w <= domain.t0 || t >= domain.t1) continue;
      out.push({ ...b, t, mid: Math.min(Math.max(t + w / 2, domain.t0), domain.t1), key: `${key}:${b.bin}` });
    }
  }
  return out.sort((a, b) => a.t - b.t);
}

// The 30-day strip ends at the REFERENCE day, never at the newest evidence day (backlog-safe).
export function dayStrip(refNow, n = 30) {
  if (!fin(refNow)) return [];
  const end = utcDayStart(refNow);
  return Array.from({ length: n }, (_, i) => {
    const t = end - (n - 1 - i) * DAY;
    return { t, key: dayKey(t), referenceDay: t === end };
  });
}

// Marks at real UTC boundaries inside [t0, t1]; the step widens with the span.
export function hourMarks(view) {
  if (!view || !(view.t1 > view.t0)) return [];
  const span = view.t1 - view.t0;
  const step = span <= 26 * HOUR ? HOUR : span <= 4 * DAY ? 6 * HOUR : DAY;
  const out = [];
  for (let t = Math.ceil(view.t0 / step) * step; t <= view.t1 && out.length < 500; t += step) {
    const d = new Date(t), h = d.getUTCHours();
    out.push({ t, hour: h, midnight: h === 0, label: h === 0 ? `${MON[d.getUTCMonth()]} ${d.getUTCDate()}` : String(h) });
  }
  return out;
}

export function domainLabel(view) {
  if (!view) return "UNKNOWN";
  if (modeOf(view) === MODES.CALENDAR_DAY) {
    const d = new Date(view.t0);
    return `${MON[d.getUTCMonth()]} ${d.getUTCDate()}`;
  }
  return `${isoZ(view.t0).slice(5, 16).replace("T", " ")} → ${isoZ(view.t1).slice(5, 16).replace("T", " ")} UTC`;
}

// Presentation only: the same instant rendered in a named IANA zone.
export function presentIn(ms, timeZone) {
  return new Intl.DateTimeFormat("en-GB", { timeZone, year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false, timeZoneName: "short" }).format(ms);
}
