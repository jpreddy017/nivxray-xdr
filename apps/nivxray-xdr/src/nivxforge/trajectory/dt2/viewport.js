/**
 * DT2-1 · temporal viewport algebra.
 *
 * PAN  = same temporal scale, different time position.
 * ZOOM = different temporal scale, investigation anchor preserved.
 * They are separate operations here and never derived from each other.
 *
 * Reference: Cisco publicly shows a STEPPED zoom — clicking a timeline
 * bar expands that range, clicking again reaches a 60-minute window
 * [PUBLICLY OBSERVED]. The exact ladder below is a NIVXFORGE DESIGN
 * DECISION and follows the Phase-B approved 30-day → 1-second range.
 */

export const MS = { s: 1000, m: 60000, h: 3600000, d: 86400000 };

/** Index 0 is the widest level. */
export const ZOOM_LEVELS = [
  30 * MS.d, 14 * MS.d, 7 * MS.d, 3 * MS.d,
  24 * MS.h, 12 * MS.h, 6 * MS.h, 4 * MS.h, 2 * MS.h, MS.h,
  30 * MS.m, 15 * MS.m, 5 * MS.m, MS.m,
  30 * MS.s, 10 * MS.s, MS.s,
];

export const MAX_SPAN_MS = ZOOM_LEVELS[0];
export const MIN_SPAN_MS = ZOOM_LEVELS[ZOOM_LEVELS.length - 1];

const clamp = (v, lo, hi) => Math.min(Math.max(v, lo), hi);

export const spanOf = (view) => Math.max(1, view.t1 - view.t0);

export function isValidWindow(view) {
  if (!view || !Number.isFinite(view.t0) || !Number.isFinite(view.t1)) {
    return false;
  }
  const span = view.t1 - view.t0;
  return span >= MIN_SPAN_MS && span <= MAX_SPAN_MS;
}

/** Nearest ladder level to an arbitrary span, on a log scale so the
 *  choice is scale-free rather than biased to the wide end. */
export function levelOf(span) {
  const s = clamp(Math.max(1, span), MIN_SPAN_MS, MAX_SPAN_MS);
  let best = 0;
  let bestD = Infinity;
  ZOOM_LEVELS.forEach((lvl, i) => {
    const d = Math.abs(Math.log(lvl) - Math.log(s));
    if (d < bestD) { bestD = d; best = i; }
  });
  return best;
}

export const spanOfLevel = (level) =>
  ZOOM_LEVELS[clamp(level, 0, ZOOM_LEVELS.length - 1)];

/** Retention/evidence bounds. `null` means "not provable", and an
 *  unprovable bound is never used to clamp — we do not invent limits. */
export function clampToBounds(view, bounds) {
  const out = { t0: view.t0, t1: view.t1 };
  const span = out.t1 - out.t0;
  const min = Number.isFinite(bounds?.min) ? bounds.min : null;
  const max = Number.isFinite(bounds?.max) ? bounds.max : null;
  if (min == null || max == null || max <= min) {
    return { view: out, atStart: false, atEnd: false, clamped: false };
  }
  if (span >= max - min) {
    /** The window is wider than the provable evidence. No position
     *  "fits", so the honest answer is to leave the analyst's window
     *  exactly where they put it and let the overhang render as UNKNOWN
     *  coverage. Repositioning here would let a 6 px gesture relocate
     *  the investigation by hours, bypassing the bounded-sensitivity
     *  governor entirely. */
    return { view: { t0: view.t0, t1: view.t1 },
             atStart: true, atEnd: true, clamped: false };
  }
  let clamped = false;
  if (out.t0 < min) { out.t0 = min; out.t1 = min + span; clamped = true; }
  if (out.t1 > max) { out.t1 = max; out.t0 = max - span; clamped = true; }
  return { view: out, atStart: out.t0 <= min, atEnd: out.t1 >= max, clamped };
}

/** PAN — fraction of the CURRENT span; the span never changes. */
export function panByFraction(view, fraction, bounds) {
  const span = spanOf(view);
  const dt = span * (Number.isFinite(fraction) ? fraction : 0);
  const moved = clampToBounds({ t0: view.t0 + dt, t1: view.t1 + dt }, bounds);
  return { ...moved,
           spanPreserved: Math.abs(spanOf(moved.view) - span) < 2 };
}

/** ZOOM — anchored. `anchorMs` stays at the same screen fraction. */
export function zoomToLevel(view, level, anchorMs, bounds) {
  const span = spanOf(view);
  const lvl = clamp(level, 0, ZOOM_LEVELS.length - 1);
  const anchor = Number.isFinite(anchorMs)
    ? clamp(anchorMs, view.t0, view.t1) : (view.t0 + view.t1) / 2;
  const frac = (anchor - view.t0) / span;
  const next = spanOfLevel(lvl);
  const zoomed = clampToBounds(
    { t0: anchor - frac * next, t1: anchor - frac * next + next }, bounds);
  return { ...zoomed, level: lvl, anchorMs: anchor,
           anchorPreserved: anchor >= zoomed.view.t0
             && anchor <= zoomed.view.t1 };
}

/** Positive `steps` widens the window (zoom OUT). */
export function zoomBySteps(view, steps, anchorMs, bounds) {
  const from = levelOf(spanOf(view));
  return zoomToLevel(view, from - steps, anchorMs, bounds);
}

export function fitRange(bounds) {
  const min = Number.isFinite(bounds?.min) ? bounds.min : null;
  const max = Number.isFinite(bounds?.max) ? bounds.max : null;
  if (min == null || max == null || max <= min) return null;
  const span = clamp(max - min, MIN_SPAN_MS, MAX_SPAN_MS);
  return clampToBounds({ t0: max - span, t1: max }, bounds).view;
}

/** Centre a moment without changing the scale. */
export function centreOn(view, atMs, bounds) {
  const span = spanOf(view);
  return clampToBounds({ t0: atMs - span / 2, t1: atMs + span / 2 }, bounds);
}

/* ── overview range selection ─────────────────────────────────────── */

export function moveRange(view, deltaMs, bounds) {
  return panByFraction(view, deltaMs / spanOf(view), bounds);
}

/** Resizing the left edge can never cross, meet or invert the right
 *  edge, and can never exceed the ladder ceiling. */
export function resizeRangeStart(view, tMs, bounds) {
  const hi = view.t1;
  const t0 = clamp(tMs, hi - MAX_SPAN_MS, hi - MIN_SPAN_MS);
  const next = clampToBounds({ t0, t1: hi }, bounds);
  return { ...next, valid: isValidWindow(next.view) };
}

export function resizeRangeEnd(view, tMs, bounds) {
  const lo = view.t0;
  const t1 = clamp(tMs, lo + MIN_SPAN_MS, lo + MAX_SPAN_MS);
  const next = clampToBounds({ t0: lo, t1 }, bounds);
  return { ...next, valid: isValidWindow(next.view) };
}

/** Screen x → time, used to anchor zoom on the pointer. */
export const timeAtX = (view, x, widthPx) =>
  view.t0 + (clamp(x, 0, Math.max(1, widthPx)) / Math.max(1, widthPx))
    * spanOf(view);
