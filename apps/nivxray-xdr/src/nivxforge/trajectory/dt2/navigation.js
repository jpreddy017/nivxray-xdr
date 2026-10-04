/**
 * DT2-1 · deterministic object navigation and selection truth.
 *
 * Ordering is (timestamp, event_iid) — never DOM order, and never
 * timestamp alone, because equal timestamps do occur.
 *
 * Process identity is ProcessInstance identity (`process_iid`). A PID
 * is NEVER used as selection identity, so PID reuse can never move the
 * analyst onto a different process.
 */

export const SELECTION_STATE = {
  VISIBLE: "SELECTED_VISIBLE",
  OUTSIDE_WINDOW: "SELECTED_OUTSIDE_WINDOW",
  NOT_IN_RETENTION: "SELECTED_NOT_IN_RETENTION",
  EVIDENCE_MISSING: "SELECTED_EVIDENCE_MISSING",
};

export const tsOf = (o) => {
  const t = Date.parse(o?.timestamp);
  return Number.isFinite(t) ? t : Number.NaN;
};

/** A detection is an ANALYTICAL object. Density, severity or colour
 *  never make something a detection. */
export const isDetection = (o) =>
  o?.is_detection === true || !!o?.detection;

export function sortObservations(list) {
  return [...(list || [])].filter((o) => Number.isFinite(tsOf(o)))
    .sort((a, b) => (tsOf(a) - tsOf(b))
      || String(a.event_iid).localeCompare(String(b.event_iid)));
}

const stepIn = (sorted, current, dir) => {
  if (!sorted.length) return null;
  if (!current) return dir > 0 ? sorted[0] : sorted[sorted.length - 1];
  const i = sorted.findIndex((o) => o.event_iid === current.event_iid);
  if (i === -1) {
    /** The anchor is not in this set: fall back to its MOMENT, still
     *  deterministically, rather than to DOM position. */
    const t = tsOf(current);
    if (dir > 0) return sorted.find((o) => tsOf(o) > t) || null;
    return [...sorted].reverse().find((o) => tsOf(o) < t) || null;
  }
  return sorted[i + dir] || null;
};

export function stepObservation(list, current, dir) {
  return stepIn(sortObservations(list), current, dir);
}

export function stepDetection(list, current, dir) {
  return stepIn(sortObservations(list).filter(isDetection), current, dir);
}

/** Never silently reselect. An unavailable selection is REPORTED. */
export function selectionState(selected, { view, loadedIds, retention } = {}) {
  if (!selected) return null;
  const t = tsOf(selected);
  const known = loadedIds instanceof Set
    ? loadedIds.has(selected.event_iid)
    : !!loadedIds?.includes?.(selected.event_iid);
  if (Number.isFinite(retention?.min) && Number.isFinite(t)
      && t < retention.min) {
    return SELECTION_STATE.NOT_IN_RETENTION;
  }
  if (view && Number.isFinite(t) && (t < view.t0 || t > view.t1)) {
    return SELECTION_STATE.OUTSIDE_WINDOW;
  }
  if (!known) return SELECTION_STATE.EVIDENCE_MISSING;
  return SELECTION_STATE.VISIBLE;
}

/** ProcessInstance identity. `pid` is deliberately not consulted. */
export const processInstanceIdOf = (o) => o?.process_iid || null;

export const sameProcessInstance = (a, b) => {
  const x = processInstanceIdOf(a);
  const y = processInstanceIdOf(b);
  return !!x && !!y && x === y;
};

/** Relationship context an anchor must keep across pan/zoom, so DT2-3
 *  can render lineage without the navigation layer being rewritten. */
export function relationshipContextOf(o) {
  if (!o) return null;
  return {
    process_iid: processInstanceIdOf(o),
    parent_process_iid: o.parent_process_iid || null,
    parent_state: o.parent_state || null,
    lane_index: Number.isInteger(o.lane_index) ? o.lane_index : null,
    parent_lane_index: Number.isInteger(o.parent_lane_index)
      ? o.parent_lane_index : null,
  };
}

export const sameRelationshipContext = (a, b) => {
  const x = relationshipContextOf(a);
  const y = relationshipContextOf(b);
  if (!x || !y) return false;
  return x.process_iid === y.process_iid
    && x.parent_process_iid === y.parent_process_iid
    && x.lane_index === y.lane_index;
};

/* ------------------------------------------------------------------ *
 * DT2-3a.2 · TIME DOMAIN
 *
 * The 24-hour navigator is DAY CONTEXT. The trajectory canvas is the
 * PRIMARY VIEWPORT and must open on the evidence-bearing interval, or
 * concentrated evidence collapses into one pixel column on a full-day
 * domain. Every bound below is computed from REAL timestamps: nothing
 * is moved, spread, spaced or synthesised.
 * ------------------------------------------------------------------ */

export const MIN_WINDOW_MS = 120_000;        // floor for a tiny span
export const MAX_WINDOW_MS = 6 * 3_600_000;  // ceiling for the first view
export const PAD_FRACTION = 0.35;            // context, in TIME

/**
 * The initial primary viewport for an evidence interval.
 *
 * @param min earliest real evidence timestamp (ms)
 * @param max latest real evidence timestamp (ms)
 * @param dayStart start of the selected day (ms) — clamps the result
 */
export function evidenceWindow(min, max, { dayStart = null, dayMs = 86_400_000,
                                           minWindow = MIN_WINDOW_MS,
                                           maxWindow = MAX_WINDOW_MS,
                                           padFraction = PAD_FRACTION } = {}) {
  if (!Number.isFinite(min) || !Number.isFinite(max)) return null;
  const lo = Math.min(min, max);
  const hi = Math.max(min, max);
  const span = hi - lo;
  let t0;
  let t1;
  if (span <= 0) {
    // one instant of evidence: a bounded interval AROUND it, in time
    const half = minWindow / 2;
    t0 = lo - half;
    t1 = hi + half;
  } else {
    const pad = span * padFraction;
    t0 = lo - pad;
    t1 = hi + pad;
    if (t1 - t0 < minWindow) {
      const mid = (t0 + t1) / 2;
      t0 = mid - minWindow / 2;
      t1 = mid + minWindow / 2;
    }
    if (t1 - t0 > maxWindow) {
      const mid = (lo + hi) / 2;
      t0 = mid - maxWindow / 2;
      t1 = mid + maxWindow / 2;
    }
  }
  if (dayStart != null) {
    const dEnd = dayStart + dayMs;
    const width = Math.min(t1 - t0, dayMs);
    if (t0 < dayStart) { t0 = dayStart; t1 = t0 + width; }
    if (t1 > dEnd) { t1 = dEnd; t0 = t1 - width; }
  }
  return { t0, t1 };
}

/** The ONE horizontal mapping. X is time; nothing else may move it. */
export const projectX = (t, t0, t1, left, drawableWidth) =>
  (t == null || !Number.isFinite(t) || !(t1 > t0) ? null
    : left + ((t - t0) / (t1 - t0)) * drawableWidth);

/** A tick step suited to the CURRENT viewport, so a 90ms window is not
 *  labelled with hour marks. */
const TICK_STEPS = [1, 5, 10, 25, 50, 100, 250, 500,
                    1e3, 5e3, 15e3, 30e3,
                    60e3, 120e3, 300e3, 900e3, 1800e3,
                    3600e3, 3 * 3600e3, 6 * 3600e3, 12 * 3600e3, 86400e3];

export function tickStepFor(spanMs, target = 12) {
  const want = Math.max(1, spanMs) / Math.max(2, target);
  return TICK_STEPS.find((s) => s >= want) || TICK_STEPS[TICK_STEPS.length - 1];
}
