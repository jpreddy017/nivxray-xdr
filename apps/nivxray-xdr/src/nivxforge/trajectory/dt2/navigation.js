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
