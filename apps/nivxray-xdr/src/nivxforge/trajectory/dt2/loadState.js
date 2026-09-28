/**
 * DT2-1 · loading and failure truth.
 *
 * NETWORK FAILURE   ≠ NO ACTIVITY
 * SERVER FAILURE    ≠ NO ACTIVITY
 * CANCELED REQUEST  ≠ NO ACTIVITY
 * EVIDENCE MISSING  ≠ NO ACTIVITY
 *
 * Only ONE state may ever be rendered as "nothing was observed", and
 * even that one says "not observed", not "nothing happened".
 */

export const WINDOW_STATE = {
  IDLE: "IDLE",
  INITIAL_LOADING: "INITIAL_LOADING",
  WINDOW_LOADING: "WINDOW_LOADING",
  PREFETCHING: "PREFETCHING",
  FOCUS_RESOLVING: "FOCUS_RESOLVING",
  REFRESHING: "REFRESHING",
  READY: "READY",
  READY_NOT_OBSERVED: "READY_NOT_OBSERVED",
  FAILED: "FAILED",
  CANCELED: "CANCELED",
  STALE_RESPONSE_DISCARDED: "STALE_RESPONSE_DISCARDED",
  UNAVAILABLE: "UNAVAILABLE",
};

/** The single source of truth for "may this be drawn as an absence of
 *  observation?". Everything else is an unknown outcome. */
export function emptinessMeaning(state) {
  if (state === WINDOW_STATE.READY_NOT_OBSERVED) {
    return { isObservationAbsence: true,
             message: "No activity was OBSERVED in this window. That is an "
                      + "absence of observation, not proof that nothing "
                      + "happened." };
  }
  if (state === WINDOW_STATE.FAILED) {
    return { isObservationAbsence: false,
             message: "This window could not be loaded. Evidence state is "
                      + "UNKNOWN." };
  }
  if (state === WINDOW_STATE.CANCELED
      || state === WINDOW_STATE.STALE_RESPONSE_DISCARDED) {
    return { isObservationAbsence: false,
             message: "The request for this window was superseded. Evidence "
                      + "state is UNKNOWN." };
  }
  if (state === WINDOW_STATE.UNAVAILABLE) {
    return { isObservationAbsence: false,
             message: "This evidence class is not available for this "
                      + "endpoint." };
  }
  return { isObservationAbsence: false, message: null };
}

export function windowStateOf({
  hasMeta = false, initial = false, loading = false, prefetching = false,
  focusResolving = false, error = null, canceled = false,
  staleDiscarded = false, unavailable = false, observationCount = 0,
} = {}) {
  if (unavailable) return WINDOW_STATE.UNAVAILABLE;
  if (error) return WINDOW_STATE.FAILED;
  if (canceled) return WINDOW_STATE.CANCELED;
  if (staleDiscarded) return WINDOW_STATE.STALE_RESPONSE_DISCARDED;
  if (focusResolving) return WINDOW_STATE.FOCUS_RESOLVING;
  if (loading && (initial || !hasMeta)) return WINDOW_STATE.INITIAL_LOADING;
  if (loading && hasMeta) {
    return observationCount > 0 ? WINDOW_STATE.REFRESHING
      : WINDOW_STATE.WINDOW_LOADING;
  }
  if (prefetching) return WINDOW_STATE.PREFETCHING;
  if (!hasMeta) return WINDOW_STATE.IDLE;
  return observationCount > 0 ? WINDOW_STATE.READY
    : WINDOW_STATE.READY_NOT_OBSERVED;
}

/** A loading window keeps the previous usable context on screen. */
export const preservesContext = (state) =>
  state === WINDOW_STATE.WINDOW_LOADING
  || state === WINDOW_STATE.REFRESHING
  || state === WINDOW_STATE.PREFETCHING
  || state === WINDOW_STATE.STALE_RESPONSE_DISCARDED;
