// Deep-link outcome mapping for Device Trajectory.
//
// The backend distinguishes a COMPLETED absence from an unfinished or unavailable lookup, and
// the UI must keep them apart. Telling an analyst "not found in retained evidence" when the
// search never finished asserts something the backend did not establish.
//
// DEFAULT-DENY on the absence claim: NOT_FOUND is reachable ONLY from an explicit completed
// zero-match response. Every other shape - an authority failure, an unknown state, an empty or
// malformed body, a state this build has not seen - is INCOMPLETE.
//
// Extracted from the page component so the decision is testable on its own: these are the exact
// branches the component renders, with no DOM involved.

export const LOOKUP_INCOMPLETE = "OBSERVATION_LOOKUP_INCOMPLETE";
export const LOOKUP_AMBIGUOUS = "OBSERVATION_IDENTIFIER_AMBIGUOUS";

/** The ONLY state that may become NOT_FOUND, and only when it also claims to be complete. */
export const LOOKUP_ABSENT = "OBSERVATION_NOT_RESOLVED";

//: Any search block that admits it stopped early. A route may report a completed-sounding
//: state while its own search block says the walk was capped or a store was unreadable.
const PARTIAL_SEARCH = /BUDGET|INCOMPLETE|PARTIAL|UNAVAILABLE|SCOPED/i;

function searchWasComplete(f) {
  if (f?.lookup_complete === false) return false;
  const s = f?.search || {};
  const markers = [s.state, s.cursor_state].filter(Boolean).map(String);
  if (markers.some((m) => PARTIAL_SEARCH.test(m))) return false;
  if (s.stores_unavailable?.length) return false;
  // a scoped search covers a window, never retained history
  if (f?.scope?.applied || s.scope?.applied) return false;
  return true;
}

/** The window the SERVER reports it actually searched, or null when the search was unscoped. */
function scopeOf(f) {
  const s = f?.scope || f?.search?.scope;
  if (!s?.applied) return null;
  const t0 = Date.parse(s.time_start ?? "");
  const t1 = Date.parse(s.time_end ?? "");
  return Number.isFinite(t0) && Number.isFinite(t1) ? { t0, t1 } : null;
}

const INCOMPLETE_NOTE =
  "The observation lookup did not complete, so it is neither found nor shown to be absent. Nothing is selected in its place.";

/** Map one `/focus` response to the component's deep-link state. Never selects a row. */
export function deepLinkFromFocus(f, { id, scope = null, attempt = 0 } = {}) {
  const state = f?.state;
  const base = { id, scope, try: attempt, select: null };
  const incomplete = (note, extra = {}) => ({
    ...base, state: "INCOMPLETE", retryable: f?.retry?.retryable !== false, candidates: [],
    reason: f?.reason || null, searched: f?.observations_searched ?? null, scoped: scopeOf(f),
    note: note || f?.missing_link || f?.meaning || INCOMPLETE_NOTE, ...extra,
  });

  if (state === LOOKUP_INCOMPLETE || state === LOOKUP_AMBIGUOUS) {
    return {
      ...base,
      state: state === LOOKUP_AMBIGUOUS ? "AMBIGUOUS" : "INCOMPLETE",
      note: f.missing_link || f.meaning || f.reason || null,
      reason: f.reason || null,
      searched: f.observations_searched ?? null,
      // ambiguity cannot be retried away: a wider search cannot make a non-unique id unique.
      retryable: f.retry?.retryable !== false,
      // candidates are OFFERED, never applied: the analyst chooses.
      candidates: f.candidates || [],
      scoped: scopeOf(f),
    };
  }

  if (state === "FOCUS_RESOLVED") {
    const t0 = Date.parse(f?.focus?.window?.time_start ?? "");
    const t1 = Date.parse(f?.focus?.window?.time_end ?? "");
    if (!Number.isFinite(t0) || !Number.isFinite(t1)) {
      return incomplete("The observation resolved but its time range was unavailable, so it could not be brought into view.");
    }
    return { ...base, state: "OUTSIDE_PAGE", select: f.focus.event_iid || id, window: { t0, t1 } };
  }

  if (state === LOOKUP_ABSENT && searchWasComplete(f)) {
    return { ...base, state: "NOT_FOUND", note: f?.missing_link || f?.reason || null };
  }

  // Everything else: authority unavailable, an unrecognised state, or no state at all.
  return incomplete();
}

/** The lookup failed to even reach a verdict (transport/abort). NOT an absence. */
export function deepLinkFromError(id, { scope = null, attempt = 0 } = {}) {
  return { state: "INCOMPLETE", id, scope, try: attempt, retryable: true, candidates: [],
           select: null,
           note: "The observation lookup could not be completed. This does not establish that it is absent." };
}

/** The selected row is the EXACT identity match, or nothing. There is no first-row fallback. */
export function selectedFor(items, wanted) {
  if (!wanted) return null;
  return (items || []).find((it) => it?.ev?.event_iid === wanted) || null;
}
