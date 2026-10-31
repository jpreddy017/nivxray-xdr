// Deep-link outcome mapping for Device Trajectory.
//
// The backend distinguishes FOUR outcomes for one identifier lookup, and the UI must keep them
// distinct. An unfinished search is the dangerous one: rendering it as "not found" tells the
// analyst that the endpoint never held the observation, which the backend did not establish.
//
// Extracted from the page component so the decision is testable on its own: these are the exact
// branches the component renders, with no DOM involved.

export const LOOKUP_INCOMPLETE = "OBSERVATION_LOOKUP_INCOMPLETE";
export const LOOKUP_AMBIGUOUS = "OBSERVATION_IDENTIFIER_AMBIGUOUS";

/** Map one `/focus` response to the component's deep-link state. Never selects a row. */
export function deepLinkFromFocus(f, { id, scope = null, attempt = 0 } = {}) {
  const state = f?.state;
  const base = { id, scope, try: attempt, select: null };
  if (state === LOOKUP_INCOMPLETE || state === LOOKUP_AMBIGUOUS) {
    return {
      ...base,
      state: state === LOOKUP_AMBIGUOUS ? "AMBIGUOUS" : "INCOMPLETE",
      note: f.missing_link || f.reason || null,
      reason: f.reason || null,
      searched: f.observations_searched ?? null,
      // ambiguity cannot be retried away: a wider search cannot make a non-unique id unique.
      retryable: f.retry?.retryable !== false,
      // candidates are OFFERED, never applied: the analyst chooses.
      candidates: f.candidates || [],
    };
  }
  if (state === "FOCUS_RESOLVED") {
    const t0 = Date.parse(f?.focus?.window?.time_start ?? "");
    const t1 = Date.parse(f?.focus?.window?.time_end ?? "");
    if (!Number.isFinite(t0) || !Number.isFinite(t1)) {
      // resolved, but with no usable window: the lookup cannot be COMPLETED into a view.
      return { ...base, state: "INCOMPLETE", retryable: true, candidates: [],
               note: "The observation resolved but its time range was unavailable, so it could not be brought into view." };
    }
    return { ...base, state: "OUTSIDE_PAGE", select: f.focus.event_iid || id, window: { t0, t1 } };
  }
  return { ...base, state: "NOT_FOUND", note: f?.missing_link || f?.reason || null };
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
