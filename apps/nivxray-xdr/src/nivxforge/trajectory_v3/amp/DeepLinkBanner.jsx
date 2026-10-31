import React from "react";

import { C } from "./theme";

// The deep-link banner. Its ONLY job is to keep four outcomes apart in front of an analyst:
//   FOCUSED / OUTSIDE_PAGE  the observation was located
//   NOT_FOUND               a COMPLETED search found nothing
//   INCOMPLETE              the search did not finish - neither found nor absent
//   AMBIGUOUS               the identifier names more than one observation
// It never selects a row and never offers an action the backend cannot carry out.

const fmt = (ms) => new Date(ms).toISOString().slice(0, 16).replace("T", " ");

export const DeepLinkBanner = ({ deep, olderCursor, loading, onRetry, onNarrow, onWiden,
                                 onCandidate, onLoadOlder, scopedNow }) => {
  if (!deep || deep.state === "FOCUSED") return null;

  if (deep.state === "INCOMPLETE" || deep.state === "AMBIGUOUS") {
    const ambiguous = deep.state === "AMBIGUOUS";
    return (
      <div role="status" data-testid="v3-deeplink-state" data-deeplink-state={deep.state}
        style={{ fontSize: 13, color: C.text, marginBottom: 8, padding: "8px 12px", border: `1px solid ${C.amber}`, borderRadius: 8 }}>
        <strong data-testid="v3-deeplink-headline">{ambiguous ? "Identifier is ambiguous" : "Lookup incomplete"}</strong>
        <div data-testid="v3-deeplink-note" style={{ color: C.muted, marginTop: 4 }}>
          {ambiguous
            ? (deep.note || `Observation ${deep.id} was exported by an older build and names more than one observation. Choose the intended one — nothing is selected automatically.`)
            : (deep.note || `The search for observation ${deep.id} did not finish, so it is neither found nor shown to be absent. Nothing is selected in its place.`)}
          {deep.searched ? ` (${deep.searched} observations compared)` : ""}
        </div>
        {ambiguous && deep.candidates?.length > 0 && (
          <ul data-testid="v3-deeplink-candidates" style={{ margin: "8px 0 0", paddingLeft: 18 }}>
            {deep.candidates.map((c) => (
              <li key={c.event_id}>
                {/* A candidate is navigable only by its PRESENTATION identity. Falling back to
                    the evidence identity would render a button that cannot resolve, so a
                    candidate without one is disabled rather than shown as a dead link. */}
                <button className="v3-link" data-testid={`v3-deeplink-candidate-${c.event_id}`} style={{ fontSize: 13 }}
                  disabled={!c.event_iid}
                  title={c.event_iid ? "Focus this observation" : "This candidate was returned without a navigable identity"}
                  onClick={() => c.event_iid && onCandidate(c)}>{c.event_id}</button>
              </li>
            ))}
          </ul>
        )}
        {deep.scoped && (
          <div data-testid="v3-deeplink-scope" style={{ color: C.muted, marginTop: 6, fontSize: 12.5 }}>
            Searched {fmt(deep.scoped.t0)} – {fmt(deep.scoped.t1)} UTC only. Evidence outside this range was not searched.
          </div>
        )}
        <div style={{ marginTop: 8, display: "flex", gap: 12 }}>
          {deep.retryable !== false && (
            <button className="v3-btn" data-testid="v3-deeplink-retry" onClick={onRetry}>Retry lookup</button>
          )}
          {/* The supported narrowing action: the SAME lookup, bounded to the range on screen.
              The server applies and reports the scope - this is not advice to the analyst. */}
          {deep.retryable !== false && (
            <button className="v3-btn" data-testid="v3-deeplink-narrow" onClick={onNarrow}>Search this time range</button>
          )}
          {scopedNow && (
            <button className="v3-btn" data-testid="v3-deeplink-widen" onClick={onWiden}>Search all retained evidence</button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div data-testid="v3-deeplink-state" data-deeplink-state={deep.state}
      style={{ fontSize: 13, color: deep.state === "NOT_FOUND" ? C.amber : C.muted, marginBottom: 8 }}>
      {deep.state === "NOT_FOUND"
        ? (deep.note || `Observation ${deep.id} was not found in retained evidence for this device.`)
        : deep.state === "OUTSIDE_PAGE"
          ? "Observation located in retained evidence. Its time range is selected; load older events if it is outside the loaded page."
          : `Locating observation ${deep.id} in history…`}
      {deep.state === "OUTSIDE_PAGE" && olderCursor && (
        <button className="v3-link" disabled={loading} onClick={onLoadOlder}>Load older events</button>
      )}
    </div>
  );
};

export default DeepLinkBanner;
