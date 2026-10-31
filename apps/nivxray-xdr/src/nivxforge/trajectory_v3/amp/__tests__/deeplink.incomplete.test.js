// An UNFINISHED identifier lookup must never reach the analyst as "not found", and must never
// cause a row to be selected. These pin the component's deep-link decision branches.
//
// SCOPE: this exercises the mapping the component renders from, not a DOM render — the package
// has no jsdom/testing-library, so no test here claims to have mounted the page.
import { describe, expect, it as test } from "vitest";

import { deepLinkFromError, deepLinkFromFocus, selectedFor } from "../deeplink.js";

const ID = "e3i1:0:c2FtZQ";

describe("incomplete lookup never becomes not-found", () => {
  test("budget-limited search renders INCOMPLETE, selects nothing, offers retry", () => {
    const d = deepLinkFromFocus({
      state: "OBSERVATION_LOOKUP_INCOMPLETE",
      reason: "SEARCH_BUDGET_REACHED_BEFORE_EXHAUSTING_RETAINED_EVIDENCE",
      observations_searched: 4000,
      retry: { retryable: true },
      missing_link: "the newest 4000 observations were compared and retained evidence continues beyond them.",
    }, { id: ID });
    expect(d.state).toBe("INCOMPLETE");
    expect(d.state).not.toBe("NOT_FOUND");
    expect(d.select).toBeNull();
    expect(d.retryable).toBe(true);
    expect(d.searched).toBe(4000);
  });

  test("unreadable evidence store renders INCOMPLETE, not an absence", () => {
    const d = deepLinkFromFocus({
      state: "OBSERVATION_LOOKUP_INCOMPLETE",
      reason: "EVIDENCE_STORE_READ_INCOMPLETE",
      retry: { retryable: true },
    }, { id: ID });
    expect(d.state).toBe("INCOMPLETE");
    expect(d.select).toBeNull();
  });

  test("a transport failure is INCOMPLETE, never NOT_FOUND", () => {
    const d = deepLinkFromError(ID, { attempt: 2 });
    expect(d.state).toBe("INCOMPLETE");
    expect(d.select).toBeNull();
    expect(d.try).toBe(2);
  });

  test("an incomplete lookup that reported a partial match still selects nothing", () => {
    const d = deepLinkFromFocus({
      state: "OBSERVATION_LOOKUP_INCOMPLETE",
      reason: "SEARCH_BUDGET_REACHED_BEFORE_EXHAUSTING_RETAINED_EVIDENCE",
      partial_matches: [{ event_id: "e3i1:0:YQ" }],
      retry: { retryable: true },
    }, { id: ID });
    expect(d.state).toBe("INCOMPLETE");
    expect(d.select).toBeNull();
  });
});

describe("ambiguity is offered, never resolved", () => {
  test("two candidates are listed and none is applied", () => {
    const d = deepLinkFromFocus({
      state: "OBSERVATION_IDENTIFIER_AMBIGUOUS",
      reason: "LEGACY_IDENTITY_MATCHES_MULTIPLE_ROWS",
      candidates: [{ event_id: "e3i1:0:YQ", event_iid: "a#1" },
                   { event_id: "e3i1:1:YQ", event_iid: "a#2" }],
      retry: { retryable: false },
    }, { id: "a" });
    expect(d.state).toBe("AMBIGUOUS");
    expect(d.select).toBeNull();
    expect(d.candidates).toHaveLength(2);
    expect(d.retryable).toBe(false);
  });
});

describe("the resolved and absent outcomes keep their own meaning", () => {
  test("a resolved lookup focuses the returned window", () => {
    const d = deepLinkFromFocus({
      state: "FOCUS_RESOLVED",
      focus: { event_iid: "x#1", window: { time_start: "2026-06-01T00:00:00Z",
                                           time_end: "2026-06-01T01:00:00Z" } },
    }, { id: "x#1" });
    expect(d.state).toBe("OUTSIDE_PAGE");
    expect(d.select).toBe("x#1");
    expect(d.window.t1 - d.window.t0).toBe(3600000);
  });

  test("a resolved lookup whose window is unusable is INCOMPLETE, not a focus", () => {
    const d = deepLinkFromFocus({ state: "FOCUS_RESOLVED", focus: { event_iid: "x#1" } },
                                { id: "x#1" });
    expect(d.state).toBe("INCOMPLETE");
    expect(d.select).toBeNull();
  });

  test("a COMPLETED zero-match search is the only path to NOT_FOUND", () => {
    const d = deepLinkFromFocus({
      state: "OBSERVATION_NOT_RESOLVED",
      reason: "EVIDENCE_IDENTITY_NOT_FOUND_FOR_THIS_ENDPOINT",
      missing_link: "no observation on this endpoint carries the requested identifier.",
    }, { id: ID });
    expect(d.state).toBe("NOT_FOUND");
    expect(d.select).toBeNull();
  });
});

describe("only an explicit completed absence may become NOT_FOUND", () => {
  const cases = [
    ["FOCUS_AUTHORITY_UNAVAILABLE", { state: "FOCUS_AUTHORITY_UNAVAILABLE", reason: "RuntimeError" }],
    ["the superseded incomplete state name", { state: "OBSERVATION_NOT_RESOLVED_SEARCH_INCOMPLETE" }],
    ["an unresolvable endpoint", { state: "ENDPOINT_NOT_RESOLVED" }],
    ["no identifier supplied", { state: "NO_IDENTIFIER_SUPPLIED" }],
    ["a state this build has never seen", { state: "SOMETHING_NEW" }],
    ["an empty body", {}],
    ["no body at all", null],
    ["undefined", undefined],
    ["absent but self-declared incomplete", { state: "OBSERVATION_NOT_RESOLVED", lookup_complete: false }],
    ["absent with a capped search block", { state: "OBSERVATION_NOT_RESOLVED", search: { state: "PAGE_BUDGET_REACHED_8" } }],
    ["absent with a legacy capped cursor_state", { state: "OBSERVATION_NOT_RESOLVED", search: { cursor_state: "PAGE_BUDGET_REACHED_2" } }],
    ["absent with an unreadable store", { state: "OBSERVATION_NOT_RESOLVED", search: { state: "EXHAUSTED_SEARCH_COMPLETED", stores_unavailable: ["xdr_canonical_evidence"] } }],
    ["absent from a scoped search only", { state: "OBSERVATION_NOT_RESOLVED", scope: { applied: true } }],
  ];

  cases.forEach(([name, body]) => {
    test(`${name} is INCOMPLETE, never NOT_FOUND`, () => {
      const d = deepLinkFromFocus(body, { id: ID });
      expect(d.state).toBe("INCOMPLETE");
      expect(d.state).not.toBe("NOT_FOUND");
      expect(d.select).toBeNull();
      expect(d.note).toBeTruthy();
    });
  });

  test("a completed, unscoped, fully-read zero-match search IS not found", () => {
    const d = deepLinkFromFocus({
      state: "OBSERVATION_NOT_RESOLVED",
      lookup_complete: true,
      search: { state: "EXHAUSTED_SEARCH_COMPLETED", stores_unavailable: [], scope: { applied: false } },
    }, { id: ID });
    expect(d.state).toBe("NOT_FOUND");
    expect(d.select).toBeNull();
  });
});

describe("selection is an exact identity match or nothing", () => {
  const items = [{ ev: { event_iid: "a#1" } }, { ev: { event_iid: "b#2" } }];

  test("an unresolved deep link does not fall through to the first row", () => {
    expect(selectedFor(items, "missing#9")).toBeNull();
    expect(selectedFor(items, null)).toBeNull();
    expect(selectedFor([], "a#1")).toBeNull();
  });

  test("an exact match selects that row and only that row", () => {
    expect(selectedFor(items, "b#2").ev.event_iid).toBe("b#2");
  });
});
