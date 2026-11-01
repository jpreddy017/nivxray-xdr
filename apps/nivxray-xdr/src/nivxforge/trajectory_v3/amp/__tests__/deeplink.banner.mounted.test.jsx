// @vitest-environment jsdom
//
// MOUNTED component cover for the deep-link banner. This renders the real component into a DOM
// and clicks real buttons, so the claims below are about what an analyst actually sees - not
// about a mapping function's return value.
//
// The invariant: an unfinished lookup must never reach the screen as "not found", and must
// never cause an observation to be selected.
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import React from "react";
import { afterEach, describe, expect, it as test, vi } from "vitest";

import { DeepLinkBanner } from "../DeepLinkBanner";
import { deepLinkFromFocus } from "../deeplink.js";

afterEach(cleanup);

const noop = () => {};
const mount = (deep, over = {}) => render(
  <DeepLinkBanner deep={deep} olderCursor={null} loading={false} scopedNow={false}
    onRetry={noop} onNarrow={noop} onWiden={noop} onCandidate={noop} onLoadOlder={noop}
    {...over} />,
);

const ID = "e3_ZTNpMTowOllR";

describe("an incomplete lookup is rendered as incomplete", () => {
  test("the banner says Lookup incomplete and never says not found", () => {
    mount(deepLinkFromFocus({
      state: "OBSERVATION_LOOKUP_INCOMPLETE",
      reason: "SEARCH_BUDGET_REACHED_BEFORE_EXHAUSTING_RETAINED_EVIDENCE",
      observations_searched: 4000,
      retry: { retryable: true },
    }, { id: ID }));

    const el = screen.getByTestId("v3-deeplink-state");
    expect(el.getAttribute("data-deeplink-state")).toBe("INCOMPLETE");
    expect(screen.getByTestId("v3-deeplink-headline").textContent).toBe("Lookup incomplete");
    expect(el.textContent).not.toMatch(/was not found/i);
    expect(el.textContent).toMatch(/4000 observations compared/);
    // no candidate list is offered and nothing is selectable from an incomplete lookup
    expect(screen.queryByTestId("v3-deeplink-candidates")).toBeNull();
  });

  test("an authority failure is incomplete, with a working retry", () => {
    const onRetry = vi.fn();
    mount(deepLinkFromFocus({ state: "FOCUS_AUTHORITY_UNAVAILABLE", reason: "RuntimeError" },
                            { id: ID }), { onRetry });
    expect(screen.getByTestId("v3-deeplink-state").getAttribute("data-deeplink-state"))
      .toBe("INCOMPLETE");
    fireEvent.click(screen.getByTestId("v3-deeplink-retry"));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  test("an unknown state from a future build is incomplete, not an absence", () => {
    mount(deepLinkFromFocus({ state: "SOMETHING_THIS_BUILD_HAS_NOT_SEEN" }, { id: ID }));
    expect(screen.getByTestId("v3-deeplink-state").getAttribute("data-deeplink-state"))
      .toBe("INCOMPLETE");
  });

  test("the scoped search states what it actually covered", () => {
    mount(deepLinkFromFocus({
      state: "OBSERVATION_LOOKUP_INCOMPLETE",
      reason: "SCOPED_SEARCH_FOUND_NOTHING_IN_THE_REQUESTED_WINDOW",
      scope: { applied: true, time_start: "2026-06-01T00:00:00Z", time_end: "2026-06-01T06:00:00Z" },
      retry: { retryable: true },
    }, { id: ID }));
    const scope = screen.getByTestId("v3-deeplink-scope");
    expect(scope.textContent).toMatch(/2026-06-01 00:00 – 2026-06-01 06:00 UTC only/);
    expect(scope.textContent).toMatch(/outside this range was not searched/);
  });

  test("Search this time range is offered and fires the scoped lookup", () => {
    const onNarrow = vi.fn();
    mount(deepLinkFromFocus({ state: "OBSERVATION_LOOKUP_INCOMPLETE", retry: { retryable: true } },
                            { id: ID }), { onNarrow });
    fireEvent.click(screen.getByTestId("v3-deeplink-narrow"));
    expect(onNarrow).toHaveBeenCalledTimes(1);
  });

  test("Search all retained evidence appears only while a scope is in force", () => {
    const deep = deepLinkFromFocus({ state: "OBSERVATION_LOOKUP_INCOMPLETE", retry: { retryable: true } },
                                   { id: ID });
    mount(deep);
    expect(screen.queryByTestId("v3-deeplink-widen")).toBeNull();
    cleanup();
    const onWiden = vi.fn();
    mount(deep, { scopedNow: true, onWiden });
    fireEvent.click(screen.getByTestId("v3-deeplink-widen"));
    expect(onWiden).toHaveBeenCalledTimes(1);
  });
});

describe("an ambiguous identifier offers candidates and selects none", () => {
  const ambiguous = (candidates) => deepLinkFromFocus({
    state: "OBSERVATION_IDENTIFIER_AMBIGUOUS",
    reason: "LEGACY_IDENTITY_MATCHES_MULTIPLE_ROWS",
    candidates,
    retry: { retryable: false },
  }, { id: "act_dup" });

  test("both candidates render and a click hands back the PRESENTATION identity", () => {
    const onCandidate = vi.fn();
    mount(ambiguous([{ event_id: "e3i1:0:YQ", event_iid: "e3_ZTNpMTowOllR" },
                     { event_id: "e3i1:1:YQ", event_iid: "e3_ZTNpMToxOllR" }]), { onCandidate });

    expect(screen.getByTestId("v3-deeplink-headline").textContent).toBe("Identifier is ambiguous");
    expect(screen.getByTestId("v3-deeplink-candidates").querySelectorAll("li")).toHaveLength(2);
    // ambiguity is not retryable: a wider search cannot make a non-unique id unique
    expect(screen.queryByTestId("v3-deeplink-retry")).toBeNull();
    expect(screen.queryByTestId("v3-deeplink-narrow")).toBeNull();

    fireEvent.click(screen.getByTestId("v3-deeplink-candidate-e3i1:1:YQ"));
    expect(onCandidate).toHaveBeenCalledTimes(1);
    expect(onCandidate.mock.calls[0][0].event_iid).toBe("e3_ZTNpMToxOllR");
  });

  test("a candidate with no navigable identity is disabled and cannot be clicked through", () => {
    const onCandidate = vi.fn();
    mount(ambiguous([{ event_id: "e3i1:0:YQ" }, { event_id: "e3i1:1:YQ" }]), { onCandidate });
    const btn = screen.getByTestId("v3-deeplink-candidate-e3i1:0:YQ");
    expect(btn.disabled).toBe(true);
    fireEvent.click(btn);
    expect(onCandidate).not.toHaveBeenCalled();
  });
});

describe("the completed outcomes keep their own words", () => {
  test("a completed zero-match search is the only banner that says not found", () => {
    mount(deepLinkFromFocus({
      state: "OBSERVATION_NOT_RESOLVED",
      lookup_complete: true,
      search: { state: "EXHAUSTED_SEARCH_COMPLETED", stores_unavailable: [] },
      missing_link: "no observation on this endpoint carries the requested identifier.",
    }, { id: ID }));
    const el = screen.getByTestId("v3-deeplink-state");
    expect(el.getAttribute("data-deeplink-state")).toBe("NOT_FOUND");
    expect(screen.queryByTestId("v3-deeplink-headline")).toBeNull();
  });

  test("a resolved lookup renders the located message, not an error", () => {
    mount(deepLinkFromFocus({
      state: "FOCUS_RESOLVED",
      focus: { event_iid: ID, window: { time_start: "2026-06-01T00:00:00Z", time_end: "2026-06-01T01:00:00Z" } },
    }, { id: ID }));
    const el = screen.getByTestId("v3-deeplink-state");
    expect(el.getAttribute("data-deeplink-state")).toBe("OUTSIDE_PAGE");
    expect(el.textContent).toMatch(/located in retained evidence/);
  });

  test("a focused observation renders no banner at all", () => {
    mount({ state: "FOCUSED", id: ID });
    expect(screen.queryByTestId("v3-deeplink-state")).toBeNull();
  });
});
