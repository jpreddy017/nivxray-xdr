// @vitest-environment jsdom
//
// Dashboard · current fleet state and historical evidence must stay apart, and
// every number must say what it counted.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({ default: { get: vi.fn(), post: vi.fn() } }));
vi.mock("@/nivxforge/components/TelemetryFreshness", () => ({
  TelemetryFreshnessBanner: () => <div data-testid="freshness-banner" />,
}));

import api from "@/lib/api";
import EdrDashboardBody from "@/nivxforge/pages/EdrDashboardBody";

const DEVICE = "ep_2d57cbe6f80152062109";
const SHA = "17a623f303e2489770e64a9eab9420c66e576ec5ad215ea7c46ec392a2212f49";

const fleet = (over = {}) => ({ ok: true, tenant_id: "default", fleet: {
  enrolled: 671, delivering: 0, stale: 0, blind: 671,
  last_read_at: "2026-11-03T15:59:00+00:00", condition: "FLEET_VISIBILITY_LOST",
  headline: "Fleet visibility lost · 0 of 671 enrolled endpoints delivering",
  basis: "Delivering = telemetry within 15 minutes", ...over } });

const board = (over = {}) => ({
  ok: true, tenant_id: "default",
  range: { start: "2026-09-06T00:00:00+00:00", end: "2026-10-18T23:59:59+00:00",
           basis: "observed UTC" },
  files: [{ sha256: SHA, name: "sleep", sightings: 809, paths: 14, endpoints: 1,
            activities: { "Process observed": 797, "File created": 12 } },
          { sha256: "b".repeat(64), name: "dash", sightings: 850, paths: 2,
            endpoints: 1, activities: { "Process observed": 850 } }],
  files_total: 28,
  selected_file: { sha256: SHA, name: "sleep", sightings: 809,
    activities: { "Process observed": 797, "File created": 12 },
    recorded_paths: 14, computers: 1,
    observation_note: "A process observation is a sensor observation, not a launch." },
  events: [{ raw_id: "raw_a107807c2febdbfc17da2d71", endpoint_id: DEVICE,
             observed_at: "2026-10-18T14:01:06.493826+00:00",
             sha256: SHA, path: "/usr/bin/sleep", activity: "PROCESS_OBSERVED",
             activity_label: "Process observed", pid: 27516 }],
  events_matching: 784, sightings_in_range: 39990,
  events_note: "Showing 1 of 784 matching sightings, filtered on path filter across the whole window",
  activities_available: ["PROCESS_OBSERVED", "CREATE", "DELETE"],
  scan: { events_read: 784, cap: 40000, truncated: false,
          note: "every event delivered in this window was read, so the counts are totals, not a subset",
          observed_basis: "rows are selected on the time the ENDPOINT observed them" },
  ...over });

const route = (f, b) => (url) => Promise.resolve({
  data: /dashboard\/fleet/.test(url) ? f : b });

const mount = () => render(
  <MemoryRouter><EdrDashboardBody /></MemoryRouter>);

beforeEach(() => { api.get.mockReset(); });
afterEach(() => cleanup());

describe("EDR Dashboard", () => {
  it("states fleet condition as current, never as the selected range", async () => {
    api.get.mockImplementation(route(fleet(), board()));
    mount();
    const band = await screen.findByTestId("dash-fleet-band");
    expect(band.getAttribute("data-condition")).toBe("FLEET_VISIBILITY_LOST");
    expect(band.textContent).toContain("0 of 671 enrolled endpoints delivering");
    expect(band.textContent).toMatch(/not the selected date range/);
    expect(screen.getByTestId("dash-fleet-enrolled").textContent).toBe("671");
    expect(screen.getByTestId("dash-fleet-blind").textContent).toBe("671");
    expect(screen.getByTestId("dash-fleet-read").textContent).toMatch(/Last successful read/);
  });

  it("keeps the full pipeline explanation behind Diagnostics", async () => {
    api.get.mockImplementation(route(fleet(), board()));
    mount();
    await screen.findByTestId("dash-fleet-band");
    expect(screen.queryByTestId("freshness-banner")).toBeNull();
    fireEvent.click(screen.getByTestId("dash-diagnostics"));
    expect(screen.getByTestId("freshness-banner")).toBeTruthy();
  });

  it("sizes files by sightings and drives the activity panel from the selection", async () => {
    api.get.mockImplementation(route(fleet(), board()));
    mount();
    await screen.findByTestId("dash-treemap");
    expect(screen.getByTestId("dash-files-note").textContent)
      .toBe("Top 2 files by sightings of 28 in range");
    expect(screen.getByTestId("dash-file-0").getAttribute("data-sha256")).toBe(SHA);
    expect(screen.getByTestId("dash-file-0").getAttribute("data-selected")).toBe("1");
    expect(screen.getByTestId("dash-activity-process-observed").getAttribute("data-count"))
      .toBe("797");
    expect(screen.getByTestId("dash-activity-file-created").getAttribute("data-count"))
      .toBe("12");
    expect(screen.getByTestId("dash-paths").textContent).toContain("14 recorded paths");
    expect(screen.getByTestId("dash-computers").textContent).toContain("1 computer");
    expect(screen.getByTestId("dash-observation-note").textContent)
      .toMatch(/not a launch/);

    api.get.mockClear();
    fireEvent.click(screen.getByTestId("dash-file-1"));
    await waitFor(() => expect(api.get).toHaveBeenCalledWith(
      "/edr/dashboard/board",
      expect.objectContaining({ params: expect.objectContaining({ sha256: "b".repeat(64) }) })));
  });

  it("says what it counted and what it capped", async () => {
    api.get.mockImplementation(route(fleet(), board()));
    mount();
    expect((await screen.findByTestId("dash-events-note")).textContent)
      .toBe("Showing 1 of 784 matching sightings, filtered on path filter across the whole window");
    expect(screen.getByTestId("dash-scan-note").textContent)
      .toMatch(/counts are totals, not a subset/);
    expect(screen.getByTestId("dash-scan-note").textContent)
      .toMatch(/time the ENDPOINT observed them/);
  });

  it("lands Investigate on the exact sighting, by evidence id", async () => {
    api.get.mockImplementation(route(fleet(), board()));
    mount();
    const row = await screen.findByTestId("dash-event-raw_a107807c2febdbfc17da2d71");
    expect(row.textContent).toContain("2026-10-18 14:01:06Z");
    expect(row.textContent).toContain("27516");
    const href = screen.getByTestId("dash-investigate-raw_a107807c2febdbfc17da2d71")
      .getAttribute("href");
    expect(href).toContain(`device=${DEVICE}`);
    expect(href).toContain("sighting=raw_a107807c2febdbfc17da2d71");
    expect(href).toContain(`sha256=${SHA}`);
    expect(href).toContain("at=2026-10-18T14%3A01%3A06.493826%2B00%3A00");
    expect(href).toContain("tenant=default");
  });

  it("refuses to call a backwards range an empty result", async () => {
    api.get.mockImplementation(route(fleet(), {
      ok: false, reason: "EMPTY_RANGE",
      note: "the range ends before it starts, so nothing was looked up. This is not an empty result." }));
    mount();
    expect((await screen.findByTestId("dash-error")).textContent)
      .toMatch(/nothing was looked up. This is not an empty result/);
  });

  it("says Unavailable with a reason when the fleet read fails", async () => {
    api.get.mockImplementation((url) => /dashboard\/fleet/.test(url)
      ? Promise.reject({ response: { data: { detail: { reason: "fleet read refused" } } } })
      : Promise.resolve({ data: board() }));
    mount();
    expect((await screen.findByTestId("dash-fleet-unavailable")).textContent)
      .toMatch(/Unavailable · fleet read refused/);
    expect(screen.getByTestId("dash-fleet-band").getAttribute("data-condition"))
      .toBe("UNAVAILABLE");
  });

  it("filters before limiting, and asks the server to do it", async () => {
    api.get.mockImplementation(route(fleet(), board()));
    mount();
    await screen.findByTestId("dash-events-table");
    api.get.mockClear();
    fireEvent.change(screen.getByTestId("dash-path-filter"),
                     { target: { value: "/var/tmp" } });
    await waitFor(() => expect(api.get).toHaveBeenCalledWith(
      "/edr/dashboard/board",
      expect.objectContaining({ params: expect.objectContaining({
        path_contains: "/var/tmp", limit: 100 }) })));
  });
});
