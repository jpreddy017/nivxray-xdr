// @vitest-environment jsdom
//
// File Trajectory, laid out the way Cisco Secure Endpoint lays it out:
// visibility → entry point → file details → the computers-against-time graphic
// with a detail pane → event history. And the rule the whole surface turns on:
// a sighting opens the device canvas at the time the ENDPOINT observed it, not
// at the time the record was ingested, which can be the following UTC day.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import EdrFilesPage, { sightingHref } from "../EdrFilesPage";
import api from "@/lib/api";

vi.mock("@/lib/api", () => ({ default: { get: vi.fn(), post: vi.fn() } }));
vi.mock("@/nivxforge/NivXForgeConsole", () => ({
  default: ({ children }) => <div>{children}</div>,
  useIncidentContext: () => null,
}));

const HASH = "15fc4c72f49c86639a383121eec6fbdbcd32ec9d03db915cb3096928295e1a17";
const DEVICE = "ep_2d57cbe6f80152062109";
const OTHER = "ep_second0000000000000";

const SHIFTED = {
  raw_id: "raw_shift", endpoint_id: DEVICE, path: "/usr/bin/dash",
  activity: "PROCESS_OBSERVED",
  observed_at: "2026-09-23T18:28:31.162868+00:00",
  ingested_at: "2026-09-24T01:47:41.235148+00:00",
  observed_day_utc: "2026-09-23", ingest_day_utc: "2026-09-24",
  ingest_day_differs: true, pid: 4242, ppid: 1, user: "root",
  command_line: "/bin/sh -c zip -r /tmp/data_db_backup.zip /data/db",
  parent_image: "/usr/bin/bash", collection_method: "PROC_POLL",
  sensor_version: "0.1.0", trust_state: "AUTHENTICATED",
};
const LATER = { ...SHIFTED, raw_id: "raw_late", path: "/var/tmp/copy/dash",
  observed_at: "2026-10-18T14:35:56.000000+00:00",
  ingested_at: "2026-10-18T14:35:57.000000+00:00",
  observed_day_utc: "2026-10-18", ingest_day_utc: "2026-10-18",
  ingest_day_differs: false, pid: 28698 };
const ELSEWHERE = { ...LATER, raw_id: "raw_other", endpoint_id: OTHER,
  observed_at: "2026-10-19T09:00:00.000000+00:00", path: "/usr/bin/dash" };

const payload = (over = {}) => ({
  ok: true, sha256: HASH, tenant: "default", total_sightings: 3,
  endpoint_count: 2,
  observed_paths: ["/usr/bin/dash", "/var/tmp/copy/dash"],
  observed_names: ["dash"],
  first_observed: SHIFTED.observed_at, last_observed: ELSEWHERE.observed_at,
  visibility: { first_observed: SHIFTED.observed_at,
                last_observed: ELSEWHERE.observed_at, endpoints: 2 },
  entry_points: [{ endpoint_id: DEVICE, hostname: "agent-env-630704a1",
                   first_observed: SHIFTED.observed_at }],
  activity_breakdown: { PROCESS_OBSERVED: 3 },
  attributes: { sha256: HASH, known_names: ["dash"], users: ["root"],
                parent_images: ["/usr/bin/bash"], sensor_versions: ["0.1.0"],
                collection_methods: ["PROC_POLL"] },
  not_collected: ["file size", "real file type", "signing certificate"],
  day_shifted_sightings: 1, day_shifted_examples: [SHIFTED],
  scanned: 3, truncated: false,
  endpoints: [
    { endpoint_id: DEVICE, hostname: "agent-env-630704a1", identity: "registered",
      sighting_count: 2, paths: ["/usr/bin/dash", "/var/tmp/copy/dash"],
      first_observed: SHIFTED.observed_at, last_observed: LATER.observed_at,
      sightings: [LATER, SHIFTED] },
    { endpoint_id: OTHER, hostname: "second-host", identity: "registered",
      sighting_count: 1, paths: ["/usr/bin/dash"],
      first_observed: ELSEWHERE.observed_at, last_observed: ELSEWHERE.observed_at,
      sightings: [ELSEWHERE] },
  ],
  ...over,
});

const mount = (search = `?sha256=${HASH}`) => render(
  <MemoryRouter initialEntries={[`/edr/files${search}`]}><EdrFilesPage /></MemoryRouter>);

afterEach(cleanup);

describe("a sighting opens the device canvas at the observed time", () => {
  it("builds the link from the observation time, not the ingest time", () => {
    const u = new URL(sightingHref(HASH, SHIFTED, "default"), "https://x.test");
    expect(u.pathname).toBe("/edr/device-trajectory");
    expect(u.searchParams.get("device")).toBe(DEVICE);
    expect(u.searchParams.get("at")).toBe(SHIFTED.observed_at);
    expect(u.searchParams.get("at")).not.toBe(SHIFTED.ingested_at);
    expect(u.searchParams.get("at").slice(0, 10)).toBe("2026-09-23");
    expect(u.searchParams.get("tenant")).toBe("default");
  });

  it("offers nothing to open when a sighting names no endpoint or time", () => {
    expect(sightingHref(HASH, { endpoint_id: DEVICE }, "default")).toBeNull();
    expect(sightingHref(HASH, { observed_at: SHIFTED.observed_at }, "d")).toBeNull();
  });

  it("renders history rows as new-tab links, keeping this page open", async () => {
    api.get.mockResolvedValue({ data: payload() });
    mount();
    const a = await screen.findByTestId("edr-files-event-row-0-open");
    expect(a.tagName).toBe("A");
    expect(a.getAttribute("target")).toBe("_blank");
    expect(a.getAttribute("rel")).toBe("noopener noreferrer");
    expect(a.textContent).toMatch(/opens in a new tab/);
  });

  it("calls out the sightings whose delivery crossed midnight", async () => {
    api.get.mockResolvedValue({ data: payload() });
    mount();
    const sec = await screen.findByTestId("edr-files-day-shift");
    expect(sec.textContent).toMatch(/different UTC day/);
    expect(screen.getByTestId("edr-files-shift-row-0").getAttribute("data-day-shift")).toBe("1");
    expect(screen.getByTestId("edr-files-shift-row-0-open").getAttribute("href"))
      .toContain("at=2026-09-23T18%3A28%3A31.162868%2B00%3A00");
  });
});

describe("the Cisco Secure Endpoint layout", () => {
  it("states visibility and the entry point computer", async () => {
    api.get.mockResolvedValue({ data: payload() });
    mount();
    expect((await screen.findByTestId("edr-files-first")).textContent).toContain("2026-09-23");
    expect(screen.getByTestId("edr-files-last").textContent).toContain("2026-10-19");
    expect(screen.getByTestId("edr-files-entry-0").textContent).toContain("agent-env-630704a1");
    // The entry point is the earliest observation, and the page says so rather
    // than claiming the file arrived there.
    expect(screen.getByTestId("edr-files-entry-point").textContent)
      .toMatch(/not the same as proof of where it arrived from/);
  });

  it("draws one lane per computer and one glyph per sighting", async () => {
    api.get.mockResolvedValue({ data: payload() });
    mount();
    await screen.findByTestId("edr-files-graphic");
    expect(screen.getByTestId("edr-files-lane-0").getAttribute("data-endpoint")).toBe(DEVICE);
    expect(screen.getByTestId("edr-files-lane-1").getAttribute("data-endpoint")).toBe(OTHER);
    expect(screen.getByTestId("edr-files-glyph-0-0")).toBeTruthy();
    expect(screen.getByTestId("edr-files-glyph-0-1").getAttribute("data-day-shift")).toBe("1");
    expect(screen.getByTestId("edr-files-glyph-1-0")).toBeTruthy();
    // Only the first computer saw it first.
    expect(screen.getByTestId("edr-files-lane-0-entry")).toBeTruthy();
    expect(screen.queryByTestId("edr-files-lane-1-entry")).toBeNull();
  });

  it("names the event types it can never show instead of implying none occurred", async () => {
    api.get.mockResolvedValue({ data: payload() });
    mount();
    const legend = await screen.findByTestId("edr-files-legend");
    expect(legend.textContent).toMatch(/created · moved · scanned · quarantined/);
    fireEvent.click(screen.getByTestId("edr-files-details-toggle"));
    expect(screen.getByTestId("edr-files-not-collected").textContent)
      .toMatch(/signing certificate/);
  });

  it("opens a sighting's detail beside the graphic, with its own link", async () => {
    api.get.mockResolvedValue({ data: payload() });
    mount();
    expect(await screen.findByTestId("edr-files-detail-empty")).toBeTruthy();
    fireEvent.click(screen.getByTestId("edr-files-glyph-0-1"));
    const d = await screen.findByTestId("edr-files-detail");
    expect(d.getAttribute("data-raw-id")).toBe("raw_shift");
    expect(d.textContent).toContain("/bin/sh -c zip");
    expect(screen.getByTestId("edr-files-detail-day-shift").textContent)
      .toMatch(/Observed 2026-09-23, delivered 2026-09-24/);
    expect(screen.getByTestId("edr-files-detail-open").getAttribute("href"))
      .toContain("at=2026-09-23T18%3A28%3A31.162868%2B00%3A00");
  });

  it("filters the graphic by path and says the counts still describe everything read", async () => {
    api.get.mockResolvedValue({ data: payload() });
    mount();
    await screen.findByTestId("edr-files-graphic");
    fireEvent.change(screen.getByTestId("edr-files-path-filter"),
                     { target: { value: "/var/tmp" } });
    await waitFor(() => expect(screen.queryByTestId("edr-files-lane-1")).toBeNull());
    expect(screen.getByTestId("edr-files-filtered-note").textContent)
      .toMatch(/counts above still describe everything that was read/);
    expect(screen.getByTestId("edr-files-result").getAttribute("data-total")).toBe("3");
    fireEvent.change(screen.getByTestId("edr-files-path-filter"),
                     { target: { value: "/nothing-matches" } });
    await waitFor(() => expect(screen.getByTestId("edr-files-filter-empty")).toBeTruthy());
    expect(screen.getByTestId("edr-files-filter-empty").textContent)
      .toMatch(/nothing was re-read/);
  });
});

describe("the lookup answers honestly", () => {
  it("reads the hash from the URL and scopes it to the acting customer", async () => {
    api.get.mockResolvedValue({ data: payload() });
    mount();
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(api.get.mock.calls[0][0]).toBe(`/edr/files/${HASH}/sightings`);
    expect((await screen.findByTestId("edr-files-customer")).textContent).toBe("default");
  });

  it("states a zero as a zero for THIS customer", async () => {
    api.get.mockResolvedValue({ data: payload({
      total_sightings: 0, endpoint_count: 0, endpoints: [], entry_points: [],
      day_shifted_sightings: 0, day_shifted_examples: [],
      first_observed: null, last_observed: null }) });
    mount();
    const none = await screen.findByTestId("edr-files-none");
    expect(none.textContent).toMatch(/honest zero/);
    expect(none.textContent).toMatch(/not a failed read/);
    expect(screen.queryByTestId("edr-files-graphic")).toBeNull();
    expect(screen.queryByTestId("edr-files-entry-point")).toBeNull();
  });

  it("refuses a malformed hash instead of calling it an empty result", async () => {
    api.get.mockResolvedValue({ data: { ok: false, reason: "INVALID_SHA256",
      key: "nope", note: "A SHA-256 is 64 hexadecimal characters." } });
    mount("?sha256=nope");
    expect((await screen.findByTestId("edr-files-rejected")).getAttribute("data-reason"))
      .toBe("INVALID_SHA256");
  });

  it("reports a failed read as a failure, not as an absence", async () => {
    api.get.mockRejectedValue({ response: { status: 403,
      data: { detail: { reason: "tenant is not registered" } } } });
    mount();
    const err = await screen.findByTestId("edr-files-error");
    expect(err.textContent).toMatch(/tenant is not registered/);
    expect(err.textContent).toMatch(/not an absence of sightings/);
    expect(screen.queryByTestId("edr-files-none")).toBeNull();
  });

  it("asks for a customer instead of reporting a red error", async () => {
    api.get.mockRejectedValue({ response: { status: 403, data: { detail: {
      code: "TENANT_REQUIRED",
      reason: "platform-scoped principal must name the customer" } } } });
    mount();
    const box = await screen.findByTestId("edr-files-no-customer");
    expect(box.getAttribute("data-code")).toBe("TENANT_REQUIRED");
    expect(box.textContent).toMatch(/Select a customer/);
    expect(screen.queryByTestId("edr-files-error")).toBeNull();
  });

  it("says when a busy digest returned only part of its history", async () => {
    api.get.mockResolvedValue({ data: payload({ truncated: true, scanned: 4000 }) });
    mount();
    expect((await screen.findByTestId("edr-files-truncated")).textContent)
      .toMatch(/more sightings than one read returns/);
  });
});
