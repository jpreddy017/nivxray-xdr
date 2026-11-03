// @vitest-environment jsdom
//
// File Trajectory: a SHA-256 lookup inside ONE customer, and a sighting that
// opens the device canvas at the time the ENDPOINT observed it — not at the
// time the record was ingested, which can be the following UTC day.
import { cleanup, render, screen, waitFor } from "@testing-library/react";
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
vi.mock("@/lib/actingCustomer", () => ({
  readActingCustomer: () => ({ customer: "default" }),
}));

const HASH = "15fc4c72f49c86639a383121eec6fbdbcd32ec9d03db915cb3096928295e1a17";
const DEVICE = "ep_2d57cbe6f80152062109";

const SHIFTED = {
  raw_id: "raw_shift", endpoint_id: DEVICE, path: "/usr/bin/dash",
  activity: "PROCESS_OBSERVED",
  observed_at: "2026-09-23T18:28:31.162868+00:00",
  ingested_at: "2026-09-24T01:47:41.235148+00:00",
  observed_day_utc: "2026-09-23", ingest_day_utc: "2026-09-24",
  ingest_day_differs: true, pid: 4242, user: "root",
  command_line: "/bin/sh -c zip -r /tmp/data_db_backup.zip /data/db",
};

const payload = (over = {}) => ({
  ok: true, sha256: HASH, tenant: "default", total_sightings: 2,
  endpoint_count: 1, observed_paths: ["/usr/bin/dash"],
  first_observed: SHIFTED.observed_at,
  last_observed: "2026-10-18T14:35:56.000000+00:00",
  day_shifted_sightings: 1, day_shifted_examples: [SHIFTED],
  scanned: 2, truncated: false,
  endpoints: [{
    endpoint_id: DEVICE, hostname: "agent-env-630704a1", identity: "registered",
    sighting_count: 2, paths: ["/usr/bin/dash"],
    first_observed: SHIFTED.observed_at, last_observed: "2026-10-18T14:35:56.000000+00:00",
    sightings: [SHIFTED],
  }],
  ...over,
});

const mount = (search = `?sha256=${HASH}`) => render(
  <MemoryRouter initialEntries={[`/edr/files${search}`]}><EdrFilesPage /></MemoryRouter>);

afterEach(cleanup);

describe("a sighting opens the device canvas at the observed time", () => {
  it("builds the link from the observation time, not the ingest time", () => {
    const href = sightingHref(HASH, SHIFTED, "default");
    const u = new URL(href, "https://x.test");
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

  it("renders the sighting as a new-tab link, keeping this page open", async () => {
    api.get.mockResolvedValue({ data: payload() });
    mount();
    const a = await screen.findByTestId("edr-files-endpoint-0-row-0-open");
    expect(a.tagName).toBe("A");
    expect(a.getAttribute("target")).toBe("_blank");
    expect(a.getAttribute("rel")).toBe("noopener noreferrer");
    expect(a.getAttribute("href")).toContain(`at=${encodeURIComponent(SHIFTED.observed_at)}`);
    expect(a.textContent).toMatch(/opens in a new tab/);
  });

  it("calls out the sightings whose delivery crossed midnight", async () => {
    api.get.mockResolvedValue({ data: payload() });
    mount();
    const sec = await screen.findByTestId("edr-files-day-shift");
    expect(sec.textContent).toMatch(/different UTC day/);
    const row = screen.getByTestId("edr-files-shift-row-0");
    expect(row.getAttribute("data-day-shift")).toBe("1");
    expect(screen.getByTestId("edr-files-shift-row-0-open").getAttribute("href"))
      .toContain("at=2026-09-23T18%3A28%3A31.162868%2B00%3A00");
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
      total_sightings: 0, endpoint_count: 0, endpoints: [],
      day_shifted_sightings: 0, day_shifted_examples: [],
      first_observed: null, last_observed: null }) });
    mount();
    const none = await screen.findByTestId("edr-files-none");
    expect(none.textContent).toMatch(/honest zero/);
    expect(none.textContent).toMatch(/not a failed read/);
    expect(screen.queryByTestId("edr-files-endpoint-0")).toBeNull();
  });

  it("refuses a malformed hash instead of calling it an empty result", async () => {
    api.get.mockResolvedValue({ data: { ok: false, reason: "INVALID_SHA256",
      key: "nope", note: "A SHA-256 is 64 hexadecimal characters." } });
    mount("?sha256=nope");
    const box = await screen.findByTestId("edr-files-rejected");
    expect(box.getAttribute("data-reason")).toBe("INVALID_SHA256");
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

  it("says when a busy digest returned only part of its history", async () => {
    api.get.mockResolvedValue({ data: payload({ truncated: true, scanned: 4000 }) });
    mount();
    expect((await screen.findByTestId("edr-files-truncated")).textContent)
      .toMatch(/more sightings than one read returns/);
  });
});

describe("no customer is a prompt, not a failure", () => {
  it("asks for a customer instead of reporting a red error", async () => {
    api.get.mockRejectedValue({ response: { status: 403, data: { detail: {
      code: "TENANT_REQUIRED",
      reason: "platform-scoped principal must name the customer it is operating in" } } } });
    mount();
    const box = await screen.findByTestId("edr-files-no-customer");
    expect(box.getAttribute("data-code")).toBe("TENANT_REQUIRED");
    expect(box.textContent).toMatch(/Select a customer/);
    expect(screen.queryByTestId("edr-files-error")).toBeNull();
    expect(screen.queryByTestId("edr-files-none")).toBeNull();
  });
});
