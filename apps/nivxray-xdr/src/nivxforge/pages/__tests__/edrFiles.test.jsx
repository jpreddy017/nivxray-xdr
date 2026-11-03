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
  entry_point_basis: "the earliest observation of this digest in this customer. An endpoint seeing the same digest is not evidence that the file moved there from another endpoint; transfer is not observed.",
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
      .toMatch(/not evidence that the file moved there/);
  });

  it("draws one lane per computer and one glyph per sighting", async () => {
    api.get.mockResolvedValue({ data: payload() });
    mount();
    await screen.findByTestId("edr-files-graphic");
    expect(screen.getByTestId("edr-files-lane-0").getAttribute("data-endpoint")).toBe(DEVICE);
    expect(screen.getByTestId("edr-files-lane-1").getAttribute("data-endpoint")).toBe(OTHER);
    expect(screen.getByTestId("edr-files-glyph-0-0")).toBeTruthy();
    expect(screen.getByTestId("edr-files-glyph-0-1").getAttribute("data-day-shift")).toBe("1");
    // An execution and a creation are different marks, because they are
    // different facts about the file.
    expect(screen.getByTestId("edr-files-glyph-0-0").getAttribute("data-activity")).toBe("executed");
    expect(screen.getByTestId("edr-files-glyph-1-0").getAttribute("data-activity")).toBe("executed");
    expect(screen.getByTestId("edr-files-glyph-1-0")).toBeTruthy();
    // Only the first computer saw it first.
    expect(screen.getByTestId("edr-files-lane-0-entry")).toBeTruthy();
    expect(screen.queryByTestId("edr-files-lane-1-entry")).toBeNull();
  });

  it("names the event types it can never show instead of implying none occurred", async () => {
    api.get.mockResolvedValue({ data: payload() });
    mount();
    const legend = await screen.findByTestId("edr-files-legend");
    expect(legend.textContent).toMatch(/moved · scanned · quarantined · written · deleted/);
    expect(legend.textContent).toMatch(/file created — in a directory the sensor watches/);
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

  it("filters on the SERVER across every sighting, not on the rows it holds", async () => {
    // The real failure this replaces: /var/tmp creations are older than the
    // newest 300 executions, so filtering the returned rows found nothing and
    // read as "never created there".
    api.get.mockResolvedValue({ data: payload() });
    mount();
    await screen.findByTestId("edr-files-graphic");
    api.get.mockClear();
    api.get.mockResolvedValue({ data: payload({
      total_sightings: 24, total_sightings_unfiltered: 809,
      filter: { path_contains: "/var/tmp", matched_sightings: 24,
                of_sightings: 809, applied: "across every authorized sighting" },
    }) });
    fireEvent.change(screen.getByTestId("edr-files-path-filter"),
                     { target: { value: "/var/tmp" } });
    fireEvent.click(screen.getByTestId("edr-files-path-filter-apply"));

    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(api.get.mock.calls[0][1].params.path_contains).toBe("/var/tmp");

    const note = await screen.findByTestId("edr-files-filtered-note");
    expect(note.getAttribute("data-matched")).toBe("24");
    expect(note.getAttribute("data-of")).toBe("809");
    expect(note.textContent).toMatch(/not only the newest ones/);
    expect(screen.getByTestId("edr-files-result").getAttribute("data-total")).toBe("24");
  });

  it("calls a filtered zero a real zero, because the server matched everything", async () => {
    api.get.mockResolvedValue({ data: payload({
      total_sightings: 0, total_sightings_unfiltered: 809, endpoints: [],
      filter: { path_contains: "/nothing-matches", matched_sightings: 0,
                of_sightings: 809, applied: "across every authorized sighting" },
    }) });
    render(
      <MemoryRouter initialEntries={[`/edr/files?sha256=${HASH}&path=/nothing-matches`]}>
        <EdrFilesPage />
      </MemoryRouter>);
    const empty = await screen.findByTestId("edr-files-none");
    expect(empty.textContent).toMatch(/honest zero/);
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

describe("the graphic does not redraw history it did not read", () => {
  it("spans the digest's known range, not just the returned slice", async () => {
    // The endpoint has 500 sightings but only the newest two came back.
    api.get.mockResolvedValue({ data: payload({
      total_sightings: 500, endpoint_count: 1, truncated: true, scanned: 4000,
      endpoints: [{ endpoint_id: DEVICE, hostname: "agent-env-630704a1",
        identity: "registered", sighting_count: 500,
        paths: ["/usr/bin/dash"],
        first_observed: "2026-09-06T08:17:03.000000+00:00",
        last_observed: LATER.observed_at,
        sightings: [LATER, SHIFTED] }] }) });
    mount();
    await screen.findByTestId("edr-files-graphic");
    // Visibility starts 2026-09-06, so the axis must start there too.
    expect(screen.getByTestId("edr-files-graphic-t0").textContent).toContain("2026-09-06");
    expect(screen.getByTestId("edr-files-graphic-partial").textContent)
      .toMatch(/newest 2 of 500 sightings/);
  });
});

describe("a lane dense with sightings stays clickable", () => {
  // 809 executions of the same image land on one lane. Drawn one mark per
  // sighting they overlap and intercept each other's clicks, so marks closer
  // than one mark wide are grouped — and the group has to say so.
  const burst = Array.from({ length: 40 }, (_, k) => ({
    ...LATER, raw_id: `raw_burst_${k}`,
    observed_at: `2026-10-18T14:${String(35 - k).padStart(2, "0")}:00.000000+00:00`,
  }));

  it("groups marks that would overlap and names how many each covers", async () => {
    api.get.mockResolvedValue({ data: payload({
      total_sightings: 41, endpoint_count: 1,
      endpoints: [{ endpoint_id: DEVICE, hostname: "agent-env-630704a1",
                    identity: "registered", sighting_count: 41,
                    paths: ["/var/tmp/copy/dash"],
                    first_observed: SHIFTED.observed_at,
                    last_observed: LATER.observed_at,
                    sightings: [...burst, SHIFTED] }],
    }) });
    mount();
    await screen.findByTestId("edr-files-result");

    const marks = screen.getAllByTestId(/^edr-files-glyph-0-/);
    expect(marks.length).toBeLessThan(41);          // overlapping marks collapsed
    expect(marks.length).toBeGreaterThan(1);        // but the span is still read

    const grouped = marks.find((m) => Number(m.getAttribute("data-covers")) > 1);
    expect(grouped).toBeTruthy();
    fireEvent.click(grouped);
    const covers = await screen.findByTestId("edr-files-detail-covers");
    expect(covers.textContent).toMatch(/covers \d+ sightings between/);
    expect(covers.textContent).toMatch(/listed in Event history/);

    // nothing was dropped: every sighting read is still a history row
    expect(screen.getAllByTestId(/^edr-files-event-row-\d+$/).length).toBe(41);
  });
});

describe("a ringed mark the graphic cannot show is named, not implied", () => {
  it("says how many day-shifted sightings fall outside the marks drawn", async () => {
    // Visibility counts the day-shifted sighting; the read returned only newer
    // marks, so no ringed mark is drawn. Saying nothing would leave the legend
    // promising a mark that is not there.
    api.get.mockResolvedValue({ data: payload({
      total_sightings: 850, day_shifted_sightings: 1,
      day_shifted_examples: [SHIFTED],
      endpoint_count: 1,
      endpoints: [{ endpoint_id: DEVICE, hostname: "agent-env-630704a1",
                    identity: "registered", sighting_count: 850,
                    paths: ["/usr/bin/dash"],
                    first_observed: SHIFTED.observed_at,
                    last_observed: LATER.observed_at,
                    sightings: [LATER] }],
    }) });
    mount();
    const note = await screen.findByTestId("edr-files-graphic-shift-offaxis");
    expect(note.getAttribute("data-count")).toBe("1");
    expect(note.textContent).toMatch(/older than the marks drawn here/);
    expect(screen.queryAllByTestId(/^edr-files-glyph-/).filter(
      (m) => m.getAttribute("data-day-shift") === "1")).toHaveLength(0);
  });

  it("stays quiet when every day-shifted sighting is actually drawn", async () => {
    api.get.mockResolvedValue({ data: payload() });   // SHIFTED is in the lane
    mount();
    await screen.findByTestId("edr-files-result");
    expect(screen.queryByTestId("edr-files-graphic-shift-offaxis")).toBeNull();
  });
});

describe("an individual sighting inside a group stays reachable", () => {
  // A grouped marker opens the NEWEST member. The older members have to be
  // selectable too, or the evidence the analyst wants is behind a mark that
  // keeps answering with a different event.
  it("follows the exact evidence id selected from Event history", async () => {
    api.get.mockResolvedValue({ data: payload() });
    mount();
    const rows = await screen.findAllByTestId(/^edr-files-event-row-\d+$/);
    expect(rows.length).toBeGreaterThan(1);

    // the OLDEST row — the one a grouped marker would not open
    fireEvent.click(rows[rows.length - 1]);
    const d = await screen.findByTestId("edr-files-detail");
    expect(d.getAttribute("data-raw-id")).toBe("raw_shift");
    // it is this sighting's own evidence, not the group's lead
    expect(screen.queryByTestId("edr-files-detail-covers")).toBeNull();
    expect(d.textContent).toContain("raw_shift");
    // and the pivot carries THIS sighting's endpoint and observed time
    const href = screen.getByTestId("edr-files-detail-open").getAttribute("href");
    expect(href).toContain(`device=${DEVICE}`);
    expect(href).toContain("at=2026-09-23T18%3A28%3A31.162868%2B00%3A00");
  });

  it("labels polling records as observations, not as launches", async () => {
    api.get.mockResolvedValue({ data: payload({
      process_observation_basis: "PROCESS_OBSERVED is one row per process identity that /proc polling actually saw, so this is a count of observations, not of launches.",
      activity_breakdown_unfiltered: { PROCESS_OBSERVED: 797, CREATE: 12 },
    }) });
    mount();
    const rows = await screen.findAllByTestId(/^edr-files-event-row-\d+$/);
    expect(rows[0].textContent).toContain("Process observed");
    fireEvent.click(screen.getByTestId("edr-files-details-toggle"));
    expect(screen.getByTestId("edr-files-attribute-facts").textContent)
      .toMatch(/Process observed ×797 · File created ×12/);
    expect(screen.getByTestId("edr-files-observation-basis").textContent)
      .toMatch(/count of observations, not of launches/);
  });

  it("names which field supplied the path, so the digest's subject is clear", async () => {
    api.get.mockResolvedValue({ data: payload() });
    mount();
    const rows = await screen.findAllByTestId(/^edr-files-event-row-\d+$/);
    fireEvent.click(rows[0]);
    const d = await screen.findByTestId("edr-files-detail");
    expect(d.textContent).toMatch(/Path source/);
  });
});
