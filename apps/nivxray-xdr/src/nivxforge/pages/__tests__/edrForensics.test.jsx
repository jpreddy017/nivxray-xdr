// @vitest-environment jsdom
//
// Forensic Snapshots · the two entry points must open ONE job, and every
// status must read as what it is. A capture that ran and found nothing is not
// a failure; an old sensor is not an empty machine; an unanswered job says
// nothing about the endpoint.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  default: { get: vi.fn(), post: vi.fn() },
}));
vi.mock("@/nivxforge/NivXForgeConsole", () => ({
  default: ({ children }) => <div>{children}</div>,
}));

import api from "@/lib/api";
import EdrForensicsPage from "@/nivxforge/pages/EdrForensicsPage";

const DEVICE = "ep_2d57cbe6f80152062109";
const JOB = "cmd_f732ecd7789d4a909570";

const job = (over = {}) => ({
  job_id: JOB, tenant_id: "default", endpoint_id: DEVICE,
  requested_by: "admin@nivxray.com",
  requested_at: "2026-11-03T15:02:38.807011+00:00",
  capture_started_at: "2026-11-03T15:02:52.623079+00:00",
  capture_finished_at: "2026-11-03T15:02:52.623852+00:00",
  row_count: 2, status: "COMPLETED_WITH_ROWS",
  status_meaning: "the sensor captured and returned process rows",
  command_state: "EXECUTED", sensor_version: "0.2.0",
  not_observed: ["command line", "user"],
  sections: [
    { section: "Running processes", state: "COLLECTED", rows: 2,
      note: "pid, name and executable path from one /proc walk at capture time" },
    { section: "Logged-in users", state: "NOT_COLLECTED", rows: null,
      note: "not collected by this sensor" },
    { section: "Open network ports", state: "NOT_COLLECTED", rows: null,
      note: "not collected on demand; connections are not collected at all" },
    { section: "Memory image", state: "NOT_COLLECTED", rows: null,
      note: "never collected; a snapshot is metadata, not a memory dump" },
  ],
  retention_note: "No retention job runs in this preview: every snapshot and its rows are kept until the database is cleared. Cisco's console keeps a snapshot for two days.",
  rows: [{ pid: 1, name: "entrypoint.sh", path: "/usr/bin/bash" },
         { pid: 10, name: "uvicorn", path: null, path_unavailable: "PermissionError" }],
  ...over,
});

const history = (jobs) => ({
  ok: true, tenant_id: "default", jobs, count: jobs.length,
  timeout_seconds: 180,
  collection_basis: "Every row comes from a fresh read on the endpoint at capture time.",
});

const mount = (search = `?device=${DEVICE}&job=${JOB}`) => render(
  <MemoryRouter initialEntries={[`/edr/forensics${search}`]}>
    <EdrForensicsPage />
  </MemoryRouter>);

const route = (j, list) => (url) => {
  if (/\/snapshots\/[^/]+$/.test(url)) return Promise.resolve({ data: j });
  return Promise.resolve({ data: list });
};

beforeEach(() => { api.get.mockReset(); api.post.mockReset(); });
afterEach(() => cleanup());

describe("Forensic Snapshots history and result", () => {
  it("shows the capture window, rows, and what the capture did not collect", async () => {
    api.get.mockImplementation(route(job(), history([job()])));
    mount();
    const card = await screen.findByTestId("snapshot-job");
    expect(card.getAttribute("data-job-id")).toBe(JOB);
    expect(screen.getByTestId("snapshot-job-id").textContent).toBe(JOB);
    expect(screen.getByTestId("snapshot-status").getAttribute("data-status"))
      .toBe("COMPLETED_WITH_ROWS");
    expect(card.textContent).toContain("2026-11-03 15:02:52Z");
    expect(screen.getByTestId("snapshot-row-0").textContent).toContain("/usr/bin/bash");
    // a row whose path could not be read says so rather than showing blank
    expect(screen.getByTestId("snapshot-row-1").textContent).toMatch(/not readable · PermissionError/);
    expect(screen.getByTestId("snapshot-not-observed").textContent)
      .toMatch(/command line · user/);

    // Cisco's snapshot covers more than this one. The sections say which parts
    // exist here and which do not, so the two consoles can be compared.
    expect(screen.getByTestId("snapshot-section-running-processes")
      .getAttribute("data-state")).toBe("COLLECTED");
    expect(screen.getByTestId("snapshot-section-running-processes").textContent)
      .toContain("2");
    for (const s of ["logged-in-users", "open-network-ports", "memory-image"]) {
      expect(screen.getByTestId(`snapshot-section-${s}`)
        .getAttribute("data-state")).toBe("NOT_COLLECTED");
    }
    expect(screen.getByTestId("snapshot-section-memory-image").textContent)
      .toMatch(/not a memory dump/);
    expect(screen.getByTestId("snapshot-retention").textContent)
      .toMatch(/kept until the database is cleared/);
  });

  it("calls a zero-row capture an empty result, not a failure", async () => {
    const z = job({ status: "COMPLETED_ZERO_ROWS", row_count: 0, rows: [],
      status_meaning: "the capture ran and returned NO rows — this is an empty result, not a failure, and not a timeout" });
    api.get.mockImplementation(route(z, history([z])));
    mount();
    const empty = await screen.findByTestId("snapshot-rows-empty");
    expect(empty.textContent).toMatch(/empty result, not a failure/);
    expect(empty.textContent).toMatch(/stored telemetry was not used/);
    expect(screen.getByTestId("snapshot-status").getAttribute("data-status"))
      .toBe("COMPLETED_ZERO_ROWS");
  });

  it("says an older sensor cannot collect, instead of showing an empty machine", async () => {
    const u = job({ status: "CAPABILITY_UNAVAILABLE", row_count: null, rows: [],
      capture_started_at: null, capture_finished_at: null,
      status_meaning: "this sensor build cannot collect on demand. Nothing was captured, and history was NOT used to answer in its place" });
    api.get.mockImplementation(route(u, history([u])));
    mount();
    const card = await screen.findByTestId("snapshot-job");
    expect(card.getAttribute("data-status")).toBe("CAPABILITY_UNAVAILABLE");
    expect(screen.getByTestId("snapshot-job-meaning").textContent)
      .toMatch(/history was NOT used to answer in its place/);
    expect(screen.queryByTestId("snapshot-rows")).toBeNull();
  });

  it("keeps a queued job from reading as a statement about the endpoint", async () => {
    const q = job({ status: "QUEUED", row_count: null, rows: [],
      capture_started_at: null, capture_finished_at: null,
      command_state: "REQUESTED",
      status_meaning: "recorded and waiting for the sensor to claim it; nothing has run" });
    api.get.mockImplementation(route(q, history([q])));
    mount();
    expect((await screen.findByTestId("snapshot-job-meaning")).textContent)
      .toMatch(/nothing has run/);
  });

  it("lists history for the customer and opens a job from a row", async () => {
    const other = { ...job(), job_id: "cmd_other", endpoint_id: "ep_second",
                    status: "TIMED_OUT", row_count: null };
    api.get.mockImplementation(route(job(), history([job(), other])));
    mount(`?device=${DEVICE}&job=${JOB}`);
    await screen.findByTestId("edr-forensics-history");
    const row = screen.getByTestId("edr-forensics-history-row-1");
    expect(row.getAttribute("data-job-id")).toBe("cmd_other");
    expect(row.textContent).toContain("ep_second");
    fireEvent.click(row);
    await waitFor(() => expect(api.get).toHaveBeenCalledWith(
      expect.stringContaining("/edr/forensics/snapshots/cmd_other")));
  });

  it("says an empty history is an empty read, not a missing feature", async () => {
    api.get.mockImplementation(route(null, history([])));
    mount("");
    const empty = await screen.findByTestId("edr-forensics-empty");
    expect(empty.textContent).toMatch(/read succeeded and returned nothing/);
  });

  it("requests a snapshot for the preselected computer and opens that job", async () => {
    api.get.mockImplementation(route(job(), history([job()])));
    api.post.mockResolvedValue({ data: { job_id: "cmd_new", status: "QUEUED" } });
    mount(`?device=${DEVICE}`);
    await screen.findByTestId("snapshot-request-btn");
    expect(screen.getByTestId("snapshot-target").textContent).toBe(DEVICE);
    fireEvent.click(screen.getByTestId("snapshot-request-btn"));
    await waitFor(() => expect(api.post).toHaveBeenCalledWith(
      "/edr/forensics/snapshots",
      expect.objectContaining({ endpoint_id: DEVICE })));
    // the new job is opened, so request and result are one surface
    await waitFor(() => expect(api.get).toHaveBeenCalledWith(
      expect.stringContaining("/edr/forensics/snapshots/cmd_new")));
  });

  it("surfaces a refusal in the server's own words", async () => {
    api.get.mockImplementation(route(null, history([])));
    api.post.mockRejectedValue({ response: { data: { detail: {
      error: "RESPONSE_EXECUTE_NOT_AUTHORIZED",
      reason: "analyst@x does not hold response.execute" } } } });
    mount(`?device=${DEVICE}`);
    fireEvent.click(await screen.findByTestId("snapshot-request-btn"));
    const err = await screen.findByTestId("edr-forensics-error");
    expect(err.textContent).toMatch(/does not hold response.execute/);
  });
});
