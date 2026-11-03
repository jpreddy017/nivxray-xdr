// @vitest-environment jsdom
//
// Live Query · the answer must carry the question and the target, and an
// answer of NO MATCHES must read as an answer rather than a failure.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({ default: { get: vi.fn(), post: vi.fn() } }));
vi.mock("@/nivxforge/NivXForgeConsole", () => ({
  default: ({ children }) => <div>{children}</div>,
}));

import api from "@/lib/api";
import EdrLiveQueryPage from "@/nivxforge/pages/EdrLiveQueryPage";

const DEVICE = "ep_2d57cbe6f80152062109";
const QID = "cmd_185ec0f120f44456826e";
const QUESTION = "Which running processes match this exact name on this computer now?";

const q = (over = {}) => ({
  query_id: QID, tenant_id: "default", endpoint_id: DEVICE,
  requested_by: "admin@nivxray.com",
  requested_at: "2026-11-03T15:25:43+00:00",
  question: QUESTION, process_name: "mongod", name_compared: "mongod",
  name_truncated: false, match_basis: "exact match on /proc/<pid>/comm ('mongod')",
  collected_at: "2026-11-03T15:25:57.332018+00:00",
  match_count: 1, processes_examined: 24, sensor_version: "0.2.0",
  status: "COMPLETED_WITH_MATCHES",
  status_meaning: "the endpoint ran the query and found matches",
  command_state: "EXECUTED",
  not_observed: ["command line", "user"],
  rows: [{ pid: 291, name: "mongod", path: "/usr/bin/mongod" }],
  ...over,
});

const hist = (rows) => ({ ok: true, tenant_id: "default", question: QUESTION,
  queries: rows, count: rows.length, timeout_seconds: 180,
  collection_basis: "Every answer comes from a fresh read on the endpoint when the query was claimed." });

const route = (one, list) => (url) => {
  if (/\/queries\/[^/]+$/.test(url)) return Promise.resolve({ data: one });
  return Promise.resolve({ data: list });
};

const mount = (search = `?device=${DEVICE}&query=${QID}`) => render(
  <MemoryRouter initialEntries={[`/edr/live-query${search}`]}>
    <EdrLiveQueryPage />
  </MemoryRouter>);

beforeEach(() => { api.get.mockReset(); api.post.mockReset(); });
afterEach(() => cleanup());

describe("Live Query", () => {
  it("shows the question, the target and the matches together", async () => {
    api.get.mockImplementation(route(q(), hist([q()])));
    mount();
    const res = await screen.findByTestId("lq-result");
    expect(res.getAttribute("data-query-id")).toBe(QID);
    expect(screen.getByTestId("lq-asked").textContent).toContain(QUESTION);
    expect(screen.getByTestId("lq-asked").textContent).toContain("mongod");
    expect(screen.getByTestId("lq-asked").textContent).toContain(DEVICE);
    expect(res.textContent).toContain("2026-11-03 15:25:57Z");   // collected
    expect(screen.getByTestId("lq-row-0").textContent).toContain("/usr/bin/mongod");
    expect(screen.getByTestId("lq-row-0").textContent).toContain("291");
    expect(screen.getByTestId("lq-not-observed").textContent).toMatch(/command line/);
  });

  it("calls zero matches an answer, and still shows what was read", async () => {
    const z = q({ status: "COMPLETED_NO_MATCHES", match_count: 0, rows: [],
      process_name: "definitelynotaprocess", name_compared: "definitelynotap",
      name_truncated: true,
      match_basis: "Linux truncates /proc/<pid>/comm to 15 characters, so this matches on 'definitelynotap'",
      status_meaning: "the endpoint ran the query and NOTHING matched. That is an answer — the process is not running under this name right now — not a failure and not a timeout" });
    api.get.mockImplementation(route(z, hist([z])));
    mount();
    const empty = await screen.findByTestId("lq-rows-empty");
    expect(empty.textContent).toMatch(/is running under definitelynotaprocess right now/);
    expect(empty.textContent).toMatch(/not a failure/);
    expect(empty.textContent).toMatch(/stored telemetry was not searched/);
    // a truncated comparison is never presented as an exact one
    expect(screen.getByTestId("lq-truncated").textContent).toContain("definitelynotap");
    expect(screen.getByTestId("lq-match-basis").textContent).toMatch(/truncates/);
    expect(screen.getByTestId("lq-result").textContent).toContain("24");  // examined
  });

  it("says an older sensor cannot answer, instead of showing nothing running", async () => {
    const u = q({ status: "CAPABILITY_UNAVAILABLE", match_count: null, rows: [],
      collected_at: null,
      status_meaning: "this sensor build cannot answer a live query. Nothing was asked of the endpoint, and stored telemetry was NOT used in its place" });
    api.get.mockImplementation(route(u, hist([u])));
    mount();
    expect((await screen.findByTestId("lq-meaning")).textContent)
      .toMatch(/stored telemetry was NOT used in its place/);
    expect(screen.queryByTestId("lq-rows")).toBeNull();
  });

  it("asks the preselected computer and opens that query", async () => {
    api.get.mockImplementation(route(q(), hist([q()])));
    api.post.mockResolvedValue({ data: { query_id: "cmd_new", status: "QUEUED" } });
    mount(`?device=${DEVICE}`);
    expect(screen.getByTestId("lq-target").textContent).toBe(DEVICE);
    fireEvent.change(screen.getByTestId("lq-name"), { target: { value: "mongod" } });
    fireEvent.click(screen.getByTestId("lq-run"));
    await waitFor(() => expect(api.post).toHaveBeenCalledWith(
      "/edr/live-query/queries",
      { endpoint_id: DEVICE, process_name: "mongod" }));
    await waitFor(() => expect(api.get).toHaveBeenCalledWith(
      expect.stringContaining("/edr/live-query/queries/cmd_new")));
  });

  it("lists history for the customer and opens a query from a row", async () => {
    const other = { ...q(), query_id: "cmd_other", status: "TIMED_OUT",
                    match_count: null, process_name: "sleep" };
    api.get.mockImplementation(route(q(), hist([q(), other])));
    mount();
    await screen.findByTestId("edr-live-query-history");
    const row = screen.getByTestId("edr-live-query-history-row-1");
    expect(row.getAttribute("data-query-id")).toBe("cmd_other");
    expect(row.textContent).toContain("sleep");
    fireEvent.click(row);
    await waitFor(() => expect(api.get).toHaveBeenCalledWith(
      expect.stringContaining("/edr/live-query/queries/cmd_other")));
  });

  it("asks for a computer before asking a question", async () => {
    api.get.mockImplementation(route(null, hist([])));
    mount("");
    expect((await screen.findByTestId("lq-no-device")).textContent)
      .toMatch(/Actions → Live Query/);
    expect(screen.queryByTestId("lq-run")).toBeNull();
    expect((await screen.findByTestId("edr-live-query-empty")).textContent)
      .toMatch(/read succeeded and returned nothing/);
  });

  it("surfaces a refusal in the server's own words", async () => {
    api.get.mockImplementation(route(null, hist([])));
    api.post.mockRejectedValue({ response: { data: { detail: {
      error: "EMPTY_PROCESS_NAME",
      reason: "a live query needs a process name to match; nothing was asked of the endpoint" } } } });
    mount(`?device=${DEVICE}`);
    fireEvent.change(screen.getByTestId("lq-name"), { target: { value: "x" } });
    fireEvent.click(screen.getByTestId("lq-run"));
    expect((await screen.findByTestId("edr-live-query-error")).textContent)
      .toMatch(/nothing was asked of the endpoint/);
  });
});
