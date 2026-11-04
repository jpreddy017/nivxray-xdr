// @vitest-environment jsdom
import React from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import api from "@/lib/api";
import TrajectoryPage from "../TrajectoryPage";

vi.mock("@/lib/api", () => ({ default: { get: vi.fn(), post: vi.fn() } }));
vi.mock("../Grid", () => ({ default: () => null }));
vi.mock("../Header", () => ({ default: ({ data }) => <div data-testid="host">{data?.computer?.hostname}</div> }));
vi.mock("../Navigator", () => ({ default: ({ onView }) => <button onClick={() => onView({ t0: Date.parse("2026-10-29T00:00:00Z"), t1: Date.parse("2026-10-30T00:00:00Z") })}>Other day</button> }));
vi.mock("../AttackStrip", () => ({ AttackPanel: () => null }));
vi.mock("../Activity", () => ({
  ActivityList: ({ items, onSelect, hidden }) => hidden ? null : <div>{items.map((it) => <button key={it.ev.event_iid} onClick={() => onSelect(it)}>{it.ev.name}</button>)}</div>,
  ActivityDetails: ({ onBack }) => <button onClick={onBack}>Back to activity</button>,
}));
vi.mock("../Artifacts", () => ({ NetworkSummary: () => null }));
vi.mock("../Filters", () => ({ FiltersPanel: () => null }));
vi.mock("../Menu", () => ({ ApprovalDialog: () => null, ContextMenu: () => null }));
vi.mock("../model", () => ({
  DEFAULT_ON: [], lineage: () => new Set(), matches: () => true, passes: () => true, presentKinds: () => new Set(),
  buildModel: (events) => ({ items: events.map((ev) => ({ ev, actorIid: ev.event_iid, targetIid: ev.event_iid })), rows: [], total: events.length, ncol: 0 }),
}));

let visibility;
const response = (names, cursor = null, host = "KUSHU") => ({ data: { v3: {
  events: names.map((name) => ({ event_iid: name, name })),
  computer: { hostname: host, platform: "windows" }, activity: { days: [] }, lane_axis: { lanes: [] },
  e3_preview: { older_cursor: cursor, data_label: "REAL PRODUCTION EVIDENCE", detections_all: [] },
} } });
const settle = async () => { await act(async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); }); };
const tick = async (ms = 10000) => { await act(async () => { vi.advanceTimersByTime(ms); }); await settle(); };
const mount = async (query = "") => { render(<MemoryRouter initialEntries={["/" + query]}><TrajectoryPage device="ep_fixture" /></MemoryRouter>); await settle(); };

beforeEach(() => {
  vi.useFakeTimers(); vi.setSystemTime(new Date("2026-11-01T10:00:00Z"));
  visibility = "visible";
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => visibility });
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  api.get.mockReset();
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); });

it("refreshes without clearing the displayed activity while the next read is pending", async () => {
  let finish;
  api.get.mockResolvedValueOnce(response(["first"])).mockImplementationOnce(() => new Promise((r) => { finish = r; }));
  await mount(); await tick();
  expect(screen.getByText("first")).toBeTruthy();
  expect(api.get).toHaveBeenCalledTimes(2);
  finish(response(["second", "third"])); await settle();
  expect(screen.queryByText("first")).toBeNull();
  expect(screen.getByText("second")).toBeTruthy();
});

it("moves the default live window forward", async () => {
  api.get.mockResolvedValue(response([])); await mount();
  const firstEnd = api.get.mock.calls[0][1].params.time_end;
  await tick();
  expect(Date.parse(api.get.mock.calls[1][1].params.time_end) - Date.parse(firstEnd)).toBe(10000);
});

it("keeps explicit historical bounds fixed while refreshing recovered history", async () => {
  api.get.mockResolvedValue(response([])); await mount("?t0=1793404800000&t1=1793491200000");
  const bounds = api.get.mock.calls[0][1].params;
  await tick();
  expect(api.get.mock.calls[1][1].params.time_start).toBe(bounds.time_start);
  expect(api.get.mock.calls[1][1].params.time_end).toBe(bounds.time_end);
});

it("supports pause and resume", async () => {
  api.get.mockResolvedValue(response([])); await mount();
  fireEvent.click(screen.getByTestId("v3-auto-refresh")); await tick(30000);
  expect(api.get).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByTestId("v3-auto-refresh")); await tick();
  expect(api.get).toHaveBeenCalledTimes(2);
});

it("keeps event inspection stable and resumes after closing details", async () => {
  api.get.mockResolvedValue(response(["inspect"])); await mount();
  fireEvent.click(screen.getByText("inspect")); await settle(); await tick(30000);
  expect(screen.getByText("Back to activity")).toBeTruthy();
  expect(api.get).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByText("Back to activity")); await tick();
  expect(api.get).toHaveBeenCalledTimes(2);
});

it("does not poll hidden tabs and refreshes on return", async () => {
  api.get.mockResolvedValue(response([])); await mount();
  visibility = "hidden"; await tick(30000);
  expect(api.get).toHaveBeenCalledTimes(1);
  visibility = "visible"; fireEvent(document, new Event("visibilitychange")); await settle();
  expect(api.get).toHaveBeenCalledTimes(2);
});

it("does not overlap a slow read with more polling requests", async () => {
  api.get.mockResolvedValueOnce(response([])).mockImplementationOnce(() => new Promise(() => {}));
  await mount(); await tick(); await tick(60000);
  expect(api.get).toHaveBeenCalledTimes(2);
});

it("retains older pages and pauses refresh until Latest in range is chosen", async () => {
  api.get.mockResolvedValueOnce(response(["head"], "next")).mockResolvedValueOnce(response(["older"])).mockResolvedValue(response(["new head"]));
  await mount(); fireEvent.click(screen.getByTestId("v3-load-older")); await settle(); await tick(30000);
  expect(screen.getByText("older")).toBeTruthy();
  expect(api.get).toHaveBeenCalledTimes(2);
  fireEvent.click(screen.getByTestId("v3-refresh-latest")); await settle();
  expect(screen.getByText("new head")).toBeTruthy();
  expect(screen.queryByText("older")).toBeNull();
});

it("ignores a stale response after changing the time window", async () => {
  let late;
  api.get.mockResolvedValueOnce(response(["first"])).mockImplementationOnce(() => new Promise((r) => { late = r; })).mockResolvedValue(response(["right day"]));
  await mount(); await tick();
  fireEvent.click(screen.getByText("Other day")); await settle();
  late(response(["wrong day"])); await settle();
  expect(screen.getByText("right day")).toBeTruthy();
  expect(screen.queryByText("wrong day")).toBeNull();
});

it("retains activity and exposes a background read failure", async () => {
  api.get.mockResolvedValueOnce(response(["retained"])).mockRejectedValueOnce(new Error("network failure"));
  await mount(); await tick();
  expect(screen.getByText("retained")).toBeTruthy();
  expect(screen.getByTestId("v3-read-error")).toBeTruthy();
  await tick(30000); expect(api.get).toHaveBeenCalledTimes(2);
});

it("does not reopen a closed inspection when its event leaves the refreshed head", async () => {
  api.get.mockResolvedValueOnce(response(["inspect"]))
    .mockResolvedValue(response(["new head"]));
  await mount();
  fireEvent.click(screen.getByText("inspect")); await settle();
  fireEvent.click(screen.getByText("Back to activity")); await settle();
  await tick();
  expect(screen.getByText("new head")).toBeTruthy();
  expect(api.get).toHaveBeenCalledTimes(2);
  expect(api.get.mock.calls.every(([url]) => !url.endsWith("/focus"))).toBe(true);
});



it("resolves file observation links within their supplied window and opens the exact event", async () => {
  const ms=Date.parse("2026-10-30T03:16:32.321Z");
  api.get.mockImplementation(async (url, options) => {
    if (url.endsWith("/focus")) return {data:{state:"FOCUS_RESOLVED",focus:{event_iid:"v3_exact",observed_at:new Date(ms).toISOString()}}};
    const p=options.params;
    return response(Date.parse(p.time_end)-Date.parse(p.time_start) === 2001 ? ["v3_exact"] : []);
  });
  await mount(`?source=file_search&observation_id=obs_exact&event=legacy_row&t0=${ms-60000}&t1=${ms+60000}`);
  await settle();
  const lookup=api.get.mock.calls.find(([url])=>url.endsWith("/focus"));
  expect(lookup[1].params.observation_id).toBe("obs_exact");
  expect(Date.parse(lookup[1].params.time_start)).toBe(ms-60000);
  expect(Date.parse(lookup[1].params.time_end)).toBe(ms+60000);
  expect(screen.getByText("Back to activity")).toBeTruthy();
});
