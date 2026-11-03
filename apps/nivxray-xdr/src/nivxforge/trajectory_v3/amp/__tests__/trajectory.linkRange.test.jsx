// @vitest-environment jsdom
//
// A deep link from an XDR incident states the range the incident is ABOUT.
// Opening on "the last 24 hours" instead shows a different period than the
// link promised, which is how an analyst ends up reading the wrong evidence.
import { cleanup, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import TrajectoryPage from "../TrajectoryPage";
import api from "@/lib/api";
import { bindServerTenant, resetServerTenant } from "@/lib/tenant";

vi.mock("@/lib/api", () => ({ default: { get: vi.fn(), post: vi.fn() } }));

global.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };

const DEVICE = "ep_2d57cbe6f80152062109";

const mountAt = (search) => render(
  <MemoryRouter initialEntries={[`/edr/device-trajectory${search}`]}>
    <TrajectoryPage device={DEVICE} onLegacy={() => {}} />
  </MemoryRouter>);

const trajectoryParams = () => api.get.mock.calls
  .filter(([u]) => /\/trajectory$/.test(u))
  .map(([, cfg]) => cfg?.params)[0] || {};

beforeEach(() => {
  resetServerTenant();
  window.localStorage.clear();
  api.get.mockReset();
  api.get.mockImplementation((u) => Promise.resolve(
    /\/attack$/.test(u) ? { data: { techniques: [] } }
      : /\/hours$/.test(u) ? { data: { hours: [] } }
        : { data: { v3: { events: [], lane_axis: { lanes: [] },
                          computer: {}, activity: { days: [] } } } }));
  bindServerTenant("acme-corp", { switchable: false });
});
afterEach(() => { cleanup(); resetServerTenant(); window.localStorage.clear(); });

describe("the canvas opens on the range the link states", () => {
  it("reads time_start/time_end from a cross-product deep link", async () => {
    mountAt("?time_start=2026-10-18T00%3A00%3A00%2B00%3A00"
            + "&time_end=2026-10-18T23%3A59%3A00%2B00%3A00");
    await waitFor(() => expect(trajectoryParams().time_start).toBeTruthy());
    const p = trajectoryParams();
    expect(p.time_start).toBe("2026-10-18T00:00:00.000Z");
    expect(p.time_end).toBe("2026-10-18T23:59:00.000Z");
  });

  it("falls back to the last 24 hours when the link carries no range", async () => {
    mountAt("");
    await waitFor(() => expect(trajectoryParams().time_start).toBeTruthy());
    const p = trajectoryParams();
    const span = Date.parse(p.time_end) - Date.parse(p.time_start);
    expect(span).toBe(86_400_000);
  });

  it("lets in-canvas navigation win over the link", async () => {
    const t0 = Date.parse("2026-09-01T00:00:00Z");
    const t1 = Date.parse("2026-09-02T00:00:00Z");
    mountAt(`?t0=${t0}&t1=${t1}`
            + "&time_start=2026-10-18T00%3A00%3A00%2B00%3A00"
            + "&time_end=2026-10-18T23%3A59%3A00%2B00%3A00");
    await waitFor(() => expect(trajectoryParams().time_start).toBeTruthy());
    expect(trajectoryParams().time_start).toBe("2026-09-01T00:00:00.000Z");
  });

  it("ignores an unparseable range rather than opening on nothing", async () => {
    mountAt("?time_start=not-a-date");
    await waitFor(() => expect(trajectoryParams().time_start).toBeTruthy());
    const p = trajectoryParams();
    expect(Date.parse(p.time_end) - Date.parse(p.time_start)).toBe(86_400_000);
  });

  it("ignores an inverted range rather than reading backwards", async () => {
    mountAt("?time_start=2026-10-18T06%3A00%3A00Z&time_end=2026-10-18T00%3A00%3A00Z");
    await waitFor(() => expect(trajectoryParams().time_start).toBeTruthy());
    const p = trajectoryParams();
    expect(Date.parse(p.time_end)).toBeGreaterThan(Date.parse(p.time_start));
  });
});
