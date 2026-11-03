// @vitest-environment jsdom
//
// MOUNTED cover for the trajectory canvas states. Loading, access denied, an
// empty result and a genuine failure must be four DIFFERENT things on screen,
// and only a retryable failure gets Retry.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import TrajectoryPage from "../TrajectoryPage";
import api from "@/lib/api";
import { bindServerTenant, resetServerTenant, sealTenantAuthority } from "@/lib/tenant";

vi.mock("@/lib/api", () => ({ default: { get: vi.fn(), post: vi.fn() } }));

global.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };

const DEVICE = "ep_2d57cbe6f80152062109";
const OWN = "acme-corp";

const mount = () => render(
  <MemoryRouter><TrajectoryPage device={DEVICE} onLegacy={() => {}} /></MemoryRouter>);

const ok = (events = []) => ({ data: { v3: {
  events, lane_axis: { lanes: [] }, computer: { hostname: "WS-ONE" },
  activity: { days: [] }, e3_preview: { data_label: "REAL PRODUCTION EVIDENCE" },
} } });

// Route by URL: the ATT&CK strip and the hour histogram are children, so their
// effects run BEFORE the page's own read — call ORDER proves nothing here.
const route = ({ trajectory }) => (u) => {
  if (/\/trajectory$/.test(u)) {
    return trajectory instanceof Error || trajectory?.response || trajectory?.code
      ? Promise.reject(trajectory) : Promise.resolve(trajectory || ok());
  }
  if (/\/attack$/.test(u)) return Promise.resolve({ data: { techniques: [] } });
  if (/\/hours$/.test(u)) return Promise.resolve({ data: { hours: [] } });
  return Promise.resolve({ data: {} });
};

const trajectoryCalls = () =>
  api.get.mock.calls.filter(([u]) => /\/trajectory$/.test(u));

beforeEach(() => {
  resetServerTenant();
  window.localStorage.clear();
  api.get.mockReset();
  api.get.mockImplementation(route({}));
});
afterEach(() => { cleanup(); resetServerTenant(); window.localStorage.clear(); });

describe("tenant-scoped evidence is not requested before a customer resolves", () => {
  it("shows loading and requests nothing while the authority is pending", () => {
    mount();
    expect(screen.getByTestId("v3-loading")).toBeTruthy();
    expect(trajectoryCalls()).toHaveLength(0);
    expect(screen.queryByTestId("v3-read-error")).toBeNull();
  });

  it("states access denied — with no Retry — when the authority is sealed", async () => {
    sealTenantAuthority();
    mount();
    await waitFor(() => expect(screen.getByTestId("v3-read-error")).toBeTruthy());
    const box = screen.getByTestId("v3-read-error");
    expect(box.getAttribute("data-error-kind")).toBe("DENIED");
    expect(box.getAttribute("data-retryable")).toBe("false");
    expect(screen.queryByTestId("v3-retry-read")).toBeNull();
    expect(trajectoryCalls()).toHaveLength(0);
  });

  it("asks for a customer, neutrally, when none is selected", async () => {
    bindServerTenant(null, { switchable: true });
    mount();
    await waitFor(() => expect(screen.getByTestId("v3-read-error")).toBeTruthy());
    const box = screen.getByTestId("v3-read-error");
    expect(box.getAttribute("data-error-kind")).toBe("NO_CUSTOMER");
    expect(box.getAttribute("role")).toBe("status");
    expect(box.textContent).toMatch(/Select a customer/);
    expect(screen.getByTestId("v3-loaded-count").textContent)
      .toBe("No customer selected");
    expect(trajectoryCalls()).toHaveLength(0);
  });

  it("reads the trajectory once a customer is bound", async () => {
    bindServerTenant(OWN, { switchable: false });
    mount();
    await waitFor(() => expect(trajectoryCalls()).toHaveLength(1));
    expect(screen.queryByTestId("v3-read-error")).toBeNull();
  });
});

describe("an empty range is not a failure", () => {
  it("states the range was read and returned nothing", async () => {
    bindServerTenant(OWN, { switchable: false });
    mount();
    await waitFor(() => expect(screen.getByTestId("v3-empty")).toBeTruthy());
    expect(screen.getByTestId("v3-empty").textContent)
      .toMatch(/empty result, not a failed request/);
    expect(screen.queryByTestId("v3-read-error")).toBeNull();
    expect(screen.getByTestId("v3-loaded-count").textContent)
      .toMatch(/0 events loaded/);
  });
});

describe("a real API failure is reported as one, and can be retried", () => {
  it("offers Retry on a server failure and re-reads when pressed", async () => {
    bindServerTenant(OWN, { switchable: false });
    api.get.mockImplementation(route({ trajectory: { response: { status: 503 } } }));
    mount();
    await waitFor(() => expect(screen.getByTestId("v3-read-error")).toBeTruthy());
    const box = screen.getByTestId("v3-read-error");
    expect(box.getAttribute("data-error-kind")).toBe("FAILED");
    expect(box.getAttribute("role")).toBe("alert");
    expect(box.textContent).toMatch(/Trajectory unavailable/);

    const before = trajectoryCalls().length;
    api.get.mockImplementation(route({}));
    fireEvent.click(screen.getByTestId("v3-retry-read"));
    await waitFor(() => expect(trajectoryCalls().length).toBeGreaterThan(before));
    await waitFor(() => expect(screen.queryByTestId("v3-read-error")).toBeNull());
  });

  it("renders a server refusal as access denied, not as a broken service", async () => {
    bindServerTenant(OWN, { switchable: false });
    api.get.mockImplementation(route({ trajectory: { response: { status: 403,
      data: { detail: { code: "TENANT_REQUIRED",
        reason: "platform-scoped principal must name the customer it is "
          + "operating in" } } } } }));
    mount();
    await waitFor(() => expect(screen.getByTestId("v3-read-error")).toBeTruthy());
    const box = screen.getByTestId("v3-read-error");
    expect(box.getAttribute("data-error-kind")).toBe("DENIED");
    expect(box.textContent).toMatch(/Access denied/);
    expect(box.textContent).not.toMatch(/check the backend service/);
    expect(screen.queryByTestId("v3-retry-read")).toBeNull();
  });
});

describe("a refused read is not dressed as a finished investigation", () => {
  const mountDeep = () => render(
    <MemoryRouter initialEntries={[
      `/edr/device-trajectory?device=${DEVICE}&incident_id=inc_e2eb6978efca42aa88a7`
      + "&at=2026-10-31T17:55:31.272472%2B00:00&tenant=p0f-c375caa0"]}>
      <TrajectoryPage device={DEVICE} onLegacy={() => {}} />
    </MemoryRouter>);

  const refuse = (status, reason) => api.get.mockImplementation(
    route({ trajectory: { response: { status, data: { detail: { reason } } } } }));

  it("shows the refusal alone — no ATT&CK, no counts, no device actions", async () => {
    bindServerTenant(OWN, { switchable: false });
    refuse(403, "customer p0f-c375caa0 is not registered in this control plane");
    mountDeep();
    await waitFor(() => expect(screen.getByTestId("v3-read-error")).toBeTruthy());

    expect(screen.getByTestId("v3-page").getAttribute("data-refused")).toBe("DENIED");
    for (const gone of ["dt-attack-strip", "v3-toolbar", "v3-workspace",
                        "v3-status-bar", "v3-actions", "v3-loaded-count",
                        "v3-activity-panel", "v3-empty"]) {
      expect(screen.queryByTestId(gone), gone).toBeNull();
    }
    expect(screen.queryByText(/Loading ATT&CK mapping/)).toBeNull();
    expect(screen.queryByTestId("v3-retry-read")).toBeNull();
  });

  it("states what was refused and offers the way back to the incident", async () => {
    bindServerTenant(OWN, { switchable: false });
    refuse(403, "customer p0f-c375caa0 is not registered in this control plane");
    mountDeep();
    const back = await screen.findByTestId("v3-refused-return");
    expect(back.getAttribute("href")).toBe("/xdr/incidents/inc_e2eb6978efca42aa88a7");
    expect(screen.getByTestId("v3-refused-request").textContent).toContain(DEVICE);
    expect(screen.getByTestId("v3-refused-meaning").textContent)
      .toMatch(/would not mean the device was quiet/);
  });

  it("treats an unresolved device the same way", async () => {
    bindServerTenant(OWN, { switchable: false });
    refuse(404, "no endpoint entity matches ep_f in this customer");
    mountDeep();
    await waitFor(() => expect(screen.getByTestId("v3-page")
      .getAttribute("data-refused")).toBe("NOT_RESOLVED"));
    expect(screen.queryByTestId("v3-workspace")).toBeNull();
    expect(screen.getByTestId("v3-refused-return")).toBeTruthy();
  });
});

describe("an empty canvas does not erase the sighting that sent the analyst here", () => {
  // Real case: a FILE/CREATE sighting observed 2026-09-08 exists in raw
  // authenticated evidence, while the canonical store holds nothing for that
  // day. A bare "no activity" then reads as a denial of evidence that exists.
  const SIGHTING = {
    raw_id: "raw_98b8aec512212938f62fd84a", endpoint_id: DEVICE,
    activity: "CREATE", path: "/var/tmp/nivxforge-watch/nivx-p03-proof-1788827716",
    observed_at: "2026-09-08T00:35:30.688220+00:00", size: 68432,
  };
  const HASH = "17a623f303e2489770e64a9eab9420c66e576ec5ad215ea7c46ec392a2212f49";

  const mountPivot = (sighting = SIGHTING.raw_id) => render(
    <MemoryRouter initialEntries={[
      `/edr/device-trajectory?device=${DEVICE}&at=${SIGHTING.observed_at}`
      + `&sha256=${HASH}&sighting=${sighting}&tenant=${OWN}`]}>
      <TrajectoryPage device={DEVICE} onLegacy={() => {}} />
    </MemoryRouter>);

  const withSighting = (rows) => api.get.mockImplementation((u, cfg) => {
    if (/\/sightings$/.test(u)) {
      expect(cfg.params.raw_id).toBe(SIGHTING.raw_id);
      return Promise.resolve({ data: { ok: true, sha256: HASH, tenant: OWN,
        endpoints: rows.length ? [{ endpoint_id: DEVICE, sightings: rows }] : [] } });
    }
    return route({})(u);
  });

  it("keeps the sighting on screen and names the gap between the two reads", async () => {
    bindServerTenant(OWN, { switchable: false });
    withSighting([SIGHTING]);
    mountPivot();
    const panel = await screen.findByTestId("v3-source-sighting");
    expect(panel.getAttribute("data-raw-id")).toBe(SIGHTING.raw_id);
    expect(panel.textContent).toContain("File created");
    expect(panel.textContent).toContain(SIGHTING.path);
    expect(panel.textContent).toContain("2026-09-08 00:35:30Z");
    expect(panel.textContent).toMatch(/canonicalisation gap for this range/);
    expect(panel.textContent).toMatch(/not an absence of activity/);
    expect(screen.getByTestId("v3-source-sighting-back").getAttribute("href"))
      .toBe(`/edr/files?sha256=${HASH}`);
  });

  it("asserts nothing when the sighting cannot be re-read in this customer", async () => {
    bindServerTenant(OWN, { switchable: false });
    withSighting([]);
    mountPivot();
    const miss = await screen.findByTestId("v3-source-sighting-missing");
    expect(miss.textContent).toMatch(/nothing about it is asserted here/);
    expect(screen.queryByTestId("v3-source-sighting")).toBeNull();
  });

  it("stays out of the way when the canvas actually has events", async () => {
    bindServerTenant(OWN, { switchable: false });
    api.get.mockImplementation(route({ trajectory: ok([{
      event_iid: "ev1", event_time: SIGHTING.observed_at, kind: "process_create",
      process: { image: "sleep", image_path: "/usr/bin/sleep" },
    }]) }));
    mountPivot();
    await waitFor(() => expect(screen.queryByTestId("v3-empty")).toBeNull());
    expect(screen.queryByTestId("v3-source-sighting")).toBeNull();
  });
});
