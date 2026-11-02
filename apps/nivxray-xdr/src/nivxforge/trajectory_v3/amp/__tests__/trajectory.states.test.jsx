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
