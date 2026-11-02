// @vitest-environment jsdom
//
// Computers is tenant-scoped evidence. The grid used to request it on mount —
// before the console resolved the acting customer — so an authenticated
// analyst saw `403 TENANT_REQUIRED` in the console and a failure on screen.
// The server's refusal was CORRECT; the client must not provoke it.
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import EdrComputersPage from "../EdrComputersPage";
import {
  bindServerTenant, resetServerTenant, sealTenantAuthority, setActiveTenant,
} from "@/lib/tenant";
import { getComputers } from "@/nivxforge/onboardingApi";

vi.mock("@/nivxforge/NivXForgeConsole", () => ({
  default: ({ children }) => <div>{children}</div>,
  useIncidentContext: () => ({}),
}));
vi.mock("@/nivxforge/onboardingApi", () => ({ getComputers: vi.fn() }));

const OWN = "acme-corp";
const FOREIGN = "contoso-corp";

const fleet = (hostname) => ({
  count: 1, status_contract: "contract", detection_count_method: "method",
  computers: [{ endpoint_id: `ep_${hostname}`, hostname, status: "CONNECTED",
                status_basis: "authenticated telemetry", os: "Windows",
                telemetry: { event_count: 1 }, detections_24h: 0,
                detections_total: 0, detections_window_hours: 24,
                detections_basis: "counted" }],
});

const mount = () => render(
  <MemoryRouter><EdrComputersPage /></MemoryRouter>);

beforeEach(() => {
  resetServerTenant();
  window.localStorage.clear();
  getComputers.mockReset();
});
afterEach(() => { cleanup(); resetServerTenant(); window.localStorage.clear(); });

describe("no tenant-scoped request is made before a customer is resolved", () => {
  it("renders loading and asks for nothing while the authority is pending", async () => {
    mount();
    expect(screen.getByTestId("edr-computers-loading")).toBeTruthy();
    expect(getComputers).not.toHaveBeenCalled();
    expect(screen.queryByTestId("edr-computers-refusal")).toBeNull();
    expect(screen.queryByTestId("edr-computers-no-customer")).toBeNull();
  });

  it("reads the fleet once the server bound a customer", async () => {
    getComputers.mockResolvedValue(fleet("WS-ONE"));
    bindServerTenant(OWN, { switchable: false });
    mount();
    await waitFor(() => expect(screen.getByText("WS-ONE")).toBeTruthy());
    expect(getComputers).toHaveBeenCalledTimes(1);
  });

  it("states 'select a customer' instead of failing when none is selected", () => {
    bindServerTenant(null, { switchable: true });
    mount();
    expect(screen.getByTestId("edr-computers-no-customer")).toBeTruthy();
    expect(screen.queryByTestId("edr-computers-loading")).toBeNull();
    expect(getComputers).not.toHaveBeenCalled();
  });

  it("states access denied when the authority is sealed", () => {
    sealTenantAuthority();
    mount();
    expect(screen.getByTestId("edr-computers-denied").textContent)
      .toMatch(/Access denied/);
    expect(getComputers).not.toHaveBeenCalled();
  });
});

describe("switching customer discards the previous customer's rows", () => {
  it("clears the grid and re-reads for the new customer", async () => {
    getComputers.mockResolvedValueOnce(fleet("WS-ONE"))
                .mockResolvedValueOnce(fleet("WS-TWO"));
    bindServerTenant(null, { switchable: true });
    setActiveTenant(OWN);
    mount();
    await waitFor(() => expect(screen.getByText("WS-ONE")).toBeTruthy());

    await waitFor(() => {
      setActiveTenant(FOREIGN);
      window.dispatchEvent(new CustomEvent("nvx-tenant-bound",
                                          { detail: FOREIGN }));
    });
    await waitFor(() => expect(screen.getByText("WS-TWO")).toBeTruthy());
    expect(screen.queryByText("WS-ONE")).toBeNull();
    expect(getComputers).toHaveBeenCalledTimes(2);
  });

  it("ignores a stale response that lands after the switch", async () => {
    let releaseFirst;
    getComputers
      .mockImplementationOnce(() => new Promise((res) => { releaseFirst = res; }))
      .mockResolvedValueOnce(fleet("WS-TWO"));
    bindServerTenant(null, { switchable: true });
    setActiveTenant(OWN);
    mount();
    await waitFor(() => expect(getComputers).toHaveBeenCalledTimes(1));

    await waitFor(() => {
      setActiveTenant(FOREIGN);
      window.dispatchEvent(new CustomEvent("nvx-tenant-bound",
                                          { detail: FOREIGN }));
    });
    await waitFor(() => expect(screen.getByText("WS-TWO")).toBeTruthy());

    releaseFirst(fleet("WS-ONE"));               // the abandoned customer answers
    await new Promise((r) => setTimeout(r, 0));
    expect(screen.queryByText("WS-ONE")).toBeNull();
    expect(screen.getByText("WS-TWO")).toBeTruthy();
  });
});
