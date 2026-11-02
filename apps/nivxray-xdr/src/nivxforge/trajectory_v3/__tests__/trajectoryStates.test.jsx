// @vitest-environment jsdom
//
// "No device selected" is a PRECONDITION, not a failure, and a refusal is not
// a broken service. The canvas previously requested
// `/edr/endpoints/null/trajectory`, failed, and told the analyst the backend
// had failed — for not having picked a computer.
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import DeviceTrajectoryPage from "../DeviceTrajectoryPage";
import { classifyReadError } from "../amp/TrajectoryPage";

vi.mock("@/nivxforge/NivXForgeConsole", () => ({
  default: ({ children }) => <div data-testid="console">{children}</div>,
  useIncidentContext: () => ({}),
}));
vi.mock("@/nivxforge/trajectory/EdrDeviceTrajectoryPage", () => ({
  default: () => <div data-testid="legacy-page" />,
}));
vi.mock("../amp/TrajectoryPage", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    default: ({ device }) => <div data-testid="v3-page" data-device={device} />,
    classifyReadError: actual.classifyReadError,
  };
});

afterEach(cleanup);

const at = (search) => render(
  <MemoryRouter initialEntries={[`/edr/device-trajectory${search}`]}>
    <DeviceTrajectoryPage />
  </MemoryRouter>);

describe("the canvas is not opened against a device nobody chose", () => {
  it("states 'select a computer' when no device is in the URL", () => {
    at("");
    expect(screen.getByTestId("v3-no-device").textContent)
      .toMatch(/Select a computer to view its trajectory/);
    expect(screen.queryByTestId("v3-page")).toBeNull();
    expect(screen.getByTestId("v3-no-device-open-computers")).toBeTruthy();
  });

  it("never blames the backend for an unselected device", () => {
    at("");
    const panel = screen.getByTestId("v3-no-device");
    const prose = [...panel.querySelectorAll("strong, p")]
      .map((n) => n.textContent).join(" ");
    expect(prose).not.toMatch(/unavailable/i);
    expect(prose).not.toMatch(/fail/i);
    expect(prose).not.toMatch(/retry/i);
  });

  it("treats a blank device as no device at all", () => {
    at("?device=%20%20");
    expect(screen.getByTestId("v3-no-device")).toBeTruthy();
  });

  it("opens the canvas as soon as a device is named", () => {
    at("?device=ep_2d57cbe6f80152062109");
    expect(screen.getByTestId("v3-page").getAttribute("data-device"))
      .toBe("ep_2d57cbe6f80152062109");
    expect(screen.queryByTestId("v3-no-device")).toBeNull();
  });
});

describe("a refusal, a timeout and a broken service are different facts", () => {
  it("a 403 is access denied and is NOT retryable", () => {
    const e = { response: { status: 403, data: { detail: {
      code: "TENANT_REQUIRED", reason: "platform-scoped principal must name "
        + "the customer it is operating in" } } } };
    const c = classifyReadError(e);
    expect(c.kind).toBe("DENIED");
    expect(c.title).toBe("Access denied");
    expect(c.retryable).toBe(false);
    expect(c.text).toMatch(/must name the customer/);
  });

  it("a 404 is an unresolved device, not a failed request", () => {
    const c = classifyReadError({ response: { status: 404, data: {
      detail: { reason: "ENDPOINT_NOT_RESOLVED" } } } });
    expect(c.kind).toBe("NOT_RESOLVED");
    expect(c.retryable).toBe(false);
    expect(c.title).toMatch(/Device not resolved/);
  });

  it("a timeout says evidence could not be read, not that there was none", () => {
    const c = classifyReadError({ code: "ECONNABORTED" });
    expect(c.kind).toBe("TIMEOUT");
    expect(c.retryable).toBe(true);
    expect(c.text).toMatch(/does not mean the endpoint had no activity/);
  });

  it("a genuine server failure is retryable", () => {
    const c = classifyReadError({ response: { status: 503 } });
    expect(c.kind).toBe("FAILED");
    expect(c.retryable).toBe(true);
    expect(c.title).toBe("Trajectory unavailable");
  });

  it("a transport error with no response is still a retryable failure", () => {
    const c = classifyReadError(new Error("Network Error"));
    expect(c.kind).toBe("FAILED");
    expect(c.retryable).toBe(true);
  });
});
