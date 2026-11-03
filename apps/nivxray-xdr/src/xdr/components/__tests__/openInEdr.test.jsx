// @vitest-environment jsdom
//
// Cross-product navigation contract: an XDR incident must stay open while the
// associated device's EDR trajectory opens in a NEW TAB, carrying the customer,
// endpoint, incident and the incident's time range — and never silently
// substituting a different device or customer.
import { cleanup, render, screen } from "@testing-library/react";
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import OpenInEdr, { buildEdrTrajectoryLink, resolveEndpoint } from "../OpenInEdr";
import { pivotTrajectory } from "@/xdr/incidents/investigationPivots";

vi.mock("@/productOrigins", () => ({
  isCrossOrigin: () => true,
  productHref: (product, path) => `https://edr.nivxforge.com${path}`,
}));

afterEach(cleanup);

const CTX = {
  device: "ep_2d57cbe6f80152062109",
  incidentId: "inc_8812",
  tenant: "acme-corp",
  timeStart: "2026-10-18T00:00:00Z",
  timeEnd: "2026-10-18T06:00:00Z",
};

describe("the deep link carries the whole investigation context", () => {
  it("names the endpoint, incident, customer and time range", () => {
    const { href } = buildEdrTrajectoryLink(CTX);
    const u = new URL(href);
    expect(u.origin).toBe("https://edr.nivxforge.com");
    expect(u.pathname).toBe("/edr/device-trajectory");
    expect(u.searchParams.get("device")).toBe(CTX.device);
    expect(u.searchParams.get("incident_id")).toBe("inc_8812");
    expect(u.searchParams.get("tenant")).toBe("acme-corp");
    expect(u.searchParams.get("time_start")).toBe(CTX.timeStart);
    expect(u.searchParams.get("time_end")).toBe(CTX.timeEnd);
  });

  it("carries no credential or token", () => {
    const { href } = buildEdrTrajectoryLink({ ...CTX, at: "2026-10-18T03:00:00Z" });
    expect(href).not.toMatch(/token|authorization|bearer|password|secret|jwt/i);
  });

  it("omits what the record does not state instead of inventing it", () => {
    const u = new URL(buildEdrTrajectoryLink({ device: "ep_1" }).href);
    expect([...u.searchParams.keys()]).toEqual(["device"]);
  });
});

describe("an instant is stated as an instant", () => {
  it("sends `at` instead of a zero-length range", () => {
    const u = new URL(buildEdrTrajectoryLink({
      device: "ep_1",
      timeStart: "2026-11-02T10:06:51.589166+00:00",
      timeEnd: "2026-11-02T10:06:51.589166+00:00",
    }).href);
    expect(u.searchParams.get("at")).toBe("2026-11-02T10:06:51.589166+00:00");
    expect(u.searchParams.get("time_start")).toBeNull();
    expect(u.searchParams.get("time_end")).toBeNull();
  });

  it("sends `at` when the incident has no end at all", () => {
    const u = new URL(buildEdrTrajectoryLink({
      device: "ep_1", timeStart: "2026-11-02T10:06:51Z",
    }).href);
    expect(u.searchParams.get("at")).toBe("2026-11-02T10:06:51Z");
    expect(u.searchParams.get("time_start")).toBeNull();
  });

  it("keeps a real range as a range", () => {
    const u = new URL(buildEdrTrajectoryLink({
      device: "ep_1", timeStart: "2026-10-18T00:00:00Z",
      timeEnd: "2026-10-18T06:00:00Z",
    }).href);
    expect(u.searchParams.get("time_start")).toBe("2026-10-18T00:00:00Z");
    expect(u.searchParams.get("time_end")).toBe("2026-10-18T06:00:00Z");
    expect(u.searchParams.get("at")).toBeNull();
  });
});

describe("an unresolvable endpoint is explained, never guessed", () => {
  it("refuses when no endpoint is named", () => {
    expect(resolveEndpoint({}).reason).toBe("NO_ENDPOINT");
    expect(buildEdrTrajectoryLink({}).href).toBeNull();
  });

  it("refuses when the record names two different endpoints", () => {
    const r = resolveEndpoint({ device: "ep_a", endpointId: "ep_b" });
    expect(r.reason).toBe("AMBIGUOUS_ENDPOINT");
    expect(r.candidates).toEqual(["ep_a", "ep_b"]);
    expect(buildEdrTrajectoryLink({ device: "ep_a", endpointId: "ep_b" }).href)
      .toBeNull();
  });

  it("accepts one endpoint stated twice", () => {
    expect(resolveEndpoint({ device: "ep_a", endpointId: "ep_a" }).endpoint)
      .toBe("ep_a");
  });

  it("says which fact is missing in the UI", () => {
    render(<OpenInEdr />);
    const note = screen.getByTestId("open-in-edr-unavailable");
    expect(note.getAttribute("data-reason")).toBe("NO_ENDPOINT");
    expect(screen.queryByRole("link")).toBeNull();
  });

  it("names the competing endpoints when ambiguous", () => {
    render(<OpenInEdr device="ep_a" endpointId="ep_b" />);
    const note = screen.getByTestId("open-in-edr-unavailable");
    expect(note.getAttribute("data-reason")).toBe("AMBIGUOUS_ENDPOINT");
    expect(note.getAttribute("title")).toMatch(/ep_a · ep_b/);
  });
});

describe("the control opens a new tab and keeps the incident open", () => {
  it("is a real link with a safe target", () => {
    render(<OpenInEdr {...CTX} />);
    const a = screen.getByTestId("open-in-edr");
    expect(a.tagName).toBe("A");
    expect(a.getAttribute("target")).toBe("_blank");
    expect(a.getAttribute("rel")).toBe("noopener noreferrer");
    expect(a.getAttribute("href")).toMatch(/^https:\/\/edr\.nivxforge\.com\//);
  });

  it("announces that it opens in a new tab", () => {
    render(<OpenInEdr {...CTX} />);
    expect(screen.getByTestId("open-in-edr").textContent)
      .toMatch(/\(opens in a new tab\)/);
  });
});

describe("the Process / device trajectory pivot leaves for EDR", () => {
  it("builds the same contract and asks for a new tab", () => {
    const p = pivotTrajectory({ kind: "device", id: "ep_7", value: "WS-ONE" },
                              { id: "inc_1", tenant: "acme-corp",
                                created_at: "2026-10-18T00:00:00Z",
                                updated_at: "2026-10-18T06:00:00Z" });
    expect(p.newTab).toBe(true);
    expect(p.product).toBe("edr");
    const u = new URL(p.to);
    expect(u.pathname).toBe("/edr/device-trajectory");
    expect(u.searchParams.get("device")).toBe("ep_7");
    expect(u.searchParams.get("incident_id")).toBe("inc_1");
    expect(u.searchParams.get("tenant")).toBe("acme-corp");
    expect(u.searchParams.get("time_start")).toBe("2026-10-18T00:00:00Z");
  });

  it("is not offered at all for an entity with no endpoint identity", () => {
    expect(pivotTrajectory({ kind: "hash", value: "abc" }, { id: "inc_1" }))
      .toBeNull();
  });
});
