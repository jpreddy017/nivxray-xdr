// @vitest-environment jsdom
//
// The Timeline tab's "Open Device Trajectory" control must obey the same
// cross-product contract as the incident header: carry this incident's
// customer, endpoint, reference and time range into a NEW TAB, and refuse
// — with a reason — when the record names no endpoint. It used to open a
// context-free /edr/trajectory canvas for any incident at all.
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import ActivityTab from "../tabs/ActivityTab";
import { incidentEndpointId } from "@/xdr/components/OpenInEdr";

vi.mock("@/productOrigins", () => ({
  isCrossOrigin: () => true,
  productHref: (product, path) => `https://edr.nivxforge.com${path}`,
}));

vi.mock("@/lib/api", () => ({
  default: { post: vi.fn(async () => ({ data: { entities: {} } })) },
}));

afterEach(cleanup);

const INCIDENT = {
  id: "inc_938b6edb24544e4aa974",
  tenant: "p0f2-23e870cf",
  created_at: "2026-11-02T10:06:51.589166+00:00",
  updated_at: "2026-11-02T16:00:00.000000+00:00",
  endpoint_campaign: { endpoint_id: "ep_camp1", hostname: "lab-linux-01" },
};

describe("the Timeline trajectory control carries the incident", () => {
  it("opens the incident's own device, customer and range in a new tab", async () => {
    render(<ActivityTab incident={INCIDENT} />);
    const a = await screen.findByTestId("activity-open-trajectory");
    expect(a.tagName).toBe("A");
    expect(a.getAttribute("target")).toBe("_blank");
    expect(a.getAttribute("rel")).toBe("noopener noreferrer");

    const u = new URL(a.getAttribute("href"));
    expect(u.pathname).toBe("/edr/device-trajectory");
    expect(u.searchParams.get("device")).toBe("ep_camp1");
    expect(u.searchParams.get("incident_id")).toBe(INCIDENT.id);
    expect(u.searchParams.get("tenant")).toBe("p0f2-23e870cf");
    expect(u.searchParams.get("time_start")).toBe(INCIDENT.created_at);
    expect(u.searchParams.get("time_end")).toBe(INCIDENT.updated_at);
    expect(a.textContent).toMatch(/\(opens in a new tab\)/);
  });

  it("explains a missing endpoint instead of opening a blank canvas", async () => {
    render(<ActivityTab incident={{ id: "inc_nodevice", tenant: "p0f-c00c9ffe" }} />);
    const note = await screen.findByTestId("activity-open-trajectory-unavailable");
    expect(note.getAttribute("data-reason")).toBe("NO_ENDPOINT");
    await waitFor(() => expect(screen.queryByRole("link")).toBeNull());
    expect(screen.queryByTestId("activity-open-trajectory")).toBeNull();
  });
});

describe("one endpoint resolution for the whole record", () => {
  it("prefers an authoritative endpoint id over a projected hostname", () => {
    expect(incidentEndpointId(INCIDENT)).toBe("ep_camp1");
  });

  it("falls back to the hostname the incident does state", () => {
    expect(incidentEndpointId({
      ssot: { investigation_object: { host: "lab-linux-01" } },
    })).toBe("lab-linux-01");
  });

  it("returns nothing when the record names no endpoint", () => {
    expect(incidentEndpointId({ id: "inc_1" })).toBeNull();
    expect(incidentEndpointId(null)).toBeNull();
  });
});
