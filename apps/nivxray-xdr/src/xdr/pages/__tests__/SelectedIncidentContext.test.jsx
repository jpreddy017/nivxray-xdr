import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { StaticRouter } from "react-router-dom/server";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { getIncident, getIncidentCanonicalEvidence } from "@/lib/incidentsApi";
import { IncidentContextDetails, incidentTabHref, readIncidentContext, requestIncidentContext } from "../SelectedIncidentContext";
vi.mock("@/lib/incidentsApi", () => ({ getIncident: vi.fn(), getIncidentCanonicalEvidence: vi.fn() }));
const scope = vi.hoisted(() => ({ tenant: "A" }));
vi.mock("@/lib/tenant", () => ({ activeTenant: () => scope.tenant, TENANT_BOUND_EVENT: "nvx-tenant-bound" }));
const incident = { id: "A/1", name: "Authorized incident", tenant: "A", priority: "P1", state: "new" };
beforeEach(() => { vi.resetAllMocks(); scope.tenant = "A"; });
const html = (result) => renderToStaticMarkup(<StaticRouter><IncidentContextDetails id={incident.id} result={result} /></StaticRouter>);
describe("Selected incident context", () => {
  it("reads only the selected authorized record and distinguishes empty evidence", async () => {
    getIncident.mockResolvedValue(incident);
    getIncidentCanonicalEvidence.mockResolvedValue({ incident_id: incident.id, rows: [] });
    const result = await readIncidentContext(incident.id);
    expect(getIncident).toHaveBeenCalledOnce(); expect(getIncident).toHaveBeenCalledWith(incident.id);
    expect(getIncidentCanonicalEvidence).toHaveBeenCalledOnce(); expect(getIncidentCanonicalEvidence).toHaveBeenCalledWith(incident.id);
    expect(html(result)).toContain("No canonical evidence references returned");
    for (const tab of ["story", "timeline", "evidence"]) expect(html(result)).toContain(incidentTabHref(incident.id, tab));
    expect(html(result)).toContain("Not recorded");
  });
  it.each([401, 403, 404])("removes all context and pivots on denial %s", async (status) => {
    getIncident.mockRejectedValue({ response: { status } });
    const result = await readIncidentContext(incident.id);
    expect(result).toEqual({ state: "denied" });
    expect(getIncidentCanonicalEvidence).not.toHaveBeenCalled();
    expect(html(result)).not.toContain("A/1");
    expect(html(result)).not.toContain("Open Story");
  });
  it("clears authorized incident content if the evidence request is denied", async () => {
    getIncident.mockResolvedValue(incident);
    getIncidentCanonicalEvidence.mockRejectedValue({ response: { status: 403 } });
    expect(await readIncidentContext(incident.id)).toEqual({ state: "denied" });
  });
  it("rejects mismatched record identity and does not request its evidence", async () => {
    getIncident.mockResolvedValue({ ...incident, id: "B/2" });
    expect(await readIncidentContext(incident.id)).toEqual({ state: "unavailable" });
    expect(getIncidentCanonicalEvidence).not.toHaveBeenCalled();
  });
  it("keeps network errors distinct from empty evidence", async () => {
    getIncident.mockResolvedValue(incident);
    getIncidentCanonicalEvidence.mockRejectedValue(new Error("network"));
    const result = await readIncidentContext(incident.id);
    expect(html(result)).toContain("Evidence context could not load");
    expect(html(result)).not.toContain("No canonical evidence");
    getIncident.mockRejectedValue(new Error("network"));
    expect(await readIncidentContext(incident.id)).toEqual({ state: "error" });
  });
  it("does not label mismatched or malformed evidence as an empty result", async () => {
    getIncident.mockResolvedValue(incident);
    getIncidentCanonicalEvidence.mockResolvedValue({ incident_id: "B/2", rows: [] });
    expect(html(await readIncidentContext(incident.id))).toContain("Evidence context is not available");
  });
  it("ignores a late selection response after cleanup", async () => {
    let resolve;
    getIncident.mockReturnValue(new Promise((done) => { resolve = done; }));
    getIncidentCanonicalEvidence.mockResolvedValue({ incident_id: incident.id, rows: [] });
    const publish = vi.fn();
    const cancel = requestIncidentContext(incident.id, publish);
    cancel(); resolve(incident);
    await new Promise((done) => setTimeout(done, 0));
    expect(publish).not.toHaveBeenCalled();
  });
  it("ignores pending results when the tenant changes", async () => {
    let resolve;
    getIncident.mockReturnValue(new Promise((done) => { resolve = done; }));
    getIncidentCanonicalEvidence.mockResolvedValue({ incident_id: incident.id, rows: [] });
    const publish = vi.fn();
    requestIncidentContext(incident.id, publish);
    scope.tenant = "B"; resolve(incident);
    await new Promise((done) => setTimeout(done, 0));
    expect(publish).not.toHaveBeenCalled();
  });
  it("renders loading without incident details or investigation links", () => {
    expect(html({ state: "loading" })).toContain("Loading selected incident");
    expect(html({ state: "loading" })).not.toContain("Open Evidence");
  });
});
