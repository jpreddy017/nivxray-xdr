import { describe, expect, it } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import Legend from "../Legend";
import DetailsPane from "../DetailsPane";
import Toolbar from "../Toolbar";
import { ApprovalDialog } from "../ContextMenu";

const noop = () => {};

describe("Legend", () => {
  const html = renderToStaticMarkup(<Legend present={new Map([["PROCESS_START", 1]])} />);
  it("explains every connector style, color and approval/retro/late glyph", () => {
    for (const id of ["legend-connector-PROVEN_CAUSAL", "legend-connector-CORRELATED", "legend-connector-UNRESOLVED", "legend-color-MALICIOUS",
      "legend-color-MATCH", "legend-color-UNKNOWN", "legend-color-NO_DETECTION", "legend-color-CLEAN", "legend-mark-RETRO",
      "legend-mark-APPROVAL", "legend-mark-LATE", "legend-gap"]) expect(html).toContain(`data-testid="${id}"`);
  });
  it("marks sensor-gap event types as not collected", () => {
    expect(html).toMatch(/File write \/ modify<em[^>]*> · not collected by sensor \(S-2\)/);
    expect(html).not.toMatch(/Process start<em/);
  });
});

describe("DetailsPane", () => {
  const lane = { lane_id: "pi:t:d:7420:1", lane_type: "PROCESS", causal_state: "PROVEN_CAUSAL", parent_lane: "pi:t:d:7040:1", sha256: "a1" };
  const event = { event_id: "e1", kind: "PROCESS_START", observed_ms: 1790912820000, ingested_ms: 1790912822000, severity: "MEDIUM",
    lateness: { state: "ON_TIME", lateness_ms: 2000, late: false }, process: { pid: 7420, sha256: "a1", image: "C:\\T\\upd.exe" },
    provenance: { store: "v2_shadow_observations", ref: "obs_1", label: "SYNTHETIC" }, sources: ["v2_shadow_observations"] };
  const fileStatus = { detection_state: "NO_DETECTION", detections: [], reputation: [{ state: "UNKNOWN", provider: "none_configured", assessed_at: "t", evidence: [], detail: "UNKNOWN is not CLEAN" }],
    assessment: { state: "UNASSESSED", basis: "none" } };
  const html = renderToStaticMarkup(<DetailsPane lane={lane} event={event} eventId="e1" fileStatus={fileStatus} sha="a1"
    statusEvents={[{ status_event_id: "se1", subject: "a1", kind: "RETRO_DETECTION", state: "DETECTED", recorded_at: "2026-10-02T04:25:00.000Z", provenance: {} }]}
    approvals={[{ request_id: "r1", action: "ISOLATE_DEVICE", state: "APPROVAL_REQUESTED", executed: false, target: { lane_id: lane.lane_id } }]} />);
  it("renders detection, reputation and assessment as separate sections", () => {
    for (const id of ["identity", "detection", "reputation", "assessment", "status-history", "approvals", "times", "cannot-tell", "evidence"]) {
      expect(html).toContain(`data-testid="details-${id}"`);
    }
  });
  it("shows states verbatim without implying clean", () => {
    expect(html).toContain(">UNKNOWN</span>");
    expect(html).toContain(">NO_DETECTION</span>");
    expect(html).not.toMatch(/>Clean</);
  });
  it("marks retrospective entries and keeps approvals un-executed", () => {
    expect(html).toContain("Added later at 2026-10-02T04:25:00.000Z; original event unchanged.");
    expect(html).toContain("Approval requested — not executed. Execution is owned by E1.");
    expect(html).toContain("2026-10-02 03:47:00 UTC");
  });
});

describe("Toolbar filter indicator", () => {
  const props = { present: new Map([["FILE_WRITE", 6]]), setKinds: noop, query: "", setQuery: noop, onSearch: noop, isolation: null,
    onClearIsolation: noop, hideOthers: false, setHideOthers: noop, tzMode: "UTC", setTzMode: noop, legendOpen: false, setLegendOpen: noop, onZoom: noop };
  it("visible 'Showing X of Y' with one-click reset when active", () => {
    const html = renderToStaticMarkup(<Toolbar {...props} kinds={new Set(["FILE_WRITE"])} summary={{ active: true, shown: 6, total: 10, text: "Showing 6 of 10 events" }} />);
    expect(html).toContain('data-active="true"');
    expect(html).toContain("Showing 6 of 10 events");
    expect(html).toContain('data-testid="filter-reset"');
  });
  it("no reset and no filtered label when inactive; isolation chip when active", () => {
    const html = renderToStaticMarkup(<Toolbar {...props} kinds={new Set()} isolation={{ label: "upd.exe", count: 5 }} summary={{ active: false, shown: 10, total: 10, text: "10 events" }} />);
    expect(html).not.toContain("filter-reset");
    expect(html).toContain("Isolation active · upd.exe · 5 rows");
  });
});

describe("ApprovalDialog", () => {
  it("result phase states request-only and never success", () => {
    const html = renderToStaticMarkup(<ApprovalDialog onConfirm={noop} onClose={noop} dialog={{ action: "ISOLATE_DEVICE", phase: "result", target: { device_id: "D" },
      result: { created: true, request: { request_id: "apr_1", state: "APPROVAL_REQUESTED", executed: false } } }} />);
    expect(html).toContain("Approval requested — not executed. Execution is owned by E1.");
    expect(html).not.toMatch(/success|contained|verified/i);
  });
  it("confirm phase explains nothing is sent to the endpoint", () => {
    const html = renderToStaticMarkup(<ApprovalDialog onConfirm={noop} onClose={noop} dialog={{ action: "QUARANTINE_FILE", phase: "confirm", target: { device_id: "D", path: "p" } }} />);
    expect(html).toContain("approval request");
    expect(html).toContain('data-testid="approval-confirm"');
  });
});
