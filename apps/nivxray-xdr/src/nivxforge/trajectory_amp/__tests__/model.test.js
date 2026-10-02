import { describe, expect, it } from "vitest";
import { CONNECTOR, PAL, SEMANTIC, approvalMarkers, approvalText, cannotTell, connectorSource, connectorStyle, filterSummary,
         fmtInstant, groupMarkers, isolateRows, retroMarkers, semanticOf } from "../model";
import { E3_DT_CONTRACT_PREVIEW } from "../flags";

describe("color / semantic mapping", () => {
  it("UNKNOWN-like and NO_DETECTION states are never green or 'Clean'", () => {
    for (const s of ["UNKNOWN", "NO_HIT", "NO_DETECTION", "PROVIDER_ERROR", "RATE_LIMITED", "OUTAGE", "UNASSESSED", "SOMETHING_NEW"]) {
      const m = semanticOf(s);
      expect(m.color).not.toBe(PAL.green);
      expect(m.label).not.toMatch(/^clean/i);
    }
  });
  it("MATCH / DETECTED is amber, never red or 'Malicious'", () => {
    for (const s of ["MATCH", "DETECTED"]) {
      expect(semanticOf(s).color).toBe(PAL.amber);
      expect(semanticOf(s).color).not.toBe(PAL.red);
      expect(semanticOf(s).label).not.toMatch(/malicious/i);
    }
  });
  it("red and green need evidence", () => {
    expect(semanticOf("MALICIOUS").color).toBe(PAL.grey);
    expect(semanticOf("CLEAN").color).toBe(PAL.grey);
    expect(semanticOf("MALICIOUS", [{ ref: "x" }])).toBe(SEMANTIC.MALICIOUS);
    expect(semanticOf("CLEAN", [{ ref: "known-good" }])).toBe(SEMANTIC.CLEAN);
  });
});

describe("connector style per causal state", () => {
  it("solid / dashed / dotted+?", () => {
    expect(connectorStyle("PROVEN_CAUSAL").dash).toBeNull();
    expect(connectorStyle("CORRELATED").dash).toBe("6 4");
    expect(connectorStyle("UNRESOLVED")).toEqual(expect.objectContaining({ mark: "?" }));
    expect(connectorStyle(null)).toBe(CONNECTOR.UNRESOLVED);
  });
  it("CORRELATED draws from the candidate parent, others from parent_lane", () => {
    expect(connectorSource({ causal_state: "CORRELATED", candidate_parent: "c", parent_lane: "ur" })).toBe("c");
    expect(connectorSource({ causal_state: "PROVEN_CAUSAL", parent_lane: "p" })).toBe("p");
    expect(connectorSource({ causal_state: "UNRESOLVED", parent_lane: null })).toBeNull();
  });
});

const VP = [
  { lane_id: "p1", mode: "EVENTS", count: 3, markers: [{ event_id: "a", kind: "PROCESS_START", t_ms: 0 }, { event_id: "b", kind: "FILE_CREATE", t_ms: 10 },
    { event_id: "c", kind: "NETWORK_CONNECT", t_ms: 20 }] },
  { lane_id: "file:x", mode: "EVENTS", count: 1, markers: [{ event_id: "b", kind: "FILE_CREATE", t_ms: 10 }] },
  { lane_id: "p2", mode: "BUCKETS", count: 7, buckets: [{ i: 0, from_ms: 0, to_ms: 10, count: 7, kinds: { FILE_WRITE: 6, PROCESS_START: 1 } }] },
];
const META = { p1: { lane_type: "PROCESS" }, "file:x": { lane_type: "FILE", touched_by: ["p1"] }, p2: { lane_type: "PROCESS" } };

describe("filtered-state indicator counts", () => {
  it("counts unique events (file rows touched by a process are not double counted)", () => {
    expect(filterSummary(VP, META, new Set())).toEqual({ active: false, shown: 10, total: 10, text: "10 events" });
  });
  it("Showing X of Y with an active filter, across marker and bucket lanes", () => {
    const s = filterSummary(VP, META, new Set(["FILE_WRITE", "FILE_CREATE"]));
    expect(s).toEqual(expect.objectContaining({ active: true, shown: 7, total: 10 }));
    expect(s.text).toBe("Showing 7 of 10 events");
  });
});

describe("isolation", () => {
  const lanes = [{ lane_id: "p1", lane_type: "PROCESS" }, { lane_id: "p2", lane_type: "PROCESS" },
    { lane_id: "file:x", lane_type: "FILE", touched_by: ["p1"] }, { lane_id: "file:y", lane_type: "FILE", touched_by: ["p2"] }];
  it("keeps lineage rows and files they touched; null when inactive", () => {
    expect([...isolateRows(lanes, ["p1"])].sort()).toEqual(["file:x", "p1"]);
    expect(isolateRows(lanes, null)).toBeNull();
    expect(isolateRows(lanes, []).size).toBe(0);
  });
});

describe("approval UI state text", () => {
  it("APPROVAL_REQUESTED → requested, not executed, owned by E1", () => {
    expect(approvalText({ state: "APPROVAL_REQUESTED", executed: false })).toBe("Approval requested — not executed. Execution is owned by E1.");
  });
  it("never renders a success/contained/verified outcome", () => {
    for (const st of ["ACCEPTED", "EXECUTED", "CONTAINED", "VERIFIED"]) {
      const t = approvalText({ state: st, executed: true });
      expect(t).toMatch(/owned by E1 and is not displayed as an outcome/);
      expect(t).not.toMatch(/success|succeeded|completed/i);
    }
  });
});

describe("UTC / local / DST formatting", () => {
  it("UTC is a fixed instant rendering", () => {
    expect(fmtInstant(Date.parse("2026-10-02T04:30:00Z"))).toBe("2026-10-02 04:30:00 UTC");
    expect(fmtInstant(1790915400123)).toBe("2026-10-02 04:30:00.123 UTC");
    expect(fmtInstant(null)).toBe("—");
  });
  it("EU DST 2026-03-29: two seconds apart in UTC, one hour jump locally, no phantom hour", () => {
    expect(fmtInstant(1774745999000, "LOCAL", "Europe/Berlin")).toBe("2026-03-29 01:59:59 GMT+1");
    expect(fmtInstant(1774746001000, "LOCAL", "Europe/Berlin")).toBe("2026-03-29 03:00:01 GMT+2");
    expect(fmtInstant(1774745999000, "UTC")).toBe("2026-03-29 00:59:59 UTC");
  });
  it("US DST end 2025-11-02: local 01:xx repeats, UTC order preserved", () => {
    expect(fmtInstant(1762063140000, "LOCAL", "America/New_York")).toBe("2025-11-02 01:59:00 EDT");
    expect(fmtInstant(1762063260000, "LOCAL", "America/New_York")).toBe("2025-11-02 01:01:00 EST");
  });
});

describe("grouped-marker expansion thresholds", () => {
  const lane = (gapMs, n = 4) => ({ mode: "EVENTS", markers: Array.from({ length: n }, (_, i) => ({ event_id: `e${i}`, kind: "FILE_WRITE", t_ms: i * gapMs })) });
  it("markers closer than 7px group; further apart stay individual", () => {
    expect(groupMarkers(lane(5), 0, 1000, 1000)).toHaveLength(1);
    expect(groupMarkers(lane(5), 0, 1000, 1000)[0]).toEqual(expect.objectContaining({ group: true, count: 4 }));
    expect(groupMarkers(lane(8), 0, 1000, 1000)).toHaveLength(4);
  });
  it("zooming in (narrower window) expands a group", () => {
    expect(groupMarkers(lane(5), 0, 1000, 1000)).toHaveLength(1);
    expect(groupMarkers(lane(5), 0, 500, 1000)).toHaveLength(4);
  });
  it("server buckets render as counted groups and honour kind filters", () => {
    const g = groupMarkers(VP[2], 0, 100, 1000, new Set(["FILE_WRITE"]));
    expect(g).toEqual([expect.objectContaining({ group: true, bucket: true, count: 6 })]);
    expect(groupMarkers(VP[2], 0, 100, 1000, new Set(["DNS_QUERY"]))).toEqual([]);
  });
});

describe("negative explainability", () => {
  it("names missing parent, correlation, spoof, file hash and attribution gaps", () => {
    const ids = (x) => cannotTell(x).map((c) => c.id);
    expect(ids({ lane: { lane_type: "UNRESOLVED_PARENT", causal_state: "UNRESOLVED" } })).toEqual(expect.arrayContaining(["parent-not-observed", "parent-unresolved"]));
    expect(ids({ lane: { lane_type: "PROCESS", causal_state: "CORRELATED" } })).toEqual(expect.arrayContaining(["parent-correlated", "S-1", "S-5"]));
    expect(ids({ lane: { lane_type: "PROCESS", causal_state: "PROVEN_CAUSAL", parent_spoof: { suspected: true } } })).toContain("spoof-unverified");
    expect(ids({ lane: { lane_type: "FILE" }, event: { kind: "FILE_CREATE", file: {} } })).toEqual(expect.arrayContaining(["S-2", "S-3"]));
    expect(ids({ lane: { lane_type: "UNATTRIBUTED_NETWORK" } })).toContain("no-attribution");
    expect(ids({ lane: { lane_type: "FILE" }, fileStatus: { reputation: [{ provider: "none_configured", state: "UNKNOWN" }] } })).toContain("rep-none_configured");
  });
});

describe("timeline placement of retro status and approvals", () => {
  it("retro entries land on rows carrying the subject hash; approvals on their target row", () => {
    const lanes = [{ lane_id: "p", lane_type: "PROCESS", sha256: "h" }, { lane_id: "file:f", lane_type: "FILE", sha256: "h" },
      { lane_id: "creator", lane_type: "PROCESS", sha256: "other" }];
    const r = retroMarkers([{ subject: "h", recorded_at: "2026-10-02T04:25:00Z" }], lanes);
    expect(r.map((x) => x.lane_id)).toEqual(["p", "file:f"]);
    expect(approvalMarkers([{ target: { lane_id: "p", t_ms: 5 } }, { target: { lane_id: "gone" } }], lanes, 0)).toHaveLength(1);
  });
});

it("contract-preview source flag defaults OFF", () => {
  expect(E3_DT_CONTRACT_PREVIEW).toBe(false);
});
