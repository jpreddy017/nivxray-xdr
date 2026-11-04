import { describe, expect, it } from "vitest";

import { cacheIdentityOf, suppressRepeats, windowFor } from "../repeatCache";
import { axisRowsOf, ROW_FILE, ROW_PROCESS } from "../graphModel";
import { msUTC } from "../instant";

const at = (iso) => ({ times: { source_time: iso } });

describe("Cisco per-file event cache · display-side, reversible", () => {
  it("uses the documented windows only", () => {
    expect(windowFor("CLEAN")).toBe(7 * 24 * 3600 * 1000);
    expect(windowFor("UNKNOWN")).toBe(3600 * 1000);
    expect(windowFor("MALICIOUS")).toBe(3600 * 1000);
  });

  it("fails to NO suppression where Cisco documents no rule", () => {
    for (const d of ["UNKNOWN_NOT_ASSESSED", "SUSPICIOUS", null, undefined,
                     "CONFLICTING"]) {
      expect(windowFor(d)).toBeNull();
    }
  });

  it("prefers content identity and declares a path surrogate", () => {
    expect(cacheIdentityOf({ attributes: { sha256: "ab" } }))
      .toMatchObject({ authority: "CONTENT_IDENTITY", downgraded: false });
    const surrogate = cacheIdentityOf({ label: "C:\\x\\a.log",
                                        process_node_id: "p" });
    expect(surrogate).toMatchObject({
      authority: "PATH_SURROGATE", downgraded: true,
      derivation_basis: "OBSERVED_PATH_PLUS_ACTOR_NOT_CONTENT" });
  });

  const rep = (iso, disp) => ({
    family: "FILE", label: "C:\\x\\a.exe", process_node_id: "p",
    disposition: disp, ...at(iso) });

  it("collapses repeats inside the window and counts them honestly", () => {
    const acts = [rep("2026-09-22 15:00:00.000", "MALICIOUS"),
                  rep("2026-09-22 15:10:00.000", "MALICIOUS"),
                  rep("2026-09-22 15:20:00.000", "MALICIOUS")];
    const out = suppressRepeats(acts, (a) => msUTC(a.times.source_time));
    expect(out).toHaveLength(1);
    expect(out[0].suppressedCount).toBe(2);
    expect(out[0].suppressed).toHaveLength(2);      // recoverable
    expect(out[0].suppressionBasis.authority).toBe("PATH_SURROGATE");
  });

  it("draws the event again once the window has passed", () => {
    const out = suppressRepeats(
      [rep("2026-09-22 15:00:00.000", "MALICIOUS"),
       rep("2026-09-22 16:30:00.000", "MALICIOUS")],
      (a) => msUTC(a.times.source_time));
    expect(out).toHaveLength(2);
  });

  it("suppresses nothing when the disposition has no documented rule", () => {
    const out = suppressRepeats(
      [rep("2026-09-22 15:00:00.000", "UNKNOWN_NOT_ASSESSED"),
       rep("2026-09-22 15:00:01.000", "UNKNOWN_NOT_ASSESSED")],
      (a) => msUTC(a.times.source_time));
    expect(out).toHaveLength(2);
    expect(out[0].suppressedCount).toBeUndefined();
  });
});

describe("Cisco process de-selection · presentation only", () => {
  const g = () => ({
    process_nodes: [
      { node_id: "p1", node_type: "PROCESS", depth: 0, label: "parent.exe",
        lifeline: { first_evidence_at: "2026-09-22 15:00:00.000",
                    last_evidence_at: "2026-09-22 15:05:00.000" } },
      { node_id: "p2", node_type: "PROCESS", depth: 1, label: "child.exe",
        parent_node_id: "p1",
        lifeline: { first_evidence_at: "2026-09-22 15:01:00.000",
                    last_evidence_at: "2026-09-22 15:02:00.000" } },
    ],
    activity_nodes: [],
    edges: [{ edge_id: "e1", relationship_type: "PROCESS_PROCESS",
              source_node_id: "p1", target_node_id: "p2" }],
    root_node_ids: ["p1"],
  });

  it("removes only the de-selected trajectory", () => {
    const rows = axisRowsOf(g(), { hiddenProcesses: new Set(["p1"]) });
    expect(rows.map((r) => r.nodeId)).toEqual(["p2"]);
    expect(rows[0].kind).toBe(ROW_PROCESS);
  });

  it("never re-parents a child onto a surviving ancestor", () => {
    const [child] = axisRowsOf(g(), { hiddenProcesses: new Set(["p1"]) });
    expect(child.parentNodeId).toBe("p1");     // unchanged claim
    expect(child.parentHidden).toBe(true);     // and it is declared hidden
  });

  it("keeps the child's own evidence and relationship intact", () => {
    const rows = axisRowsOf(g(), { hiddenProcesses: new Set(["p1"]) });
    expect(rows[0].lifeline.startMs).toBe(msUTC("2026-09-22T15:01:00Z"));
    expect(g().edges).toHaveLength(1);
  });

  it("file rows of a hidden process are not orphaned onto the axis", () => {
    const graph = g();
    graph.activity_nodes = [{ node_id: "a1", family: "FILE",
                              kind: "file_write", label: "C:\\x\\a.exe",
                              process_node_id: "p1", edge_id: "ef",
                              ...at("2026-09-22 15:03:00.000") }];
    graph.edges.push({ edge_id: "ef", relationship_type: "PROCESS_FILE",
                       source_node_id: "p1", target_node_id: "a1" });
    const rows = axisRowsOf(graph, { hiddenProcesses: new Set(["p1"]) });
    expect(rows.filter((r) => r.kind === ROW_FILE)).toHaveLength(0);
  });
});
