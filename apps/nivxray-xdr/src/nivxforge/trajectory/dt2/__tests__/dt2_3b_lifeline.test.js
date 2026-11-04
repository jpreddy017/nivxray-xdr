import { describe, expect, it } from "vitest";

import { msUTC } from "../instant";
import { laneRowsOf, lifelineOf } from "../graphModel";

describe("client instant parsing", () => {
  it("reads Sysmon's space form as UTC, not as the analyst's local time", () => {
    expect(msUTC("2026-09-22 15:43:31.770"))
      .toBe(msUTC("2026-09-22T15:43:31.770Z"));
    expect(msUTC("2026-09-22 15:43:31.770")).toBe(Date.UTC(2026, 8, 22, 15, 43, 31, 770));
  });

  it("accepts Windows 100 ns precision without rounding up", () => {
    expect(msUTC("2026-09-22T16:46:06.3636853Z"))
      .toBe(Date.UTC(2026, 8, 22, 16, 46, 6, 363));
  });

  it("converts an explicit offset to UTC", () => {
    expect(msUTC("2026-09-22T17:43:31.770+02:00"))
      .toBe(msUTC("2026-09-22 15:43:31.770"));
  });

  it("returns null rather than a guess", () => {
    for (const bad of [null, "", "not-a-time", undefined]) {
      expect(msUTC(bad)).toBeNull();
    }
  });
});

describe("observed evidence span drives the horizontal lifeline", () => {
  const node = (id, first, last, exit = null) => ({
    node_id: id, node_type: "PROCESS", label: id, depth: 0,
    lifeline: { first_evidence_at: first, last_evidence_at: last,
                end_time: exit, exit_observed: Boolean(exit),
                end_state: exit ? "EXIT_OBSERVED"
                  : "PROCESS_END_EVIDENCE_UNAVAILABLE" },
  });

  it("spans first→last observed evidence and stays NOT terminated", () => {
    const l = lifelineOf(node("a", "2026-09-22 15:43:10.000",
                              "2026-09-22 15:47:42.000"));
    expect(l.startMs).toBe(msUTC("2026-09-22T15:43:10Z"));
    expect(l.endMs).toBe(msUTC("2026-09-22T15:47:42Z"));
    expect(l.terminated).toBe(false);
    expect(l.semantics).toBe("OBSERVED_EVIDENCE_SPAN");
    expect(l.instant).toBe(false);
  });

  it("a single observed instant is an instant, not an invented span", () => {
    const l = lifelineOf(node("b", "2026-09-22 15:43:10.000",
                              "2026-09-22 15:43:10.000"));
    expect(l.startMs).toBe(l.endMs);
    expect(l.instant).toBe(true);
    expect(l.terminated).toBe(false);
  });

  it("only real termination evidence makes a span terminated", () => {
    const l = lifelineOf(node("c", "2026-09-22 15:43:10.000",
                              "2026-09-22 15:47:42.000",
                              "2026-09-22 15:48:00.000"));
    expect(l.terminated).toBe(true);
    expect(l.endMs).toBe(msUTC("2026-09-22T15:48:00Z"));
    expect(l.semantics).toBe("TERMINATION_OBSERVED");
  });

  it("carries the span onto the row the canvas draws", () => {
    const g = { process_nodes: [node("a", "2026-09-22 15:43:10.000",
                                     "2026-09-22 15:47:42.000")],
                activity_nodes: [], edges: [], root_node_ids: ["a"] };
    const [row] = laneRowsOf(g);
    expect(row.lifeline.endMs - row.lifeline.startMs).toBe(272000);
  });
});
