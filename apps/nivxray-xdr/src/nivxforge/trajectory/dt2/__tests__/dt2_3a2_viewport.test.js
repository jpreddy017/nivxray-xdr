/**
 * DT2-3a.2 · TIME DOMAIN / VIEWPORT PROJECTION — focused regression.
 *
 * These tests exist because concentrated evidence was being projected on
 * a full-day primary viewport, so real timestamp differences became a
 * few pixels and the pane read as a vertical spine instead of Cisco's
 * horizontal trajectory.
 */
import { describe, expect, it } from "vitest";

import { MAX_WINDOW_MS, MIN_WINDOW_MS, evidenceWindow, projectX,
         tickStepFor } from "../navigation";
import { rowsInWindow } from "../graphModel";

const DAY = 86_400_000;
const day = Date.UTC(2026, 5, 1);
const at = (h, m = 0, s = 0, ms = 0) => day + h * 3_600_000 + m * 60_000
  + s * 1000 + ms;

const row = (id, startMs, endMs, { parent = null, acts = [] } = {}) => ({
  nodeId: id, parentNodeId: parent,
  lifeline: { startMs, endMs, terminated: false,
              semantics: "OBSERVED_EVIDENCE_SPAN" },
  activities: acts.map((t, i) => ({ node_id: `${id}:a${i}`, family: "FILE",
                                    times: { ordering_time:
                                      new Date(t).toISOString() } })),
});

describe("1 · concentrated evidence does not collapse on a full day", () => {
  it("opens a window far smaller than the day", () => {
    const w = evidenceWindow(at(10, 0, 0, 730), at(10, 0, 0, 820),
                             { dayStart: day });
    expect(w.t1 - w.t0).toBeLessThan(DAY / 100);
    expect(w.t1 - w.t0).toBeGreaterThanOrEqual(MIN_WINDOW_MS);
  });

  it("gives a 90ms evidence span a usable share of the viewport", () => {
    const lo = at(10, 0, 0, 730);
    const hi = at(10, 0, 0, 820);
    const dayView = { t0: day, t1: day + DAY };
    const focused = evidenceWindow(lo, hi, { dayStart: day });
    const pct = (v) => ((hi - lo) / (v.t1 - v.t0)) * 100;
    expect(pct(dayView)).toBeLessThan(0.001);
    expect(pct(focused)).toBeGreaterThan(pct(dayView) * 100);
  });

  it("uses a bounded time padding, never a pixel or index rule", () => {
    const lo = at(1);
    const hi = at(3);
    const w = evidenceWindow(lo, hi, { dayStart: day });
    expect(w.t0).toBe(lo - (hi - lo) * 0.35);
    expect(w.t1).toBe(hi + (hi - lo) * 0.35);
  });

  it("caps the first window and clamps to the selected day", () => {
    const w = evidenceWindow(day + 1000, day + DAY - 1000,
                             { dayStart: day });
    expect(w.t1 - w.t0).toBeLessThanOrEqual(MAX_WINDOW_MS);
    const edge = evidenceWindow(day + 10, day + 20, { dayStart: day });
    expect(edge.t0).toBeGreaterThanOrEqual(day);
    expect(edge.t1).toBeLessThanOrEqual(day + DAY);
  });
});

describe("2 · X position derives from the timestamp", () => {
  const W = 1200;
  const LEFT = 238;
  it("is ordered and proportional to time", () => {
    const w = evidenceWindow(at(10, 0, 0, 730), at(10, 0, 0, 820),
                             { dayStart: day });
    const xs = [730, 760, 790, 810, 820]
      .map((ms) => projectX(at(10, 0, 0, ms), w.t0, w.t1, LEFT, W));
    for (let i = 1; i < xs.length; i += 1) {
      expect(xs[i]).toBeGreaterThan(xs[i - 1]);
    }
    const t = (ms) => at(10, 0, 0, ms);
    const ratio = (t(790) - t(730)) / (t(820) - t(730));
    expect((xs[2] - xs[0]) / (xs[4] - xs[0])).toBeCloseTo(ratio, 10);
  });

  it("returns null rather than guessing a position", () => {
    expect(projectX(null, 0, 10, 0, 100)).toBe(null);
    expect(projectX(5, 10, 10, 0, 100)).toBe(null);
  });
});

describe("3 · changing the sub-range reprojects the trajectory", () => {
  it("moves X when the viewport moves, with the timestamp untouched", () => {
    const t = at(10, 0, 0, 800);
    const a = projectX(t, at(10), at(11), 0, 1000);
    const b = projectX(t, at(10, 0, 0, 700), at(10, 0, 0, 900), 0, 1000);
    expect(a).not.toBeCloseTo(b, 3);
    expect(b).toBeCloseTo(500, 6);
  });
});

describe("4 · no timestamp mutation", () => {
  it("never writes back to the inputs", () => {
    const lo = at(10);
    const hi = at(10, 0, 30);
    const w = evidenceWindow(lo, hi, { dayStart: day });
    expect(lo).toBe(at(10));
    expect(hi).toBe(at(10, 0, 30));
    expect(w.t0).toBeLessThan(lo);
    expect(w.t1).toBeGreaterThan(hi);
  });

  it("refuses to invent a window without real bounds", () => {
    expect(evidenceWindow(null, null)).toBe(null);
    expect(evidenceWindow(NaN, at(10))).toBe(null);
  });
});

describe("5 · last observed evidence is not a termination", () => {
  it("keeps the row's span open and its semantics observed", () => {
    const r = row("p1", at(10), at(10, 0, 0, 90));
    expect(r.lifeline.terminated).toBe(false);
    expect(r.lifeline.semantics).toBe("OBSERVED_EVIDENCE_SPAN");
    const kept = rowsInWindow([r], at(9), at(11));
    expect(kept[0].lifeline.endMs).toBe(at(10, 0, 0, 90));
  });
});

describe("6 · rows outside the window are not shown", () => {
  it("drops a row with no evidence in the viewport", () => {
    const inside = row("in", at(10), at(10, 1));
    const outside = row("out", at(20), at(20, 1));
    const kept = rowsInWindow([inside, outside], at(9, 30), at(10, 30));
    expect(kept.map((r) => r.nodeId)).toEqual(["in"]);
  });

  it("keeps a row whose only evidence is an activity in the window", () => {
    const r = row("acts", at(20), at(20), { acts: [at(10, 5)] });
    const kept = rowsInWindow([r], at(10), at(10, 30));
    expect(kept.map((x) => x.nodeId)).toEqual(["acts"]);
  });
});

describe("7 · evidenced relationship context stays visible", () => {
  it("keeps the parent of a visible child even with no own evidence", () => {
    const parent = row("parent", null, null);
    const child = row("child", at(10), at(10, 1), { parent: "parent" });
    const kept = rowsInWindow([parent, child], at(9), at(11));
    expect(kept.map((r) => r.nodeId)).toEqual(["parent", "child"]);
  });
});

describe("8 · structural bands and tick scale", () => {
  it("labels a millisecond window in milliseconds, not hours", () => {
    expect(tickStepFor(200)).toBeLessThan(1000);
    expect(tickStepFor(90)).toBeLessThan(100);
    expect(tickStepFor(13 * 3_600_000)).toBeGreaterThanOrEqual(3_600_000);
  });

  it("an empty row set is structure, not an error", () => {
    expect(rowsInWindow([], at(10), at(11))).toEqual([]);
    expect(rowsInWindow(null, at(10), at(11))).toEqual([]);
  });
});
