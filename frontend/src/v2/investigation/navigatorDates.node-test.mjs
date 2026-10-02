// Run: node --test frontend/src/v2/investigation/*.node-test.mjs  (no install needed)
import test from "node:test";
import assert from "node:assert/strict";
import { RANGE_UNKNOWN, buildDateStrip, buildTicks, densityPoints, spanLabel, timelineTitle } from "./navigatorDates.mjs";

const SEP = { start: Date.parse("2026-09-05T09:00:00Z"), end: Date.parse("2026-09-05T09:03:20Z") };

test("navigator dates derive from the trajectory bounds (September fixture)", () => {
  const s = buildDateStrip(SEP);
  assert.equal(s.state, "AVAILABLE");
  assert.equal(s.days.length, 30);
  assert.equal(s.days[s.caseDayIdx].iso, "2026-09-05");
  assert.equal(s.days[0].iso, "2026-08-07");
  assert.equal(spanLabel(SEP), "Sep 5");
  assert.equal(timelineTitle(SEP), "TIMELINE · 2026-09-05 UTC");
});

test("Jun/Jul dates cannot appear for September fixtures", () => {
  const s = buildDateStrip(SEP);
  const marks = s.days.map((d) => d.monthMark).filter(Boolean);
  assert.deepEqual(marks, ["Aug", "Sep"]);
  assert.ok(s.days.every((d) => !["Jun", "Jul"].includes(d.month)));
  assert.ok(!JSON.stringify(s).includes("Jul") && !JSON.stringify(s).includes("Jun"));
});

test("unknown bounds are UNKNOWN, never a hard-coded fallback", () => {
  for (const b of [null, { start: 0, end: 1 }, { start: NaN, end: 5 }]) {
    const s = buildDateStrip(b);
    assert.equal(s.state, "UNKNOWN");
    assert.equal(s.reason, RANGE_UNKNOWN);
    assert.deepEqual(s.days, []);
    assert.deepEqual(buildTicks(b), []);
    assert.equal(densityPoints([1, 2], b), null);
  }
  assert.equal(timelineTitle(null), "TIMELINE · TIME RANGE UNKNOWN");
});

test("hour ticks span the case, not a fixed 00:00-24:00 day", () => {
  const t = buildTicks(SEP);
  assert.equal(t[0].label, "09:00:00");
  assert.equal(t[t.length - 1].label, "09:03:20");
  assert.ok(!t.some((x) => x.label === "24:00"));
});

test("multi-day span marks every case day and labels the range", () => {
  const b = { start: Date.parse("2026-08-30T23:00:00Z"), end: Date.parse("2026-09-02T01:00:00Z") };
  const s = buildDateStrip(b);
  assert.deepEqual(s.days.filter((d) => d.inCase).map((d) => d.iso), ["2026-08-30", "2026-08-31", "2026-09-01", "2026-09-02"]);
  assert.equal(spanLabel(b), "Aug 30–Sep 2");
});

test("density derives from observed timestamps only", () => {
  assert.equal(densityPoints([], SEP), null);
  assert.equal(densityPoints([SEP.start, SEP.end], SEP, 4), "0,2.0 467,22.0 933,22.0 1400,2.0");
});
