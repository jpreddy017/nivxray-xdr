// DT time model tests T1-T15 (+ parity). Run: node --test apps/nivxray-xdr/src/nivxforge/trajectory/dt2/__tests__/timeWindow.node-test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  DAY, HOUR, MODES, SKEW_TOLERANCE_MS, advanceRolling, binsInDomain, calendarDayWindow, capOf, classifyObservations,
  covers, dayStrip, daysTouched, evidenceBoundedWindow, evidenceExtent, futurePart, hourMarks, initialWindow,
  navBounds, navDomain, observedAt, pageBudget, parseUtc, presentIn, queryInterval, rollingWindow, tailWindow,
  truncationOf, utcDayStart, windowLabel,
} from "../timeWindow.mjs";

const REF = Date.parse("2026-10-02T04:30:00Z");          // 10:00 IST
const at = (iso) => Date.parse(iso);

test("T1 · default view is rolling 24 h to the reference time and shows current-day observations", () => {
  const v = initialWindow({ refNow: REF });
  assert.equal(v.mode, MODES.ROLLING);
  assert.equal(v.t1, REF);
  assert.equal(v.t0, REF - DAY);
  const c = classifyObservations([at("2026-10-02T04:29:00Z"), at("2026-10-02T00:05:00Z")], v, REF);
  assert.equal(c.inWindow, 2);
});

test("T2 · a rolling window crossing UTC midnight joins both days' bins on absolute time", () => {
  const v = rollingWindow(REF);
  assert.deepEqual(daysTouched(v), ["2026-10-01", "2026-10-02"]);
  const bins = new Map([["2026-10-01", [{ bin: 230, total: 4 }, { bin: 10, total: 9 }]],
                        ["2026-10-02", [{ bin: 40, total: 2 }, { bin: 200, total: 1 }]]]);
  const out = binsInDomain(bins, v);
  assert.deepEqual(out.map((b) => b.key), ["2026-10-01:230", "2026-10-02:40"]);
  assert.equal(out[0].t, at("2026-10-01T00:00:00Z") + 230 * (DAY / 240));
  assert.ok(out.every((b) => b.mid >= v.t0 && b.mid <= v.t1));
});

test("T3 · calendar day only on explicit selection; today's remainder is marked not-yet-occurred", () => {
  assert.notEqual(initialWindow({ refNow: REF }).mode, MODES.CALENDAR_DAY);
  const d = calendarDayWindow(REF);
  assert.equal(d.mode, MODES.CALENDAR_DAY);
  assert.equal(d.t0, at("2026-10-02T00:00:00Z"));
  assert.equal(d.t1, at("2026-10-03T00:00:00Z"));
  assert.deepEqual(futurePart(d, REF), { from: REF, to: d.t1 });
  assert.equal(futurePart(calendarDayWindow(REF - DAY), REF), null);
});

test("T4 · stalled delivery: window stays at the reference time and says why it is empty", () => {
  const newest = at("2026-09-29T22:00:00Z");
  const v = initialWindow({ refNow: REF });
  assert.equal(v.t1, REF);
  const ex = evidenceExtent(v, at("2026-09-20T00:00:00Z"), newest);
  assert.equal(ex.state, "NONE_IN_WINDOW");
  assert.match(ex.statement, /Absence is not inactivity/);
  const strip = dayStrip(REF);
  assert.equal(strip.length, 30);
  assert.equal(strip[29].key, "2026-10-02");
  assert.equal(strip[29].referenceDay, true);
});

test("T5 · mixed backlog: late-delivered old observations are placed on their observed day", () => {
  const backlog = { observed_at: "2026-09-27T08:00:00Z", ingested_at: "2026-10-02T04:20:00Z" };
  const live = { observed_at: "2026-10-02T04:10:00Z", ingested_at: "2026-10-02T04:10:02Z" };
  const v = rollingWindow(REF);
  const c = classifyObservations([backlog, live].map(observedAt), v, REF);
  assert.deepEqual([c.inWindow, c.before], [1, 1]);
  const ex = evidenceExtent(v, observedAt(backlog), observedAt(live), REF);
  assert.equal(ex.state, "ENDS_BEFORE_WINDOW_END");
  assert.equal(ex.to, observedAt(live));
  assert.equal(evidenceExtent(v, observedAt(backlog), REF - 6 * 60_000, REF).state, "REACHES_WINDOW_END",
               "a 6-min delivery cadence is not reported as a gap");
  const today = calendarDayWindow(REF);
  assert.equal(evidenceExtent(today, observedAt(backlog), observedAt(live), REF).trailing.to, REF,
               "the gap ends at the reference time, not at the end of today");
});

test("T6 · ingested_at / received_at are never substituted for observed time", () => {
  assert.equal(observedAt({ ingested_at: "2026-10-02T04:00:00Z", received_at: "2026-10-02T04:00:00Z" }), null);
  assert.equal(observedAt({ timestamp: "2026-10-01T10:00:00Z", ingested_at: "2026-10-02T04:00:00Z" }),
               at("2026-10-01T10:00:00Z"));
  assert.equal(observedAt({ timestamp_instant_ms: 5, timestamp: "2026-10-01T10:00:00Z" }), 5);
});

test("T7 · clock skew within tolerance is reachable and not flagged future", () => {
  const t = REF + 90_000;
  const c = classifyObservations([t], rollingWindow(REF), REF);
  assert.deepEqual([c.future, c.after, c.skewed], [0, 1, 1]);
  assert.equal(navBounds({ min: REF - 30 * DAY, max: REF - 3 * DAY }, REF).max, REF + SKEW_TOLERANCE_MS);
  assert.ok(t <= navBounds({}, REF).max);
});

test("T8 · future observations beyond tolerance are counted and never stretch the window", () => {
  const v = rollingWindow(REF);
  const c = classifyObservations([REF + 3 * HOUR, REF - HOUR, NaN], v, REF);
  assert.deepEqual([c.future, c.inWindow, c.invalid], [1, 1, 1]);
  assert.equal(v.t1, REF);
  assert.equal(advanceRolling(v, REF).t1, REF);
});

test("T9 · results are identical under UTC and Asia/Kolkata (timezone is presentation only)", () => {
  const run = () => {
    const v = rollingWindow(REF);
    return JSON.stringify({ v, d: calendarDayWindow(REF), days: daysTouched(v), marks: hourMarks(v).map((m) => m.label),
                            p: parseUtc("2026-10-02 04:00:00.000"), strip: dayStrip(REF).map((s) => s.key) });
  };
  const prev = process.env.TZ;
  process.env.TZ = "UTC";
  const utc = run();
  process.env.TZ = "Asia/Kolkata";
  const ist = run();
  process.env.TZ = prev ?? "";
  assert.equal(ist, utc);
  assert.match(presentIn(REF, "Asia/Kolkata"), /02\/10\/2026, 10:00:00/);
  assert.match(presentIn(REF, "UTC"), /02\/10\/2026, 04:30:00/);
});

test("T10 · zone-less sensor strings parse as UTC, offsets are honoured", () => {
  assert.equal(parseUtc("2026-10-02 04:00:00.000"), at("2026-10-02T04:00:00Z"));
  assert.equal(parseUtc("2026-10-02T09:30:00+05:30"), at("2026-10-02T04:00:00Z"));
  assert.equal(parseUtc(""), null);
  assert.equal(parseUtc("garbage"), null);
});

test("T11 · the API query interval always covers the view and stops at reference + tolerance", () => {
  const v = rollingWindow(REF);
  const b = navBounds({ min: REF - 10 * DAY }, REF);
  const q = queryInterval(v, 0.3, b);
  assert.ok(covers(q, v));
  assert.equal(q.t1, REF + SKEW_TOLERANCE_MS);
  assert.equal(q.t0, v.t0 - 0.3 * DAY);
  const today = calendarDayWindow(REF);
  assert.ok(covers(queryInterval(today, 0.3, b), today), "a calendar day past now is still fully queried");
  assert.equal(queryInterval(null), null);
});

test("T12 · navigator domain always contains the view (band, canvas and query agree)", () => {
  const cases = [rollingWindow(REF), calendarDayWindow(REF - 3 * DAY), { t0: REF - 2 * HOUR, t1: REF - HOUR },
    { t0: at("2026-09-20T05:00:00Z"), t1: at("2026-09-20T07:00:00Z") },
    { t0: at("2026-09-20T22:00:00Z"), t1: at("2026-09-21T02:00:00Z") }, rollingWindow(REF, 7 * DAY),
    evidenceBoundedWindow(at("2026-09-20T22:00:00Z"), at("2026-09-21T01:00:00Z"))];
  for (const v of cases) {
    const d = navDomain(v, REF);
    assert.ok(covers(d, v), `${windowLabel(v)} ⊄ ${windowLabel(d)}`);
    assert.ok(covers(queryInterval(v, 0.3, navBounds({}, REF)), v));
  }
  assert.equal(navDomain({ t0: REF - 2 * HOUR, t1: REF - HOUR }, REF).mode, MODES.ROLLING);
  assert.equal(navDomain(calendarDayWindow(REF - 3 * DAY), REF).mode, MODES.CALENDAR_DAY);
});

test("T13 · only a rolling view follows the clock", () => {
  const later = REF + 5 * 60_000;
  assert.equal(advanceRolling(rollingWindow(REF), later).t1, later);
  for (const v of [calendarDayWindow(REF), { t0: 1, t1: 2 }, initialWindow({ refNow: REF, at: REF - DAY })]) {
    assert.equal(advanceRolling(v, later), v);
  }
});

test("T14 · labels name the mode; evidence-bounded never reads as 'last 24 h'", () => {
  assert.match(windowLabel(rollingWindow(REF)), /^Rolling 24\.0 h to reference time/);
  assert.match(windowLabel(calendarDayWindow(REF)), /^Calendar day 2026-10-02 \(UTC\)/);
  assert.match(windowLabel(evidenceBoundedWindow(REF - DAY, REF)), /Evidence-bounded 24\.0 h \(not "last 24 h"\)/);
  assert.match(windowLabel(initialWindow({ refNow: REF, linked: { t0: 1, t1: 2 } })), /^Linked window/);
  assert.match(windowLabel({ t0: 0, t1: HOUR }), /^Analyst window 1\.0 h/);
  assert.equal(windowLabel(null), "Window UNKNOWN");
});

test("T15 · hour marks sit on real UTC boundaries and name the midnight they cross", () => {
  const m = hourMarks(rollingWindow(REF));
  assert.equal(m.length, 24);
  assert.ok(m.every((x) => x.t % HOUR === 0));
  const mid = m.find((x) => x.midnight);
  assert.equal(mid.t, utcDayStart(REF));
  assert.equal(mid.label, "Oct 2");
  const week = hourMarks(rollingWindow(REF, 7 * DAY));
  assert.ok(week.every((x) => x.t % DAY === 0) && week.length === 7);
});

test("T16 · an oldest-first capped page is reported as truncated, never as absence", () => {
  const v = rollingWindow(REF);
  const resp = { has_more: true, matched_in_window: 6000,
                 events: [{ timestamp: "2026-10-01T03:00:00Z" }, { timestamp_instant_ms: REF - 20 * HOUR }] };
  const cap = capOf(resp);
  assert.deepEqual([cap.hasMore, cap.returned, cap.matched, cap.loadedTo], [true, 2, 6000, REF - 20 * HOUR]);
  const tr = truncationOf(cap, v);
  assert.equal(tr.state, "TRUNCATED_OLDEST_FIRST");
  assert.deepEqual(tr.hidden, { from: REF - 20 * HOUR, to: REF });
  assert.match(tr.statement, /NOT drawn \(not absent\)/);
  assert.equal(truncationOf(capOf({ has_more: false, events: [] }), v).state, "COMPLETE");
});

test("T17 · tail window keeps the newest evidence inside the page budget and ends at the reference time", () => {
  const v = rollingWindow(REF);
  const bins = [];
  for (let t = utcDayStart(v.t0); t < REF; t += DAY / 240) bins.push({ t, total: 30 });
  const budget = pageBudget(2500, 0.3);
  assert.equal(budget, 1562);
  const tw = tailWindow(bins, v, budget);
  assert.equal(tw.t1, REF);
  assert.equal(tw.mode, MODES.ROLLING);
  assert.ok(tw.estimated <= budget && tw.estimated > budget - 31);
  assert.ok(tw.t1 - tw.t0 < v.t1 - v.t0);
  assert.equal(tailWindow([], v, budget).t0, REF - 12 * HOUR, "no bins yet → halve, still ending at reference");
  assert.equal(tailWindow(bins, { t0: REF - DAY, t1: REF }, budget).mode, MODES.ANALYST);
});

test("P1 · vendored V2 copy is byte-identical (the two DT implementations cannot diverge silently)", () => {
  const here = fileURLToPath(new URL("../timeWindow.mjs", import.meta.url));
  const v2 = fileURLToPath(new URL("../../../../../../../frontend/src/v2/investigation/timeWindow.mjs", import.meta.url));
  assert.equal(readFileSync(v2, "utf8"), readFileSync(here, "utf8"));
});
