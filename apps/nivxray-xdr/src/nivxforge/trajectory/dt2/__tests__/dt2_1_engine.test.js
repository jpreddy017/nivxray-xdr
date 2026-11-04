/**
 * DT2-1 interaction-engine unit suite.
 *
 * Case ids map to the owner's 50-case matrix; the cases marked
 * PLAYWRIGHT / PYTEST / MANUAL-HARDWARE live in their own harnesses and
 * are NOT claimed here.
 */
import { describe, expect, it, vi } from "vitest";

import {
  DELTA_MODE, GOV, INTENT, LINE_TO_PX, PAGE_TO_PX, SOURCE,
  classifyIntent, classifySource, createGovernor, normalizeDelta,
  normalizeWheel,
} from "../pointer";
import {
  MAX_SPAN_MS, MIN_SPAN_MS, MS, ZOOM_LEVELS, centreOn, clampToBounds,
  fitRange, isValidWindow, levelOf, moveRange, panByFraction,
  resizeRangeEnd, resizeRangeStart, timeAtX, zoomBySteps, zoomToLevel,
} from "../viewport";
import {
  SELECTION_STATE, isDetection, processInstanceIdOf,
  relationshipContextOf, sameProcessInstance, sameRelationshipContext,
  selectionState, sortObservations, stepDetection, stepObservation,
} from "../navigation";
import {
  REQ, createCoordinator, prefetchTargets, requestKey,
} from "../requests";
import {
  HISTORY, PUSH_KEYS, assertNoSensitive, deserialize, historyMode,
  restore, serialize,
} from "../urlState";
import {
  WINDOW_STATE, emptinessMeaning, preservesContext, windowStateOf,
} from "../loadState";
import {
  assertNavigationOnly, bucketAt, bucketsOf, coverageOf, retentionBounds,
  spikes, windowForBucket,
} from "../density";
import { MAX_RENDERED_LANES, capList, clampLaneStart, laneWindow } from "../bounded";

const T0 = Date.parse("2026-06-01T00:00:00Z");
const DAY = { t0: T0, t1: T0 + MS.d };
const BOUNDS = { min: T0 - 29 * MS.d, max: T0 + MS.d };
const VIEWPORT = 760;

const wheel = (o) => ({ deltaX: 0, deltaY: 0, deltaMode: DELTA_MODE.PIXEL,
                        ctrlKey: false, metaKey: false, shiftKey: false,
                        ...o });

describe("U01-U03 · deltaMode normalization", () => {
  it("U01 pixel delta passes through unchanged", () => {
    expect(normalizeDelta(120, DELTA_MODE.PIXEL)).toBe(120);
    expect(normalizeWheel(wheel({ deltaY: 120 })).dyPx).toBe(120);
  });

  it("U02 line delta is converted, never treated as pixels", () => {
    expect(normalizeDelta(3, DELTA_MODE.LINE)).toBe(3 * LINE_TO_PX);
    const n = normalizeWheel(wheel({ deltaY: 3,
                                     deltaMode: DELTA_MODE.LINE }));
    expect(n.dyPx).toBe(48);
    expect(n.source).toBe(SOURCE.MOUSE_WHEEL);
  });

  it("U03 page delta is converted and bounded by the governor", () => {
    expect(normalizeDelta(1, DELTA_MODE.PAGE)).toBe(PAGE_TO_PX);
    const g = createGovernor(() => 0);
    const f = g.governPan(PAGE_TO_PX, VIEWPORT, SOURCE.MOUSE_WHEEL);
    expect(Math.abs(f)).toBeLessThanOrEqual(GOV.PAN_MAX_FRACTION_PER_EVENT);
  });
});

describe("U04-U08 · sensitivity", () => {
  it("U04 a small input produces a small movement", () => {
    const g = createGovernor(() => 0);
    const f = g.governPan(6, VIEWPORT, SOURCE.TRACKPAD);
    expect(Math.abs(f)).toBeGreaterThan(0);
    expect(Math.abs(f)).toBeLessThan(0.01);
    const moved = panByFraction(DAY, f, BOUNDS);
    expect(Math.abs(moved.view.t0 - DAY.t0)).toBeLessThan(15 * MS.m);
  });

  it("U05 a very large input is clamped, not proportional", () => {
    const g = createGovernor(() => 0);
    const f = g.governPan(100000, VIEWPORT, SOURCE.MOUSE_WHEEL);
    expect(Math.abs(f)).toBe(GOV.PAN_MAX_FRACTION_PER_EVENT);
  });

  it("U06 one mouse notch never moves a 24 h window by hours", () => {
    const g = createGovernor(() => 0);
    const f = g.governPan(-100, VIEWPORT, SOURCE.MOUSE_WHEEL);
    const moved = panByFraction(DAY, f, BOUNDS);
    const deltaMin = Math.abs(moved.view.t0 - DAY.t0) / MS.m;
    expect(deltaMin).toBeGreaterThan(1);
    expect(deltaMin).toBeLessThan(90);
  });

  it("U07 a trackpad burst is bounded by the rolling budget", () => {
    let t = 0;
    const g = createGovernor(() => t);
    let total = 0;
    for (let i = 0; i < 200; i += 1) {
      total += Math.abs(g.governPan(12, VIEWPORT, SOURCE.TRACKPAD));
      t += 1;
    }
    expect(total).toBeLessThanOrEqual(
      GOV.PAN_MAX_FRACTION_PER_WINDOW * 3 + 1e-9);
  });

  it("U08 medium input is proportional between the bounds", () => {
    const g = createGovernor(() => 0);
    const small = Math.abs(g.governPan(10, VIEWPORT, SOURCE.MOUSE_WHEEL));
    g.reset();
    const big = Math.abs(g.governPan(40, VIEWPORT, SOURCE.MOUSE_WHEEL));
    expect(big).toBeGreaterThan(small * 3.5);
    expect(big).toBeLessThan(small * 4.5);
  });
});

describe("U09-U11 · source and intent classification", () => {
  it("U09 low/fractional pixel deltas read as trackpad-like", () => {
    expect(classifySource(wheel({ deltaY: 8 })).source)
      .toBe(SOURCE.TRACKPAD);
    expect(classifySource(wheel({ deltaY: 118.5 })).source)
      .toBe(SOURCE.TRACKPAD);
  });

  it("U10 notch-magnitude pixel deltas read as mouse-like", () => {
    expect(classifySource(wheel({ deltaY: 100 })).source)
      .toBe(SOURCE.MOUSE_WHEEL);
  });

  it("U11 intent: ctrl/meta zoom, shift or dominant dx pan, else lanes",
     () => {
       expect(classifyIntent(wheel({ deltaY: 100, ctrlKey: true })))
         .toBe(INTENT.ZOOM);
       expect(classifyIntent(wheel({ deltaY: 100, metaKey: true })))
         .toBe(INTENT.ZOOM);
       expect(classifyIntent(wheel({ deltaY: 100, shiftKey: true })))
         .toBe(INTENT.TIME_PAN);
       expect(classifyIntent(wheel({ deltaX: 60, deltaY: 4 })))
         .toBe(INTENT.TIME_PAN);
       expect(classifyIntent(wheel({ deltaY: 100 })))
         .toBe(INTENT.LANE_SCROLL);
     });
});

describe("U12-U16 · zoom", () => {
  it("U12 zoom is anchored: the anchor keeps its screen fraction", () => {
    const anchor = T0 + 6 * MS.h;
    const fracBefore = (anchor - DAY.t0) / (DAY.t1 - DAY.t0);
    const z = zoomToLevel(DAY, levelOf(MS.h), anchor, null);
    const fracAfter = (anchor - z.view.t0) / (z.view.t1 - z.view.t0);
    expect(z.anchorPreserved).toBe(true);
    expect(Math.abs(fracAfter - fracBefore)).toBeLessThan(1e-6);
  });

  it("U13 zoom is bounded to the ladder (30 d ceiling, 1 s floor)", () => {
    const out = zoomBySteps(DAY, 99, null, null);
    expect(out.view.t1 - out.view.t0).toBe(MAX_SPAN_MS);
    const deep = zoomBySteps(DAY, -99, null, null);
    expect(deep.view.t1 - deep.view.t0).toBe(MIN_SPAN_MS);
    expect(ZOOM_LEVELS[0]).toBe(30 * MS.d);
  });

  it("U14 one governed wheel event is at most one zoom level", () => {
    const g = createGovernor(() => 0);
    expect(Math.abs(g.governZoom(100000)))
      .toBeLessThanOrEqual(GOV.ZOOM_MAX_STEPS_PER_EVENT);
  });

  it("U15 a 50-event trackpad zoom burst cannot detonate the scale", () => {
    let t = 0;
    const g = createGovernor(() => t);
    let view = DAY;
    for (let i = 0; i < 50; i += 1) {
      const steps = g.governZoom(10);
      if (steps) view = zoomBySteps(view, steps, T0 + 12 * MS.h, null).view;
      t += 8;
    }
    expect(view.t1 - view.t0).toBeLessThanOrEqual(MAX_SPAN_MS);
    expect(view.t1 - view.t0).toBeGreaterThanOrEqual(MIN_SPAN_MS);
  });

  it("U16 zoom does not pan: the anchor stays inside the window", () => {
    const anchor = T0 + 23 * MS.h;
    const z = zoomToLevel(DAY, levelOf(5 * MS.m), anchor, null);
    expect(anchor).toBeGreaterThanOrEqual(z.view.t0);
    expect(anchor).toBeLessThanOrEqual(z.view.t1);
  });
});

describe("U17-U20 · pan", () => {
  it("U17 pan preserves the scale exactly", () => {
    const p = panByFraction(DAY, 0.05, null);
    expect(p.spanPreserved).toBe(true);
    expect(p.view.t1 - p.view.t0).toBe(DAY.t1 - DAY.t0);
  });

  it("U18 pan is bounded by available evidence", () => {
    const p = panByFraction(DAY, 500, BOUNDS);
    expect(p.view.t1).toBeLessThanOrEqual(BOUNDS.max);
    expect(p.atEnd).toBe(true);
    const q = panByFraction(DAY, -500, BOUNDS);
    expect(q.view.t0).toBeGreaterThanOrEqual(BOUNDS.min);
    expect(q.atStart).toBe(true);
  });

  it("U19 unprovable bounds never clamp (no invented retention)", () => {
    const p = panByFraction(DAY, 100, { min: null, max: null });
    expect(p.clamped).toBe(false);
  });

  it("U20 a window wider than the evidence is left exactly alone", () => {
    const wide = { t0: T0 - 40 * MS.d, t1: T0 + 20 * MS.d };
    const c = clampToBounds(wide, { min: T0, max: T0 + MS.d });
    expect(c.view).toEqual(wide);
    expect(c.clamped).toBe(false);
    expect(c.atStart).toBe(true);
    expect(c.atEnd).toBe(true);
  });

  it("U20b a 6px gesture on an over-wide window cannot re-centre it",
     () => {
       /** The b01 defect: `clampToBounds` used to reposition an
        *  over-wide window onto the evidence midpoint, which let a
        *  three-event 6 px gesture relocate a 24 h investigation by
        *  18.4 h — straight past the governor. */
       const g = createGovernor(() => 0);
       const evidence = { min: T0 + 17 * MS.h, max: T0 + 19 * MS.h };
       let v = DAY;
       for (let i = 0; i < 3; i += 1) {
         v = panByFraction(v, g.governPan(-6, VIEWPORT, SOURCE.TRACKPAD),
                           evidence).view;
       }
       const moved = Math.abs(v.t0 - DAY.t0);
       expect(moved).toBeGreaterThan(0);
       expect(moved).toBeLessThanOrEqual(
         (DAY.t1 - DAY.t0) * GOV.PAN_MAX_FRACTION_PER_WINDOW);
       expect(moved / MS.h).toBeLessThan(1);
       expect(v.t1 - v.t0).toBe(DAY.t1 - DAY.t0);
     });
});

describe("U21-U24 · lane scroll and bounded rendering", () => {
  it("U21 lane scroll is integral and bounded per event", () => {
    const g = createGovernor(() => 0);
    expect(Math.abs(g.governLane(100000, 15, SOURCE.MOUSE_WHEEL)))
      .toBeLessThanOrEqual(GOV.LANE_MAX_ROWS_PER_EVENT);
  });

  it("U22 sub-row trackpad frames accumulate instead of being lost",
     () => {
       const g = createGovernor(() => 0);
       let moved = 0;
       for (let i = 0; i < 10; i += 1) moved += g.governLane(4, 15,
                                                             SOURCE.TRACKPAD);
       expect(moved).toBeGreaterThan(0);
       expect(moved).toBeLessThanOrEqual(GOV.LANE_MAX_ROWS_PER_WINDOW);
     });

  it("U23 a lane burst is bounded by the rolling budget", () => {
    let t = 0;
    const g = createGovernor(() => t);
    let moved = 0;
    for (let i = 0; i < 300; i += 1) {
      moved += Math.abs(g.governLane(120, 15, SOURCE.MOUSE_WHEEL));
      t += 1;
    }
    expect(moved).toBeLessThanOrEqual(GOV.LANE_MAX_ROWS_PER_WINDOW * 4);
  });

  it("U24 rendering work is bounded whatever the axis size", () => {
    const w = laneWindow(500000, 40, 1000000);
    expect(w.to - w.from).toBeLessThanOrEqual(MAX_RENDERED_LANES + 28);
    expect(capList(new Array(10000).fill(0), 240).items).toHaveLength(240);
    expect(clampLaneStart(1e9, 40, 100)).toBe(60);
  });
});

describe("U25-U28 · range selection", () => {
  it("U25 left resize cannot cross the right edge", () => {
    const r = resizeRangeStart(DAY, DAY.t1 + MS.h, null);
    expect(r.view.t0).toBeLessThan(r.view.t1);
    expect(r.valid).toBe(true);
  });

  it("U26 right resize cannot cross the left edge", () => {
    const r = resizeRangeEnd(DAY, DAY.t0 - MS.h, null);
    expect(r.view.t1).toBeGreaterThan(r.view.t0);
    expect(r.valid).toBe(true);
  });

  it("U27 zero/negative/oversized ranges are impossible", () => {
    expect(isValidWindow({ t0: 5, t1: 5 })).toBe(false);
    expect(isValidWindow({ t0: 10, t1: 1 })).toBe(false);
    expect(isValidWindow({ t0: 0, t1: 400 * MS.d })).toBe(false);
    expect(resizeRangeEnd(DAY, DAY.t0 + 1, null).view.t1 - DAY.t0)
      .toBe(MIN_SPAN_MS);
  });

  it("U28 move/fit/centre keep the window inside the evidence", () => {
    expect(moveRange(DAY, 99 * MS.d, BOUNDS).view.t1)
      .toBeLessThanOrEqual(BOUNDS.max);
    expect(fitRange(BOUNDS).t1).toBe(BOUNDS.max);
    expect(fitRange({ min: null, max: null })).toBeNull();
    const c = centreOn(DAY, T0 - 10 * MS.d, BOUNDS);
    expect(c.view.t0).toBeGreaterThanOrEqual(BOUNDS.min);
  });
});

describe("U29-U33 · selection and identity truth", () => {
  const obs = [
    { event_iid: "b", timestamp: "2026-06-01T01:00:00Z", process_iid: "p1" },
    { event_iid: "a", timestamp: "2026-06-01T01:00:00Z", process_iid: "p1" },
    { event_iid: "c", timestamp: "2026-06-01T02:00:00Z", process_iid: "p2",
      is_detection: true },
    { event_iid: "d", timestamp: "2026-06-01T03:00:00Z", process_iid: "p2" },
  ];

  it("U29 ordering is (timestamp, event_iid), not DOM order", () => {
    expect(sortObservations(obs).map((o) => o.event_iid))
      .toEqual(["a", "b", "c", "d"]);
  });

  it("U30 next/previous observation is deterministic", () => {
    expect(stepObservation(obs, obs[1], 1).event_iid).toBe("b");
    expect(stepObservation(obs, obs[0], -1).event_iid).toBe("a");
    expect(stepObservation(obs, obs[3], 1)).toBeNull();
  });

  it("U31 next/previous detection only walks detections", () => {
    expect(stepDetection(obs, null, 1).event_iid).toBe("c");
    expect(stepDetection(obs, obs[2], 1)).toBeNull();
    expect(isDetection(obs[3])).toBe(false);
    expect(isDetection({ detection: { rule_ids: ["r"] } })).toBe(true);
  });

  it("U32 selection state is reported, never silently replaced", () => {
    const loaded = new Set(["a", "b", "c", "d"]);
    expect(selectionState(obs[0], { view: DAY, loadedIds: loaded }))
      .toBe(SELECTION_STATE.VISIBLE);
    expect(selectionState(obs[0],
                          { view: { t0: T0 + 10 * MS.h, t1: DAY.t1 },
                            loadedIds: loaded }))
      .toBe(SELECTION_STATE.OUTSIDE_WINDOW);
    expect(selectionState(obs[0], { view: DAY, loadedIds: new Set() }))
      .toBe(SELECTION_STATE.EVIDENCE_MISSING);
    expect(selectionState(obs[0], { view: DAY, loadedIds: loaded,
                                    retention: { min: T0 + MS.d } }))
      .toBe(SELECTION_STATE.NOT_IN_RETENTION);
    expect(selectionState(null, { view: DAY })).toBeNull();
  });

  it("U33 identity is ProcessInstance; PID reuse cannot confuse it",
     () => {
       const reuseA = { process_iid: "guid-A", pid: 4242 };
       const reuseB = { process_iid: "guid-B", pid: 4242 };
       expect(processInstanceIdOf(reuseA)).toBe("guid-A");
       expect(sameProcessInstance(reuseA, reuseB)).toBe(false);
       expect(processInstanceIdOf({ pid: 4242 })).toBeNull();
       expect(sameRelationshipContext(reuseA, reuseA)).toBe(true);
       expect(relationshipContextOf(reuseA).process_iid).toBe("guid-A");
     });
});

describe("U34-U38 · request races", () => {
  it("U34 only the current generation may commit", () => {
    const c = createCoordinator();
    const a = c.begin("A");
    const b = c.begin("B");
    const z = c.begin("C");
    expect(c.commit(a.generation)).toBe(REQ.DISCARDED_STALE);
    expect(c.commit(b.generation)).toBe(REQ.DISCARDED_STALE);
    expect(c.commit(z.generation)).toBe(REQ.COMMITTED);
  });

  it("U35 superseded requests are aborted", () => {
    const c = createCoordinator();
    const a = c.begin("A");
    c.begin("B");
    expect(a.signal.aborted).toBe(true);
  });

  it("U36 identical in-flight requests are deduplicated", () => {
    const c = createCoordinator();
    const a = c.begin("A");
    const again = c.begin("A");
    expect(again.deduped).toBe(true);
    expect(again.generation).toBe(a.generation);
  });

  it("U37 the request key carries tenant and endpoint", () => {
    const k1 = requestKey({ tenantId: "t1", endpointId: "e1", t0: 1, t1: 2,
                            laneStart: 0, laneEnd: 10, filterKey: "" });
    const k2 = requestKey({ tenantId: "t2", endpointId: "e1", t0: 1, t1: 2,
                            laneStart: 0, laneEnd: 10, filterKey: "" });
    expect(k1).not.toBe(k2);
  });

  it("U38 prefetch is bounded, deduplicated and non-committing", () => {
    const c = createCoordinator();
    expect(c.beginPrefetch("p1").accepted).toBe(true);
    expect(c.beginPrefetch("p2").accepted).toBe(true);
    expect(c.beginPrefetch("p3").accepted).toBe(false);
    expect(c.beginPrefetch("p1").accepted).toBe(false);
    expect(prefetchTargets(DAY, { min: BOUNDS.min, max: BOUNDS.max + MS.d }))
      .toHaveLength(2);
    /** No evidence after `max` ⇒ no forward prefetch is issued. */
    expect(prefetchTargets(DAY, BOUNDS)).toHaveLength(1);
    expect(prefetchTargets(DAY, { min: DAY.t0, max: DAY.t1 }))
      .toHaveLength(0);
  });
});

describe("U39-U43 · URL and history", () => {
  it("U39 URL serialization round-trips the investigation", () => {
    const state = { device: "dev1", from: "2026-06-01T00:00:00.000Z",
                    to: "2026-06-02T00:00:00.000Z", zoom: "4",
                    event: "ev1", q: "powershell" };
    const s = serialize(state);
    expect(deserialize(s)).toEqual(s);
    const r = restore(s);
    expect(r.device).toBe("dev1");
    expect(r.view.t1 - r.view.t0).toBe(MS.d);
    expect(r.q).toBe("powershell");
  });

  it("U40 no secret and no raw payload may enter the URL", () => {
    expect(() => assertNoSensitive({ device: "d" })).not.toThrow();
    expect(() => assertNoSensitive({ token: "abc" })).toThrow();
    expect(() => assertNoSensitive({ raw_payload: "x" })).toThrow();
    expect(() => assertNoSensitive({ something_else: "x" })).toThrow();
    expect(() => assertNoSensitive({ q: "x".repeat(600) })).toThrow();
  });

  it("U41 PUSH only for materially different investigation", () => {
    expect(historyMode({ device: "d", event: "a" },
                       { device: "d", event: "b" })).toBe(HISTORY.PUSH);
    expect(historyMode({ device: "d" }, { device: "d2" }))
      .toBe(HISTORY.PUSH);
    expect(PUSH_KEYS).toContain("detection");
  });

  it("U42 viewport geometry REPLACES and never pushes", () => {
    expect(historyMode({ from: "a", to: "b" }, { from: "c", to: "d" }))
      .toBe(HISTORY.REPLACE);
    expect(historyMode({ zoom: "1" }, { zoom: "2" })).toBe(HISTORY.REPLACE);
  });

  it("U43 a transient gesture can never create a history entry", () => {
    expect(historyMode({ device: "d", event: "a" },
                       { device: "d", event: "b" }, { transient: true }))
      .toBe(HISTORY.REPLACE);
    expect(historyMode({ device: "d" }, { device: "d" }))
      .toBe(HISTORY.NONE);
  });
});

describe("U44-U47 · loading and failure truth", () => {
  it("U44 failure is never rendered as an absence of activity", () => {
    const s = windowStateOf({ hasMeta: true, error: "network" });
    expect(s).toBe(WINDOW_STATE.FAILED);
    expect(emptinessMeaning(s).isObservationAbsence).toBe(false);
  });

  it("U45 cancellation and staleness are never absence either", () => {
    expect(emptinessMeaning(WINDOW_STATE.CANCELED).isObservationAbsence)
      .toBe(false);
    expect(emptinessMeaning(WINDOW_STATE.STALE_RESPONSE_DISCARDED)
      .isObservationAbsence).toBe(false);
    expect(windowStateOf({ hasMeta: true, canceled: true }))
      .toBe(WINDOW_STATE.CANCELED);
    expect(windowStateOf({ hasMeta: true, staleDiscarded: true }))
      .toBe(WINDOW_STATE.STALE_RESPONSE_DISCARDED);
  });

  it("U46 only READY_NOT_OBSERVED may claim non-observation", () => {
    const states = Object.values(WINDOW_STATE)
      .filter((s) => emptinessMeaning(s).isObservationAbsence);
    expect(states).toEqual([WINDOW_STATE.READY_NOT_OBSERVED]);
    expect(emptinessMeaning(WINDOW_STATE.READY_NOT_OBSERVED).message)
      .toMatch(/absence of observation/);
  });

  it("U47 an adjacent load keeps the usable context on screen", () => {
    expect(windowStateOf({ hasMeta: true, loading: true,
                           observationCount: 12 }))
      .toBe(WINDOW_STATE.REFRESHING);
    expect(preservesContext(WINDOW_STATE.REFRESHING)).toBe(true);
    expect(preservesContext(WINDOW_STATE.INITIAL_LOADING)).toBe(false);
    expect(windowStateOf({ loading: true })).toBe(WINDOW_STATE.INITIAL_LOADING);
    expect(windowStateOf({ hasMeta: true, unavailable: true }))
      .toBe(WINDOW_STATE.UNAVAILABLE);
  });
});

describe("U48-U50 · density, coverage and retention truth", () => {
  const dt2 = {
    density: [
      { start: "2026-06-01T00:00:00Z", end: "2026-06-01T01:00:00Z",
        stream: "events", count: 5, semantics: "NAVIGATION_ONLY_NOT_SEVERITY" },
      { start: "2026-06-01T01:00:00Z", end: "2026-06-01T02:00:00Z",
        stream: "events", count: 900,
        semantics: "NAVIGATION_ONLY_NOT_SEVERITY" },
      { start: "2026-06-01T01:00:00Z", end: "2026-06-01T02:00:00Z",
        stream: "detection", count: 1,
        semantics: "NAVIGATION_ONLY_NOT_SEVERITY" },
    ],
    coverage: [
      { start: null, end: null, state: "UNKNOWN",
        authority: "NOT_PROVABLE_FROM_THIS_PROJECTION",
        boundary_certainty: "UNKNOWN", absence_inferable: false },
    ],
    available_range: { from: "2026-06-01T00:00:00Z",
                       to: "2026-06-01T02:00:00Z", state: "AVAILABLE" },
    retention_boundary: { state: "UNKNOWN",
                          basis: "RETENTION_NOT_PROVABLE_FROM_WINDOW" },
  };

  it("U48 density is navigation quantity and never severity", () => {
    const b = bucketsOf(dt2, "events");
    expect(b).toHaveLength(2);
    expect(b.every((x) => x.semantics === "NAVIGATION_ONLY_NOT_SEVERITY"))
      .toBe(true);
    expect(() => assertNavigationOnly({ severity: "HIGH" })).toThrow();
    expect(() => assertNavigationOnly({ count: 3 })).not.toThrow();
    expect(spikes(b)[0].count).toBe(900);
    expect(spikes(b)[0].isThreatClaim).toBe(false);
  });

  it("U49 a density spike navigates to a padded window", () => {
    const b = bucketsOf(dt2, "events");
    const w = windowForBucket(spikes(b)[0]);
    expect(w.t1 - w.t0).toBeGreaterThan(MS.h);
    expect(bucketAt(b, Date.parse("2026-06-01T00:30:00Z")).count).toBe(5);
    expect(bucketAt(b, T0 - MS.d)).toBeNull();
    expect(bucketsOf(null)).toEqual([]);
  });

  it("U50 coverage UNKNOWN and unprovable retention are preserved", () => {
    const cov = coverageOf(dt2);
    expect(cov[0].state).toBe("UNKNOWN");
    expect(cov[0].absenceInferable).toBe(false);
    const r = retentionBounds(dt2);
    expect(r.retentionState).toBe("UNKNOWN");
    expect(r.min).toBe(Date.parse("2026-06-01T00:00:00Z"));
    expect(retentionBounds({}).min).toBeNull();
  });
});

describe("U51 · pointer → viewport pipeline end to end", () => {
  it("normalizes, governs and transitions without runaway", () => {
    let t = 0;
    const g = createGovernor(() => t);
    let view = DAY;
    const fire = (ev) => {
      const n = normalizeWheel(wheel(ev));
      if (n.intent === INTENT.TIME_PAN) {
        const f = g.governPan(n.panPx, VIEWPORT, n.source);
        view = panByFraction(view, f, BOUNDS).view;
      } else if (n.intent === INTENT.ZOOM) {
        const steps = g.governZoom(n.dyPx);
        if (steps) {
          view = zoomBySteps(view, steps,
                             timeAtX(view, VIEWPORT / 2, VIEWPORT),
                             BOUNDS).view;
        }
      }
      t += 8;
    };
    for (let i = 0; i < 400; i += 1) fire({ deltaX: 9 });
    for (let i = 0; i < 400; i += 1) fire({ deltaY: 100, ctrlKey: true });
    expect(view.t1 - view.t0).toBeLessThanOrEqual(MAX_SPAN_MS);
    expect(view.t1 - view.t0).toBeGreaterThanOrEqual(MIN_SPAN_MS);
    expect(view.t0).toBeGreaterThanOrEqual(BOUNDS.min - MAX_SPAN_MS);
    expect(vi.isMockFunction(() => {})).toBe(false);
  });
});
