/**
 * canvas_engine · viewport + layout regression suite (M1 DoD gate).
 * Runs via `yarn test` (react-scripts jest).
 */
import {
  clamp, clampOffset, zoomAround, fit,
  isInViewport, visibleWorldRect,
} from "../core/viewport";
import { layout, ROW_H, BAND_H } from "../core/layout";

// ─────────────────────────────────────────────────────────────────────
// R2 · Anchor-preserving zoom math
// ─────────────────────────────────────────────────────────────────────
describe("viewport · zoomAround", () => {
  test("keeps the point under the pointer stable across scale change", () => {
    const vp = { offset: { x: 0, y: 0 }, scale: 1, size: { w: 800, h: 600 } };
    const pointer = { x: 400, y: 300 };
    const out = zoomAround(vp, 1.5, pointer);
    // World point under pointer should equal in both states
    const wx1 = (pointer.x - vp.offset.x)  / vp.scale;
    const wx2 = (pointer.x - out.offset.x) / out.scale;
    expect(wx2).toBeCloseTo(wx1, 6);
    const wy1 = (pointer.y - vp.offset.y)  / vp.scale;
    const wy2 = (pointer.y - out.offset.y) / out.scale;
    expect(wy2).toBeCloseTo(wy1, 6);
  });

  test("clamps scale to [0.15, 6]", () => {
    const vp = { offset: { x: 0, y: 0 }, scale: 5, size: { w: 800, h: 600 } };
    const out = zoomAround(vp, 4, { x: 100, y: 100 });
    expect(out.scale).toBe(6);
  });

  test("no-op when factor would leave scale unchanged (already at clamp)", () => {
    const vp = { offset: { x: 5, y: 5 }, scale: 6, size: { w: 800, h: 600 } };
    const out = zoomAround(vp, 2, { x: 0, y: 0 });
    expect(out).toBe(vp);
  });

  test("anchor stays fixed at 12 canonical cursor positions × 4 scales", () => {
    const size = { w: 1200, h: 800 };
    const anchors = [
      [100,100],[600,100],[1100,100],
      [100,400],[600,400],[1100,400],
      [100,700],[600,700],[1100,700],
      [1,1],[1199,1],[1199,799],
    ];
    [0.5, 1, 2, 4].forEach(startScale => {
      anchors.forEach(([px, py]) => {
        const vp = { offset: { x: 20, y: 30 }, scale: startScale, size };
        const out = zoomAround(vp, 1.35, { x: px, y: py });
        const wx1 = (px - vp.offset.x)  / vp.scale;
        const wx2 = (px - out.offset.x) / out.scale;
        expect(wx2).toBeCloseTo(wx1, 6);
      });
    });
  });
});

// ─────────────────────────────────────────────────────────────────────
// clampOffset
// ─────────────────────────────────────────────────────────────────────
describe("viewport · clampOffset", () => {
  const size = { w: 800, h: 600 };

  test("prevents scrolling past the top-left edge", () => {
    const out = clampOffset({ x: 500, y: 500 }, 1, size, 400, 1000);
    expect(out.x).toBeLessThanOrEqual(20);
    expect(out.y).toBeLessThanOrEqual(0);
  });

  test("keeps content visible when content > viewport", () => {
    const contentW = 3000, contentH = 2000, scale = 1;
    const out = clampOffset({ x: -99999, y: -99999 }, scale, size, contentH, contentW);
    // Must not push content fully off-screen — at least 20 px stays visible.
    expect(out.x).toBeGreaterThanOrEqual(size.w - contentW * scale - 20);
    expect(out.y).toBeGreaterThanOrEqual(size.h - contentH * scale - 20);
  });
});

// ─────────────────────────────────────────────────────────────────────
// fit
// ─────────────────────────────────────────────────────────────────────
describe("viewport · fit", () => {
  test("computes scale so content fits with 20 px inset", () => {
    const size = { w: 800, h: 600 };
    const out = fit({ w: 3000, h: 1000 }, size, 20);
    expect(out.scale).toBeCloseTo((800 - 40) / 3000, 6);
  });
});

// ─────────────────────────────────────────────────────────────────────
// visibleWorldRect + isInViewport
// ─────────────────────────────────────────────────────────────────────
describe("viewport · virtualization", () => {
  test("visibleWorldRect returns a rect around the viewport ± margin", () => {
    const vp = { offset: { x: -100, y: -50 }, scale: 2, size: { w: 800, h: 600 } };
    const r = visibleWorldRect(vp, 200);
    expect(r.x0).toBeLessThan(r.x1);
    expect(r.y0).toBeLessThan(r.y1);
  });

  test("point at world origin is inside the viewport when unpanned", () => {
    const vp = { offset: { x: 0, y: 0 }, scale: 1, size: { w: 800, h: 600 } };
    expect(isInViewport(400, 300, vp)).toBe(true);
    expect(isInViewport(-10000, -10000, vp)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────
// R7 · Layout — deterministic band + row ordering
// ─────────────────────────────────────────────────────────────────────
describe("layout", () => {
  const makeE = (id, band, lane, first, label) => ({
    id, label, band,
    lifetime: { start: first, end: first + 1000 },
    worstVerdict: "benign",
    type: lane,
    events: [], relationships: [], visualState: "idle",
    meta: { lane },
  });

  test("analyst view has exactly 2 bands: System and Files & Network", () => {
    const es = [
      makeE("a", "System", "process", 100, "cmd.exe"),
      makeE("b", "System", "registry", 200, "reg.dll"),
      makeE("c", "Files & Network", "file",    300, "notes.txt"),
      makeE("d", "Files & Network", "network", 400, "sock"),
    ];
    const { groups } = layout(es, { expert: false });
    expect(groups.map(g => g.label)).toEqual(["System", "Files & Network"]);
    expect(groups[0].rows).toHaveLength(2);
    expect(groups[1].rows).toHaveLength(2);
  });

  test("expert view groups by lane and preserves LANE_ORDER precedence", () => {
    const es = [
      makeE("net",  "n/a", "network",  50, "n"),
      makeE("sys",  "n/a", "system",   30, "s"),
      makeE("proc", "n/a", "process",  60, "p"),
      makeE("reg",  "n/a", "registry", 80, "r"),
      makeE("file", "n/a", "file",     70, "f"),
    ];
    const { sortedEntities } = layout(es, { expert: true });
    // Expected: system < process < file < network < registry
    expect(sortedEntities.map(e => e.type))
      .toEqual(["system", "process", "file", "network", "registry"]);
  });

  test("within a band, sort is by first_seen ascending", () => {
    const es = [
      makeE("late",  "System", "process", 300, "late.exe"),
      makeE("early", "System", "process", 100, "early.exe"),
      makeE("mid",   "System", "process", 200, "mid.exe"),
    ];
    const { sortedEntities } = layout(es, { expert: false });
    expect(sortedEntities.map(e => e.id)).toEqual(["early", "mid", "late"]);
  });

  test("determinism: same input → same rowY", () => {
    const es = [
      makeE("a", "System", "process", 100, "cmd.exe"),
      makeE("b", "System", "process", 200, "ps.exe"),
      makeE("c", "Files & Network", "file", 300, "x.txt"),
    ];
    const r1 = layout(es, { expert: false });
    const r2 = layout(es, { expert: false });
    expect(r1.rowY).toEqual(r2.rowY);
    expect(r1.contentH).toBe(r2.contentH);
  });

  test("rowY leaves BAND_H gap at every band boundary", () => {
    const es = [
      makeE("a", "System", "process", 100, "a"),
      makeE("b", "System", "process", 200, "b"),
      makeE("c", "Files & Network", "file", 300, "c"),
    ];
    const { rowY } = layout(es, { expert: false });
    // rowY[0] = BAND_H (first System header)
    expect(rowY[0]).toBe(BAND_H);
    expect(rowY[1]).toBe(BAND_H + ROW_H);
    // Third entity starts a new band → extra BAND_H gap
    expect(rowY[2]).toBe(BAND_H + ROW_H * 2 + BAND_H);
  });
});
