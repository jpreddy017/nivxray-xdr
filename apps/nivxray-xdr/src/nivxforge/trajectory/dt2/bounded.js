/**
 * DT2-1 · bounded windowed rendering.
 *
 * The existing lane/node renderer is PRESERVED (owner decision: minimum
 * safe substrate, no renderer rewrite). This module only guarantees the
 * work handed to it is bounded, so 10 K / 100 K / 1 M observations
 * cannot grow the DOM without limit.
 */

export const MAX_RENDERED_LANES = 120;
export const MAX_GLYPHS_PER_LANE = 240;
export const LANE_OVERSCAN = 14;

const clamp = (v, lo, hi) => Math.min(Math.max(v, lo), hi);

/** The lane slice to fetch and render, with a bounded overscan. */
export function laneWindow(laneStart, rows, total,
                           overscan = LANE_OVERSCAN) {
  const t = Math.max(0, Number(total) || 0);
  const r = clamp(Number(rows) || 1, 1, MAX_RENDERED_LANES);
  const start = clamp(Number(laneStart) || 0, 0, Math.max(0, t - 1));
  const from = Math.max(0, start - overscan);
  const to = Math.min(Math.max(t, r), start + r + overscan);
  return { start, rows: r, from, to,
           count: Math.min(to - from, MAX_RENDERED_LANES + 2 * overscan) };
}

export const capList = (list, max) => {
  const arr = list || [];
  return arr.length <= max ? { items: arr, truncated: 0 }
    : { items: arr.slice(0, max), truncated: arr.length - max };
};

/** Row offset clamped to the axis; a lane offset beyond the axis would
 *  render blank rows and look like missing evidence. */
export const clampLaneStart = (next, rows, total) =>
  clamp(Number(next) || 0, 0, Math.max(0, (Number(total) || 0) - rows));
