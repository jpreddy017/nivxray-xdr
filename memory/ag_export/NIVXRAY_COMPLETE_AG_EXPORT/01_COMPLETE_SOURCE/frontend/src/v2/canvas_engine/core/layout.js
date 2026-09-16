/**
 * canvas_engine/core/layout.js
 *
 * Deterministic band + row layout for the Investigation Canvas Engine.
 * Same input entities → same output row Y positions and band stripes.
 * Pure — no React, no Konva.
 */

export const ROW_H  = 24;
export const BAND_H = 20;

const EXPERT_LANE_ORDER = ["system", "process", "file", "network", "registry"];

/** Analyst-view band mapping: 2 bands (System / Files & Network). */
function analystBand(entity) {
  const lane = entity.meta?.lane || entity.type || "process";
  if (lane === "file" || lane === "network") return "Files & Network";
  return "System";
}

/** Expert-view: pass-through of the raw band, or lane if entity gives us one. */
function expertBand(entity) {
  if (entity.band) return entity.band;
  const lane = entity.meta?.lane || entity.type || "process";
  return (lane || "").toUpperCase();
}

/**
 * Compute band groups + row Y positions + total canvas height, given an
 * entity list and a mode.
 *
 * Return: `{ groups, rowY, contentH, rowIndex }` where
 *   groups   : [{ label, rows: Entity[], top: number }]
 *   rowY     : number[]                (aligned to input entity order after sort)
 *   contentH : total pixels including trailing padding
 *   rowIndex : Map<entity.id, number>  (index into rowY)
 *
 * IMPORTANT: this function also RETURNS the sorted entity array — do
 * not use the caller's original order, use the returned `sortedEntities`.
 */
export function layout(entities, { expert = false } = {}) {
  const bandFn = expert ? expertBand : analystBand;

  // Deterministic sort: by band order, then first_seen, then label.
  const bandRank = (e) => {
    if (expert) {
      const lane = e.meta?.lane || e.type || "process";
      const idx = EXPERT_LANE_ORDER.indexOf(lane);
      return idx === -1 ? 99 : idx;
    }
    return bandFn(e) === "Files & Network" ? 1 : 0;
  };
  const firstSeen = (e) => {
    const t = e.lifetime?.start ?? e.first_seen ?? e.firstTs;
    return typeof t === "string" ? new Date(t).getTime() : (t || 0);
  };

  const sortedEntities = [...entities].sort((a, b) => {
    const ba = bandRank(a), bb = bandRank(b);
    if (ba !== bb) return ba - bb;
    const fa = firstSeen(a), fb = firstSeen(b);
    if (fa !== fb) return fa - fb;
    return (a.label || "").localeCompare(b.label || "");
  });

  let y = 0;
  const rowY = [];
  const rowIndex = new Map();
  const groups = [];
  let curBand = null, curGroup = null;

  sortedEntities.forEach((e, i) => {
    const band = bandFn(e);
    if (band !== curBand) {
      y += BAND_H;
      curBand = band;
      curGroup = { label: band, rows: [], top: y };
      groups.push(curGroup);
    }
    rowY.push(y);
    rowIndex.set(e.id, i);
    curGroup.rows.push(e);
    y += ROW_H;
  });

  return {
    sortedEntities,
    groups,
    rowY,
    rowIndex,
    contentH: y + 16,
  };
}
