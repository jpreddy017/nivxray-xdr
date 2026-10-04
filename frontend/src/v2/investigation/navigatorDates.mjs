// DT-I1 navigator dates. Pure, deterministic, UTC. Every date derives from the trajectory's own bounds; none is invented.
const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DAY = 86400000;
export const RANGE_UNKNOWN = "Time range UNKNOWN — this trajectory carries no observation timestamps.";

const utcDay = (t) => Math.floor(t / DAY) * DAY;
export const isoDay = (t) => new Date(t).toISOString().slice(0, 10);
export const dayLabel = (t) => { const d = new Date(t); return `${MON[d.getUTCMonth()]} ${d.getUTCDate()}`; };

export function validBounds(b) {
  return !!b && Number.isFinite(b.start) && Number.isFinite(b.end) && b.start > 0 && b.end >= b.start;
}

export function buildDateStrip(bounds, n = 30) {
  if (!validBounds(bounds)) return { state: "UNKNOWN", reason: RANGE_UNKNOWN, days: [], caseDayIdx: -1 };
  const end = utcDay(bounds.end), start = utcDay(bounds.start);
  const days = [];
  for (let i = n - 1; i >= 0; i--) {
    const t = end - i * DAY, d = new Date(t);
    days.push({ t, iso: isoDay(t), day: String(d.getUTCDate()), month: MON[d.getUTCMonth()], inCase: t >= start });
  }
  days.forEach((d, i) => { d.monthMark = i === 0 || d.day === "1" ? d.month : null; });
  return { state: "AVAILABLE", days, caseDayIdx: n - 1, source: "trajectory_bounds" };
}

export function spanLabel(bounds) {
  if (!validBounds(bounds)) return "UNKNOWN";
  const a = dayLabel(bounds.start), b = dayLabel(bounds.end);
  return a === b ? a : `${a}–${b}`;
}

export function buildTicks(bounds, n = 7) {
  if (!validBounds(bounds)) return [];
  const span = Math.max(1, bounds.end - bounds.start);
  return Array.from({ length: n }, (_, i) => {
    const t = bounds.start + (span * i) / (n - 1), iso = new Date(t).toISOString();
    const label = span >= DAY ? `${iso.slice(5, 10)} ${iso.slice(11, 16)}` : span < 60000 ? iso.slice(11, 23) : iso.slice(11, 19);
    return { t, label };
  });
}

export function timelineTitle(bounds) {
  if (!validBounds(bounds)) return "TIMELINE · TIME RANGE UNKNOWN";
  const a = isoDay(bounds.start), b = isoDay(bounds.end);
  return `TIMELINE · ${a === b ? a : `${a} → ${b}`} UTC`;
}

// Event-density sparkline points derived from observed timestamps only; null when nothing was observed.
export function densityPoints(tsList, bounds, bins = 48) {
  if (!validBounds(bounds) || !tsList || !tsList.length) return null;
  const span = Math.max(1, bounds.end - bounds.start), c = new Array(bins).fill(0);
  tsList.forEach((t) => { c[Math.min(bins - 1, Math.max(0, Math.floor(((t - bounds.start) / span) * bins)))]++; });
  const max = Math.max(...c);
  return c.map((v, i) => `${Math.round((i * 1400) / (bins - 1))},${(22 - (v / max) * 20).toFixed(1)}`).join(" ");
}
