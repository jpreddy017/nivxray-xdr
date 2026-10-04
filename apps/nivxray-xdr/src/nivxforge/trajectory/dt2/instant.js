/**
 * One client-side instant parser, mirroring `backend/edr_plane/instant.py`.
 *
 * Genuine Windows evidence reaches the browser in two authoritative shapes:
 *
 *     2026-09-22 15:43:31.770          Sysmon `EventData/UtcTime`
 *     2026-09-22T15:43:31.7788153Z     Windows Event Log `TimeCreated`
 *
 * `Date.parse` treats the first as LOCAL time (and the shape is
 * implementation-defined), so an analyst in UTC+5:30 would have seen the same
 * evidence projected five and a half hours away from its real X. Both forms
 * are UTC by the source's own contract, so they are parsed as UTC here.
 *
 * A value that cannot be parsed returns null. It never becomes a guess.
 */
const RE = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:[.,](\d{1,9}))?\s*(Z|z|[+-]\d{2}:?\d{2})?$/;

export function msUTC(value) {
  if (value == null || value === "") return null;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  const m = RE.exec(String(value).trim());
  if (!m) {
    const t = Date.parse(String(value));      // RFC 1123 and friends
    return Number.isFinite(t) ? t : null;
  }
  const [, y, mo, d, hh, mi, ss, frac, zone] = m;
  const milli = frac ? Number(`${frac}000`.slice(0, 3)) : 0;
  let t = Date.UTC(+y, +mo - 1, +d, +hh, +mi, +(ss || 0), milli);
  if (zone && zone !== "Z" && zone !== "z") {
    const sign = zone[0] === "-" ? 1 : -1;
    const [oh, om] = zone.slice(1).replace(":", "").match(/\d{2}/g).map(Number);
    t += sign * (oh * 3600000 + om * 60000);
  }
  return Number.isFinite(t) ? t : null;
}

export default msUTC;
