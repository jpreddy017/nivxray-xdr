/**
 * DT2-1 · density overview.
 *
 * Density answers "WHEN was endpoint activity concentrated?".
 * Density is NAVIGATION QUANTITY. It is NEVER severity, and an activity
 * spike is NEVER a threat claim.
 *
 * Cisco publicly shows a sparkline with activity peaks and volume-sized
 * dots [PUBLICLY OBSERVED]. Treating volume as non-severity is a
 * NIVXFORGE DESIGN DECISION.
 */

export const SEMANTICS = "NAVIGATION_ONLY_NOT_SEVERITY";

/** If any of these ever appear on a density bucket, the contract has
 *  been violated and the bucket must not be rendered as density. */
export const SEVERITY_FORBIDDEN_KEYS = [
  "severity", "threat", "malicious", "verdict", "disposition", "risk",
  "score", "confidence",
];

export function assertNavigationOnly(bucket) {
  for (const k of Object.keys(bucket || {})) {
    if (SEVERITY_FORBIDDEN_KEYS.includes(k.toLowerCase())) {
      throw new Error(`DT2_DENSITY_SEVERITY_LEAK:${k}`);
    }
  }
  if (bucket && bucket.semantics && bucket.semantics !== SEMANTICS) {
    throw new Error(`DT2_DENSITY_SEMANTICS:${bucket.semantics}`);
  }
  return true;
}

const ms = (v) => {
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : null;
};

/** Read DT2-0 `dt2.density[]`. Returns [] when the contract is absent —
 *  an absent contract is never faked from the V1 payload. */
export function bucketsOf(dt2, stream = "events") {
  const raw = Array.isArray(dt2?.density) ? dt2.density : [];
  const out = [];
  for (const b of raw) {
    if (String(b?.stream) !== stream) continue;
    assertNavigationOnly(b);
    const t0 = ms(b.start);
    const t1 = ms(b.end);
    if (t0 == null || t1 == null || t1 <= t0) continue;
    out.push({ t0, t1, count: Number(b.count) || 0, stream,
               semantics: SEMANTICS });
  }
  return out.sort((a, b) => a.t0 - b.t0);
}

export const streamsOf = (dt2) => [...new Set(
  (Array.isArray(dt2?.density) ? dt2.density : [])
    .map((b) => String(b?.stream)).filter(Boolean))].sort();

/** Highest-count buckets, for "take me to where activity was dense".
 *  Ordered by count then by time so the result is deterministic. */
export function spikes(buckets, { count = 5 } = {}) {
  return [...(buckets || [])]
    .filter((b) => b.count > 0)
    .sort((a, b) => (b.count - a.count) || (a.t0 - b.t0))
    .slice(0, count)
    .map((b) => ({ ...b, isThreatClaim: false,
                   semantics: SEMANTICS }));
}

export const bucketAt = (buckets, atMs) =>
  (buckets || []).find((b) => atMs >= b.t0 && atMs < b.t1) || null;

/** A bucket the analyst clicked becomes the selected window, padded so
 *  the surrounding context is visible (before/after review). */
export function windowForBucket(bucket, { padFraction = 0.25 } = {}) {
  if (!bucket) return null;
  const span = Math.max(1000, bucket.t1 - bucket.t0);
  const pad = span * padFraction;
  return { t0: bucket.t0 - pad, t1: bucket.t1 + pad };
}

/** Coverage is read straight from DT2-0 and never downgraded: an
 *  unprovable interval stays UNKNOWN. */
export function coverageOf(dt2) {
  const raw = Array.isArray(dt2?.coverage) ? dt2.coverage : [];
  return raw.map((c) => ({
    t0: ms(c.start), t1: ms(c.end),
    state: String(c.state || "UNKNOWN"),
    authority: c.authority || null,
    boundaryCertainty: c.boundary_certainty || "UNKNOWN",
    absenceInferable: c.absence_inferable === true,
    reason: c.reason || null,
  }));
}

/** Retention truth: what the UI may OFFER vs what evidence PROVES. */
export function retentionBounds(dt2, fallback = {}) {
  const avail = dt2?.available_range || {};
  const min = ms(avail.from) ?? (Number.isFinite(fallback.min)
    ? fallback.min : null);
  const max = ms(avail.to) ?? (Number.isFinite(fallback.max)
    ? fallback.max : null);
  const boundary = dt2?.retention_boundary || {};
  return {
    min, max,
    availabilityState: avail.state || "UNKNOWN",
    retentionState: boundary.state || "UNKNOWN",
    retentionBasis: boundary.basis || "RETENTION_NOT_PROVABLE",
  };
}
