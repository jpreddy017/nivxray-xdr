/**
 * Cisco's per-file EVENT CACHE, reproduced in the TRAJECTORY PROJECTION only.
 *
 * Secure Endpoint User Guide p.401, verbatim:
 *
 *   "When a file triggers an event, the file is cached for a period of time
 *    before it will trigger another event. The cache time is dependent on the
 *    disposition of the file:
 *      Clean files – 7 days
 *      Unknown files – 1 hour
 *      Malicious files – 1 hour"
 *
 * WHAT THE DOCUMENT DOES NOT SAY — and what is therefore NOT assumed:
 *
 *   CACHE_IDENTITY_KEY = REFERENCE BEHAVIOR NOT VERIFIED
 *
 * No Cisco source states whether the cache is keyed on SHA-256, on path, on
 * process+path, or on an internal file identity. The connector is documented
 * to compute a SHA-256 and check a LOCAL CACHE with it (Secure Endpoint
 * Operations Guide), but that is the SCAN cache, not provably the
 * event-trigger cache. So NivXForge defines its OWN deterministic key and
 * declares its authority:
 *
 *   content SHA-256              → authority CONTENT_IDENTITY
 *   authoritative file identity  → authority FILE_IDENTITY   (not yet emitted)
 *   observed path + actor        → authority PATH_SURROGATE, downgraded
 *
 * A pathname is NEVER silently equated with content identity.
 *
 * SUPPRESSED MEANS: not drawn as another trajectory event.
 * It does NOT mean deleted, dropped, absent, or deduplicated from canonical
 * evidence. Every suppressed observation is returned on the surviving event
 * as `suppressed[]`, is counted in `suppressedCount`, and is still listed by
 * the Activity pane and the API.
 */

export const WINDOW_MS = {
  //: documented, p.401
  CLEAN: 7 * 24 * 3600 * 1000,
  UNKNOWN: 3600 * 1000,
  MALICIOUS: 3600 * 1000,
};

/**
 * The documented windows apply to a CLOUD DISPOSITION. NivXForge's
 * `UNKNOWN_NOT_ASSESSED` is not Cisco's "Unknown" — it means no verdict was
 * ever sought, which the guide does not cover. Where the rule cannot be
 * established the projection FAILS TO NO SUPPRESSION.
 */
export function windowFor(disposition) {
  switch (disposition) {
    case "CLEAN": return WINDOW_MS.CLEAN;
    case "UNKNOWN": return WINDOW_MS.UNKNOWN;
    case "MALICIOUS": return WINDOW_MS.MALICIOUS;
    default: return null;          // SUSPICIOUS · *_NOT_ASSESSED · null
  }
}

/** The cache key and how much authority it carries. */
export function cacheIdentityOf(a) {
  const at = a?.attributes || {};
  const sha = a?.sha256 || at.sha256 || at.file_sha256 || null;
  if (sha) {
    return { key: `sha256:${sha}`, authority: "CONTENT_IDENTITY",
             derivation_basis: "CONTENT_SHA256", downgraded: false };
  }
  const identity = at.file_identity || a?.file_identity || null;
  if (identity) {
    return { key: `fid:${identity}`, authority: "FILE_IDENTITY",
             derivation_basis: "AUTHORITATIVE_FILE_IDENTITY",
             downgraded: false };
  }
  const path = a?.label || at.path || null;
  if (!path) return null;
  return { key: `path:${a?.process_node_id || ""}::${path}`,
           authority: "PATH_SURROGATE",
           derivation_basis: "OBSERVED_PATH_PLUS_ACTOR_NOT_CONTENT",
           downgraded: true };
}

/**
 * Collapse repeats inside the documented window. `timeOf` is injected so
 * this file never owns a second definition of an event's instant.
 *
 * Returns the activities that remain drawable; each one carries
 * `suppressed[]`, `suppressedCount` and `suppressionBasis`.
 */
export function suppressRepeats(activities, timeOf) {
  const seen = new Map();          // key → surviving activity
  const out = [];
  for (const a of activities) {
    const id = cacheIdentityOf(a);
    const win = windowFor(a?.disposition ?? a?.attributes?.disposition);
    const t = timeOf(a);
    if (!id || win == null || t == null) { out.push(a); continue; }
    const prev = seen.get(id.key);
    if (prev && t - prev.t <= win) {
      prev.row.suppressed.push(a);
      prev.row.suppressedCount = prev.row.suppressed.length;
      continue;
    }
    const row = { ...a, suppressed: [], suppressedCount: 0,
                  suppressionBasis: id };
    seen.set(id.key, { t, row });
    out.push(row);
  }
  return out;
}
