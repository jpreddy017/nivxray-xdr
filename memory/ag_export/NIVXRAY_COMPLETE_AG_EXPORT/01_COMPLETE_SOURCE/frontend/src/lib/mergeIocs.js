/**
 * mergeIocs — preserve non-empty IOC categories across the multi-stage
 * investigation flow.
 *
 * v1.5.8 · Feb-2026 · SME/prod bug fix
 * ====================================
 *
 * Problem
 * -------
 * The deterministic pipeline (`/api/decode/smart` → RC2 orchestrator)
 * populates `iocs = {ips: ['149.28.81.19'], urls: [], ...}`. The
 * AUTO-INVESTIGATE job status poll (`/api/analyze/status/:jobId`) then
 * returns its OWN `iocs` field, which for a purely-deterministic case
 * comes back as an empty shell `{ips: [], urls: [], domains: [], ...}`.
 *
 * The pre-existing frontend logic used the JS truthiness fallback:
 *
 *     setAnalysis((a) => ({ ...a, iocs: d.iocs || a?.iocs }));
 *
 * `{}` is truthy in JS, so this returned the EMPTY iocs from the AI
 * job — clobbering the good ones the deterministic pipeline had
 * already extracted. Result: the IOCs / OSINT / TI-Hits tabs all
 * rendered "No IOCs extracted" even though the SHELLCODE-DECODED
 * banner (which pulls straight from `iocs.ips`) correctly showed
 * `C2 IP 149.28.81.19`.
 *
 * Fix
 * ---
 * Category-wise merge: for each IOC category (ips, urls, domains,
 * ...) keep the union of the prior value and the incoming value.
 * De-duplicate. Preserves everything the deterministic engine found;
 * only ADDS what the AI enrichment layer finds later, never removes.
 *
 * Special-cases the `hashes: {md5, sha1, sha256}` nested object.
 */

const IOC_CATEGORIES = [
  "urls", "ips", "domains", "emails",
  "md5", "sha1", "sha256", "bitcoin_addresses",
  "regkeys", "mutexes", "imports",
  "user_agents",  // v1.5.8 — surfaced from shellcode analysis
];

function _uniq(arr) {
  if (!Array.isArray(arr)) return [];
  return Array.from(new Set(arr.filter((v) => v != null && v !== "")));
}

export function mergeIocs(prior, incoming) {
  const p = prior || {};
  const i = incoming || {};
  const out = {};
  for (const key of IOC_CATEGORIES) {
    out[key] = _uniq([...(p[key] || []), ...(i[key] || [])]);
  }
  // Nested hashes object — preserve the shape both consumers expect.
  const ph = (p.hashes || {});
  const ih = (i.hashes || {});
  out.hashes = {
    md5:    _uniq([...(ph.md5    || []), ...(ih.md5    || [])]),
    sha1:   _uniq([...(ph.sha1   || []), ...(ih.sha1   || [])]),
    sha256: _uniq([...(ph.sha256 || []), ...(ih.sha256 || [])]),
  };
  return out;
}
