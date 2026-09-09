/**
 * NivXRay XDR — Pattern Rules (regex/glob/exact/CIDR/…).
 *
 * A Pattern Rule is a REUSABLE PRIMITIVE.  It never asserts a verdict —
 * a match becomes an EVIDENCE OBSERVATION with rule_id · matched_field ·
 * matched_value · provenance.  Downstream engines (Correlation → Verdict
 * → Recommendation) decide what to do with the observation.
 *
 *   engine ∈ { regex | glob | exact | cidr | hash | domain | url |
 *              filename | command | threshold | sequence }
 *
 * Deterministic — same input yields the same match set every time.
 * NO ML in this layer.
 *
 * Storage: LocalStorage under `nvx.patternRules.v1`.  Server-side
 * persistence lives in the future control-plane API.
 */

const KEY = "nvx.patternRules.v1";
const listeners = new Set();

// Seed rules bundled with the client so the surface has real content.
const SEED = [
  {
    id: "prule.encoded_ps",
    name: "Encoded PowerShell",
    engine: "regex",
    pattern: "(?i)(powershell|pwsh)(\\.exe)?\\s+.*(-e(nc|ncoded ?command)?)\\b",
    apply_to: ["command_line", "process_arguments"],
    on_match: "add_evidence",
    tags: ["T1059.001", "T1027"],
    severity: "high",
    confidence: "high",
    enabled: true,
    version: 1,
    created_at: "2026-02-10T00:00:00Z",
    author: "nivxray",
  },
  {
    id: "prule.ps_downloader",
    name: "PowerShell Download Cradle",
    engine: "regex",
    pattern: "(?i)(DownloadString|DownloadFile|Invoke-WebRequest|iwr|iex).*(http|https)://",
    apply_to: ["command_line", "script_content"],
    on_match: "add_evidence",
    tags: ["T1105"], severity: "high", confidence: "high",
    enabled: true, version: 1, author: "nivxray",
    created_at: "2026-02-10T00:00:00Z",
  },
  {
    id: "prule.certutil_download",
    name: "certutil URL cache download",
    engine: "regex",
    pattern: "(?i)certutil(\\.exe)?\\s+.*-urlcache.*(http|https)://",
    apply_to: ["command_line"],
    on_match: "add_evidence",
    tags: ["T1105"], severity: "high", confidence: "high",
    enabled: true, version: 1, author: "nivxray",
    created_at: "2026-02-10T00:00:00Z",
  },
  {
    id: "prule.vssadmin_delete_shadows",
    name: "vssadmin delete shadows",
    engine: "regex",
    pattern: "(?i)vssadmin(\\.exe)?\\s+delete\\s+shadows",
    apply_to: ["command_line"],
    on_match: "add_evidence",
    tags: ["T1490"], severity: "critical", confidence: "high",
    enabled: true, version: 1, author: "nivxray",
    created_at: "2026-02-10T00:00:00Z",
  },
  {
    id: "prule.mshta_remote_url",
    name: "mshta remote URL",
    engine: "regex",
    pattern: "(?i)mshta(\\.exe)?\\s+.*(http|https)://",
    apply_to: ["command_line"],
    on_match: "add_evidence",
    tags: ["T1218.005"], severity: "high", confidence: "high",
    enabled: true, version: 1, author: "nivxray",
    created_at: "2026-02-10T00:00:00Z",
  },
  {
    id: "prule.regsvr32_squiblydoo",
    name: "regsvr32 Squiblydoo",
    engine: "regex",
    pattern: "(?i)regsvr32(\\.exe)?\\s+.*(/i:|scrobj\\.dll).*(http|https)://",
    apply_to: ["command_line"],
    on_match: "add_evidence",
    tags: ["T1218.010"], severity: "high", confidence: "high",
    enabled: true, version: 1, author: "nivxray",
    created_at: "2026-02-10T00:00:00Z",
  },
];


function _load() {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) {
      localStorage.setItem(KEY, JSON.stringify(SEED));
      return [...SEED];
    }
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [...SEED];
  } catch { return [...SEED]; }
}

function _save(rules) {
  try { localStorage.setItem(KEY, JSON.stringify(rules)); }
  catch { /* localStorage disabled — ignore, in-memory copy is source */ }
  listeners.forEach((fn) => fn(rules));
}

export function listPatternRules() { return _load(); }
export function getPatternRule(id) {
  return _load().find((r) => r.id === id) || null;
}
export function upsertPatternRule(rule) {
  const cur = _load();
  const i   = cur.findIndex((r) => r.id === rule.id);
  const now = new Date().toISOString();
  const withTs = { ...rule, updated_at: now,
                            version: (rule.version || 0) + 1 };
  if (i === -1) cur.push({ created_at: now, ...withTs });
  else cur[i] = { ...cur[i], ...withTs };
  _save(cur);
  return withTs;
}
export function removePatternRule(id) {
  _save(_load().filter((r) => r.id !== id));
}
export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}


/** Deterministic dry-run evaluator.  Returns matches[] with matched
 *  field + captured groups.  Never asserts a verdict — the caller
 *  decides how to compose it with other evidence. */
export function evaluatePattern(rule, sample) {
  const target = String(sample?.text || sample || "");
  if (!rule || !target) return { matched: false, matches: [] };
  try {
    if (rule.engine === "regex") {
      const flags = rule.flags || (rule.pattern.startsWith("(?i)") ? "" : "");
      const re = new RegExp(rule.pattern, flags);
      const m  = target.match(re);
      if (!m) return { matched: false, matches: [] };
      return {
        matched: true,
        matches: [{ match: m[0], groups: m.slice(1),
                          index: m.index || 0 }],
      };
    }
    if (rule.engine === "exact") {
      const hit = target.includes(rule.pattern);
      return { matched: hit, matches: hit ? [{ match: rule.pattern }] : [] };
    }
    if (rule.engine === "glob") {
      // Simplistic glob → regex (deterministic, no ML).
      const g = rule.pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&")
                                        .replace(/\*/g, ".*").replace(/\?/g, ".");
      const re = new RegExp(`^${g}$`, "i");
      const hit = re.test(target);
      return { matched: hit, matches: hit ? [{ match: target }] : [] };
    }
  } catch (e) {
    return { matched: false, matches: [], error: String(e.message || e) };
  }
  return { matched: false, matches: [] };
}
