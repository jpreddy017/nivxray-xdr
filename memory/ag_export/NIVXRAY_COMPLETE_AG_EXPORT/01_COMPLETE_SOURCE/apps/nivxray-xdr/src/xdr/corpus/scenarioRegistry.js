/**
 * NivXRay XDR Investigation Corpus — scenario schema + registry.
 *
 * "The corpus should contain realistic complete investigations, not
 * merely logs."  Each scenario exercises the FULL loop:
 *
 *   raw evidence → correlation → verdict → severity →
 *   recommendation → playbook → response → report.
 *
 * The registry ships eight canonical categories per owner directive:
 *   benign · malicious · false-positive · ambiguous · incomplete ·
 *   conflicting · unknown · multi-stage.
 *
 * Scenarios live under docs/corpus/scenarios/<category>/<id>.json
 * (evidence-driven, no fake telemetry).  This module is the loader
 * + validator; adding a new scenario is a pure data change.
 */

// eight canonical categories — locked
export const CORPUS_CATEGORIES = [
  { key: "benign",         label: "Benign",
    purpose: "Legitimate activity that superficially resembles malicious." },
  { key: "malicious",      label: "Malicious",
    purpose: "Confirmed malicious end-to-end investigations." },
  { key: "false_positive", label: "False Positive",
    purpose: "Rule fired but evidence proves the activity is legitimate." },
  { key: "ambiguous",      label: "Ambiguous",
    purpose: "Evidence is real but inconclusive; requires human judgement." },
  { key: "incomplete",     label: "Incomplete Evidence",
    purpose: "SSOT lacks required facets; verdict must remain honest." },
  { key: "conflicting",    label: "Conflicting Evidence",
    purpose: "Two independent evidence streams disagree." },
  { key: "unknown",        label: "Unknown",
    purpose: "No prior signal — the engine must not fabricate a verdict." },
  { key: "multi_stage",    label: "Multi-Stage Attack",
    purpose: "Chained detections across time / hosts / identities." },
];


// Schema (documented; enforced at load time).
export const SCENARIO_SCHEMA_KEYS = [
  "id",                    // "SCN-2026-0001"
  "category",              // one of CORPUS_CATEGORIES.key
  "title",
  "description",
  "raw_events",            // canonical events array
  "normalized_evidence",   // expected NormalizedEvidence[]
  "expected_entities",     // { hosts[], users[], processes[], iocs[] }
  "expected_correlations", // [{ rule_id, technique_id, weight, ... }]
  "expected_rules_matched",// [{ rule_id, fields, technique }]
  "expected_mitre",        // ["T1059.001", ...]
  "expected_attack_story", // ["step 1 …", ...]
  "expected_verdict",      // { verdict, confidence, severity, reason }
  "expected_severity",     // "critical" | "high" | ...
  "expected_recommendations", // [{ kind, action, priority }]
  "expected_playbook",     // playbook_id or null
  "expected_response_outcome", // { state, evidence_ref? }
  "expected_report_sections",  // ["executive_summary", ...]
];


// Import the scenario JSON files that ship in-tree.  Vite's import.meta.glob
// eagerly loads them so the corpus is available synchronously.
const _modules = import.meta.glob(
  "../../../docs/corpus/scenarios/**/*.json",
  { eager: true, import: "default" });

function _loadScenarios() {
  const out = [];
  for (const [path, obj] of Object.entries(_modules)) {
    if (obj && obj.id && obj.category) {
      out.push({ ...obj, _path: path });
    }
  }
  return out.sort((a, b) => a.id.localeCompare(b.id));
}

const SCENARIOS = _loadScenarios();


export function listScenarios(category = null) {
  if (!category) return SCENARIOS;
  return SCENARIOS.filter((s) => s.category === category);
}

export function getScenario(id) {
  return SCENARIOS.find((s) => s.id === id) || null;
}

export function categoryCounts() {
  const t = Object.fromEntries(CORPUS_CATEGORIES.map((c) => [c.key, 0]));
  for (const s of SCENARIOS) t[s.category] = (t[s.category] || 0) + 1;
  return t;
}


/** Validate a scenario against the required schema keys.  Returns a
 *  list of missing keys; empty list = valid.  Purely deterministic.
 *  Note: `null` is a VALID value for optional facets (expected_playbook
 *  is intentionally null for benign / FP / unknown / ambiguous cases). */
export function validateScenario(s) {
  const missing = [];
  for (const k of SCENARIO_SCHEMA_KEYS) {
    if (!(k in s)) missing.push(k);   // absence, not null
  }
  const cat = CORPUS_CATEGORIES.find((c) => c.key === s.category);
  if (!cat) missing.push("category:unknown");
  return { valid: missing.length === 0, missing };
}


/** Corpus-wide sanity: every category MUST have at least one scenario
 *  once the corpus is complete.  Reports which are still empty. */
export function corpusCoverage() {
  const counts = categoryCounts();
  const empty  = CORPUS_CATEGORIES.filter((c) => counts[c.key] === 0)
                                                   .map((c) => c.key);
  return {
    total: SCENARIOS.length,
    by_category: counts,
    categories_empty: empty,
    complete_coverage: empty.length === 0,
  };
}
