/**
 * NivXRay Detection Rule Store.
 *
 * Persists rule state in ``localStorage`` for the frontend MVP.  The
 * Detection Runtime (server-side rule execution) is intentionally
 * NOT WIRED yet — that's a Phase-D milestone.  The store surfaces this
 * honestly via ``RUNTIME_STATUS`` so the UI can render an
 * "AUTHORING AVAILABLE — DETECTION RUNTIME NOT WIRED" banner.
 *
 * Owner-locked:
 *   – Never claim a rule is "running" against production telemetry.
 *   – Rule authoring / testing / replay are all client-side, evaluated
 *     against sample events the analyst supplies.  Nothing here writes
 *     to SSOT / Verdict / IKG.
 *   – Adopt Sigma taxonomy — do not invent proprietary fields.
 */
import { parseSigma, SAMPLE_RULE } from "./sigmaEngine";

const KEY = "nivxray.xdr.detection.rules.v1";

// ── Lifecycle states ────────────────────────────────────────────────
export const LIFECYCLE = ["draft", "testing", "enabled", "disabled", "deprecated"];
export const LIFECYCLE_LABELS = {
  draft:      "Draft",
  testing:    "Testing",
  enabled:    "Enabled",
  disabled:   "Disabled",
  deprecated: "Deprecated",
};
// Owner-locked lifecycle transitions — enforced by ``transitionLifecycle``.
export const LIFECYCLE_TRANSITIONS = {
  draft:      ["testing", "disabled"],
  testing:    ["enabled", "draft", "disabled"],
  enabled:    ["disabled", "testing"],
  disabled:   ["testing", "deprecated"],
  deprecated: [],
};

// The Detection Runtime does not exist yet — surface honestly.
export const RUNTIME_STATUS = {
  status: "NOT_WIRED",
  detail: "AUTHORING AVAILABLE — DETECTION RUNTIME NOT WIRED. Rules are "
             + "authored, tested, and version-controlled in this session but "
             + "not yet executed against live telemetry.",
};


// ── Types ──────────────────────────────────────────────────────────
// A "detection type" describes what kind of engine will eventually
// evaluate the rule.  We surface these types in the UI so authors
// know what infrastructure their rule needs — but we do NOT claim any
// of them are running.  Only ``event_sigma`` has a client-side
// evaluator today.
export const DETECTION_TYPES = [
  { key: "event_sigma",  label: "Event · Sigma",       supported: true },
  { key: "ioc",          label: "IOC match",           supported: false },
  { key: "threshold",    label: "Threshold",           supported: false },
  { key: "sequence",     label: "Sequence",            supported: false },
  { key: "correlation",  label: "Correlation",         supported: false },
  { key: "process_chain", label: "Process chain",     supported: false },
  { key: "network",      label: "Network",             supported: false },
  { key: "identity",     label: "Identity",            supported: false },
  { key: "file_hash",    label: "File / hash",         supported: false },
  { key: "behavioral",   label: "Behavioral",          supported: false },
  { key: "scheduled",    label: "Scheduled",           supported: false },
];


// ── Persistence ─────────────────────────────────────────────────────
function _load() {
  try   { return JSON.parse(localStorage.getItem(KEY) || "[]"); }
  catch { return []; }
}
function _save(rules) { localStorage.setItem(KEY, JSON.stringify(rules)); }


function _uuid() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}


function _seedIfEmpty() {
  const cur = _load();
  if (cur.length > 0) return cur;
  const now = new Date().toISOString();
  const seed = [{
    id: "rule-" + _uuid(),
    kind: "event_sigma",
    lifecycle: "testing",
    sigma_yaml: SAMPLE_RULE,
    // The following are derived from Sigma but cached on the record.
    title:       "Encoded PowerShell Execution",
    description: "Detects PowerShell run with the -EncodedCommand flag.",
    severity:    "high",
    tags:        ["attack.execution", "attack.t1059.001"],
    author:      "NivXRay",
    version:     1,
    versions: [
      { version: 1, at: now, by: "NivXRay", note: "Seeded on install." },
    ],
    created_at: now, updated_at: now,
    // Runtime deployment status is HONEST — the runtime does not run yet.
    runtime_status: RUNTIME_STATUS.status,
  }];
  _save(seed);
  return seed;
}


// ── CRUD ────────────────────────────────────────────────────────────
export function listRules(filter = {}) {
  const rules = _seedIfEmpty();
  return rules.filter((r) => {
    if (filter.lifecycle && r.lifecycle !== filter.lifecycle) return false;
    if (filter.severity  && r.severity  !== filter.severity)  return false;
    if (filter.q) {
      const n = filter.q.toLowerCase();
      const hay = `${r.title} ${r.description} ${(r.tags || []).join(" ")}`.toLowerCase();
      if (!hay.includes(n)) return false;
    }
    return true;
  });
}
export function getRule(id) {
  return _seedIfEmpty().find((r) => r.id === id) || null;
}


export function createRule({ kind = "event_sigma",
                                    sigma_yaml = SAMPLE_RULE, author = "NivXRay" } = {}) {
  const now = new Date().toISOString();
  const derived = _deriveFromSigma(sigma_yaml);
  const rule = {
    id: "rule-" + _uuid(),
    kind, lifecycle: "draft",
    sigma_yaml,
    ...derived,
    author, version: 1,
    versions: [{ version: 1, at: now, by: author, note: "Initial draft." }],
    created_at: now, updated_at: now,
    runtime_status: RUNTIME_STATUS.status,
  };
  const rules = _seedIfEmpty();
  rules.unshift(rule);
  _save(rules);
  return rule;
}


export function saveRule(rule, { by = "NivXRay", note } = {}) {
  const rules = _seedIfEmpty();
  const i = rules.findIndex((r) => r.id === rule.id);
  if (i < 0) throw new Error("rule_not_found");
  const prev = rules[i];
  // Version bump only when the Sigma source actually changed.
  const changed = prev.sigma_yaml !== rule.sigma_yaml;
  const next    = {
    ...prev,
    ..._deriveFromSigma(rule.sigma_yaml),
    sigma_yaml: rule.sigma_yaml,
    lifecycle:  rule.lifecycle || prev.lifecycle,
    updated_at: new Date().toISOString(),
  };
  if (changed) {
    next.version  = prev.version + 1;
    next.versions = [
      ...prev.versions,
      { version: next.version, at: next.updated_at, by,
          note: note || "Rule updated." },
    ];
  }
  rules[i] = next;
  _save(rules);
  return next;
}


export function transitionLifecycle(id, to, { by = "NivXRay" } = {}) {
  const rules = _seedIfEmpty();
  const i = rules.findIndex((r) => r.id === id);
  if (i < 0) throw new Error("rule_not_found");
  const cur = rules[i];
  const allowed = LIFECYCLE_TRANSITIONS[cur.lifecycle] || [];
  if (!allowed.includes(to)) {
    throw new Error(`invalid_transition:${cur.lifecycle}→${to}`);
  }
  const now = new Date().toISOString();
  const next = {
    ...cur, lifecycle: to, updated_at: now,
    versions: [
      ...cur.versions,
      { version: cur.version, at: now, by,
          note: `Lifecycle ${cur.lifecycle} → ${to}.` },
    ],
  };
  rules[i] = next; _save(rules); return next;
}


export function rollbackRule(id, targetVersion, { by = "NivXRay" } = {}) {
  const rules = _seedIfEmpty();
  const i = rules.findIndex((r) => r.id === id);
  if (i < 0) throw new Error("rule_not_found");
  // Rollback in this MVP restores the human-recorded version note
  // (rule YAML is not persisted per version yet — see backlog); it
  // does record an audit entry that a rollback happened.
  const now = new Date().toISOString();
  rules[i] = {
    ...rules[i],
    updated_at: now,
    versions: [
      ...rules[i].versions,
      { version: rules[i].version + 1, at: now, by,
          note: `Rollback requested to version ${targetVersion}.` },
    ],
  };
  _save(rules);
  return rules[i];
}


export function deleteRule(id) {
  const rules = _seedIfEmpty();
  _save(rules.filter((r) => r.id !== id));
}


// ── Derivations ─────────────────────────────────────────────────────
function _deriveFromSigma(source) {
  const p = parseSigma(source);
  if (!p.ok) {
    return { title: "(unparseable)", description: "", severity: "medium",
                tags: [], techniques: [], validation: { ok: false, errors: p.errors } };
  }
  const r = p.rule;
  const tags = r.tags || [];
  const techniques = tags
    .filter((t) => /^attack\.t\d/.test(t))
    .map((t) => t.split(".")[1].toUpperCase());
  return {
    title:       r.title || "(untitled)",
    description: r.description || "",
    severity:    r.level || "medium",
    tags,
    techniques,
    references:  r.references || [],
    falsepositives: r.falsepositives || [],
    logsource:   r.logsource || {},
    validation: { ok: true, unsupported: p.unsupported || [] },
  };
}


// ── Coverage view ──────────────────────────────────────────────────
//
// Detection → Data Source → MITRE Technique → Evidence Type → Incident.
// This is a projection of ONLY the rules in the store — it exposes
// gaps rather than pretty percentages.
export function buildCoverage(rules) {
  const byTechnique = {};
  const byLogsource = {};
  for (const r of rules) {
    for (const t of (r.techniques || [])) {
      (byTechnique[t] = byTechnique[t] || []).push(r);
    }
    const ls = r.logsource || {};
    const key = [ls.product, ls.category, ls.service]
                    .filter(Boolean).join(":") || "unspecified";
    (byLogsource[key] = byLogsource[key] || []).push(r);
  }
  return { byTechnique, byLogsource };
}
