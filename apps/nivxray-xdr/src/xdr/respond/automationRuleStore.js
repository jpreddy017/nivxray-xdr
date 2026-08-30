/**
 * Automation-rule store · execution-ready, design-only.
 *
 * Automation Rule = WHEN (trigger + conditions) → THEN (actions,
 * including "invoke playbook").  Owns the DECISION of when a
 * playbook fires; the playbook owns WHAT happens.
 *
 * Persists to localStorage.  Shape lines up with the eventual
 * `/api/automation-rules` endpoint so the swap is one file.
 *
 * Data shape:
 *   id, tenant_id, name, description, tags: string[],
 *   lifecycle: draft | testing | enabled | disabled | deprecated,
 *   version: int, versions: [{ v, at, by, note }],
 *   trigger:      { type },                 // incident.created | alert.created | verdict.changed | manual
 *   conditions:   [{ field, op, value }],   // AND-joined
 *   actions:      [{ kind, ... }],          // invoke_playbook | tag | assign | notify | change_severity
 *   run_order:    "sequential" | "parallel",
 *   created_at, updated_at, created_by, modified_by,
 *   audit:        [{ at, by, event }]
 */
const KEY = "nivxray-xdr:automation-rules:v1";

function _now() { return new Date().toISOString(); }
function _uid() { return "rule-" + Math.random().toString(36).slice(2, 10); }

function _read() {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? JSON.parse(raw) : {};
  } catch { return {}; }
}
function _write(map) { localStorage.setItem(KEY, JSON.stringify(map)); }


// ── Lifecycle (mirrors playbooks intentionally) ──────────────
export const LIFECYCLE = {
  DRAFT:      "draft",
  TESTING:    "testing",
  ENABLED:    "enabled",
  DISABLED:   "disabled",
  DEPRECATED: "deprecated",
};
export function canTransition(from, to) {
  const F = {
    draft:      ["testing", "disabled", "deprecated"],
    testing:    ["enabled", "draft", "disabled", "deprecated"],
    enabled:    ["disabled", "deprecated"],
    disabled:   ["draft", "testing", "enabled", "deprecated"],
    deprecated: [],
  };
  return (F[from] || []).includes(to);
}


// ── Trigger catalogue ────────────────────────────────────────
export const TRIGGERS = [
  { type: "incident.created",     label: "New incident created",
    fields: ["severity", "verdict", "confidence", "mitre_technique", "asset_type", "tag"] },
  { type: "incident.severity_changed", label: "Incident severity changed",
    fields: ["severity", "previous_severity"] },
  { type: "alert.created",        label: "New alert",
    fields: ["rule_id", "severity", "asset_type"] },
  { type: "verdict.changed",      label: "Verdict changed",
    fields: ["verdict", "previous_verdict", "confidence"] },
  { type: "manual",               label: "Manual (analyst-invoked)",
    fields: [] },
];
export function getTrigger(type) {
  return TRIGGERS.find((t) => t.type === type) || null;
}

// ── Condition operators ──────────────────────────────────────
export const OPS = [
  { op: "eq",       label: "equals" },
  { op: "neq",      label: "not equals" },
  { op: "gt",       label: "greater than" },
  { op: "gte",      label: "greater or equal" },
  { op: "lt",       label: "less than" },
  { op: "lte",      label: "less or equal" },
  { op: "in",       label: "in list" },
  { op: "contains", label: "contains" },
];

// ── Action kinds available to the rule (side actions; the main
//    action is "invoke_playbook") ─────────────────────────────
export const ACTION_KINDS = [
  { kind: "invoke_playbook",   label: "Run playbook",
    params: [{ key: "playbook_id", label: "Playbook", required: true }] },
  { kind: "tag_incident",      label: "Tag incident",
    params: [{ key: "tag", label: "Tag", required: true }] },
  { kind: "assign",            label: "Assign to analyst",
    params: [{ key: "assignee", label: "Analyst", required: true }] },
  { kind: "change_severity",   label: "Change severity",
    params: [{ key: "severity", label: "Severity", required: true }] },
  { kind: "notify",            label: "Send notification",
    params: [{ key: "channel", label: "Channel", required: true },
                { key: "message", label: "Message", required: true }] },
];
export function getActionKind(k) {
  return ACTION_KINDS.find((x) => x.kind === k) || null;
}


// ── CRUD ─────────────────────────────────────────────────────
export function listRules() {
  return Object.values(_read())
    .sort((a, b) => (b.updated_at || "").localeCompare(a.updated_at || ""));
}
export function getRule(id) { return _read()[id] || null; }

export function createRule({ name = "New automation rule",
                                    tenant_id = "default",
                                    created_by = "operator" } = {}) {
  const id = _uid();
  const rule = {
    id, tenant_id, name, description: "", tags: [],
    lifecycle:  LIFECYCLE.DRAFT,
    version:    1,
    versions:   [{ v: 1, at: _now(), by: created_by, note: "initial draft" }],
    trigger:    { type: "incident.created" },
    conditions: [],
    actions:    [],
    run_order:  "sequential",
    created_at: _now(), updated_at: _now(),
    created_by, modified_by: created_by,
    audit:      [{ at: _now(), by: created_by, event: "created" }],
  };
  const map = _read(); map[id] = rule; _write(map);
  return rule;
}

export function saveRule(rule, { by = "operator", note = "" } = {}) {
  const map = _read();
  const prev = map[rule.id];
  if (!prev) throw new Error(`rule ${rule.id} not found`);
  const next = { ...rule,
    version:    (prev.version || 1) + 1,
    versions:   [ ...(prev.versions || []),
                     { v: (prev.version || 1) + 1, at: _now(), by,
                       note: note || `saved by ${by}` } ],
    updated_at: _now(), modified_by: by,
    audit:      [ ...(prev.audit || []),
                     { at: _now(), by, event: `saved v${(prev.version || 1) + 1}` } ],
  };
  map[rule.id] = next; _write(map);
  return next;
}

export function duplicateRule(id, { by = "operator" } = {}) {
  const src = getRule(id); if (!src) return null;
  const copy = JSON.parse(JSON.stringify(src));
  copy.id = _uid();
  copy.name = (src.name || "") + " (copy)";
  copy.lifecycle = LIFECYCLE.DRAFT;
  copy.version = 1;
  copy.versions = [{ v: 1, at: _now(), by, note: `duplicated from ${id}` }];
  copy.created_at = copy.updated_at = _now();
  copy.created_by = copy.modified_by = by;
  copy.audit = [{ at: _now(), by, event: `duplicated from ${id}` }];
  const map = _read(); map[copy.id] = copy; _write(map);
  return copy;
}

export function deleteRule(id) {
  const map = _read(); const gone = !!map[id]; delete map[id]; _write(map);
  return gone;
}

export function transitionLifecycle(id, to, { by = "operator", note = "" } = {}) {
  const map = _read(); const r = map[id];
  if (!r) return null;
  if (!canTransition(r.lifecycle, to)) {
    throw new Error(`illegal transition ${r.lifecycle} → ${to}`);
  }
  r.lifecycle = to;
  r.updated_at = _now();
  r.modified_by = by;
  r.audit = [ ...(r.audit || []),
                 { at: _now(), by, event: `lifecycle → ${to}${note ? " · " + note : ""}` } ];
  _write(map);
  return r;
}


// ── Design-time simulation (does NOT execute against Response Engine) ─
export function simulate(rule, sampleEvent) {
  // Evaluate conditions against a hypothetical event.  This is a
  // pure function — it never calls the Response Engine and never
  // invokes any playbook.  It exists so a rule author can see
  // "would this rule have fired on that event".
  const matches = (rule.conditions || []).every((c) => {
    const v = sampleEvent?.[c.field];
    switch (c.op) {
      case "eq":       return String(v) === String(c.value);
      case "neq":      return String(v) !== String(c.value);
      case "gt":       return Number(v) >  Number(c.value);
      case "gte":      return Number(v) >= Number(c.value);
      case "lt":       return Number(v) <  Number(c.value);
      case "lte":      return Number(v) <= Number(c.value);
      case "in":       return String(c.value).split(",").map((x) => x.trim()).includes(String(v));
      case "contains": return String(v || "").toLowerCase().includes(String(c.value || "").toLowerCase());
      default:         return false;
    }
  });
  return {
    matched:       matches,
    would_execute: matches ? (rule.actions || []).map((a) => a.kind) : [],
    note:          "Simulation only — Response Engine NOT WIRED · no side effects performed.",
  };
}
