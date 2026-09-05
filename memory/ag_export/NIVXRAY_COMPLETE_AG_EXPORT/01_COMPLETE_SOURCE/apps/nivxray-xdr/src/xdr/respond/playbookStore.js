/**
 * Playbook store · execution-ready data model, design-only persistence.
 *
 * Persists to localStorage today.  Every method returns the same shape
 * a future `/api/playbooks` endpoint will return, so swapping the
 * backing store later is a one-file change.
 *
 * Playbook shape:
 *   id, tenant_id, name, description, tags: string[],
 *   lifecycle: DRAFT | TESTING | ENABLED | DISABLED | DEPRECATED,
 *   version: int, versions: [{ v, at, by, note }],
 *   trigger: { type, filters },
 *   nodes: [{ id, kind: start|trigger|condition|action|end,
 *             action_id?, config: {}, next: string|null,
 *             yes_next?: string, no_next?: string }],
 *   entry:  <node id>,
 *   created_at, updated_at, created_by, modified_by,
 *   audit: [{ at, by, event }]
 */
const KEY  = "nivxray-xdr:playbooks:v1";
const LIFE = ["draft", "testing", "enabled", "disabled", "deprecated"];

function _now() { return new Date().toISOString(); }
function _uid() { return "pb-" + Math.random().toString(36).slice(2, 10); }
function _nid() { return "n-" + Math.random().toString(36).slice(2, 8); }

function _read() {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? JSON.parse(raw) : {};
  } catch { return {}; }
}
function _write(map) {
  localStorage.setItem(KEY, JSON.stringify(map));
}

export const LIFECYCLE = {
  DRAFT:      "draft",
  TESTING:    "testing",
  ENABLED:    "enabled",
  DISABLED:   "disabled",
  DEPRECATED: "deprecated",
};
export const LIFECYCLE_ORDER = LIFE;
export function canTransition(from, to) {
  const F = {
    draft:      ["testing", "disabled", "deprecated"],
    testing:    ["enabled", "draft", "disabled", "deprecated"],
    enabled:    ["disabled", "deprecated"],
    disabled:   ["draft", "testing", "enabled", "deprecated"],
    deprecated: ["draft"],                 // recovery-only: user can revive
  };
  return (F[from] || []).includes(to);
}


// ── CRUD ─────────────────────────────────────────────────────
export function listPlaybooks() {
  return Object.values(_read())
    .sort((a, b) => (b.updated_at || "").localeCompare(a.updated_at || ""));
}

export function getPlaybook(id) {
  return _read()[id] || null;
}

export function createPlaybook({ name, description, tenant_id = "default",
                                        created_by = "system" } = {}) {
  const id = _uid();
  const startId = _nid();
  const endId   = _nid();
  const pb = {
    id, tenant_id,
    name:         name || "Untitled playbook",
    description:  description || "",
    tags:         [],
    lifecycle:    LIFECYCLE.DRAFT,
    version:      1,
    versions:     [{ v: 1, at: _now(), by: created_by, note: "initial draft" }],
    trigger:      { type: "incident.created", filters: [] },
    entry:        startId,
    nodes: [
      { id: startId, kind: "start", next: endId },
      { id: endId,   kind: "end",   next: null },
    ],
    created_at: _now(), updated_at: _now(),
    created_by, modified_by: created_by,
    audit: [{ at: _now(), by: created_by, event: "created" }],
  };
  const map = _read();
  map[id] = pb;
  _write(map);
  return pb;
}

export function savePlaybook(pb, { by = "system", note = "" } = {}) {
  const map = _read();
  const prev = map[pb.id];
  if (!prev) throw new Error(`playbook ${pb.id} not found`);
  const next = { ...pb,
    version:     (prev.version || 1) + 1,
    versions:    [ ...(prev.versions || []),
                      { v: (prev.version || 1) + 1, at: _now(), by,
                        note: note || `saved by ${by}` } ],
    updated_at:  _now(),
    modified_by: by,
    audit:       [ ...(prev.audit || []),
                      { at: _now(), by, event: `saved v${(prev.version || 1) + 1}` } ],
  };
  map[pb.id] = next;
  _write(map);
  return next;
}

export function duplicatePlaybook(id, { by = "system" } = {}) {
  const src = getPlaybook(id);
  if (!src) return null;
  const newId = _uid();
  const copy = { ...JSON.parse(JSON.stringify(src)),
    id: newId,
    name: (src.name || "") + " (copy)",
    lifecycle: LIFECYCLE.DRAFT,
    version: 1,
    versions: [{ v: 1, at: _now(), by, note: `duplicated from ${id}` }],
    created_at: _now(), updated_at: _now(), created_by: by, modified_by: by,
    audit: [{ at: _now(), by, event: `duplicated from ${id}` }],
  };
  const map = _read();
  map[newId] = copy;
  _write(map);
  return copy;
}

export function deletePlaybook(id) {
  const map = _read();
  const gone = !!map[id];
  delete map[id];
  _write(map);
  return gone;
}

export function transitionLifecycle(id, next, { by = "system", note = "" } = {}) {
  const map = _read();
  const pb  = map[id];
  if (!pb) return null;
  if (!canTransition(pb.lifecycle, next)) {
    throw new Error(`illegal transition ${pb.lifecycle} → ${next}`);
  }
  pb.lifecycle  = next;
  pb.updated_at = _now();
  pb.modified_by = by;
  pb.audit = [ ...(pb.audit || []),
                  { at: _now(), by, event: `lifecycle → ${next}${note ? ` · ${note}` : ""}` } ];
  _write(map);
  return pb;
}


// ── Node helpers ─────────────────────────────────────────────
export function nid() { return _nid(); }
export function insertAfter(pb, afterId, node) {
  const src = pb.nodes.find((n) => n.id === afterId);
  if (!src) return pb;
  const newNode = { id: _nid(), ...node };
  // rewire
  if (src.kind === "condition") {
    // choose yes branch by default
    newNode.next = src.yes_next;
    src.yes_next = newNode.id;
  } else {
    newNode.next = src.next;
    src.next = newNode.id;
  }
  pb.nodes.push(newNode);
  return pb;
}
export function insertCondition(pb, afterId) {
  const src = pb.nodes.find((n) => n.id === afterId);
  if (!src || src.kind === "end") return pb;
  const yesEnd = { id: _nid(), kind: "end", next: null };
  const noEnd  = { id: _nid(), kind: "end", next: null };
  const cond   = { id: _nid(), kind: "condition",
                     config: { field: "verdict", op: "eq", value: "malicious" },
                     yes_next: yesEnd.id, no_next: noEnd.id };
  cond.next    = src.next;                // legacy compat
  const orig   = src.next;
  src.next     = cond.id;
  // dangling `orig` connects to yes-end for now.  Analyst rewires.
  pb.nodes.push(cond, yesEnd, noEnd);
  return pb;
}
export function removeNode(pb, id) {
  const target = pb.nodes.find((n) => n.id === id);
  if (!target || target.kind === "start" || target.kind === "end") return pb;
  // rewire: any node whose next/yes_next/no_next points to `id` → target.next
  for (const n of pb.nodes) {
    if (n.next === id)     n.next     = target.next;
    if (n.yes_next === id) n.yes_next = target.next;
    if (n.no_next === id)  n.no_next  = target.next;
  }
  pb.nodes = pb.nodes.filter((n) => n.id !== id);
  return pb;
}
