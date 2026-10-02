// DT-I1D causal context (dt-i1.causal.v1). Pure, deterministic, bounded. Mirrors backend/edr_investigation/causal.py.
// Chronology is never causality: an edge exists only where the event itself states an identity linkage.
export const CAUSAL_VERSION = "dt-i1.causal.v1";
export const RESOLVER = "dt-i1d.frame_identity";
export const STATES = ["PROVEN_CAUSAL", "SUPPORTED_RELATIONSHIP", "CORRELATED", "UNKNOWN"];
export const BASIS_GUID = "SYSMON_PROCESS_GUID";
export const BASIS_PID_ONLY = "PID_ONLY_NOT_GLOBALLY_STABLE";
export const WINDOW_MS = 60000;
export const MAX_ITEMS = 50;
export const MAX_PRECEDING = 3;
export const GROUPS = ["observed", "preceded_by", "caused_by", "produced", "correlated", "unknown", "evidence"];
export const TEMPORAL = "Temporal order alone is never shown as causality.";
export const PARENT_UNKNOWN = "Parent process: UNKNOWN — required parent-process identity unavailable for this observation.";
export const PARENT_PID_ONLY = "Parent process: UNKNOWN — only a PID was reported; PID equality never establishes identity.";
export const CHILD_UNKNOWN = "Process identity: UNKNOWN — this event carries no stable process identity.";
export const ACTOR_UNKNOWN = "Actor process: UNKNOWN — this event carries no process identity.";
export const ACTOR_PID_ONLY = "Actor process: UNKNOWN — only a PID was reported; PID equality never establishes identity.";
export const NET_CORRELATED = "Network relationship: CORRELATED — occurred in window; telemetry does not establish the selected process initiated it.";
const EFFECT = { file: "wrote", registry: "modified", network: "connected_to", dns: "queried" };
const LANE = { process: "Process", file: "File", registry: "Registry", network: "Network", dns: "DNS" };

const tsOf = (f) => { const t = Date.parse(f.ts); return Number.isFinite(t) ? t : 0; };
const iso = (t) => new Date(t).toISOString();
export const refsOf = (f) =>
  [...new Set([f.canonical_evidence_id, f.frame_iid, ...(f.evidence_ids || [])].filter(Boolean))].slice(0, 4);

// PID never establishes identity: only a process_iid that is not PID-only counts.
export function identityOf(e) {
  if (!e) return { id: null, basis: null, pid_only: false };
  const basis = e.identity_basis || null;
  if (e.iid && basis !== BASIS_PID_ONLY) return { id: e.iid, basis: basis || "PROCESS_IID", pid_only: false };
  return { id: null, basis, pid_only: e.pid != null || basis === BASIS_PID_ONLY };
}

function effectType(f) {
  const a = (f.action || "").toLowerCase();
  if (f.lane === "file" && /exec/.test(a)) return "executed";
  if (f.lane === "network" && /dns|query/.test(a)) return "queried";
  return EFFECT[f.lane] || null;
}
const targetOf = (f) => (f.lane === "network" ? f.remote_ip || f.domain : f.target_path || f.sha256 || f.label) || null;

function edge(f, type, src, tgt, state, reason, extra = {}) {
  return {
    relationship_id: `rel:${type}:${src || "?"}->${tgt || "?"}@${f.frame_iid}`,
    relationship_type: type, source_entity: src || null, target_entity: tgt || null, relationship_state: state,
    evidence_refs: refsOf(f), timestamp: f.ts || null, window: extra.window || null, linkage: extra.linkage || null,
    reason, resolver: RESOLVER, resolver_version: CAUSAL_VERSION,
    provenance: { frame_iid: f.frame_iid, canonical_evidence_id: f.canonical_evidence_id || null,
                  identity_basis: extra.basis || null,
                  data_origin: f.investigation && f.investigation.synthetic ? "SYNTHETIC_FIXTURE" : "TRAJECTORY_API" },
  };
}

export function frameEdges(f) {
  if (!f || !f.frame_iid) return [];
  if (f.lane === "process") {
    const c = identityOf(f.entity || f.process), p = identityOf(f.parent);
    const basis = { source: p.basis, target: c.basis };
    if (!c.id) return [edge(f, "spawned", p.id, null, "UNKNOWN", CHILD_UNKNOWN, { basis })];
    if (!p.id) return [edge(f, "spawned", null, c.id, "UNKNOWN", p.pid_only ? PARENT_PID_ONLY : PARENT_UNKNOWN, { basis })];
    const proven = p.basis === BASIS_GUID && c.basis === BASIS_GUID;
    return [edge(f, "spawned", p.id, c.id, proven ? "PROVEN_CAUSAL" : "SUPPORTED_RELATIONSHIP",
      proven ? "parent and child process GUIDs are both stated on this event"
             : "parent process_iid reported on this event; identity is not GUID-backed",
      { basis, linkage: proven ? "SOURCE_PROCESS_GUID" : null })];
  }
  const type = effectType(f);
  if (!type) return [];
  const a = identityOf(f.process), tgt = targetOf(f), basis = { source: a.basis, target: null };
  if (a.id && tgt) return [edge(f, type, a.id, tgt, "SUPPORTED_RELATIONSHIP", "event states the acting process identity", { basis })];
  return [edge(f, type, null, tgt, "UNKNOWN", a.pid_only ? ACTOR_PID_ONLY : ACTOR_UNKNOWN, { basis })];
}

const strong = (e) => e.relationship_state === "PROVEN_CAUSAL" || e.relationship_state === "SUPPORTED_RELATIONSHIP";
const corrReason = (f, ent) => (f.lane === "network" ? NET_CORRELATED
  : `${LANE[f.lane] || "Event"} relationship: CORRELATED — occurred in window; telemetry does not directly link it to the selected ${ent ? "process" : "event"}.`);

export function buildCausalContext(frames, subjectId) {
  const list = (frames || []).filter((f) => f && f.frame_iid)
    .sort((a, b) => tsOf(a) - tsOf(b) || (a.frame_iid < b.frame_iid ? -1 : a.frame_iid > b.frame_iid ? 1 : 0));
  const idx = list.findIndex((f) => f.frame_iid === subjectId);
  if (idx < 0) return null;
  const s = list[idx], t0 = tsOf(s);
  const ent = s.lane === "process" ? identityOf(s.entity || s.process).id : null;
  const own = frameEdges(s);
  const causedBy = own.filter(strong);
  const unknown = own.filter((e) => e.relationship_state === "UNKNOWN");
  const produced = ent ? list.filter((f) => f.frame_iid !== s.frame_iid).flatMap(frameEdges)
    .filter((e) => strong(e) && e.source_entity === ent) : [];
  const linked = new Set([...causedBy, ...produced].map((e) => e.provenance.frame_iid));
  const related = new Set([ent, ...causedBy.map((e) => e.source_entity)].filter(Boolean));
  const window = { start: iso(t0 - WINDOW_MS), end: iso(t0 + WINDOW_MS) };
  const correlated = t0 ? list.filter((f) => f.frame_iid !== s.frame_iid && !linked.has(f.frame_iid)
      && !(f.lane === "process" && related.has(identityOf(f.entity || f.process).id))
      && Math.abs(tsOf(f) - t0) <= WINDOW_MS)
    .map((f) => edge(f, "co_occurred", ent || s.frame_iid, targetOf(f) || identityOf(f.entity || f.process).id || f.frame_iid,
      "CORRELATED", corrReason(f, ent), { window })) : [];
  const precededBy = list.slice(Math.max(0, idx - MAX_PRECEDING), idx)
    .map((f) => ({ frame_iid: f.frame_iid, ts: f.ts || null, lane: f.lane || null, label: f.label || null, relation: "CHRONOLOGICAL_ONLY" }));
  const evidence = [...new Set([...causedBy, ...produced, ...unknown].flatMap((e) => e.evidence_refs).concat(refsOf(s)))].sort();
  const cap = (a) => a.slice(0, MAX_ITEMS);
  const groups = {
    observed: [{ frame_iid: s.frame_iid, ts: s.ts || null, lane: s.lane || null, label: s.label || null, entity: ent }],
    preceded_by: precededBy, caused_by: cap(causedBy), produced: cap(produced), correlated: cap(correlated),
    unknown: cap(unknown), evidence: cap(evidence),
  };
  return { view_version: CAUSAL_VERSION, subject: s.frame_iid, groups, statements: [TEMPORAL],
           edges: cap([...groups.caused_by, ...groups.produced, ...groups.correlated, ...groups.unknown]) };
}
