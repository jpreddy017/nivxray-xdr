/**
 * DT2-3 · PROCESS / RELATIONSHIP / TIME model — pure selectors over the
 * server-derived TrajectoryGraph (`dt2.graph`, DT2-2E).
 *
 * The one rule this file exists to enforce: THE CLIENT INFERS NOTHING.
 * Every lane, lifeline, connector, attached activity, ordering step and WHY
 * string below is read from the graph the server composed from
 * DT2-2A/2B/2C/2D evidence. There is no place here where temporal
 * proximity, a shared image name, a shared user, PID adjacency or analyst
 * expectation can create a relationship — if the server produced no edge,
 * the UI shows no edge.
 */
export const GRAPH_ABSENT = "GRAPH_ABSENT";
export const GRAPH_EMPTY = "GRAPH_EMPTY";
export const GRAPH_READY = "GRAPH_READY";

export const ACTIVITY_FAMILIES = ["DNS", "NETWORK", "FILE", "REGISTRY"];

/** Evidence span ≠ process lifetime. AMP draws a lifeline; we only ever
 *  draw what was observed, and we say so. */
export const SPAN_OBSERVED = "OBSERVED_EVIDENCE_SPAN";
export const SPAN_TERMINATED = "TERMINATION_OBSERVED";

export const graphOf = (dt2) => dt2?.graph || null;

export function graphStateOf(dt2) {
  const g = graphOf(dt2);
  if (!g) return GRAPH_ABSENT;
  return (g.process_nodes || []).length ? GRAPH_READY : GRAPH_EMPTY;
}

const ms = (iso) => {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
};

/**
 * The lifeline a lane draws.
 *
 * `end_state: PROCESS_END_EVIDENCE_UNAVAILABLE` means exactly that: the span
 * ends at the LAST OBSERVED evidence, and the caller must present it as an
 * evidence span, never as a process exit.
 */
export function lifelineOf(node) {
  const l = node?.lifeline || {};
  const startMs = ms(l.first_evidence_at);
  const lastMs = ms(l.last_evidence_at);
  const endEvidence = Boolean(l.exit_observed && l.end_time);
  return {
    startMs,
    endMs: endEvidence ? ms(l.end_time) : lastMs,
    lastEvidenceMs: lastMs,
    instant: startMs != null && startMs === lastMs && !endEvidence,
    terminated: endEvidence,
    semantics: endEvidence ? SPAN_TERMINATED : SPAN_OBSERVED,
    endState: l.end_state || "PROCESS_END_EVIDENCE_UNAVAILABLE",
    basis: l.basis || null,
  };
}

export const processIndex = (g) => new Map(
  (g?.process_nodes || []).map((n) => [n.node_id, n]));

export const activityIndex = (g) => {
  const byProcess = new Map();
  for (const a of g?.activity_nodes || []) {
    const list = byProcess.get(a.process_node_id) || [];
    list.push(a);
    byProcess.set(a.process_node_id, list);
  }
  for (const list of byProcess.values()) {
    list.sort((x, y) => (ms(x.times?.ordering_time || x.times?.source_time) || 0)
      - (ms(y.times?.ordering_time || y.times?.source_time) || 0));
  }
  return byProcess;
};

export const activitiesFor = (g, nodeId) =>
  activityIndex(g).get(nodeId) || [];

/** The activity's own observed time — never the owning process's time. */
export const activityTimeMs = (a) =>
  ms(a?.times?.ordering_time) ?? ms(a?.times?.source_time)
  ?? ms(a?.times?.canonicalized_time);

export const parentOf = (g, nodeId) => {
  const node = processIndex(g).get(nodeId);
  if (!node?.parent_node_id) return null;
  return processIndex(g).get(node.parent_node_id) || null;
};

export const childrenOf = (g, nodeId) => {
  const idx = processIndex(g);
  const node = idx.get(nodeId);
  return (node?.child_node_ids || []).map((id) => idx.get(id))
    .filter(Boolean);
};

/** The edge that JUSTIFIES a drawn connector. No edge → no connector. */
export const edgeFor = (g, parentNodeId, childNodeId) =>
  (g?.edges || []).find((e) => e.relationship_type === "PROCESS_PROCESS"
    && e.source_node_id === parentNodeId
    && e.target_node_id === childNodeId) || null;

export const activityEdgeFor = (g, activityNode) =>
  (g?.edges || []).find((e) => e.edge_id === activityNode?.edge_id) || null;

/** The compact WHY. Every field comes from the edge the server emitted. */
export function whyOf(edge) {
  if (!edge) return null;
  return {
    type: edge.relationship_type,
    basis: edge.derivation_basis,
    reason: edge.reason,
    authority: edge.authority,
    downgraded: Boolean(edge.downgraded),
    evidenceCount: (edge.evidence_ref || []).length,
    evidence: edge.evidence_ref || [],
  };
}

/**
 * Lane order: every root, then each root's descendants depth-first, ordered
 * by first observed evidence. Rendering order only — it creates no edge.
 */
export function laneRowsOf(g, { max = 120 } = {}) {
  if (!g) return [];
  const idx = processIndex(g);
  const acts = activityIndex(g);
  const seen = new Set();
  const out = [];
  const byTime = (a, b) => (lifelineOf(a).startMs || 0)
    - (lifelineOf(b).startMs || 0);

  const walk = (node) => {
    if (!node || seen.has(node.node_id) || out.length >= max) return;
    seen.add(node.node_id);
    out.push({
      node,
      nodeId: node.node_id,
      depth: node.depth || 0,
      lifeline: lifelineOf(node),
      activities: acts.get(node.node_id) || [],
      parentNodeId: node.parent_node_id || null,
      parentState: node.parent_state || null,
      childNodeIds: node.child_node_ids || [],
    });
    childrenOf(g, node.node_id).sort(byTime).forEach(walk);
  };

  const roots = (g.root_node_ids || []).map((id) => idx.get(id))
    .filter(Boolean).sort(byTime);
  roots.forEach(walk);
  // Any node whose parent is outside the window is still an honest lane.
  (g.process_nodes || []).slice().sort(byTime).forEach(walk);
  return out;
}

/** The time bounds the lanes actually occupy (never invented padding). */
export function graphBoundsOf(g) {
  let min = null;
  let max = null;
  const bump = (t) => {
    if (t == null) return;
    min = min == null ? t : Math.min(min, t);
    max = max == null ? t : Math.max(max, t);
  };
  for (const n of g?.process_nodes || []) {
    const l = lifelineOf(n);
    bump(l.startMs);
    bump(l.endMs);
  }
  for (const a of g?.activity_nodes || []) bump(activityTimeMs(a));
  return { min, max, instant: min != null && min === max };
}

/**
 * BEFORE / AFTER over the server's evidence ordering (DT2-2C).
 *
 * `link_to_previous` is carried through untouched: `CAUSALITY_UNKNOWN` stays
 * unknown. Stepping to the next step NEVER asserts that the previous step
 * caused it.
 */
export function stepsOf(g) {
  const order = g?.order || [];
  const ids = g?.navigation?.ordered_step_ids;
  if (!ids?.length) return order;
  const byId = new Map(order.map((s) => [s.step_id, s]));
  return ids.map((id) => byId.get(id)).filter(Boolean);
}

export function stepIndexFor(g, { stepId, nodeId } = {}) {
  const steps = stepsOf(g);
  if (stepId) {
    const i = steps.findIndex((s) => s.step_id === stepId);
    if (i >= 0) return i;
  }
  if (nodeId) {
    const i = steps.findIndex((s) => s.node_id === nodeId
      || s.actor_node_id === nodeId);
    if (i >= 0) return i;
  }
  return -1;
}

export function neighbourStep(g, current, dir) {
  const steps = stepsOf(g);
  if (!steps.length) return null;
  const at = stepIndexFor(g, current);
  const next = at < 0 ? (dir > 0 ? 0 : steps.length - 1) : at + dir;
  if (next < 0 || next >= steps.length) return null;
  const step = steps[next];
  return {
    step,
    causality: step.link_to_previous || "CAUSALITY_UNKNOWN",
    causalityReason: step.link_reason || null,
    // ordering is ordering; it is not a causal claim
    implies_causality: false,
  };
}

export const FOCUS_UNRESOLVED = "FOCUS_UNRESOLVED";

/**
 * Exact focus, or an explicit unresolved state. We never quietly select the
 * nearest convenient process/event and call it exact.
 */
export function focusOf(g) {
  const f = g?.focus;
  if (!f) return { state: FOCUS_UNRESOLVED, exact: false, nodeId: null,
                   basis: null, requested: false };
  const exact = f.state === "RESOLVED_EXACT";
  return {
    state: f.state || FOCUS_UNRESOLVED,
    exact,
    nodeId: exact ? (f.process_node_id || null) : null,
    observationId: exact ? (f.observation_id || null) : null,
    timestampOnly: f.timestamp_only || null,
    basis: f.basis || null,
    window: f.window || null,
    requested: true,
  };
}

export const availabilityOf = (g) => g?.availability || {};

/** Which activity families this window's evidence actually contains. */
export function familiesPresent(g) {
  const seen = new Set((g?.activity_nodes || []).map((a) => a.family));
  return ACTIVITY_FAMILIES.reduce((acc, fam) => {
    acc[fam] = seen.has(fam) ? "OBSERVED" : "NOT_OBSERVED";
    return acc;
  }, {});
}

export const ROW_PROCESS = "PROCESS";
export const ROW_FILE = "FILE";

/**
 * DT2-3b · Cisco's vertical axis is "a list of files and processes"
 * (User Guide p.401). A FILE row is therefore a first-class trajectory
 * row — but only where CANONICAL FILE EVIDENCE names the artefact AND
 * the server produced the process → artefact edge for it.
 *
 * No file row is derived from a label alone, from timestamp proximity,
 * from a matching name, from the same user or PID, or from adjacency.
 * A FILE activity without a server edge stays on the process row, where
 * it makes no relationship claim at all.
 *
 * This reuses the server relationship graph. It builds no second
 * relationship engine: `activityEdgeFor` is the only authority.
 */
export function axisRowsOf(g, { max = 120 } = {}) {
  const lanes = laneRowsOf(g, { max });
  const out = [];
  for (const lane of lanes) {
    const files = new Map();
    const kept = [];
    for (const a of lane.activities) {
      const label = a.family === "FILE" && a.label ? String(a.label) : null;
      const edge = label ? activityEdgeFor(g, a) : null;
      if (!label || !edge) { kept.push(a); continue; }
      const key = `${lane.nodeId}::${label}`;
      const row = files.get(key) || { key, label, edge, activities: [] };
      row.activities.push(a);
      files.set(key, row);
    }
    out.push({ ...lane, kind: ROW_PROCESS, activities: kept });
    for (const f of files.values()) {
      const times = f.activities.map(activityTimeMs)
        .filter((t) => t != null);
      if (!times.length) continue;
      out.push({
        kind: ROW_FILE,
        nodeId: f.key,
        node: { label: f.label, image: f.label },
        depth: (lane.depth || 0) + 1,
        parentNodeId: lane.nodeId,
        activityEdge: f.edge,
        activities: f.activities,
        lifeline: {
          startMs: Math.min(...times),
          endMs: Math.max(...times),
          terminated: false,
          semantics: SPAN_OBSERVED,
        },
      });
    }
    if (out.length >= max) break;
  }
  return out.slice(0, max);
}

/** DT2-3c · an event may be presented as an indication of compromise
 *  only where its own evidence says so. No cross-event association is
 *  inferred: Cisco's blue halo needs a proven contributor set, and the
 *  NivXForge contract does not yet publish one. */
export const isCompromise = (n) => Boolean(
  n && (n.detection === true || n.is_detection === true
        || n.detection_name || (n.labels || []).includes("DETECTION")));
