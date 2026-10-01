/**
 * DT2-3c · COMPROMISE / IOC presentation model.
 *
 * Everything here is READ from the server contract. This module contains
 * no inference and no fallback that could manufacture a compromise or a
 * contributor:
 *
 *   event.kind     = what was OBSERVED
 *   detection      = what a detection engine CONCLUDED
 *   compromise     = what an authoritative correlation / IOC mechanism
 *                    CONCLUDED
 *
 * Contributor membership arrives already resolved as
 * `row.contributor_of` (server-side, against `observation_id`). The
 * canvas must never derive it from proximity in time, the same PID, the
 * same lane, or adjacency on screen.
 */

export const CONTRACT_REF_IDENTITY = "observation_id";
export const NOT_OBSERVED = "NO_AUTHORITATIVE_COMPROMISE_OBSERVED";
export const RESOLVED = "AUTHORITATIVE_COMPROMISES_RESOLVED";
export const CONTRIBUTORS_PROVEN = "CONTRIBUTORS_PROVEN_BY_AUTHORITY";
export const CONTRIBUTORS_NOT_PROVEN = "CONTRIBUTORS_NOT_PROVEN_BY_AUTHORITY";

const msOf = (iso) => {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
};

/**
 * The compromise layer for one trajectory payload.
 *
 * `events` is the authority's own list. `byId` indexes them.
 * `contributorsById` maps a compromise id to the observation ids it
 * proved. `state` is the server's word for whether any authoritative
 * compromise exists at all — `NO_AUTHORITATIVE_COMPROMISE_OBSERVED` is a
 * real answer and is NOT a clean claim.
 */
export function indexCompromise(payload) {
  const contract = payload?.compromise_contract || null;
  const raw = Array.isArray(payload?.compromise_events)
    ? payload.compromise_events : [];
  const events = raw.map((c) => ({
    ...c,
    observedMs: msOf(c.observed_at),
    contributorIds: Array.isArray(c.resolved_observation_ids)
      ? c.resolved_observation_ids : [],
    unresolved: Array.isArray(c.unresolved_event_refs)
      ? c.unresolved_event_refs : [],
    contributorsProven: c.contributors_state === CONTRIBUTORS_PROVEN
      && (c.resolved_observation_ids || []).length > 0,
  }));
  const byId = new Map(events.map((c) => [c.compromise_event_id, c]));
  const contributorsById = new Map(
    events.map((c) => [c.compromise_event_id, c.contributorIds]));
  return {
    events,
    byId,
    contributorsById,
    contract,
    state: contract?.state || (events.length ? RESOLVED : NOT_OBSERVED),
    // Loud, because this is the honest result for the real Windows
    // corpus and it must never be softened into "clean".
    observed: events.length > 0,
    referenceIdentity: contract?.reference_identity || CONTRACT_REF_IDENTITY,
    inferenceAllowed: contract?.frontend_may_infer_contributors === true,
    rejected: contract?.rejected || [],
  };
}

/** The compromise ids a row was PROVEN to contribute to. Server only. */
export const contributorIdsOf = (node) => (
  Array.isArray(node?.contributor_of) ? node.contributor_of : []);

/** Whether this row carries proven contributor membership. */
export const isProvenContributor = (node) => contributorIdsOf(node).length > 0;

/** The compromise events that fall inside a viewport, by their own time. */
export function compromisesInWindow(layer, t0, t1) {
  if (!layer?.events?.length || !(t1 > t0)) return [];
  return layer.events.filter(
    (c) => c.observedMs != null && c.observedMs >= t0 && c.observedMs <= t1);
}

/** MITRE, presented only when the authority actually carried it. */
export function mitreOf(compromise) {
  return {
    tactics: Array.isArray(compromise?.tactics) ? compromise.tactics : [],
    techniques: Array.isArray(compromise?.techniques)
      ? compromise.techniques : [],
    state: ((compromise?.tactics || []).length
      || (compromise?.techniques || []).length)
      ? "ATTRIBUTED" : "NO_MITRE_ATTRIBUTION_CARRIED",
  };
}

/** The compromises this row contributed to, resolved to full records. */
export function compromisesOfRow(layer, node) {
  return contributorIdsOf(node)
    .map((id) => layer?.byId?.get(id))
    .filter(Boolean);
}

/** Why the authority said this row contributed — its own words. */
export function contributionBasisOf(compromise, observationId) {
  const ref = (compromise?.contributing_event_refs || []).find(
    (r) => r.observation_id === observationId);
  return ref?.contribution_basis || null;
}

/** The OBSERVATION ids a DT2 node was projected from. Server-provided
 *  evidence references only. */
const observationIdsOf = (n) => (n?.evidence_ref || [])
  .filter((r) => r && r.kind === "OBSERVATION" && r.id)
  .map((r) => r.id);

/**
 * Stamp `contributor_of` onto the DT2 graph.
 *
 * This is an IDENTITY JOIN, not an inference: the authority named
 * observation ids, the server resolved them, and each node already
 * carries the OBSERVATION evidence references it was projected from.
 * A node is emphasised only when one of ITS OWN references is in the
 * authority's list. Nothing is matched on time, PID, lane or label.
 */
export function attachContributors(graph, layer) {
  if (!graph || !layer?.observed) return graph;
  const owners = new Map();
  for (const c of layer.events) {
    for (const oid of c.contributorIds) {
      const list = owners.get(oid) || [];
      list.push(c.compromise_event_id);
      owners.set(oid, list);
    }
  }
  if (!owners.size) return graph;
  const stamp = (n) => {
    const ids = new Set();
    for (const oid of observationIdsOf(n)) {
      for (const cid of owners.get(oid) || []) ids.add(cid);
    }
    if (!ids.size) return n;
    return { ...n, contributor_of: [...ids],
      contributor_state: "PROVEN_BY_AUTHORITY" };
  };
  return {
    ...graph,
    process_nodes: (graph.process_nodes || []).map(stamp),
    activity_nodes: (graph.activity_nodes || []).map(stamp),
  };
}
